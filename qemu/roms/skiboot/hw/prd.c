/* Copyright 2014-2015 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * imitations under the License.
 */

#include <skiboot.h>
#include <opal.h>
#include <lock.h>
#include <xscom.h>
#include <chip.h>
#include <opal-msg.h>
#include <fsp.h>
#include <mem_region.h>
#include <prd-fw-msg.h>

enum events {
	EVENT_ATTN	= 1 << 0,
	EVENT_OCC_ERROR	= 1 << 1,
	EVENT_OCC_RESET	= 1 << 2,
	EVENT_SBE_PASSTHROUGH = 1 << 3,
};

static uint8_t events[MAX_CHIPS];
static uint64_t ipoll_status[MAX_CHIPS];
static uint8_t _prd_msg_buf[sizeof(struct opal_prd_msg) +
			    sizeof(struct prd_fw_msg)];
static struct opal_prd_msg *prd_msg = (struct opal_prd_msg *)&_prd_msg_buf;
static bool prd_msg_inuse, prd_active;
static struct dt_node *prd_node;
static bool prd_enabled = false;

/* Locking:
 *
 * The events lock serialises access to the events, ipoll_status,
 * prd_msg_inuse, and prd_active variables.
 *
 * The ipoll_lock protects against concurrent updates to the ipoll registers.
 *
 * The ipoll_lock may be acquired with events_lock held. This order must
 * be preserved.
 */
static struct lock events_lock = LOCK_UNLOCKED;
static struct lock ipoll_lock = LOCK_UNLOCKED;

static uint64_t prd_ipoll_mask_reg;
static uint64_t prd_ipoll_status_reg;
static uint64_t prd_ipoll_mask;

/* PRD registers */
#define PRD_P8_IPOLL_REG_MASK		0x01020013
#define PRD_P8_IPOLL_REG_STATUS		0x01020014
#define PRD_P8_IPOLL_XSTOP		PPC_BIT(0) /* Xstop for host/core/millicode */
#define PRD_P8_IPOLL_RECOV		PPC_BIT(1) /* Recoverable */
#define PRD_P8_IPOLL_SPEC_ATTN		PPC_BIT(2) /* Special attention */
#define PRD_P8_IPOLL_HOST_ATTN		PPC_BIT(3) /* Host attention */
#define PRD_P8_IPOLL_MASK		PPC_BITMASK(0, 3)

#define PRD_P9_IPOLL_REG_MASK		0x000F0033
#define PRD_P9_IPOLL_REG_STATUS		0x000F0034
#define PRD_P9_IPOLL_XSTOP		PPC_BIT(0) /* Xstop for host/core/millicode */
#define PRD_P9_IPOLL_RECOV		PPC_BIT(1) /* Recoverable */
#define PRD_P9_IPOLL_SPEC_ATTN		PPC_BIT(2) /* Special attention */
#define PRD_P9_IPOLL_UNIT_CS		PPC_BIT(3) /* Unit Xstop */
#define PRD_P9_IPOLL_HOST_ATTN		PPC_BIT(4) /* Host attention */
#define PRD_P9_IPOLL_MASK_INTR		PPC_BIT(5) /* Host interrupt */
#define PRD_P9_IPOLL_MASK		PPC_BITMASK(0, 5)

static void send_next_pending_event(void);

static void prd_msg_consumed(void *data)
{
	struct opal_prd_msg *msg = data;
	uint32_t proc;
	uint8_t event = 0;

	lock(&events_lock);
	switch (msg->hdr.type) {
	case OPAL_PRD_MSG_TYPE_ATTN:
		proc = msg->attn.proc;

		/* If other ipoll events have been received in the time
		 * between prd_msg creation and consumption, we'll need to
		 * raise a separate ATTN message for those. So, we only
		 * clear the event if we don't have any further ipoll_status
		 * bits.
		 */
		ipoll_status[proc] &= ~msg->attn.ipoll_status;
		if (!ipoll_status[proc])
			event = EVENT_ATTN;

		break;
	case OPAL_PRD_MSG_TYPE_OCC_ERROR:
		proc = msg->occ_error.chip;
		event = EVENT_OCC_ERROR;
		break;
	case OPAL_PRD_MSG_TYPE_OCC_RESET:
		proc = msg->occ_reset.chip;
		event = EVENT_OCC_RESET;
		break;
	case OPAL_PRD_MSG_TYPE_FIRMWARE_RESPONSE:
		break;
	case OPAL_PRD_MSG_TYPE_SBE_PASSTHROUGH:
		proc = msg->sbe_passthrough.chip;
		event = EVENT_SBE_PASSTHROUGH;
		break;
	default:
		prlog(PR_ERR, "PRD: invalid msg consumed, type: 0x%x\n",
				msg->hdr.type);
	}

	if (event)
		events[proc] &= ~event;
	prd_msg_inuse = false;
	send_next_pending_event();
	unlock(&events_lock);
}

static int populate_ipoll_msg(struct opal_prd_msg *msg, uint32_t proc)
{
	uint64_t ipoll_mask;
	int rc;

	lock(&ipoll_lock);
	rc = xscom_read(proc, prd_ipoll_mask_reg, &ipoll_mask);
	unlock(&ipoll_lock);

	if (rc) {
		prlog(PR_ERR, "PRD: Unable to read ipoll status (chip %d)!\n",
				proc);
		return -1;
	}

	msg->attn.proc = proc;
	msg->attn.ipoll_status = ipoll_status[proc];
	msg->attn.ipoll_mask = ipoll_mask;
	return 0;
}

static void send_next_pending_event(void)
{
	struct proc_chip *chip;
	uint32_t proc;
	uint8_t event;

	assert(!prd_msg_inuse);

	if (!prd_active)
		return;

	event = 0;

	for_each_chip(chip) {
		proc = chip->id;
		if (events[proc]) {
			event = events[proc];
			break;
		}
	}

	if (!event)
		return;

	prd_msg_inuse = true;
	prd_msg->token = 0;
	prd_msg->hdr.size = sizeof(*prd_msg);

	if (event & EVENT_ATTN) {
		prd_msg->hdr.type = OPAL_PRD_MSG_TYPE_ATTN;
		populate_ipoll_msg(prd_msg, proc);
	} else if (event & EVENT_OCC_ERROR) {
		prd_msg->hdr.type = OPAL_PRD_MSG_TYPE_OCC_ERROR;
		prd_msg->occ_error.chip = proc;
	} else if (event & EVENT_OCC_RESET) {
		prd_msg->hdr.type = OPAL_PRD_MSG_TYPE_OCC_RESET;
		prd_msg->occ_reset.chip = proc;
		occ_msg_queue_occ_reset();
	} else if (event & EVENT_SBE_PASSTHROUGH) {
		prd_msg->hdr.type = OPAL_PRD_MSG_TYPE_SBE_PASSTHROUGH;
		prd_msg->sbe_passthrough.chip = proc;
	}

	/*
	 * We always need to handle PSI interrupts, but if the is PRD is
	 * disabled then we shouldn't propagate PRD events to the host.
	 */
	if (prd_enabled)
		_opal_queue_msg(OPAL_MSG_PRD, prd_msg, prd_msg_consumed, 4,
				(uint64_t *)prd_msg);
}

static void __prd_event(uint32_t proc, uint8_t event)
{
	events[proc] |= event;
	if (!prd_msg_inuse)
		send_next_pending_event();
}

static void prd_event(uint32_t proc, uint8_t event)
{
	lock(&events_lock);
	__prd_event(proc, event);
	unlock(&events_lock);
}

static int __ipoll_update_mask(uint32_t proc, bool set, uint64_t bits)
{
	uint64_t mask;
	int rc;

	rc = xscom_read(proc, prd_ipoll_mask_reg, &mask);
	if (rc)
		return rc;

	if (set)
		mask |= bits;
	else
		mask &= ~bits;

	return xscom_write(proc, prd_ipoll_mask_reg, mask);
}

static int ipoll_record_and_mask_pending(uint32_t proc)
{
	uint64_t status;
	int rc;

	lock(&ipoll_lock);
	rc = xscom_read(proc, prd_ipoll_status_reg, &status);
	status &= prd_ipoll_mask;
	if (!rc)
		__ipoll_update_mask(proc, true, status);
	unlock(&ipoll_lock);

	if (!rc)
		ipoll_status[proc] |= status;

	return rc;
}

/* Entry point for interrupts */
void prd_psi_interrupt(uint32_t proc)
{
	int rc;

	lock(&events_lock);

	rc = ipoll_record_and_mask_pending(proc);
	if (rc)
		prlog(PR_ERR, "PRD: Failed to update IPOLL mask\n");

	__prd_event(proc, EVENT_ATTN);

	unlock(&events_lock);
}

void prd_tmgt_interrupt(uint32_t proc)
{
	prd_event(proc, EVENT_OCC_ERROR);
}

void prd_occ_reset(uint32_t proc)
{
	prd_event(proc, EVENT_OCC_RESET);
}

void prd_sbe_passthrough(uint32_t proc)
{
	prd_event(proc, EVENT_SBE_PASSTHROUGH);
}

/* incoming message handlers */
static int prd_msg_handle_attn_ack(struct opal_prd_msg *msg)
{
	int rc;

	lock(&ipoll_lock);
	rc = __ipoll_update_mask(msg->attn_ack.proc, false,
			msg->attn_ack.ipoll_ack & prd_ipoll_mask);
	unlock(&ipoll_lock);

	if (rc)
		prlog(PR_ERR, "PRD: Unable to unmask ipoll!\n");

	return rc;
}

static int prd_msg_handle_init(struct opal_prd_msg *msg)
{
	struct proc_chip *chip;

	lock(&ipoll_lock);
	for_each_chip(chip) {
		__ipoll_update_mask(chip->id, false,
			msg->init.ipoll & prd_ipoll_mask);
	}
	unlock(&ipoll_lock);

	/* we're transitioning from inactive to active; send any pending tmgt
	 * interrupts */
	lock(&events_lock);
	prd_active = true;
	if (!prd_msg_inuse)
		send_next_pending_event();
	unlock(&events_lock);

	return OPAL_SUCCESS;
}

static int prd_msg_handle_fini(void)
{
	struct proc_chip *chip;

	lock(&events_lock);
	prd_active = false;
	unlock(&events_lock);

	lock(&ipoll_lock);
	for_each_chip(chip) {
		__ipoll_update_mask(chip->id, true, prd_ipoll_mask);
	}
	unlock(&ipoll_lock);

	return OPAL_SUCCESS;
}

static int prd_msg_handle_firmware_req(struct opal_prd_msg *msg)
{
	unsigned long fw_req_len, fw_resp_len;
	struct prd_fw_msg *fw_req, *fw_resp;
	int rc;

	fw_req_len = be64_to_cpu(msg->fw_req.req_len);
	fw_resp_len = be64_to_cpu(msg->fw_req.resp_len);
	fw_req = (struct prd_fw_msg *)msg->fw_req.data;

	/* do we have a full firmware message? */
	if (fw_req_len < sizeof(struct prd_fw_msg))
		return -EINVAL;

	/* does the total (outer) PRD message len provide enough data for the
	 * claimed (inner) FW message?
	 */
	if (msg->hdr.size < fw_req_len +
			offsetof(struct opal_prd_msg, fw_req.data))
		return -EINVAL;

	/* is there enough response buffer for a base response? Type-specific
	 * responses may be larger, but anything less than BASE_SIZE is
	 * invalid. */
	if (fw_resp_len < PRD_FW_MSG_BASE_SIZE)
		return -EINVAL;

	/* prepare a response message. */
	lock(&events_lock);
	prd_msg_inuse = true;
	prd_msg->token = 0;
	prd_msg->hdr.type = OPAL_PRD_MSG_TYPE_FIRMWARE_RESPONSE;
	fw_resp = (void *)prd_msg->fw_resp.data;

	switch (be64_to_cpu(fw_req->type)) {
	case PRD_FW_MSG_TYPE_REQ_NOP:
		fw_resp->type = cpu_to_be64(PRD_FW_MSG_TYPE_RESP_NOP);
		prd_msg->fw_resp.len = cpu_to_be64(PRD_FW_MSG_BASE_SIZE);
		prd_msg->hdr.size = cpu_to_be16(sizeof(*prd_msg));
		rc = 0;
		break;
	default:
		rc = -ENOSYS;
	}

	if (!rc)
		rc = _opal_queue_msg(OPAL_MSG_PRD, prd_msg, prd_msg_consumed, 4,
				(uint64_t *) prd_msg);
	else
		prd_msg_inuse = false;

	unlock(&events_lock);

	return rc;
}

/* Entry from the host above */
static int64_t opal_prd_msg(struct opal_prd_msg *msg)
{
	int rc;

	/* fini is a little special: the kernel (which may not have the entire
	 * opal_prd_msg definition) can send a FINI message, so we don't check
	 * the full size */
	if (msg->hdr.size >= sizeof(struct opal_prd_msg_header) &&
			msg->hdr.type == OPAL_PRD_MSG_TYPE_FINI)
		return prd_msg_handle_fini();

	if (msg->hdr.size < sizeof(*msg))
		return OPAL_PARAMETER;

	switch (msg->hdr.type) {
	case OPAL_PRD_MSG_TYPE_INIT:
		rc = prd_msg_handle_init(msg);
		break;
	case OPAL_PRD_MSG_TYPE_ATTN_ACK:
		rc = prd_msg_handle_attn_ack(msg);
		break;
	case OPAL_PRD_MSG_TYPE_OCC_RESET_NOTIFY:
		rc = occ_msg_queue_occ_reset();
		break;
	case OPAL_PRD_MSG_TYPE_FIRMWARE_REQUEST:
		rc = prd_msg_handle_firmware_req(msg);
		break;
	default:
		rc = OPAL_UNSUPPORTED;
	}

	return rc;
}


/*
 * Initialise the Opal backend for the PRD daemon. This must be called from
 * platform probe or init function.
 */
void prd_init(void)
{
	struct proc_chip *chip;

	switch (proc_gen) {
	case proc_gen_p8:
		prd_ipoll_mask_reg = PRD_P8_IPOLL_REG_MASK;
		prd_ipoll_status_reg = PRD_P8_IPOLL_REG_STATUS;
		prd_ipoll_mask = PRD_P8_IPOLL_MASK;
		break;
	case proc_gen_p9:
		prd_ipoll_mask_reg = PRD_P9_IPOLL_REG_MASK;
		prd_ipoll_status_reg = PRD_P9_IPOLL_REG_STATUS;
		prd_ipoll_mask = PRD_P9_IPOLL_MASK;
		break;
	default:
		assert(0);
	}

	/* mask everything */
	lock(&ipoll_lock);
	for_each_chip(chip) {
		__ipoll_update_mask(chip->id, true, prd_ipoll_mask);
	}
	unlock(&ipoll_lock);

	prd_enabled = true;
	opal_register(OPAL_PRD_MSG, opal_prd_msg, 1);

	prd_node = dt_new(opal_node, "diagnostics");
	dt_add_property_strings(prd_node, "compatible", "ibm,opal-prd");
}

void prd_register_reserved_memory(void)
{
	struct mem_region *region;

	if (!prd_node)
		return;

	lock(&mem_region_lock);
	for (region = mem_region_next(NULL); region;
			region = mem_region_next(region)) {

		if (region->type != REGION_FW_RESERVED)
			continue;

		if (!region->node)
			continue;

		if (!dt_find_property(region->node, "ibm,prd-label")) {
			dt_add_property_string(region->node, "ibm,prd-label",
					region->name);
		}
	}
	unlock(&mem_region_lock);
}
