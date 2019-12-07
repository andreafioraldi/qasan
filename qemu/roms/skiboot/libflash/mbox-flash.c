/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define pr_fmt(fmt) "MBOX-FLASH: " fmt

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <skiboot.h>
#include <inttypes.h>
#include <timebase.h>
#include <timer.h>
#include <libflash/libflash.h>
#include <libflash/mbox-flash.h>
#include <lpc.h>
#include <lpc-mbox.h>

#include <ccan/container_of/container_of.h>

#ifndef __SKIBOOT__
#error "This libflash backend must be compiled with skiboot"
#endif

#define MBOX_DEFAULT_TIMEOUT 30

struct lpc_window {
	uint32_t lpc_addr; /* Offset into LPC space */
	uint32_t cur_pos;  /* Current position of the window in the flash */
	uint32_t size;     /* Size of the window into the flash */
	bool open;
};

struct mbox_flash_data {
	int version;
	uint32_t shift;
	struct lpc_window read;
	struct lpc_window write;
	struct blocklevel_device bl;
	uint32_t total_size;
	uint32_t erase_granule;
	int rc;
	bool reboot;
	bool pause;
	bool busy;
	bool ack;
	uint8_t seq;
	/* Plus one, commands start at 1 */
	void (*handlers[MBOX_COMMAND_COUNT + 1])(struct mbox_flash_data *, struct bmc_mbox_msg*);
	struct bmc_mbox_msg msg_mem;
};

static void mbox_flash_callback(struct bmc_mbox_msg *msg, void *priv);
static void mbox_flash_attn(uint8_t attn, void *priv);

static int protocol_init(struct mbox_flash_data *mbox_flash);

static int lpc_window_read(struct mbox_flash_data *mbox_flash, uint32_t pos,
			   void *buf, uint32_t len)
{
	uint32_t off = mbox_flash->read.lpc_addr + (pos - mbox_flash->read.cur_pos);
	int rc;

	prlog(PR_TRACE, "Reading at 0x%08x for 0x%08x offset: 0x%08x\n",
			pos, len, off);

	while(len) {
		uint32_t chunk;
		uint32_t dat;

		/* XXX: make this read until it's aligned */
		if (len > 3 && !(off & 3)) {
			rc = lpc_read(OPAL_LPC_FW, off, &dat, 4);
			if (!rc)
				*(uint32_t *)buf = dat;
			chunk = 4;
		} else {
			rc = lpc_read(OPAL_LPC_FW, off, &dat, 1);
			if (!rc)
				*(uint8_t *)buf = dat;
			chunk = 1;
		}
		if (rc) {
			prlog(PR_ERR, "lpc_read failure %d to FW 0x%08x\n", rc, off);
			return rc;
		}
		len -= chunk;
		off += chunk;
		buf += chunk;
	}

	return 0;
}

static int lpc_window_write(struct mbox_flash_data *mbox_flash, uint32_t pos,
			    const void *buf, uint32_t len)
{
	uint32_t off = mbox_flash->write.lpc_addr + (pos - mbox_flash->write.cur_pos);
	int rc;


	prlog(PR_TRACE, "Writing at 0x%08x for 0x%08x offset: 0x%08x\n",
			pos, len, off);

	while(len) {
		uint32_t chunk;

		if (len > 3 && !(off & 3)) {
			rc = lpc_write(OPAL_LPC_FW, off,
				       *(uint32_t *)buf, 4);
			chunk = 4;
		} else {
			rc = lpc_write(OPAL_LPC_FW, off,
				       *(uint8_t *)buf, 1);
			chunk = 1;
		}
		if (rc) {
			prlog(PR_ERR, "lpc_write failure %d to FW 0x%08x\n", rc, off);
			return rc;
		}
		len -= chunk;
		off += chunk;
		buf += chunk;
	}

	return 0;
}

static uint64_t mbox_flash_mask(struct mbox_flash_data *mbox_flash)
{
	return (1ULL << mbox_flash->shift) - 1;
}

__unused static uint8_t msg_get_u8(struct bmc_mbox_msg *msg, int i)
{
	return msg->args[i];
}

static void msg_put_u8(struct bmc_mbox_msg *msg, int i, uint8_t val)
{
	msg->args[i] = val;
}

static uint16_t msg_get_u16(struct bmc_mbox_msg *msg, int i)
{
	return le16_to_cpu(*(uint16_t *)(&msg->args[i]));
}

static void msg_put_u16(struct bmc_mbox_msg *msg, int i, uint16_t val)
{
	uint16_t tmp = cpu_to_le16(val);
	memcpy(&msg->args[i], &tmp, sizeof(val));
}

static uint32_t msg_get_u32(struct bmc_mbox_msg *msg, int i)
{
	return le32_to_cpu(*(uint32_t *)(&msg->args[i]));
}

static void msg_put_u32(struct bmc_mbox_msg *msg, int i, uint32_t val)
{
	uint32_t tmp = cpu_to_le32(val);
	memcpy(&msg->args[i], &tmp, sizeof(val));
}

static uint32_t blocks_to_bytes(struct mbox_flash_data *mbox_flash, uint16_t blocks)
{
	return blocks << mbox_flash->shift;
}

static uint16_t bytes_to_blocks(struct mbox_flash_data *mbox_flash,
				uint32_t bytes)
{
	return bytes >> mbox_flash->shift;
}

static struct bmc_mbox_msg *msg_alloc(struct mbox_flash_data *mbox_flash,
		uint8_t command)
{
	/*
	 * Yes this causes *slow*.
	 * This file and lpc-mbox have far greater slow points, zeroed
	 * data regs are VERY useful for debugging. Think twice if this is
	 * really the performance optimisation you want to make.
	 */
	memset(&mbox_flash->msg_mem, 0, sizeof(mbox_flash->msg_mem));
	mbox_flash->msg_mem.seq = ++mbox_flash->seq;
	mbox_flash->msg_mem.command = command;
	return &mbox_flash->msg_mem;
}

static void msg_free_memory(struct bmc_mbox_msg *mem __unused)
{
	/* Allocation is so simple this isn't required */
}

/*
 * The BMC may send is an out of band message to say that it doesn't
 * own the flash anymore.
 * It guarantees we can still access our (open) windows but it does
 * not guarantee their contents until it clears the bit without
 * sending us a corresponding bit to say that the windows are bad
 * first.
 * Since this is all things that will happen in the future, we should
 * not perform any calls speculatively as its almost impossible to
 * rewind.
 */
static bool is_paused(struct mbox_flash_data *mbox_flash)
{
	return mbox_flash->pause;
}

/*
 * After a read or a write it is wise to check that the window we just
 * read/write to/from is still valid otherwise it is possible some of
 * the data didn't make it.
 * This check is an optimisation as we'll close all our windows on any
 * notification from the BMC that the windows are bad. See the above
 * comment about is_paused().
 * A foolproof (but much closer) method of validating reads/writes
 * would be to attempt to close the window, if that fails then we can
 * be sure that the read/write was no good.
 */
static bool is_valid(struct mbox_flash_data *mbox_flash, struct lpc_window *win)
{
	return !is_paused(mbox_flash) && win->open;
}

/*
 * Check if we've received a BMC reboot notification.
 * The strategy is to check on entry to mbox-flash and return a
 * failure accordingly. Races will be handled by the fact that the BMC
 * won't respond so timeouts will occur. As an added precaution
 * msg_send() checks right before sending a message (to make the race
 * as small as possible to avoid needless timeouts).
 */
static bool is_reboot(struct mbox_flash_data *mbox_flash)
{
	return mbox_flash->reboot;
}

static int msg_send(struct mbox_flash_data *mbox_flash, struct bmc_mbox_msg *msg)
{
	if (is_reboot(mbox_flash))
		return FLASH_ERR_AGAIN;
	mbox_flash->busy = true;
	mbox_flash->rc = 0;
	return bmc_mbox_enqueue(msg);
}

static int wait_for_bmc(struct mbox_flash_data *mbox_flash, unsigned int timeout_sec)
{
	unsigned long last = 1, start = tb_to_secs(mftb());
	prlog(PR_TRACE, "Waiting for BMC\n");
	while (mbox_flash->busy && timeout_sec) {
		long now = tb_to_secs(mftb());
		if (now - start > last) {
			timeout_sec--;
			last = now - start;
			if (last < timeout_sec / 2)
				prlog(PR_TRACE, "Been waiting for the BMC for %lu secs\n", last);
			else
				prlog(PR_ERR, "BMC NOT RESPONDING %lu second wait\n", last);
		}
		/*
		 * Both functions are important.
		 * Well time_wait_ms() relaxes the spin... so... its nice
		 */
		time_wait_ms(MBOX_DEFAULT_POLL_MS);
		check_timers(false);
		asm volatile ("" ::: "memory");
	}

	if (mbox_flash->busy) {
		prlog(PR_ERR, "Timeout waiting for BMC\n");
		mbox_flash->busy = false;
		return MBOX_R_TIMEOUT;
	}

	return mbox_flash->rc;
}

static int mbox_flash_ack(struct mbox_flash_data *mbox_flash, uint8_t reg)
{
	struct bmc_mbox_msg *msg;
	int rc;

	msg = msg_alloc(mbox_flash, MBOX_C_BMC_EVENT_ACK);
	if (!msg)
		return FLASH_ERR_MALLOC_FAILED;

	msg_put_u8(msg, 0, reg);

	/* Clear this first so msg_send() doesn't freak out */
	mbox_flash->reboot = false;

	rc = msg_send(mbox_flash, msg);

	/* Still need to deal with it, we've only acked it now. */
	mbox_flash->reboot = true;

	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		goto out;
	}

	/*
	 * Use a lower timeout - there is strong evidence to suggest the
	 * BMC won't respond, don't waste time spinning here just have the
	 * high levels retry when the BMC might be back
	 */
	rc = wait_for_bmc(mbox_flash, 3);
	if (rc)
		prlog(PR_ERR, "Error waiting for BMC\n");

out:
	msg_free_memory(msg);
	return rc;
}

static int do_acks(struct mbox_flash_data *mbox_flash)
{
	int rc;

	if (!mbox_flash->ack)
		return 0; /* Nothing to do */

	rc = mbox_flash_ack(mbox_flash, bmc_mbox_get_attn_reg() & MBOX_ATTN_ACK_MASK);
	if (!rc)
		mbox_flash->ack = false;

	return rc;
}

static void mbox_flash_do_nop(struct mbox_flash_data *mbox_flash __unused,
		struct bmc_mbox_msg *msg __unused)
{
}

/* Version 1 and Version 2 compatible */
static void mbox_flash_do_get_mbox_info(struct mbox_flash_data *mbox_flash,
		struct bmc_mbox_msg *msg)
{

	mbox_flash->version = msg_get_u8(msg, 0);
	if (mbox_flash->version == 1) {
		/* Not all version 1 daemons set argument 5 correctly */
		mbox_flash->shift = 12; /* Protocol hardcodes to 4K anyway */
		mbox_flash->read.size = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 1));
		mbox_flash->write.size = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 3));
	} else { /* V2 compatible */
		mbox_flash->shift = msg_get_u8(msg, 5);
	}
	/* Callers will handle the case where the version is not known
	 *
	 * Here we deliberately ignore the 'default' sizes.
	 * All windows opened will not provide a hint and we're
	 * happy to let the BMC figure everything out.
	 * Future optimisations may use the default size.
	 */
}

static void mbox_flash_do_get_flash_info_v2(struct mbox_flash_data *mbox_flash,
		struct bmc_mbox_msg *msg)
{
	mbox_flash->total_size = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 0));
	mbox_flash->erase_granule = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 2));
}

static void mbox_flash_do_get_flash_info_v1(struct mbox_flash_data *mbox_flash,
		struct bmc_mbox_msg *msg)
{
	mbox_flash->total_size = msg_get_u32(msg, 0);
	mbox_flash->erase_granule = msg_get_u32(msg, 4);
}

static void mbox_flash_do_create_read_window_v2(struct mbox_flash_data *mbox_flash,
		struct bmc_mbox_msg *msg)
{
	mbox_flash->read.lpc_addr = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 0));
	mbox_flash->read.size = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 2));
	mbox_flash->read.cur_pos = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 4));
	mbox_flash->read.open = true;
	mbox_flash->write.open = false;
}

static void mbox_flash_do_create_read_window_v1(struct mbox_flash_data *mbox_flash,
		struct bmc_mbox_msg *msg)
{
	mbox_flash->read.lpc_addr = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 0));
	mbox_flash->read.open = true;
	mbox_flash->write.open = false;
}

static void mbox_flash_do_create_write_window_v2(struct mbox_flash_data *mbox_flash,
		struct bmc_mbox_msg *msg)
{
	mbox_flash->write.lpc_addr = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 0));
	mbox_flash->write.size = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 2));
	mbox_flash->write.cur_pos = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 4));
	mbox_flash->write.open = true;
	mbox_flash->read.open = false;
}

static void mbox_flash_do_create_write_window_v1(struct mbox_flash_data *mbox_flash,
		struct bmc_mbox_msg *msg)
{
	mbox_flash->write.lpc_addr = blocks_to_bytes(mbox_flash, msg_get_u16(msg, 0));
	mbox_flash->write.open = true;
	mbox_flash->read.open = false;
}

/* Version 1 and Version 2 compatible */
static void mbox_flash_do_close_window(struct mbox_flash_data *mbox_flash,
		struct bmc_mbox_msg *msg __unused)
{
	mbox_flash->read.open = false;
	mbox_flash->write.open = false;
}

static int handle_reboot(struct mbox_flash_data *mbox_flash)
{
	int rc;

	/*
	 * If the BMC ready bit isn't present then we're basically
	 * guaranteed to timeout trying to talk to it so just fail
	 * whatever is trying to happen.
	 * Importantly, we can't trust that the presence of the bit means
	 * the daemon is ok - don't assume it is going to respond at all
	 * from here onwards
	 */
	if (!(bmc_mbox_get_attn_reg() & MBOX_ATTN_BMC_DAEMON_READY))
		return FLASH_ERR_AGAIN;

	/* Clear this first so msg_send() doesn't freak out */
	mbox_flash->reboot = false;

	rc = do_acks(mbox_flash);
	if (rc) {
		if (rc == MBOX_R_TIMEOUT)
			rc = FLASH_ERR_AGAIN;
		mbox_flash->reboot = true;
		return rc;
	}

	rc = protocol_init(mbox_flash);
	if (rc)
		mbox_flash->reboot = true;

	return rc;
}

static bool do_delayed_work(struct mbox_flash_data *mbox_flash)
{
	return is_paused(mbox_flash) || do_acks(mbox_flash) ||
		(is_reboot(mbox_flash) && handle_reboot(mbox_flash));
}

static int mbox_flash_mark_write(struct mbox_flash_data *mbox_flash,
				 uint64_t pos, uint64_t len, int type)
{
	struct bmc_mbox_msg *msg;
	int rc;

	msg = msg_alloc(mbox_flash, type);
	if (!msg)
		return FLASH_ERR_MALLOC_FAILED;

	if (mbox_flash->version == 1) {
		uint32_t start = ALIGN_DOWN(pos, 1 << mbox_flash->shift);
		msg_put_u16(msg, 0, bytes_to_blocks(mbox_flash, pos));
		/*
		 * We need to make sure that we mark dirty until up to atleast
		 * pos + len.
		 */
		msg_put_u32(msg, 2, pos + len - start);
	} else {
		uint64_t window_pos = pos - mbox_flash->write.cur_pos;
		uint16_t start = bytes_to_blocks(mbox_flash, window_pos);
		uint16_t end = bytes_to_blocks(mbox_flash,
					       ALIGN_UP(window_pos + len,
							1 << mbox_flash->shift));

		msg_put_u16(msg, 0, start);
		msg_put_u16(msg, 2, end - start); /* Total Length */
	}

	rc = msg_send(mbox_flash, msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		goto out;
	}

	rc = wait_for_bmc(mbox_flash, MBOX_DEFAULT_TIMEOUT);
	if (rc) {
		prlog(PR_ERR, "Error waiting for BMC\n");
		goto out;
	}

out:
	msg_free_memory(msg);
	return rc;
}

static int mbox_flash_dirty(struct mbox_flash_data *mbox_flash, uint64_t pos,
		uint64_t len)
{
	if (!mbox_flash->write.open) {
		prlog(PR_ERR, "Attempting to dirty without an open write window\n");
		return FLASH_ERR_DEVICE_GONE;
	}

	return mbox_flash_mark_write(mbox_flash, pos, len,
				     MBOX_C_MARK_WRITE_DIRTY);
}

static int mbox_flash_erase(struct mbox_flash_data *mbox_flash, uint64_t pos,
			    uint64_t len)
{
	if (!mbox_flash->write.open) {
		prlog(PR_ERR, "Attempting to erase without an open write window\n");
		return FLASH_ERR_DEVICE_GONE;
	}

	return mbox_flash_mark_write(mbox_flash, pos, len,
				     MBOX_C_MARK_WRITE_ERASED);
}

static int mbox_flash_flush(struct mbox_flash_data *mbox_flash)
{
	struct bmc_mbox_msg *msg;
	int rc;

	if (!mbox_flash->write.open) {
		prlog(PR_ERR, "Attempting to flush without an open write window\n");
		return FLASH_ERR_DEVICE_GONE;
	}

	msg = msg_alloc(mbox_flash, MBOX_C_WRITE_FLUSH);
	if (!msg)
		return FLASH_ERR_MALLOC_FAILED;

	rc = msg_send(mbox_flash, msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		goto out;
	}

	rc = wait_for_bmc(mbox_flash, MBOX_DEFAULT_TIMEOUT);
	if (rc)
		prlog(PR_ERR, "Error waiting for BMC\n");

out:
	msg_free_memory(msg);
	return rc;
}

/* Is the current window able perform the complete operation */
static bool mbox_window_valid(struct lpc_window *win, uint64_t pos,
			      uint64_t len)
{
	if (!win->open)
		return false;
	if (pos < win->cur_pos) /* start */
		return false;
	if ((pos + len) > (win->cur_pos + win->size)) /* end */
		return false;
	return true;
}

static int mbox_window_move(struct mbox_flash_data *mbox_flash,
			    struct lpc_window *win, uint8_t command,
			    uint64_t pos, uint64_t len, uint64_t *size)
{
	struct bmc_mbox_msg *msg;
	int rc;

	/* Is the window currently open valid */
	if (mbox_window_valid(win, pos, len)) {
		*size = len;
		return 0;
	}

	prlog(PR_DEBUG, "Adjusting the window\n");

	/* V1 needs to remember where it has opened the window, note it
	 * here.
	 * If we're running V2 the response to the CREATE_*_WINDOW command
	 * will overwrite what we've noted here.
	 */
	win->cur_pos = pos & ~mbox_flash_mask(mbox_flash);

	msg = msg_alloc(mbox_flash, command);
	if (!msg)
		return FLASH_ERR_MALLOC_FAILED;

	msg_put_u16(msg, 0, bytes_to_blocks(mbox_flash, pos));
	rc = msg_send(mbox_flash, msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		goto out;
	}

	rc = wait_for_bmc(mbox_flash, MBOX_DEFAULT_TIMEOUT);
	if (rc) {
		prlog(PR_ERR, "Error waiting for BMC\n");
		goto out;
	}

	*size = len;
	/* Is length past the end of the window? */
	if ((pos + len) > (win->cur_pos + win->size))
		/* Adjust size to meet current window */
		*size =  (win->cur_pos + win->size) - pos;

	/*
	 * It doesn't make sense for size to be zero if len isn't zero.
	 * If this condition happens we're most likely going to spin since
	 * the caller will likely decerement pos by zero then call this
	 * again.
	 * Debateable as to if this should return non zero. At least the
	 * bug will be obvious from the barf.
	 */
	if (len != 0 && *size == 0) {
		prlog(PR_ERR, "Move window is indicating size zero!\n");
		prlog(PR_ERR, "pos: 0x%" PRIx64 ", len: 0x%" PRIx64 "\n", pos, len);
		prlog(PR_ERR, "win pos: 0x%08x win size: 0x%08x\n", win->cur_pos, win->size);
	}

out:
	msg_free_memory(msg);
	return rc;
}

static int mbox_flash_write(struct blocklevel_device *bl, uint64_t pos,
			    const void *buf, uint64_t len)
{
	struct mbox_flash_data *mbox_flash;
	uint64_t size;

	int rc = 0;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	mbox_flash = container_of(bl, struct mbox_flash_data, bl);

	if (do_delayed_work(mbox_flash))
		return FLASH_ERR_AGAIN;

	prlog(PR_TRACE, "Flash write at %#" PRIx64 " for %#" PRIx64 "\n", pos, len);
	while (len > 0) {
		/* Move window and get a new size to read */
		rc = mbox_window_move(mbox_flash, &mbox_flash->write,
				      MBOX_C_CREATE_WRITE_WINDOW, pos, len,
				      &size);
		if (rc)
			return rc;

 		/* Perform the read for this window */
		rc = lpc_window_write(mbox_flash, pos, buf, size);
		if (rc)
			return rc;

		rc = mbox_flash_dirty(mbox_flash, pos, size);
		if (rc)
			return rc;

		/*
		 * Must flush here as changing the window contents
		 * without flushing entitles the BMC to throw away the
		 * data. Unlike the read case there isn't a need to explicitly
		 * validate the window, the flush command will fail if the
		 * window was compromised.
		 */
		rc = mbox_flash_flush(mbox_flash);
		if (rc)
			return rc;

		len -= size;
		pos += size;
		buf += size;
	}
	return rc;
}

static int mbox_flash_read(struct blocklevel_device *bl, uint64_t pos,
			   void *buf, uint64_t len)
{
	struct mbox_flash_data *mbox_flash;
	uint64_t size;

	int rc = 0;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	mbox_flash = container_of(bl, struct mbox_flash_data, bl);

	if (do_delayed_work(mbox_flash))
		return FLASH_ERR_AGAIN;

	prlog(PR_TRACE, "Flash read at %#" PRIx64 " for %#" PRIx64 "\n", pos, len);
	while (len > 0) {
		/* Move window and get a new size to read */
		rc = mbox_window_move(mbox_flash, &mbox_flash->read,
				      MBOX_C_CREATE_READ_WINDOW, pos,
				      len, &size);
		if (rc)
			return rc;

 		/* Perform the read for this window */
		rc = lpc_window_read(mbox_flash, pos, buf, size);
		if (rc)
			return rc;

		len -= size;
		pos += size;
		buf += size;
		/*
		 * Ensure my window is still open, if it isn't we can't trust
		 * what we read
		 */
		if (!is_valid(mbox_flash, &mbox_flash->read))
			return FLASH_ERR_AGAIN;
	}
	return rc;
}

static int mbox_flash_get_info(struct blocklevel_device *bl, const char **name,
		uint64_t *total_size, uint32_t *erase_granule)
{
	struct mbox_flash_data *mbox_flash;
	struct bmc_mbox_msg *msg;
	int rc;

	mbox_flash = container_of(bl, struct mbox_flash_data, bl);

	if (do_delayed_work(mbox_flash))
		return FLASH_ERR_AGAIN;

	msg = msg_alloc(mbox_flash, MBOX_C_GET_FLASH_INFO);
	if (!msg)
		return FLASH_ERR_MALLOC_FAILED;

	/*
	 * We want to avoid runtime mallocs in skiboot. The expected
	 * behavour to uses of libflash is that one can free() the memory
	 * returned.
	 * NULL will do for now.
	 */
	if (name)
		*name = NULL;

	mbox_flash->busy = true;
	rc = msg_send(mbox_flash, msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		goto out;
	}

	if (wait_for_bmc(mbox_flash, MBOX_DEFAULT_TIMEOUT)) {
		prlog(PR_ERR, "Error waiting for BMC\n");
		goto out;
	}

	mbox_flash->bl.erase_mask = mbox_flash->erase_granule - 1;

	if (total_size)
		*total_size = mbox_flash->total_size;
	if (erase_granule)
		*erase_granule = mbox_flash->erase_granule;

out:
	msg_free_memory(msg);
	return rc;
}

static int mbox_flash_erase_v2(struct blocklevel_device *bl, uint64_t pos,
			       uint64_t len)
{
	struct mbox_flash_data *mbox_flash;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	mbox_flash = container_of(bl, struct mbox_flash_data, bl);

	prlog(PR_TRACE, "Flash erase at 0x%08x for 0x%08x\n", (u32) pos, (u32) len);
	while (len > 0) {
		uint64_t size;
		int rc;

		/* Move window and get a new size to erase */
		rc = mbox_window_move(mbox_flash, &mbox_flash->write,
				      MBOX_C_CREATE_WRITE_WINDOW, pos, len, &size);
		if (rc)
			return rc;

		rc = mbox_flash_erase(mbox_flash, pos, size);
		if (rc)
			return rc;

		/*
		* Flush directly, don't mark that region dirty otherwise it
		* isn't clear if a write happened there or not
		*/

		rc = mbox_flash_flush(mbox_flash);
		if (rc)
			return rc;

		len -= size;
		pos += size;
	}

	return 0;
}

static int mbox_flash_erase_v1(struct blocklevel_device *bl __unused,
			       uint64_t pos __unused, uint64_t len __unused)
{
	/*
	* We can probably get away with doing nothing.
	* TODO: Rethink this, causes interesting behaviour in pflash.
	* Users do expect pflash -{e,E} to do something. This is because
	* on real flash this would have set that region to all 0xFF but
	* really the erase at the blocklevel interface was only designed
	* to be "please make this region writeable".
	* It may be wise (despite the large performance penalty) to
	* actually write all 0xFF here. I'll leave that as an exercise
	* for the future.
	*/

	return 0;
}

/* Called from interrupt handler, don't send any mbox messages */
static void mbox_flash_attn(uint8_t attn, void *priv)
{
	struct mbox_flash_data *mbox_flash = priv;

	if (attn & MBOX_ATTN_ACK_MASK)
		mbox_flash->ack = true;
	if (attn & MBOX_ATTN_BMC_REBOOT) {
		mbox_flash->reboot = true;
		mbox_flash->read.open = false;
		mbox_flash->write.open = false;
		attn &= ~MBOX_ATTN_BMC_REBOOT;
	}

	if (attn & MBOX_ATTN_BMC_WINDOW_RESET) {
		mbox_flash->read.open = false;
		mbox_flash->write.open = false;
		attn &= ~MBOX_ATTN_BMC_WINDOW_RESET;
	}

	if (attn & MBOX_ATTN_BMC_FLASH_LOST) {
		mbox_flash->pause = true;
		attn &= ~MBOX_ATTN_BMC_FLASH_LOST;
	} else {
		mbox_flash->pause = false;
	}

	if (attn & MBOX_ATTN_BMC_DAEMON_READY)
		attn &= ~MBOX_ATTN_BMC_DAEMON_READY;
}

static void mbox_flash_callback(struct bmc_mbox_msg *msg, void *priv)
{
	struct mbox_flash_data *mbox_flash = priv;

	prlog(PR_TRACE, "BMC OK command %u\n", msg->command);

	if (msg->response != MBOX_R_SUCCESS) {
		prlog(PR_ERR, "Bad response code from BMC %d\n", msg->response);
		mbox_flash->rc = msg->response;
		goto out;
	}

	if (msg->seq != mbox_flash->seq) {
		/* Uhoh */
		prlog(PR_ERR, "Sequence numbers don't match! Got: %02x Expected: %02x\n",
				msg->seq, mbox_flash->seq);
		mbox_flash->rc = MBOX_R_SYSTEM_ERROR;
		goto out;
	}

	if (msg->command > MBOX_COMMAND_COUNT) {
		prlog(PR_ERR, "Got response to unknown command %02x\n", msg->command);
		mbox_flash->rc = -1;
		goto out;
	}

	if (!mbox_flash->handlers[msg->command]) {
		prlog(PR_ERR, "Couldn't find handler for message! command: %u, seq: %u\n",
				msg->command, msg->seq);
		mbox_flash->rc = MBOX_R_SYSTEM_ERROR;
		goto out;
	}

	mbox_flash->rc = 0;

	mbox_flash->handlers[msg->command](mbox_flash, msg);

out:
	mbox_flash->busy = false;
}

static int protocol_init(struct mbox_flash_data *mbox_flash)
{
	struct bmc_mbox_msg *msg;
	int rc;

	/* Assume V2 */
	mbox_flash->bl.read = &mbox_flash_read;
	mbox_flash->bl.write = &mbox_flash_write;
	mbox_flash->bl.erase = &mbox_flash_erase_v2;
	mbox_flash->bl.get_info = &mbox_flash_get_info;

	/* Assume V2 */
	mbox_flash->handlers[0] = NULL;
	mbox_flash->handlers[MBOX_C_RESET_STATE] = &mbox_flash_do_nop;
	mbox_flash->handlers[MBOX_C_GET_MBOX_INFO] = &mbox_flash_do_get_mbox_info;
	mbox_flash->handlers[MBOX_C_GET_FLASH_INFO] = &mbox_flash_do_get_flash_info_v2;
	mbox_flash->handlers[MBOX_C_CREATE_READ_WINDOW] = &mbox_flash_do_create_read_window_v2;
	mbox_flash->handlers[MBOX_C_CLOSE_WINDOW] = &mbox_flash_do_close_window;
	mbox_flash->handlers[MBOX_C_CREATE_WRITE_WINDOW] = &mbox_flash_do_create_write_window_v2;
	mbox_flash->handlers[MBOX_C_MARK_WRITE_DIRTY] = &mbox_flash_do_nop;
	mbox_flash->handlers[MBOX_C_WRITE_FLUSH] = &mbox_flash_do_nop;
	mbox_flash->handlers[MBOX_C_BMC_EVENT_ACK] = &mbox_flash_do_nop;
	mbox_flash->handlers[MBOX_C_MARK_WRITE_ERASED] = &mbox_flash_do_nop;


	bmc_mbox_register_callback(&mbox_flash_callback, mbox_flash);
	bmc_mbox_register_attn(&mbox_flash_attn, mbox_flash);

	/*
	 * For V1 of the protocol this is fixed.
	 * V2: The init code will update this
	 */
	mbox_flash->shift = 12;

	/*
	 * Always attempt init with V2.
	 * The GET_MBOX_INFO response will confirm that the other side can
	 * talk V2, we'll update this variable then if V2 is not supported
	 */
	mbox_flash->version = 2;

	msg = msg_alloc(mbox_flash, MBOX_C_GET_MBOX_INFO);
	if (!msg)
		return FLASH_ERR_MALLOC_FAILED;

	msg_put_u8(msg, 0, mbox_flash->version);
	rc = msg_send(mbox_flash, msg);
	if (rc) {
		prlog(PR_ERR, "Failed to enqueue/send BMC MBOX message\n");
		goto out;
	}

	rc = wait_for_bmc(mbox_flash, MBOX_DEFAULT_TIMEOUT);
	if (rc) {
		prlog(PR_ERR, "Error waiting for BMC\n");
		goto out;
	}

	msg_free_memory(msg);

	prlog(PR_INFO, "Detected mbox protocol version %d\n", mbox_flash->version);
	if (mbox_flash->version == 1) {
		mbox_flash->bl.erase = &mbox_flash_erase_v1;
		/* Not all handlers differ, update those which do */
		mbox_flash->handlers[MBOX_C_GET_FLASH_INFO] = &mbox_flash_do_get_flash_info_v1;
		mbox_flash->handlers[MBOX_C_CREATE_READ_WINDOW] =
			&mbox_flash_do_create_read_window_v1;
		mbox_flash->handlers[MBOX_C_CREATE_WRITE_WINDOW] =
			&mbox_flash_do_create_write_window_v1;
		mbox_flash->handlers[MBOX_C_MARK_WRITE_ERASED] = NULL; /* Not in V1 */
	} else if (mbox_flash->version > 2) {
		/*
		 * Uh, we requested version 2... The BMC is can only lower the
		 * requested version not do anything else. FWIW there is no
		 * verion 0
		 */
		prlog(PR_CRIT, "Bad version: %u\n", mbox_flash->version);
		rc = FLASH_ERR_PARM_ERROR;
		goto out;
	}


	return 0;
out:
	msg_free_memory(msg);
	return rc;
}

int mbox_flash_init(struct blocklevel_device **bl)
{
	struct mbox_flash_data *mbox_flash;
	int rc;

	if (!bl)
		return FLASH_ERR_PARM_ERROR;

	*bl = NULL;

	mbox_flash = zalloc(sizeof(struct mbox_flash_data));
	if (!mbox_flash)
		return FLASH_ERR_MALLOC_FAILED;

	/* Assume V2 */
	mbox_flash->bl.read = &mbox_flash_read;
	mbox_flash->bl.write = &mbox_flash_write;
	mbox_flash->bl.erase = &mbox_flash_erase_v2;
	mbox_flash->bl.get_info = &mbox_flash_get_info;

	if (bmc_mbox_get_attn_reg() & MBOX_ATTN_BMC_REBOOT)
		rc = handle_reboot(mbox_flash);
	else
		rc = protocol_init(mbox_flash);
	if (rc) {
		free(mbox_flash);
		return rc;
	}

	mbox_flash->bl.keep_alive = 0;

	*bl = &(mbox_flash->bl);
	return 0;
}

void mbox_flash_exit(struct blocklevel_device *bl)
{
	struct mbox_flash_data *mbox_flash;
	if (bl) {
		mbox_flash = container_of(bl, struct mbox_flash_data, bl);
		free(mbox_flash);
	}
}
