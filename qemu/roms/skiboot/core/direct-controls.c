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

#include <skiboot.h>
#include <opal.h>
#include <cpu.h>
#include <xscom.h>
#include <timebase.h>
#include <chip.h>

#define P9_RAS_STATUS			0x10a02
#define P9_THREAD_QUIESCED(t)		PPC_BITMASK(0 + 8*(t), 3 + 8*(t))
#define P9_QUIESCE_RETRIES		100

#define P9_EC_DIRECT_CONTROLS		0x10a9c
#define P9_THREAD_STOP(t)		PPC_BIT(7 + 8*(t))
#define P9_THREAD_CONT(t)		PPC_BIT(6 + 8*(t))
#define P9_THREAD_SRESET(t)		PPC_BIT(4 + 8*(t))
#define P9_THREAD_PWR(t)		PPC_BIT(32 + 8*(t))

/* EC_PPM_SPECIAL_WKUP_HYP */
#define P9_SPWKUP_SET			PPC_BIT(0)

#define P9_EC_PPM_SSHHYP		0x0114
#define P9_SPECIAL_WKUP_DONE		PPC_BIT(1)

/* Waking may take up to 5ms for deepest sleep states. Set timeout to 100ms */
#define P9_SPWKUP_POLL_INTERVAL		100
#define P9_SPWKUP_TIMEOUT		100000

/*
 * This implements direct control facilities of processor cores and threads
 * using scom registers.
 */

static int p9_core_set_special_wakeup(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t swake_addr;
	uint32_t sshhyp_addr;
	uint64_t val;
	int i;

	swake_addr = XSCOM_ADDR_P9_EC_SLAVE(core_id, EC_PPM_SPECIAL_WKUP_HYP);
	sshhyp_addr = XSCOM_ADDR_P9_EC_SLAVE(core_id, P9_EC_PPM_SSHHYP);

	if (xscom_write(chip_id, swake_addr, P9_SPWKUP_SET)) {
		prlog(PR_ERR, "Could not set special wakeup on %u:%u:"
				" Unable to write PPM_SPECIAL_WKUP_HYP.\n",
				chip_id, core_id);
		return OPAL_HARDWARE;
	}

	for (i = 0; i < P9_SPWKUP_TIMEOUT/P9_SPWKUP_POLL_INTERVAL; i++) {
		if (xscom_read(chip_id, sshhyp_addr, &val)) {
			prlog(PR_ERR, "Could not set special wakeup on %u:%u:"
					" Unable to read PPM_SSHHYP.\n",
					chip_id, core_id);
			goto out_fail;
		}
		if (val & P9_SPECIAL_WKUP_DONE)
			return 0;

		time_wait_us(P9_SPWKUP_POLL_INTERVAL);
	}

	prlog(PR_ERR, "Could not set special wakeup on %u:%u:"
			" timeout waiting for SPECIAL_WKUP_DONE.\n",
			chip_id, core_id);

out_fail:
	/* De-assert special wakeup after a small delay. */
	time_wait_us(1);
	xscom_write(chip_id, swake_addr, 0);

	return OPAL_HARDWARE;
}

static int p9_core_clear_special_wakeup(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t swake_addr;

	swake_addr = XSCOM_ADDR_P9_EC_SLAVE(core_id, EC_PPM_SPECIAL_WKUP_HYP);

	/*
	 * De-assert special wakeup after a small delay.
	 * The delay may help avoid problems setting and clearing special
	 * wakeup back-to-back. This should be confirmed.
	 */
	time_wait_us(1);
	if (xscom_write(chip_id, swake_addr, 0)) {
		prlog(PR_ERR, "Could not clear special wakeup on %u:%u:"
				" Unable to write PPM_SPECIAL_WKUP_HYP.\n",
				chip_id, core_id);
		return OPAL_HARDWARE;
	}

	return OPAL_SUCCESS;
}

static int p9_thread_quiesced(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t ras_addr;
	uint64_t ras_status;

	ras_addr = XSCOM_ADDR_P9_EC(core_id, P9_RAS_STATUS);
	if (xscom_read(chip_id, ras_addr, &ras_status)) {
		prlog(PR_ERR, "Could not check thread state on %u:%u:"
				" Unable to read RAS_STATUS.\n",
				chip_id, core_id);
		return OPAL_HARDWARE;
	}

	if ((ras_status & P9_THREAD_QUIESCED(thread_id))
			== P9_THREAD_QUIESCED(thread_id))
		return 1;

	return 0;
}

static int p9_stop_thread(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t dctl_addr;
	int rc;
	int i;

	dctl_addr = XSCOM_ADDR_P9_EC(core_id, P9_EC_DIRECT_CONTROLS);

	rc = p9_thread_quiesced(cpu);
	if (rc < 0)
		return rc;
	if (rc)
		prlog(PR_WARNING, "Stopping thread %u:%u:%u warning:"
				" thread is quiesced already.\n",
				chip_id, core_id, thread_id);

	if (xscom_write(chip_id, dctl_addr, P9_THREAD_STOP(thread_id))) {
		prlog(PR_ERR, "Could not stop thread %u:%u:%u:"
				" Unable to write EC_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}

	for (i = 0; i < P9_QUIESCE_RETRIES; i++) {
		int rc = p9_thread_quiesced(cpu);
		if (rc < 0)
			break;
		if (rc)
			return 0;
	}

	prlog(PR_ERR, "Could not stop thread %u:%u:%u:"
			" Unable to quiesce thread.\n",
			chip_id, core_id, thread_id);

	if (xscom_write(chip_id, dctl_addr, P9_THREAD_CONT(thread_id))) {
		prlog(PR_ERR, "Could not resume thread %u:%u:%u:"
				" Unable to write EC_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
	}

	return OPAL_HARDWARE;
}

static int p9_cont_thread(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t dctl_addr;

	dctl_addr = XSCOM_ADDR_P9_EC(core_id, P9_EC_DIRECT_CONTROLS);
	if (xscom_write(chip_id, dctl_addr, P9_THREAD_CONT(thread_id))) {
		prlog(PR_ERR, "Could not resume thread %u:%u:%u:"
				" Unable to write EC_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
	}

	return 0;
}

static int p9_sreset_thread(struct cpu_thread *cpu)
{
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t dctl_addr;

	dctl_addr = XSCOM_ADDR_P9_EC(core_id, P9_EC_DIRECT_CONTROLS);

	if (xscom_write(chip_id, dctl_addr, P9_THREAD_SRESET(thread_id))) {
		prlog(PR_ERR, "Could not sreset thread %u:%u:%u:"
				" Unable to write EC_DIRECT_CONTROLS.\n",
				chip_id, core_id, thread_id);
		return OPAL_HARDWARE;
	}

	return 0;
}

static int dctl_set_special_wakeup(struct cpu_thread *t)
{
	struct cpu_thread *c = t->primary;
	int rc = OPAL_SUCCESS;

	if (proc_gen != proc_gen_p9)
		return OPAL_UNSUPPORTED;

	lock(&c->dctl_lock);
	if (c->special_wakeup_count == 0)
		rc = p9_core_set_special_wakeup(c);
	if (!rc)
		c->special_wakeup_count++;
	unlock(&c->dctl_lock);

	return rc;
}

static int dctl_clear_special_wakeup(struct cpu_thread *t)
{
	struct cpu_thread *c = t->primary;
	int rc = OPAL_SUCCESS;

	if (proc_gen != proc_gen_p9)
		return OPAL_UNSUPPORTED;

	lock(&c->dctl_lock);
	if (!c->special_wakeup_count)
		goto out;
	if (c->special_wakeup_count == 1)
		rc = p9_core_clear_special_wakeup(c);
	if (!rc)
		c->special_wakeup_count--;
out:
	unlock(&c->dctl_lock);

	return rc;
}

static int dctl_stop(struct cpu_thread *t)
{
	struct cpu_thread *c = t->primary;
	int rc;

	if (proc_gen != proc_gen_p9)
		return OPAL_UNSUPPORTED;

	lock(&c->dctl_lock);
	if (t->dctl_stopped) {
		unlock(&c->dctl_lock);
		return OPAL_BUSY;
	}
	rc = p9_stop_thread(t);
	if (!rc)
		t->dctl_stopped = true;
	unlock(&c->dctl_lock);

	return rc;
}

static int dctl_cont(struct cpu_thread *t)
{
	struct cpu_thread *c = t->primary;
	int rc;

	if (proc_gen != proc_gen_p9)
		return OPAL_UNSUPPORTED;

	lock(&c->dctl_lock);
	if (!t->dctl_stopped) {
		unlock(&c->dctl_lock);
		return OPAL_BUSY;
	}
	rc = p9_cont_thread(t);
	if (!rc)
		t->dctl_stopped = false;
	unlock(&c->dctl_lock);

	return rc;
}

static int dctl_sreset(struct cpu_thread *t)
{
	struct cpu_thread *c = t->primary;
	int rc;

	if (proc_gen != proc_gen_p9)
		return OPAL_UNSUPPORTED;

	lock(&c->dctl_lock);
	if (!t->dctl_stopped) {
		unlock(&c->dctl_lock);
		return OPAL_BUSY;
	}
	rc = p9_sreset_thread(t);
	if (!rc)
		t->dctl_stopped = false;
	unlock(&c->dctl_lock);

	return rc;
}

/*
 * This provides a way for the host to raise system reset exceptions
 * on other threads using direct control scoms on POWER9.
 *
 * We assert special wakeup on the core first.
 * Then stop target thread and wait for it to quiesce.
 * Then sreset the target thread, which resumes execution on that thread.
 * Then de-assert special wakeup on the core.
 */
static int64_t p9_sreset_cpu(struct cpu_thread *cpu)
{
	int rc;

	if (this_cpu() == cpu) {
		prlog(PR_ERR, "SRESET: Unable to reset self\n");
		return OPAL_PARAMETER;
	}

	rc = dctl_set_special_wakeup(cpu);
	if (rc)
		return rc;

	rc = dctl_stop(cpu);
	if (rc)
		goto out_spwk;

	rc = dctl_sreset(cpu);
	if (rc)
		goto out_cont;

	dctl_clear_special_wakeup(cpu);

	return 0;

out_cont:
	dctl_cont(cpu);
out_spwk:
	dctl_clear_special_wakeup(cpu);

	return rc;
}

static struct lock sreset_lock = LOCK_UNLOCKED;

int64_t opal_signal_system_reset(int cpu_nr)
{
	struct cpu_thread *cpu;
	int64_t ret;

	if (proc_gen != proc_gen_p9)
		return OPAL_UNSUPPORTED;

	/*
	 * Broadcasts unsupported. Not clear what threads should be
	 * signaled, so it's better for the OS to perform one-at-a-time
	 * for now.
	 */
	if (cpu_nr < 0)
		return OPAL_CONSTRAINED;

	/* Reset a single CPU */
	cpu = find_cpu_by_server(cpu_nr);
	if (!cpu) {
		prlog(PR_ERR, "SRESET: could not find cpu by server %d\n", cpu_nr);
		return OPAL_PARAMETER;
	}

	lock(&sreset_lock);
	ret = p9_sreset_cpu(cpu);
	unlock(&sreset_lock);

	return ret;
}

void direct_controls_init(void)
{
	uint32_t version;

	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		return;

	if (proc_gen != proc_gen_p9)
		return;

	/* DD1 has some sreset quirks we do not support */
	version = mfspr(SPR_PVR);
	if (is_power9n(version) && PVR_VERS_MAJ(version) == 1)
		return;

	opal_register(OPAL_SIGNAL_SYSTEM_RESET, opal_signal_system_reset, 1);
}
