/* Copyright 2013-2014 IBM Corp.
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
#include <cpu.h>
#include <fsp.h>
#include <psi.h>
#include <opal.h>
#include <xscom.h>
#include <interrupts.h>
#include <cec.h>
#include <timebase.h>
#include <pci.h>
#include <chip.h>
#include <chiptod.h>
#include <ipmi.h>

#define P8_EX_TCTL_DIRECT_CONTROLS(t)	(0x10013000 + (t) * 0x10)
#define P8_DIRECT_CTL_STOP		PPC_BIT(63)
#define P8_DIRECT_CTL_PRENAP		PPC_BIT(47)
#define P8_DIRECT_CTL_SRESET		PPC_BIT(60)


/* Flag tested by the OPAL entry code */
uint8_t reboot_in_progress;
static volatile bool fast_boot_release;
static struct cpu_thread *last_man_standing;
static struct lock reset_lock = LOCK_UNLOCKED;

static int set_special_wakeup(struct cpu_thread *cpu)
{
	uint64_t val, poll_target, stamp;
	uint32_t core_id;
	int rc;

	/*
	 * Note: HWP checks for checkstops, but I assume we don't need to
	 * as we wouldn't be running if one was present
	 */

	/* Grab core ID once */
	core_id = pir_to_core_id(cpu->pir);

	prlog(PR_DEBUG, "RESET Waking up core 0x%x\n", core_id);
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		return OPAL_SUCCESS;

	/*
	 * The original HWp reads the XSCOM first but ignores the result
	 * and error, let's do the same until I know for sure that is
	 * not necessary
	 */
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);

	/* Then we write special wakeup */
	rc = xscom_write(cpu->chip_id,
			 XSCOM_ADDR_P8_EX_SLAVE(core_id,
						EX_PM_SPECIAL_WAKEUP_PHYP),
			 PPC_BIT(0));
	if (rc) {
		prerror("RESET: XSCOM error %d asserting special"
			" wakeup on 0x%x\n", rc, cpu->pir);
		return rc;
	}

	/*
	 * HWP uses the history for Perf register here, dunno why it uses
	 * that one instead of the pHyp one, maybe to avoid clobbering it...
	 *
	 * In any case, it does that to check for run/nap vs.sleep/winkle/other
	 * to decide whether to poll on checkstop or not. Since we don't deal
	 * with checkstop conditions here, we ignore that part.
	 */

	/*
	 * Now poll for completion of special wakeup. The HWP is nasty here,
	 * it will poll at 5ms intervals for up to 200ms. This is not quite
	 * acceptable for us at runtime, at least not until we have the
	 * ability to "context switch" HBRT. In practice, because we don't
	 * winkle, it will never take that long, so we increase the polling
	 * frequency to 1us per poll. However we do have to keep the same
	 * timeout.
	 *
	 * We don't use time_wait_ms() either for now as we don't want to
	 * poll the FSP here.
	 */
	stamp = mftb();
	poll_target = stamp + msecs_to_tb(200);
	val = 0;
	while (!(val & EX_PM_GP0_SPECIAL_WAKEUP_DONE)) {
		/* Wait 1 us */
		time_wait_us(1);

		/* Read PM state */
		rc = xscom_read(cpu->chip_id,
				XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_GP0),
				&val);
		if (rc) {
			prerror("RESET: XSCOM error %d reading PM state on"
				" 0x%x\n", rc, cpu->pir);
			return rc;
		}
		/* Check timeout */
		if (mftb() > poll_target)
			break;
	}

	/* Success ? */
	if (val & EX_PM_GP0_SPECIAL_WAKEUP_DONE) {
		uint64_t now = mftb();
		prlog(PR_TRACE, "RESET: Special wakeup complete after %ld us\n",
		      tb_to_usecs(now - stamp));
		return 0;
	}

	/*
	 * We timed out ...
	 *
	 * HWP has a complex workaround for HW255321 which affects
	 * Murano DD1 and Venice DD1. Ignore that for now
	 *
	 * Instead we just dump some XSCOMs for error logging
	 */
	prerror("RESET: Timeout on special wakeup of 0x%0x\n", cpu->pir);
	prerror("RESET:      PM0 = 0x%016llx\n", val);
	val = -1;
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);
	prerror("RESET: SPC_WKUP = 0x%016llx\n", val);
	val = -1;
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id,
					  EX_PM_IDLE_STATE_HISTORY_PHYP),
		   &val);
	prerror("RESET:  HISTORY = 0x%016llx\n", val);

	return OPAL_HARDWARE;
}

static int clr_special_wakeup(struct cpu_thread *cpu)
{
	uint64_t val;
	uint32_t core_id;
	int rc;

	/*
	 * Note: HWP checks for checkstops, but I assume we don't need to
	 * as we wouldn't be running if one was present
	 */

	/* Grab core ID once */
	core_id = pir_to_core_id(cpu->pir);

	prlog(PR_DEBUG, "RESET: Releasing core 0x%x wakeup\n", core_id);
	if (chip_quirk(QUIRK_MAMBO_CALLOUTS))
		return OPAL_SUCCESS;

	/*
	 * The original HWp reads the XSCOM first but ignores the result
	 * and error, let's do the same until I know for sure that is
	 * not necessary
	 */
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);

	/* Then we write special wakeup */
	rc = xscom_write(cpu->chip_id,
			 XSCOM_ADDR_P8_EX_SLAVE(core_id,
						EX_PM_SPECIAL_WAKEUP_PHYP), 0);
	if (rc) {
		prerror("RESET: XSCOM error %d deasserting"
			" special wakeup on 0x%x\n", rc, cpu->pir);
		return rc;
	}

	/*
	 * The original HWp reads the XSCOM again with the comment
	 * "This puts an inherent delay in the propagation of the reset
	 * transition"
	 */
	xscom_read(cpu->chip_id,
		   XSCOM_ADDR_P8_EX_SLAVE(core_id, EX_PM_SPECIAL_WAKEUP_PHYP),
		   &val);

	return 0;
}

extern unsigned long callthru_tcl(const char *str, int len);

static void set_direct_ctl(struct cpu_thread *cpu, uint64_t bits)
{
	uint32_t core_id = pir_to_core_id(cpu->pir);
	uint32_t chip_id = pir_to_chip_id(cpu->pir);
	uint32_t thread_id = pir_to_thread_id(cpu->pir);
	uint32_t xscom_addr;
	char tcl_cmd[50];

	if (chip_quirk(QUIRK_MAMBO_CALLOUTS)) {
		if (bits != P8_DIRECT_CTL_SRESET)
			return;
		snprintf(tcl_cmd, sizeof(tcl_cmd), "mysim cpu %i:%i set spr pc 0x100", core_id, thread_id);
		callthru_tcl(tcl_cmd, strlen(tcl_cmd));
		return;
	}

	xscom_addr = XSCOM_ADDR_P8_EX(core_id,
				      P8_EX_TCTL_DIRECT_CONTROLS(thread_id));

	xscom_write(chip_id, xscom_addr, bits);
}

static bool fast_reset_p8(void)
{
	struct cpu_thread *cpu;

	/* Mark ourselves as last man standing in need of a reset */
	last_man_standing = this_cpu();

	prlog(PR_DEBUG, "RESET: Resetting from cpu: 0x%x (core 0x%x)\n",
	      this_cpu()->pir, pir_to_core_id(this_cpu()->pir));

	/* Assert special wakup on all cores. Only on operational cores. */
	for_each_cpu(cpu) {
		/* GARDed CPUs are marked unavailable. Skip them.  */
		if (cpu->state == cpu_state_unavailable)
			continue;

		if (cpu->primary == cpu)
			if (set_special_wakeup(cpu) != OPAL_SUCCESS)
				return false;
	}

	prlog(PR_DEBUG, "RESET: Stopping the world...\n");

	/* Put everybody in stop except myself */
	for_each_cpu(cpu) {
		/* GARDed CPUs are marked unavailable. Skip them.  */
		if (cpu->state == cpu_state_unavailable)
			continue;

		if (cpu != this_cpu())
			set_direct_ctl(cpu, P8_DIRECT_CTL_STOP);

		/* Also make sure that saved_r1 is 0 ! That's what will
		 * make our reset vector jump to fast_reboot_entry
		 */
		cpu->save_r1 = 0;
	}

	/* Restore skiboot vectors  */
	copy_exception_vectors();
	setup_reset_vector();

	prlog(PR_DEBUG, "RESET: Pre-napping all threads but one...\n");

	/* Put everybody in pre-nap except myself */
	for_each_cpu(cpu) {
		/* GARDed CPUs are marked unavailable. Skip them.  */
		if (cpu->state == cpu_state_unavailable)
			continue;

		if (cpu != this_cpu())
			set_direct_ctl(cpu, P8_DIRECT_CTL_PRENAP);
	}

	prlog(PR_DEBUG, "RESET: Resetting all threads but one...\n");

	/* Reset everybody except my own core threads */
	for_each_cpu(cpu) {
		/* GARDed CPUs are marked unavailable. Skip them.  */
		if (cpu->state == cpu_state_unavailable)
			continue;

		if (cpu != this_cpu())
			set_direct_ctl(cpu, P8_DIRECT_CTL_SRESET);
	}

	return true;
}

extern void *fdt;
extern struct lock capi_lock;

static const char *fast_reboot_disabled = NULL;
static struct lock fast_reboot_disabled_lock = LOCK_UNLOCKED;

void disable_fast_reboot(const char *reason)
{
	lock(&fast_reboot_disabled_lock);
	fast_reboot_disabled = reason;
	unlock(&fast_reboot_disabled_lock);
}

void fast_reboot(void)
{
	bool success;
	static int fast_reboot_count = 0;

	if (proc_gen != proc_gen_p8) {
		prlog(PR_DEBUG,
		      "RESET: Fast reboot not available on this CPU\n");
		return;
	}
	if (chip_quirk(QUIRK_NO_DIRECT_CTL)) {
		prlog(PR_DEBUG,
		      "RESET: Fast reboot disabled by quirk\n");
		return;
	}

	lock(&fast_reboot_disabled_lock);
	if (fast_reboot_disabled) {
		prlog(PR_DEBUG, "RESET: Fast reboot disabled because %s\n",
		      fast_reboot_disabled);
		unlock(&fast_reboot_disabled_lock);
		return;
	}
	unlock(&fast_reboot_disabled_lock);

	prlog(PR_NOTICE, "RESET: Initiating fast reboot %d...\n", ++fast_reboot_count);
	free(fdt);

	/* XXX We need a way to ensure that no other CPU is in skiboot
	 * holding locks (via the OPAL APIs) and if they are, we need
	 * for them to get out. Hopefully that isn't happening, but...
	 *
	 * To fix this properly, we want to keep track of OPAL entry/exit
	 * on all CPUs.
	 */
	reboot_in_progress = 1;
	time_wait_ms(200);

	/* Lock so the new guys coming don't reset us */
	lock(&reset_lock);

	fast_boot_release = false;

	success = fast_reset_p8();

	/* Unlock, at this point we go away */
	unlock(&reset_lock);

	if (success) {
		if (!next_cpu(first_cpu()))
			/* Only 1 CPU, so fake reset ourselves */
			asm volatile("ba 0x100 " : : : );
		/* Don't return */
		for (;;)
			;
	}
}

static void cleanup_cpu_state(void)
{
	struct cpu_thread *cpu = this_cpu();

	/* Per core cleanup */
	if (cpu_is_thread0(cpu)) {
		/* Shared SPRs whacked back to normal */

		/* XXX Update the SLW copies ! Also dbl check HIDs etc... */
		init_shared_sprs();

		/* If somebody was in fast_sleep, we may have a workaround
		 * to undo
		 */
		if (cpu->in_fast_sleep) {
			prlog(PR_DEBUG, "RESET: CPU 0x%04x in fast sleep"
			      " undoing workarounds...\n", cpu->pir);
			fast_sleep_exit();
		}

		/* And we might have lost TB sync */
		chiptod_wakeup_resync();

		/* The TLB surely contains garbage */
		cleanup_local_tlb();
	}

	/* Per-thread additional cleanup */
	init_replicated_sprs();

	// XXX Cleanup SLW, check HIDs ...
}

void __noreturn enter_nap(void);

static void check_split_core(void)
{
	struct cpu_thread *cpu;
	u64 mask, hid0;

        hid0 = mfspr(SPR_HID0);
	mask = SPR_HID0_POWER8_4LPARMODE | SPR_HID0_POWER8_2LPARMODE;

	if ((hid0 & mask) == 0)
		return;

	prlog(PR_INFO, "RESET: CPU 0x%04x is split !\n", this_cpu()->pir);

	/* If it's a secondary thread, just send it to nap */
	if (this_cpu()->pir & 7) {
		/* Prepare to be woken up */
		icp_prep_for_pm();
		/* Setup LPCR to wakeup on external interrupts only */
		mtspr(SPR_LPCR, ((mfspr(SPR_LPCR) & ~SPR_LPCR_P8_PECE) |
				 SPR_LPCR_P8_PECE2));
		/* Go to nap (doesn't return) */
		enter_nap();
	}

	prlog(PR_INFO, "RESET: Primary, unsplitting... \n");

	/* Trigger unsplit operation and update SLW image */
	hid0 &= ~SPR_HID0_POWER8_DYNLPARDIS;
	set_hid0(hid0);
	opal_slw_set_reg(this_cpu()->pir, SPR_HID0, hid0);

	/* Wait for unsplit */
	while (mfspr(SPR_HID0) & mask)
		cpu_relax();

	/* Now the guys are sleeping, wake'em up. They will come back
	 * via reset and continue the fast reboot process normally.
	 * No need to wait.
	 */
	prlog(PR_INFO, "RESET: Waking unsplit secondaries... \n");

	for_each_cpu(cpu) {
		if (!cpu_is_sibling(cpu, this_cpu()) || (cpu == this_cpu()))
			continue;
		icp_kick_cpu(cpu);
	}
}


/* Entry from asm after a fast reset */
void __noreturn fast_reboot_entry(void);

void __noreturn fast_reboot_entry(void)
{
	struct cpu_thread *cpu;

	prlog(PR_DEBUG, "RESET: CPU 0x%04x reset in\n", this_cpu()->pir);
	time_wait_ms(100);

	lock(&reset_lock);
	if (last_man_standing && next_cpu(first_cpu())) {
		prlog(PR_DEBUG, "RESET: last man standing fixup...\n");
		set_direct_ctl(last_man_standing, P8_DIRECT_CTL_PRENAP);
		set_direct_ctl(last_man_standing, P8_DIRECT_CTL_SRESET);
	}
	last_man_standing = NULL;
	unlock(&reset_lock);

	/* We reset our ICP first ! Otherwise we might get stray interrupts
	 * when unsplitting
	 */
	reset_cpu_icp();

	/* If we are split, we need to unsplit. Since that can send us
	 * to NAP, which will come back via reset, we do it now
	 */
	check_split_core();

	/* Are we the original boot CPU ? If not, we spin waiting
	 * for a relase signal from CPU 1, then we clean ourselves
	 * up and go processing jobs.
	 */
	if (this_cpu() != boot_cpu) {
		this_cpu()->state = cpu_state_present;
		while (!fast_boot_release) {
			smt_lowest();
			sync();
		}
		smt_medium();
		cleanup_cpu_state();
		__secondary_cpu_entry();
	}

	prlog(PR_INFO, "RESET: Boot CPU waiting for everybody...\n");

	/* We are the original boot CPU, wait for secondaries to
	 * be captured.
	 */
	for_each_cpu(cpu) {
		if (cpu == this_cpu())
			continue;

		/* GARDed CPUs are marked unavailable. Skip them.  */
		if (cpu->state == cpu_state_unavailable)
			continue;

		/* XXX Add a callin timeout ? */
		while (cpu->state != cpu_state_present) {
			smt_lowest();
			sync();
		}
		smt_medium();
	}

	prlog(PR_INFO, "RESET: Releasing secondaries...\n");

	/* Release everybody */
	fast_boot_release = true;
	sync();

	/* Wait for them to respond */
	for_each_cpu(cpu) {
		if (cpu == this_cpu())
			continue;

		/* GARDed CPUs are marked unavailable. Skip them.  */
		if (cpu->state == cpu_state_unavailable)
			continue;

		/* XXX Add a callin timeout ? */
		while (cpu->state == cpu_state_present) {
			smt_lowest();
			sync();
		}
	}

	prlog(PR_DEBUG, "RESET: Releasing special wakeups...\n");

	for_each_cpu(cpu) {
		/* GARDed CPUs are marked unavailable. Skip them.  */
		if (cpu->state == cpu_state_unavailable)
			continue;

		if (cpu->primary == cpu)
			clr_special_wakeup(cpu);
	}

	prlog(PR_INFO, "RESET: All done, cleaning up...\n");

	/* Clear release flag for next time */
	fast_boot_release = false;
	reboot_in_progress = 0;

	/* Cleanup ourselves */
	cleanup_cpu_state();

	/* Set our state to active */
	this_cpu()->state = cpu_state_active;

	/* Let the CPU layer do some last minute global cleanups */
	cpu_fast_reboot_complete();

	/* We can now do NAP mode */
	cpu_set_sreset_enable(true);
	cpu_set_ipi_enable(true);

	/* Start preloading kernel and ramdisk */
	start_preload_kernel();

	/* Poke the consoles (see comments in the code there) */
	fsp_console_reset();

	/* Reset/EOI the PSI interrupt */
	psi_irq_reset();

	/* Remove all PCI devices */
	pci_reset();

	ipmi_set_fw_progress_sensor(IPMI_FW_PCI_INIT);

	/* Load and boot payload */
	load_and_boot_kernel(true);
}
