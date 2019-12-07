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
#include <device.h>
#include <lpc.h>
#include <console.h>
#include <opal.h>
#include <psi.h>
#include <bt.h>
#include <errorlog.h>
#include <ipmi.h>

/* BT config */
#define BT_IO_BASE	0xe4
#define BT_IO_COUNT	3
#define BT_LPC_IRQ	10

static bool bt_device_present;

static void qemu_ipmi_error(struct ipmi_msg *msg)
{
	prlog(PR_DEBUG, "QEMU: error sending msg. cc = %02x\n", msg->cc);

	ipmi_free_msg(msg);
}

static void qemu_ipmi_setenables(void)
{
	struct ipmi_msg *msg;

	struct {
		uint8_t oem2_en : 1;
		uint8_t oem1_en : 1;
		uint8_t oem0_en : 1;
		uint8_t reserved : 1;
		uint8_t sel_en : 1;
		uint8_t msgbuf_en : 1;
		uint8_t msgbuf_full_int_en : 1;
		uint8_t rxmsg_queue_int_en : 1;
	} data;

	memset(&data, 0, sizeof(data));

	/* The spec says we need to read-modify-write to not clobber
	 * the state of the other flags. These are set on by the bmc */
	data.rxmsg_queue_int_en = 1;
	data.sel_en = 1;

	/* These are the ones we want to set on */
	data.msgbuf_en = 1;

	msg = ipmi_mkmsg_simple(IPMI_SET_ENABLES, &data, sizeof(data));
	if (!msg) {
		prlog(PR_ERR, "QEMU: failed to set enables\n");
		return;
	}

	msg->error = qemu_ipmi_error;

	ipmi_queue_msg(msg);

}

static void qemu_init(void)
{
	/* Setup UART console for use by Linux via OPAL API */
	set_opal_console(&uart_opal_con);

	/* Setup LPC RTC and use it as time source. Call after
	 * chiptod_init()
	 */
	lpc_rtc_init();

	if (!bt_device_present)
		return;

	/* Register the BT interface with the IPMI layer */
	bt_init();
	/* Initialize elog */
	elog_init();
	ipmi_sel_init();
	ipmi_wdt_init();
	ipmi_opal_init();
	ipmi_fru_init(0);
	ipmi_sensor_init();

	/* As soon as IPMI is up, inform BMC we are in "S0" */
	ipmi_set_power_state(IPMI_PWR_SYS_S0_WORKING, IPMI_PWR_NOCHANGE);

	/* Enable IPMI OEM message interrupts */
	qemu_ipmi_setenables();

	ipmi_set_fw_progress_sensor(IPMI_FW_MOTHERBOARD_INIT);
}

static void qemu_dt_fixup_uart(struct dt_node *lpc)
{
	/*
	 * The official OF ISA/LPC binding is a bit odd, it prefixes
	 * the unit address for IO with "i". It uses 2 cells, the first
	 * one indicating IO vs. Memory space (along with bits to
	 * represent aliasing).
	 *
	 * We pickup that binding and add to it "2" as a indication
	 * of FW space.
	 *
	 * TODO: Probe the UART instead if the LPC bus allows for it
	 */
	struct dt_node *uart;
	char namebuf[32];
#define UART_IO_BASE	0x3f8
#define UART_IO_COUNT	8
#define UART_LPC_IRQ	4

	/* check if the UART device was defined by qemu */
	dt_for_each_child(lpc, uart) {
		if (dt_node_is_compatible(uart, "pnpPNP,501")) {
			prlog(PR_WARNING, "QEMU: uart device already here\n");
			return;
		}
	}

	snprintf(namebuf, sizeof(namebuf), "serial@i%x", UART_IO_BASE);
	uart = dt_new(lpc, namebuf);

	dt_add_property_cells(uart, "reg",
			      1, /* IO space */
			      UART_IO_BASE, UART_IO_COUNT);
	dt_add_property_strings(uart, "compatible",
				"ns16550",
				"pnpPNP,501");
	dt_add_property_cells(uart, "clock-frequency", 1843200);
	dt_add_property_cells(uart, "current-speed", 115200);
	dt_add_property_cells(uart, "interrupts", UART_LPC_IRQ);
	dt_add_property_cells(uart, "interrupt-parent", lpc->phandle);

	/*
	 * This is needed by Linux for some obscure reasons,
	 * we'll eventually need to sanitize it but in the meantime
	 * let's make sure it's there
	 */
	dt_add_property_strings(uart, "device_type", "serial");
}

/*
 * This adds the legacy RTC device to the device-tree
 * for Linux to use
 */
static void qemu_dt_fixup_rtc(struct dt_node *lpc)
{
	struct dt_node *rtc;
	char namebuf[32];

	/* check if the RTC device was defined by qemu */
	dt_for_each_child(lpc, rtc) {
		if (dt_node_is_compatible(rtc, "pnpPNP,b00")) {
			prlog(PR_WARNING, "QEMU: rtc device already here\n");
			return;
		}
	}

	/*
	 * Follows the structure expected by the kernel file
	 * arch/powerpc/sysdev/rtc_cmos_setup.c
	 */
	snprintf(namebuf, sizeof(namebuf), "rtc@i%x", 0x70);
	rtc = dt_new(lpc, namebuf);
	dt_add_property_string(rtc, "compatible", "pnpPNP,b00");
	dt_add_property_cells(rtc, "reg",
			      1, /* IO space */
			      0x70, 2);
}

static void qemu_dt_fixup(void)
{
	struct dt_node *n, *primary_lpc = NULL;

	/* Find the primary LPC bus */
	dt_for_each_compatible(dt_root, n, "ibm,power8-lpc") {
		if (!primary_lpc || dt_has_node_property(n, "primary", NULL))
			primary_lpc = n;
		if (dt_has_node_property(n, "#address-cells", NULL))
			break;
	}

	if (!primary_lpc)
		return;

	qemu_dt_fixup_rtc(primary_lpc);
	qemu_dt_fixup_uart(primary_lpc);

	/* check if the BT device was defined by qemu */
	dt_for_each_child(primary_lpc, n) {
		if (dt_node_is_compatible(n, "bt"))
			bt_device_present = true;
	}
}

static void qemu_ext_irq_serirq_cpld(unsigned int chip_id)
{
	lpc_all_interrupts(chip_id);
}

static int64_t qemu_ipmi_power_down(uint64_t request)
{
	if (request != IPMI_CHASSIS_PWR_DOWN) {
		prlog(PR_WARNING, "PLAT: unexpected shutdown request %llx\n",
				   request);
	}

	return ipmi_chassis_control(request);
}

static int64_t qemu_ipmi_reboot(void)
{
	return ipmi_chassis_control(IPMI_CHASSIS_HARD_RESET);
}

static bool qemu_probe(void)
{
	if (!dt_node_is_compatible(dt_root, "qemu,powernv"))
		return false;

	/* Add missing bits of device-tree such as the UART */
	qemu_dt_fixup();

	psi_set_external_irq_policy(EXTERNAL_IRQ_POLICY_SKIBOOT);

	/* Setup UART and use it as console */
	uart_init();

	return true;
}

DECLARE_PLATFORM(qemu) = {
	.name		= "Qemu",
	.probe		= qemu_probe,
	.init		= qemu_init,
	.external_irq   = qemu_ext_irq_serirq_cpld,
	.cec_power_down = qemu_ipmi_power_down,
	.cec_reboot     = qemu_ipmi_reboot,
	.terminate	= ipmi_terminate,
};
