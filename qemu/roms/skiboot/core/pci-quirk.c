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
#include <pci.h>
#include <pci-quirk.h>
#include <ast.h>

static void quirk_astbmc_vga(struct phb *phb __unused,
			     struct pci_device *pd)
{
	struct dt_node *np = pd->dn;
	uint32_t revision, mcr_configuration, mcr_scu_mpll, mcr_scu_strap;

	/*
	 * These accesses will only work if the BMC address 0x1E6E2180 is set
	 * to 0x7B, which is its default state on current systems.  In future,
	 * for security purposes it is proposed to configure this register to
	 * disallow accesses from the host, and provide the properties that
	 * the Linux ast VGA driver used through the device tree instead.
	 * Here we set those properties so we can test how things would work
	 * if the window into BMC memory was closed.
	 *
	 * If both the petitboot kernel and the host kernel have an ast driver
	 * that reads properties from the device tree, setting 0x1E6E2180 to
	 * 0x79 will disable the backdoor into BMC memory and the only way the
	 * ast driver can operate is using the device tree properties.
	 */

	revision = ast_ahb_readl(SCU_REVISION_ID);
	mcr_configuration = ast_ahb_readl(MCR_CONFIGURATION);
	mcr_scu_mpll = ast_ahb_readl(MCR_SCU_MPLL);
	mcr_scu_strap = ast_ahb_readl(MCR_SCU_STRAP);
	dt_add_property_cells(np, "aspeed,scu-revision-id", revision);
	dt_add_property_cells(np, "aspeed,mcr-configuration", mcr_configuration);
	dt_add_property_cells(np, "aspeed,mcr-scu-mpll", mcr_scu_mpll);
	dt_add_property_cells(np, "aspeed,mcr-scu-strap", mcr_scu_strap);

	/*
	 * if
	 *    - the petitboot kernel supports an ast driver that uses DT
	 *    - every host kernel supports an ast driver that uses DT
	 *    - the host can't flash unsigned skiboots
	 *
	 * then enabling the line below will allow the host and the BMC to be
	 * securely isolated from each other, without changing what's running
	 * on the BMC.
	 */

	/* ast_ahb_writel(0x79, 0x1E6E2180); */
}

/* Quirks are: {fixup function, vendor ID, (device ID or PCI_ANY_ID)} */
static const struct pci_quirk quirk_table[] = {
	/* ASPEED 2400 VGA device */
	{ &quirk_astbmc_vga, 0x1a03, 0x2000 },
	{NULL}
};

void pci_handle_quirk(struct phb *phb, struct pci_device *pd)
{
	const struct pci_quirk *quirks = quirk_table;

	while (quirks->vendor_id) {
		if (quirks->vendor_id == PCI_VENDOR_ID(pd->vdid) &&
		    (quirks->device_id == PCI_ANY_ID ||
		     quirks->device_id == PCI_DEVICE_ID(pd->vdid)))
			quirks->fixup(phb, pd);
		quirks++;
	}
}
