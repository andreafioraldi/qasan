// VGA / STI code for parisc architecture
//
// Copyright (C) 2017  Helge Deller <deller@gmx.de>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "autoconf.h"
#include "types.h"
#include "std/optionrom.h"
#include "hw/pci.h" // pci_config_readl
#include "hw/pci_regs.h" // PCI_BASE_ADDRESS_0
#include "vgahw.h"

/****************************************************************
 * PCI Data
 ****************************************************************/
#if 0
struct pci_data __VISIBLE rom_pci_data = {
    .signature = PCI_ROM_SIGNATURE,
    .vendor = CONFIG_VGA_VID,
    .device = CONFIG_VGA_DID,
    .dlen = 0x18,
    .class_hi = 0x300,
    .irevision = 1,
    .type = PCIROM_CODETYPE_X86,
    .indicator = 0x80,
};
#endif

extern void handle_100e(struct bregs *regs);

void parisc_teletype_output(struct bregs *regs)
{
	// re-read PCI addresses. Linux kernel reconfigures those at boot.
	parisc_vga_mem = pci_config_readl(VgaBDF, PCI_BASE_ADDRESS_0);
	parisc_vga_mem &= PCI_BASE_ADDRESS_MEM_MASK;
	VBE_framebuffer = parisc_vga_mem;
	parisc_vga_mmio = pci_config_readl(VgaBDF, PCI_BASE_ADDRESS_2);
	parisc_vga_mmio &= PCI_BASE_ADDRESS_MEM_MASK;

	handle_100e(regs);
}

