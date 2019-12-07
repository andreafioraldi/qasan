/* Copyright 2013-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <skiboot.h>
#include <io.h>
#include <timebase.h>
#include <pci-cfg.h>
#include <pci.h>
#include <pci-slot.h>
#include <pci-virt.h>
#include <interrupts.h>
#include <opal.h>
#include <opal-api.h>
#include <cpu.h>
#include <device.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <affinity.h>
#include <npu2-regs.h>
#include <npu2.h>
#include <lock.h>
#include <xscom.h>
#include <bitutils.h>
#include <chip.h>
#include <phys-map.h>
#include <nvram.h>
#include <xive.h>

#define NPU2_IRQ_BASE_SHIFT 13
#define NPU2_N_DL_IRQS 23
#define NPU2_N_DL_IRQS_ALIGN 32

#define VENDOR_CAP_START    0x80
#define VENDOR_CAP_END      0x90
#define VENDOR_CAP_LEN      0x10
#define VENDOR_CAP_VERSION  0x01
#define VENDOR_CAP_PCI_DEV_OFFSET 0x0d

/*
 * NPU2 BAR layout definition. We have 3 stacks and each of them
 * contains 2 bricks. So every NPU2 has 6 bricks in total. There are 2
 * PHY BARs and each of them is shared by 3 bricks. Every brick has
 * one NTL BAR and two bricks share one GENID BAR. There is also a
 * global MMIO BAR. We only expose DL and GENID BARs to the OS and all
 * other BARs will be hidden in skiboot.
 *
 * Before the global MMIO BAR is configured, scom is the only way to
 * access the BAR registers. At NPU2 PHB probing time, we rely on scom
 * to assign all BARs until the global MMIO BAR is established.
 *
 * We need to access 4 SM registers in the same stack in order to
 * configure one particular BAR.
 */

static bool is_p9dd1(void)
{
	struct proc_chip *chip = next_chip(NULL);

	return chip &&
	       (chip->type == PROC_CHIP_P9_NIMBUS ||
		chip->type == PROC_CHIP_P9_CUMULUS) &&
	       (chip->ec_level & 0xf0) == 0x10;
}

/*
 * We use the indirect method because it uses the same addresses as
 * the MMIO offsets (NPU RING)
 */
static void npu2_scom_set_addr(uint64_t gcid, uint64_t scom_base,
			       uint64_t addr, uint64_t size)
{
	uint64_t isa = is_p9dd1() ? NPU2_DD1_MISC_SCOM_IND_SCOM_ADDR :
				    NPU2_MISC_SCOM_IND_SCOM_ADDR;

	addr = SETFIELD(NPU2_MISC_DA_ADDR, 0ull, addr);
	addr = SETFIELD(NPU2_MISC_DA_LEN, addr, size);
	xscom_write(gcid, scom_base + isa, addr);
}

static void npu2_scom_write(uint64_t gcid, uint64_t scom_base,
			    uint64_t reg, uint64_t size,
			    uint64_t val)
{
	uint64_t isd = is_p9dd1() ? NPU2_DD1_MISC_SCOM_IND_SCOM_DATA :
				    NPU2_MISC_SCOM_IND_SCOM_DATA;

	npu2_scom_set_addr(gcid, scom_base, reg, size);
	xscom_write(gcid, scom_base + isd, val);
}

static uint64_t npu2_scom_read(uint64_t gcid, uint64_t scom_base,
			       uint64_t reg, uint64_t size)
{
	uint64_t val;
	uint64_t isd = is_p9dd1() ? NPU2_DD1_MISC_SCOM_IND_SCOM_DATA :
				    NPU2_MISC_SCOM_IND_SCOM_DATA;

	npu2_scom_set_addr(gcid, scom_base, reg, size);
	xscom_read(gcid, scom_base + isd, &val);

	return val;
}

void npu2_write_4b(struct npu2 *p, uint64_t reg, uint32_t val)
{
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_4B,
			(uint64_t)val << 32);
}

uint32_t npu2_read_4b(struct npu2 *p, uint64_t reg)
{
	return npu2_scom_read(p->chip_id, p->xscom_base, reg,
			      NPU2_MISC_DA_LEN_4B) >> 32;
}

void npu2_write(struct npu2 *p, uint64_t reg, uint64_t val)
{
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_8B, val);
}

uint64_t npu2_read(struct npu2 *p, uint64_t reg)
{
	return npu2_scom_read(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_8B);
}

void npu2_write_mask(struct npu2 *p, uint64_t reg, uint64_t val, uint64_t mask)
{
	uint64_t new_val;

	new_val = npu2_read(p, reg);
	new_val &= ~mask;
	new_val |= val & mask;
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_8B, new_val);
}

/* Set a specific flag in the vendor config space */
void npu2_set_link_flag(struct npu2_dev *ndev, uint8_t flag)
{
	ndev->link_flags |= flag;
	PCI_VIRT_CFG_INIT_RO(ndev->pvd, VENDOR_CAP_START +
			     VENDOR_CAP_PCI_DEV_OFFSET, 1, ndev->link_flags);
}

void npu2_clear_link_flag(struct npu2_dev *ndev, uint8_t flag)
{
	ndev->link_flags &= ~flag;
	PCI_VIRT_CFG_INIT_RO(ndev->pvd, VENDOR_CAP_START +
			     VENDOR_CAP_PCI_DEV_OFFSET, 1, ndev->link_flags);
}

static inline void npu2_ioda_sel(struct npu2 *p, uint32_t table,
				uint32_t index, bool autoinc)
{
	out_be64(p->regs + NPU2_ATS_IODA_TBL,
		 (autoinc ? NPU2_ATS_IODA_TBL_AUTOINC : 0ul)	|
		 SETFIELD(NPU2_ATS_IODA_TBL_SELECT, 0ul, table)	|
		 SETFIELD(NPU2_ATS_IODA_TBL_INDEX,  0ul, index));
}

static struct npu2_dev *npu2_bdf_to_dev(struct npu2 *p,
					uint32_t bdfn)
{
	struct pci_virt_device *pvd;

	/* All emulated devices are attached to root bus */
	if (bdfn & ~0xff)
		return NULL;

	pvd = pci_virt_find_device(&p->phb, bdfn);
	if (pvd)
		return pvd->data;

	return NULL;
}

static inline void npu2_get_bar(uint32_t gcid, struct npu2_bar *bar)
{
	phys_map_get(gcid, bar->type, bar->index, &bar->base, &bar->size);
}

static void npu2_read_bar(struct npu2 *p, struct npu2_bar *bar)
{
	uint64_t reg, val;
	int enabled;

	reg = NPU2_REG_OFFSET(0, NPU2_BLOCK_SM_0, bar->reg);
	val = npu2_read(p, reg);

	switch (NPU2_REG(bar->reg)) {
	case NPU2_PHY_BAR:
		bar->base = GETFIELD(NPU2_PHY_BAR_ADDR, val) << 21;
		enabled = GETFIELD(NPU2_PHY_BAR_ENABLE, val);

		if (NPU2_REG_STACK(reg) == NPU2_STACK_STCK_2)
			/* This is the global MMIO BAR */
			bar->size = 0x1000000;
		else
			bar->size = 0x200000;
		break;
	case NPU2_NTL0_BAR:
	case NPU2_NTL1_BAR:
		bar->base = GETFIELD(NPU2_NTL_BAR_ADDR, val) << 16;
		enabled = GETFIELD(NPU2_NTL_BAR_ENABLE, val);

		if (is_p9dd1())
			bar->size = 0x20000;
		else
			bar->size = 0x10000 << GETFIELD(NPU2_NTL_BAR_SIZE, val);
		break;
	case NPU2_GENID_BAR:
		bar->base = GETFIELD(NPU2_GENID_BAR_ADDR, val) << 16;
		enabled = GETFIELD(NPU2_GENID_BAR_ENABLE, val);
		bar->size = 0x20000;
		break;
	default:
		bar->base = 0ul;
		enabled = 0;
		bar->size = 0;
		break;
	}

	bar->flags = SETFIELD(NPU2_BAR_FLAG_ENABLED, bar->flags, enabled);
}

static void npu2_write_bar(struct npu2 *p,
			   struct npu2_bar *bar,
			   uint32_t gcid,
			   uint32_t scom)
{
	uint64_t reg, val, enable = !!(bar->flags & NPU2_BAR_FLAG_ENABLED);
	int block;

	switch (NPU2_REG(bar->reg)) {
	case NPU2_PHY_BAR:
		val = SETFIELD(NPU2_PHY_BAR_ADDR, 0ul, bar->base >> 21);
		val = SETFIELD(NPU2_PHY_BAR_ENABLE, val, enable);
		break;
	case NPU2_NTL0_BAR:
	case NPU2_NTL1_BAR:
		val = SETFIELD(NPU2_NTL_BAR_ADDR, 0ul, bar->base >> 16);
		val = SETFIELD(NPU2_NTL_BAR_ENABLE, val, enable);

		if (!is_p9dd1())
			val = SETFIELD(NPU2_NTL_BAR_SIZE, val, 1);
		break;
	case NPU2_GENID_BAR:
		val = SETFIELD(NPU2_GENID_BAR_ADDR, 0ul, bar->base >> 16);
		val = SETFIELD(NPU2_GENID_BAR_ENABLE, val, enable);
		break;
	default:
		val = 0ul;
	}

	for (block = NPU2_BLOCK_SM_0; block <= NPU2_BLOCK_SM_3; block++) {
		reg = NPU2_REG_OFFSET(0, block, bar->reg);
		if (p)
			npu2_write(p, reg, val);
		else
			npu2_scom_write(gcid, scom, reg, NPU2_MISC_DA_LEN_8B, val);
	}
}

/* Trap for PCI command (0x4) to enable or disable device's BARs */
static int64_t npu2_cfg_write_cmd(void *dev,
				  struct pci_cfg_reg_filter *pcrf __unused,
				  uint32_t offset, uint32_t size,
				  uint32_t *data, bool write)
{
	struct pci_virt_device *pvd = dev;
	struct npu2_dev *ndev = pvd->data;
	struct npu2_bar *ntl_npu_bar, *genid_npu_bar;
	bool enabled;

	if (!write)
		return OPAL_PARTIAL;

	if (offset != PCI_CFG_CMD)
		return OPAL_PARAMETER;
	if (size != 1 && size != 2 && size != 4)
		return OPAL_PARAMETER;

	/*
	 * Enable or disable NTL and GENID BAR. Two bricks share
	 * one GENID BAR, which is exposed via the first brick.
	 */
	enabled = !!(*data & PCI_CFG_CMD_MEM_EN);
	ntl_npu_bar = &ndev->bars[0].npu2_bar;
	genid_npu_bar = &ndev->bars[1].npu2_bar;

	ntl_npu_bar->flags = SETFIELD(NPU2_BAR_FLAG_ENABLED, ntl_npu_bar->flags, enabled);
	npu2_write_bar(ndev->npu, ntl_npu_bar, 0, 0);

	/*
	 * Enable/disable the GENID BAR. Two bricks share one GENID
	 * BAR which is exposed via the first brick so we need to
	 * track the enables separately.
	 */
	if (NPU2DEV_BRICK(ndev))
		genid_npu_bar->flags = SETFIELD(NPU2_BAR_FLAG_ENABLED1, genid_npu_bar->flags,
						enabled);
	else
		genid_npu_bar->flags = SETFIELD(NPU2_BAR_FLAG_ENABLED0, genid_npu_bar->flags,
						enabled);

	/* Enable the BAR if either device requests it enabled, otherwise disable it */
	genid_npu_bar->flags = SETFIELD(NPU2_BAR_FLAG_ENABLED, genid_npu_bar->flags,
					!!(genid_npu_bar->flags & (NPU2_BAR_FLAG_ENABLED0 |
								   NPU2_BAR_FLAG_ENABLED1)));
	npu2_write_bar(ndev->npu, genid_npu_bar, 0, 0);

	return OPAL_PARTIAL;
}

static int64_t npu2_cfg_read_bar(struct npu2_dev *dev __unused,
				 struct pci_cfg_reg_filter *pcrf,
				 uint32_t offset, uint32_t size,
				 uint32_t *data)
{
	struct npu2_pcie_bar *bar = (struct npu2_pcie_bar *) pcrf->data;

	if (!(bar->flags & NPU2_PCIE_BAR_FLAG_TRAPPED))
		return OPAL_PARTIAL;

	if ((size != 4) ||
	    (offset != pcrf->start && offset != pcrf->start + 4))
		return OPAL_PARAMETER;

	if (bar->flags & NPU2_PCIE_BAR_FLAG_SIZE_HI)
		*data = bar->npu2_bar.size >> 32;
	else
		*data = bar->npu2_bar.size;
	bar->flags &= ~(NPU2_PCIE_BAR_FLAG_TRAPPED | NPU2_PCIE_BAR_FLAG_SIZE_HI);

	return OPAL_SUCCESS;
}

static int64_t npu2_cfg_write_bar(struct npu2_dev *dev,
				  struct pci_cfg_reg_filter *pcrf,
				  uint32_t offset, uint32_t size,
				  uint32_t data)
{
	struct pci_virt_device *pvd = dev->pvd;
	struct npu2_pcie_bar *bar = (struct npu2_pcie_bar *) pcrf->data;
	struct npu2_bar old_bar, *npu2_bar = &bar->npu2_bar;
	uint32_t pci_cmd;

	if ((size != 4) ||
	    (offset != pcrf->start && offset != pcrf->start + 4))
		return OPAL_PARAMETER;

	/* Return BAR size on next read */
	if (data == 0xffffffff) {
		bar->flags |= NPU2_PCIE_BAR_FLAG_TRAPPED;
		if (offset == pcrf->start + 4)
			bar->flags |= NPU2_PCIE_BAR_FLAG_SIZE_HI;

		return OPAL_SUCCESS;
	}

	if (offset == pcrf->start) {
		npu2_bar->base &= 0xffffffff00000000;
		npu2_bar->base |= (data & 0xfffffff0);
	} else {
		npu2_bar->base &= 0x00000000ffffffff;
		npu2_bar->base |= ((uint64_t)data << 32);

		PCI_VIRT_CFG_NORMAL_RD(pvd, PCI_CFG_CMD, 4, &pci_cmd);

		if (NPU2_REG(npu2_bar->reg) == NPU2_GENID_BAR && NPU2DEV_BRICK(dev))
			npu2_bar->base -= 0x10000;

		old_bar.reg = npu2_bar->reg;
		npu2_read_bar(dev->npu, &old_bar);

		/* Only allow changing the base address if the BAR is not enabled */
		if ((npu2_bar->flags & NPU2_BAR_FLAG_ENABLED) &&
		    (npu2_bar->base != old_bar.base)) {
			npu2_bar->base = old_bar.base;
			return OPAL_HARDWARE;
		}

		npu2_write_bar(dev->npu, &bar->npu2_bar, 0, 0);
	}

	/* To update the config cache */
	return OPAL_PARTIAL;
}

static int64_t npu2_dev_cfg_bar(void *dev, struct pci_cfg_reg_filter *pcrf,
				uint32_t offset, uint32_t len, uint32_t *data,
				bool write)
{
	struct pci_virt_device *pvd = dev;
	struct npu2_dev *ndev = (struct npu2_dev *) pvd->data;

	if (write)
		return npu2_cfg_write_bar(ndev, pcrf, offset, len, *data);

	return npu2_cfg_read_bar(ndev, pcrf, offset, len, data);
}

static int64_t npu2_dev_cfg_exp_devcap(void *dev,
		struct pci_cfg_reg_filter *pcrf __unused,
		uint32_t offset, uint32_t size,
		uint32_t *data, bool write)
{
	struct pci_virt_device *pvd = dev;
	struct npu2_dev *ndev = pvd->data;

	assert(write);

	if ((size != 2) || (offset & 1)) {
		/* Short config writes are not supported */
		prlog(PR_ERR, "NPU%d: Unsupported write to pcie control register\n",
		      ndev->phb->opal_id);
		return OPAL_PARAMETER;
	}

	if (*data & PCICAP_EXP_DEVCTL_FUNC_RESET)
		npu2_dev_procedure_reset(ndev);

	return OPAL_PARTIAL;
}

#define NPU2_CFG_READ(size, type)					\
static int64_t npu2_cfg_read##size(struct phb *phb, uint32_t bdfn,	\
				   uint32_t offset, type *data)		\
{									\
	uint32_t val;							\
	int64_t ret;							\
									\
	ret = pci_virt_cfg_read(phb, bdfn, offset,			\
				sizeof(*data), &val);			\
	*data = (type)val;						\
        return ret;							\
}
#define NPU2_CFG_WRITE(size, type)					\
static int64_t npu2_cfg_write##size(struct phb *phb, uint32_t bdfn,	\
				    uint32_t offset, type data)		\
{									\
	uint32_t val = data;						\
	int64_t ret;							\
									\
	ret = pci_virt_cfg_write(phb, bdfn, offset,			\
				 sizeof(data), val);			\
	return ret;							\
}

NPU2_CFG_READ(8, u8);
NPU2_CFG_READ(16, u16);
NPU2_CFG_READ(32, u32);
NPU2_CFG_WRITE(8, u8);
NPU2_CFG_WRITE(16, u16);
NPU2_CFG_WRITE(32, u32);

static int __npu2_dev_bind_pci_dev(struct phb *phb __unused,
				  struct pci_device *pd,
				  void *data)
{
	struct npu2_dev *dev = data;
	struct dt_node *pci_dt_node;
	char *pcislot;

	/* Ignore non-nvidia PCI devices */
	if ((pd->vdid & 0xffff) != 0x10de)
		return 0;

	/* Find the PCI device's slot location */
	for (pci_dt_node = pd->dn;
	     pci_dt_node && !dt_find_property(pci_dt_node, "ibm,slot-label");
	     pci_dt_node = pci_dt_node->parent);

	if (!pci_dt_node)
		return 0;

	pcislot = (char *)dt_prop_get(pci_dt_node, "ibm,slot-label");

	prlog(PR_DEBUG, "NPU2: comparing GPU '%s' and NPU2 '%s'\n",
	      pcislot, dev->slot_label);

	if (streq(pcislot, dev->slot_label))
		return 1;

	return 0;
}

static void npu2_dev_bind_pci_dev(struct npu2_dev *dev)
{
	struct phb *phb;
	uint32_t i;

	if (dev->pd)
		return;

	for (i = 0; i < 64; i++) {
		if (dev->npu->phb.opal_id == i)
			continue;

		phb = pci_get_phb(i);
		if (!phb)
			continue;

		dev->pd = pci_walk_dev(phb, NULL, __npu2_dev_bind_pci_dev, dev);
		if (dev->pd) {
			dev->phb = phb;
			/* Found the device, set the bit in config space */
			npu2_set_link_flag(dev, NPU2_DEV_PCI_LINKED);
			return;
		}
	}

	prlog(PR_INFO, "%s: No PCI device for NPU2 device %04x:00:%02x.0 to bind to. If you expect a GPU to be there, this is a problem.\n",
	      __func__, dev->npu->phb.opal_id, dev->index);
}

static struct lock pci_npu_phandle_lock = LOCK_UNLOCKED;

static void npu2_append_phandle(struct dt_node *dn,
				u32 phandle)
{
	struct dt_property *prop;
	uint32_t *npu_phandles;
	size_t len;

	/*
	 * Use a lock to make sure no one else has a reference to an
	 * ibm,npu property (this assumes this is the only function
	 * that holds a reference to it)
	 */
	lock(&pci_npu_phandle_lock);

	/* This function shouldn't be called unless ibm,npu exists */
	prop = (struct dt_property *)dt_require_property(dn, "ibm,npu", -1);

	/* Need to append to the properties */
	len = prop->len + sizeof(*npu_phandles);
	dt_resize_property(&prop, len);
	prop->len = len;

	npu_phandles = (uint32_t *)prop->prop;
	npu_phandles[len / sizeof(*npu_phandles) - 1] = phandle;
	unlock(&pci_npu_phandle_lock);
}

static struct dt_node *npu2_create_memory_dn(uint64_t addr, uint64_t size)
{
	struct dt_node *mem;
	char *name;
	size_t namesz;
	static u32 chip_id = 255;

	/*
	 * Find and return the node if it already exists.
	 */
	namesz = sizeof("memory@") + STR_MAX_CHARS(addr);
	name = malloc(namesz);
	if (!name)
		return NULL;
	snprintf(name, namesz, "memory@%llx", (long long)addr);
	mem = dt_find_by_name(dt_root, name);
	free(name);
	if (mem)
		return mem;

	mem = dt_new_addr(dt_root, "memory", addr);
	if (!mem)
		return NULL;
	dt_add_property_string(mem, "device_type", "memory");
	dt_add_property_string(mem, "compatible", "ibm,coherent-device-memory");
	dt_add_property_u64s(mem, "reg", addr, size);
	dt_add_property_cells(mem, "ibm,chip-id", chip_id);
	dt_add_property_u64s(mem, "linux,usable-memory", addr, 0);
	dt_add_property_cells(mem, "ibm,associativity", 4, chip_id, chip_id, chip_id, chip_id);
	chip_id--;

	assert(chip_id);
	return mem;
}

/* There are potentially multiple links per GPU, so lookup the GPU memory based
 * on bdfn. */
static void npu2_get_gpu_base(struct npu2_dev *ndev, uint64_t *addr, uint64_t *size)
{
	int group;

	group = (ndev->bdfn >> 3) & 0x1f;
	phys_map_get(ndev->npu->chip_id, GPU_MEM, group, addr, size);
}

static void npu2_dn_fixup_gmb(struct dt_node *pd_dn, struct npu2_dev *ndev)
{
	uint64_t gpu_base, gpu_size, gta;
	struct dt_node *mem_dn;

	npu2_get_gpu_base(ndev, &gpu_base, &gpu_size);
	mem_dn = npu2_create_memory_dn(gpu_base, gpu_size);
	assert(mem_dn);
	dt_add_property_cells(pd_dn, "memory-region", mem_dn->phandle);

	/* Coral mode address compression. This is documented in Figure 3.5
	 * "P9->GPU RA Compression (Coral) of the NPU2 workbook". */
	gta  = ((gpu_base >> 42) & 0x1) << 42;
	gta |= ((gpu_base >> 45) & 0x3) << 43;
	gta |= ((gpu_base >> 49) & 0x3) << 45;
	gta |= gpu_base & ((1UL << 43) - 1);

	dt_add_property_u64s(pd_dn, "ibm,device-tgt-addr", gta);
}

static int npu2_assign_gmb(struct npu2_dev *ndev)
{
	struct npu2 *p = ndev->npu;
	int peers, mode;
	uint32_t bdfn;
	uint64_t base, size, reg, val, old_val, gmb;

	/* Need to work out number of link peers. This amount to
	 * working out the maximum function number. So work start at
	 * the highest bdfn (fn = 6) and count back until we find a
	 * npu2_dev. */
	for (bdfn = (ndev->bdfn & ~0x7) | NPU2_LINKS_PER_CHIP;
	     (bdfn & 0x7) != 0x7; bdfn = (bdfn & ~0x7) | ((bdfn & 0x7) - 1))
		if (npu2_bdf_to_dev(p, bdfn))
			break;
	peers = bdfn & 0x7;

	npu2_get_gpu_base(ndev, &base, &size);

	/* Base address is in GB */
	base >>= 30;
	val = SETFIELD(NPU2_MEM_BAR_SEL_MEM, 0ULL, 4);
	val = SETFIELD(NPU2_MEM_BAR_NODE_ADDR, val, base);
	val = SETFIELD(NPU2_MEM_BAR_GROUP | NPU2_MEM_BAR_CHIP, val, p->chip_id);
	val = SETFIELD(NPU2_MEM_BAR_POISON, val, 1);
	val = SETFIELD(NPU2_MEM_BAR_GRANULE, val, 0);

	/* We don't know how much memory the GPU has, so we may as well just
	 * pass the whole aperture through at this point. */
	val = SETFIELD(NPU2_MEM_BAR_BAR_SIZE, val, ilog2(size >> 30));

	switch (peers) {
	case 0:
		mode = 0;
		break;
	case 1:
		mode = 1;
		break;
	case 2:
		mode = 3;
		break;
	case 3:
		mode = 6;
		break;
	case 5:
		mode = 10;
		break;
	default:
		/* Hardware does not support this configuration */
		assert(0);
	}

	mode += ndev->bdfn & 0x7;
	val = SETFIELD(NPU2_MEM_BAR_MODE, val, mode);

	gmb = NPU2_GPU0_MEM_BAR;
	if (NPU2DEV_BRICK(ndev) && !is_p9dd1())
		gmb = NPU2_GPU1_MEM_BAR;

	reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + NPU2DEV_STACK(ndev),
			      NPU2_BLOCK_SM_0, gmb);

	if (is_p9dd1()) {
		old_val = npu2_read(p, reg);
		if (NPU2DEV_BRICK(ndev))
			val = SETFIELD(PPC_BITMASK(32, 63), old_val, val >> 32);
		else
			val = SETFIELD(PPC_BITMASK(0, 31), old_val, val >> 32);
	}

	npu2_write(p, reg, val);
	reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + NPU2DEV_STACK(ndev),
			      NPU2_BLOCK_SM_1, gmb);
	npu2_write(p, reg, val);
	reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + NPU2DEV_STACK(ndev),
			      NPU2_BLOCK_SM_2, gmb);
	npu2_write(p, reg, val);
	reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + NPU2DEV_STACK(ndev),
			      NPU2_BLOCK_SM_3, gmb);
	npu2_write(p, reg, val);

	return 0;
}

static int npu2_dn_fixup(struct phb *phb,
			 struct pci_device *pd,
			 void *data __unused)
{
	struct npu2 *p = phb_to_npu2(phb);
	struct npu2_dev *dev;
	uint32_t speed;
	const char *label;

	dev = npu2_bdf_to_dev(p, pd->bdfn);
	assert(dev);
	if (dev->phb || dev->pd)
		return 0;

	npu2_assign_gmb(dev);
	npu2_dn_fixup_gmb(pd->dn, dev);
	dt_add_property_cells(pd->dn, "ibm,nvlink", dev->dt_node->phandle);

	/*
	 * NVLink supports multiple speeds and device drivers need to know what
	 * speed has been set by firmware. Hostboot does the inits that set the
	 * link speed and tell us via HDAT and we need to copy that from the
	 * link node.
	 */
	speed = dt_prop_get_u32_def(dev->dt_node, "nvidia,link-speed", 0xff);
	if (speed != 0xff)
		dt_add_property_cells(pd->dn, "ibm,nvlink-speed", speed);

	/*
	 * NPU2 devices require a slot location to associate with GPUs.
	 * This can be added via the slot table matching, otherwise we
	 * read it from the link node.
	 */
	label = dt_prop_get_def(pd->dn, "ibm,slot-label", NULL);

	if (!label) {
		label = dt_prop_get_def(dev->dt_node, "ibm,slot-label", NULL);
		if (label)
			dt_add_property_string(pd->dn, "ibm,slot-label", label);
	}

	if (!label) {
		/**
		 * @fwts-label NPUNoPHBSlotLabel
		 * @fwts-advice No GPU/NPU2 slot information was found.
		 * NVLink2 functionality will not work.
		 */
		prlog(PR_ERR, "NPU2: Cannot find GPU slot information\n");
		return 0;
	}

	dev->slot_label = label;

	/*
	 * Bind the emulated PCI device with the real one, which can't
	 * be done until the PCI devices are populated. Once the real
	 * PCI device is identified, we also need fix the device-tree
	 * for it
	 */
	npu2_dev_bind_pci_dev(dev);
	if (dev->phb && dev->pd && dev->pd->dn) {
		if (dt_find_property(dev->pd->dn, "ibm,npu"))
			npu2_append_phandle(dev->pd->dn, pd->dn->phandle);
		else
			dt_add_property_cells(dev->pd->dn, "ibm,npu", pd->dn->phandle);

		dt_add_property_cells(pd->dn, "ibm,gpu", dev->pd->dn->phandle);
		dev->gpu_bdfn = dev->pd->bdfn;
	}

	return 0;
}

static void npu2_phb_final_fixup(struct phb *phb)
{
	pci_walk_dev(phb, NULL, npu2_dn_fixup, NULL);
}

static void npu2_init_ioda_cache(struct npu2 *p)
{
	uint64_t val[2];
	uint32_t i;

	/*
	 * PE mapping: there are two sets of registers. One of them
	 * is used to map PEs for transactions. Another set is used
	 * for error routing. We should have consistent setting in
	 * both of them. Note that each brick can support 3 PEs at
	 * the maximal degree. For now, we just support one PE per
	 * brick.
	 */
	val[0] = NPU2_CQ_BRICK_BDF2PE_MAP_ENABLE;
	val[0] = SETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_PE,
			  val[0], NPU2_RESERVED_PE_NUM);
	val[1] = NPU2_MISC_BRICK_BDF2PE_MAP_ENABLE;
	val[1] = SETFIELD(NPU2_MISC_BRICK_BDF2PE_MAP_PE,
			  val[1], NPU2_RESERVED_PE_NUM);
	for (i = 0; i < ARRAY_SIZE(p->bdf2pe_cache); i++) {
		if (i < ARRAY_SIZE(p->bdf2pe_cache))
			p->bdf2pe_cache[i] = SETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_BDF,
						      val[0], i / 3);
		else
			p->bdf2pe_cache[i] = SETFIELD(NPU2_MISC_BRICK_BDF2PE_MAP_BDF,
						      val[1], i / 3);

		if (i % 3)
			p->bdf2pe_cache[i] = 0ul;
	}

	/* TVT */
	memset(p->tve_cache, 0, sizeof(p->tve_cache));
}

static int64_t npu2_ioda_reset(struct phb *phb, bool purge)
{
	struct npu2 *p = phb_to_npu2(phb);
	uint32_t i;

	if (purge) {
		NPU2DBG(p, "Purging all IODA tables...\n");
		npu2_init_ioda_cache(p);
	}

	/* TVT */
	npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->tve_cache); i++)
		out_be64(p->regs + NPU2_ATS_IODA_DATA, p->tve_cache[i]);

	return OPAL_SUCCESS;
}

static void npu2_hw_init(struct npu2 *p)
{
	int i;
	uint64_t val, size, addr, gpu_min_addr, gpu_max_addr, total_size;

	npu2_ioda_reset(&p->phb, false);

	/* Enable XTS retry mode */
	val = npu2_read(p, NPU2_XTS_CFG);
	npu2_write(p, NPU2_XTS_CFG, val | NPU2_XTS_CFG_MMIOSD | NPU2_XTS_CFG_TRY_ATR_RO);

	if (!is_p9dd1()) {
		val = npu2_read(p, NPU2_XTS_CFG2);
		npu2_write(p, NPU2_XTS_CFG2, val | NPU2_XTS_CFG2_NO_FLUSH_ENA);
	}

	/* Init memory cache directory (MCD) registers. */
	phys_map_get(p->chip_id, GPU_MEM, NPU2_LINKS_PER_CHIP - 1,
			&gpu_min_addr, NULL);
	phys_map_get(p->chip_id, GPU_MEM, 0, &gpu_max_addr, &size);
	gpu_max_addr += size;

	/* We assume GPU memory is contiguous from the first possible GPU to the
	 * last and that the size is the same so best to check that. */
	for (i = 0; i < NPU2_LINKS_PER_CHIP; i++) {
		uint64_t tmp;
		phys_map_get(p->chip_id, GPU_MEM, i, &addr, &tmp);
		assert((addr >= gpu_min_addr) && (addr + tmp <= gpu_max_addr));
		assert(tmp == size);
	}

	/* We have two MCDs, so if neccessary we can split the region covered
	 * across both if total_size is not a power of two. */
	total_size = gpu_max_addr - gpu_min_addr;
	size = 1ull << ilog2(total_size);

	/* Allocate the biggest chunk first as we assume gpu_max_addr has the
	 * highest alignment. */
	addr = gpu_max_addr - size;
	val = PPC_BIT(0);
	val = SETFIELD(PPC_BITMASK(13, 29), val, (size >> 25) - 1);
	val = SETFIELD(PPC_BITMASK(33, 63), val, addr >> 25);
	xscom_write(p->chip_id, MCD0_BANK0_CN3, val);
	total_size -= size;
	if (total_size) {
	/* total_size was not a power of two, but the remainder should
	 * be if all GPUs were assigned the same size. */
		assert(is_pow2(total_size));
		size = 1ull << ilog2(total_size);
		addr -= size;
		assert(addr <= gpu_min_addr);
		val = PPC_BIT(0);
		val = SETFIELD(PPC_BITMASK(13, 29), val, (size >> 25) - 1);
		val = SETFIELD(PPC_BITMASK(33, 63), val, addr >> 25);
		xscom_write(p->chip_id, MCD1_BANK0_CN3, val);
	}
}

static int64_t npu2_map_pe_dma_window_real(struct phb *phb,
					   uint64_t pe_num,
					   uint16_t window_id,
					   uint64_t pci_start_addr,
					   uint64_t pci_mem_size)
{
	struct npu2 *p = phb_to_npu2(phb);
	uint64_t end;
	uint64_t tve;

	/* Sanity check. Each PE has one corresponding TVE */
	if (pe_num >= NPU2_MAX_PE_NUM ||
	    window_id != pe_num)
		return OPAL_PARAMETER;

	if (pci_mem_size) {
		/* Enable */

		end = pci_start_addr + pci_mem_size;

		/* We have to be 16M aligned */
		if ((pci_start_addr & 0x00ffffff) ||
		    (pci_mem_size & 0x00ffffff))
			return OPAL_PARAMETER;

		/*
		 * It *looks* like this is the max we can support (we need
		 * to verify this. Also we are not checking for rollover,
		 * but then we aren't trying too hard to protect ourselves
		 * againt a completely broken OS.
		 */
		if (end > 0x0003ffffffffffffull)
			return OPAL_PARAMETER;

		/*
		 * Put start address bits 49:24 into TVE[52:53]||[0:23]
		 * and end address bits 49:24 into TVE[54:55]||[24:47]
		 * and set TVE[51]
		 */
		tve  = (pci_start_addr << 16) & (0xffffffull << 40);
		tve |= (pci_start_addr >> 38) & (3ull << 10);
		tve |= (end >>  8) & (0xfffffful << 16);
		tve |= (end >> 40) & (3ull << 8);
		tve |= PPC_BIT(51);
	} else {
		/* Disable */
		tve = 0;
	}

	npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, window_id, false);
	out_be64(p->regs + NPU2_ATS_IODA_DATA, tve);
	p->tve_cache[window_id] = tve;

	return OPAL_SUCCESS;
}

static int64_t npu2_map_pe_dma_window(struct phb *phb,
				      uint64_t pe_num,
				      uint16_t window_id,
				      uint16_t tce_levels,
				      uint64_t tce_table_addr,
				      uint64_t tce_table_size,
				      uint64_t tce_page_size)
{
	struct npu2 *p = phb_to_npu2(phb);
	uint64_t tts_encoded;
	uint64_t data64 = 0;

	/* Sanity check. Each PE has one corresponding TVE */
	if (pe_num >= NPU2_MAX_PE_NUM ||
	    window_id != pe_num)
		return OPAL_PARAMETER;

	/*
	 * Special condition, zero TCE table size used to disable
	 * the TVE.
	 */
	if (!tce_table_size) {
		npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, window_id, false);
		out_be64(p->regs + NPU2_ATS_IODA_DATA, 0ul);
		p->tve_cache[window_id] = 0ul;
		return OPAL_SUCCESS;
	}

	/* Additional arguments validation */
	if (tce_levels < 1 ||
	    tce_levels > 4 ||
	    !is_pow2(tce_table_size) ||
	    tce_table_size < 0x1000)
		return OPAL_PARAMETER;

	/* TCE table size */
	data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_TTA, 0ul, tce_table_addr >> 12);
	tts_encoded = ilog2(tce_table_size) - 11;
	if (tts_encoded > 39)
		return OPAL_PARAMETER;
	data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_SIZE, data64, tts_encoded);

	/* TCE page size */
	switch (tce_page_size) {
	case 0x10000:		/* 64K */
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 5);
		break;
	case 0x1000000:		/* 16M */
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 13);
		break;
	case 0x10000000:	/* 256M */
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 17);
		break;
	case 0x1000:		/* 4K */
	default:
		data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_PSIZE, data64, 1);
	}

	/* Number of levels */
	data64 = SETFIELD(NPU2_ATS_IODA_TBL_TVT_LEVEL, data64, tce_levels - 1);

	/* Update to hardware */
	npu2_ioda_sel(p, NPU2_ATS_IODA_TBL_TVT, window_id, false);
	out_be64(p->regs + NPU2_ATS_IODA_DATA, data64);
	p->tve_cache[window_id] = data64;

	return OPAL_SUCCESS;
}

static int64_t npu2_set_pe(struct phb *phb,
			   uint64_t pe_num,
			   uint64_t bdfn,
			   uint8_t bcompare,
			   uint8_t dcompare,
			   uint8_t fcompare,
			   uint8_t action)
{
	struct npu2 *p = phb_to_npu2(phb);
	struct npu2_dev *dev;
	uint64_t reg, val;

	/* Sanity check */
	if (action != OPAL_MAP_PE && action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;
	if (pe_num >= NPU2_MAX_PE_NUM)
		return OPAL_PARAMETER;
	if (bdfn >> 8)
		return OPAL_PARAMETER;
	if (bcompare != OpalPciBusAll ||
	    dcompare != OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare != OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_UNSUPPORTED;

	/* Get the NPU2 device */
	dev = npu2_bdf_to_dev(p, bdfn);
	if (!dev)
		return OPAL_PARAMETER;

	val = NPU2_CQ_BRICK_BDF2PE_MAP_ENABLE;
	val = SETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_PE, val, pe_num);
	val = SETFIELD(NPU2_CQ_BRICK_BDF2PE_MAP_BDF, val, dev->gpu_bdfn);

	if (!NPU2DEV_BRICK(dev))
		reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + dev->index/2,
				      NPU2_BLOCK_CTL, NPU2_CQ_BRICK0_BDF2PE_MAP0);
	else
		reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0 + dev->index/2,
				      NPU2_BLOCK_CTL, NPU2_CQ_BRICK1_BDF2PE_MAP0);

	npu2_write(p, reg, val);
	val = NPU2_MISC_BRICK_BDF2PE_MAP_ENABLE;
	val = SETFIELD(NPU2_MISC_BRICK_BDF2PE_MAP_PE, val, pe_num);
	val = SETFIELD(NPU2_MISC_BRICK_BDF2PE_MAP_BDF, val, dev->gpu_bdfn);
	reg = NPU2_REG_OFFSET(NPU2_STACK_MISC, NPU2_BLOCK_MISC,
			      NPU2_MISC_BRICK0_BDF2PE_MAP0 + (dev->index * 0x18));
	p->bdf2pe_cache[dev->index] = val;
	npu2_write(p, reg, val);

	return OPAL_SUCCESS;
}

static int64_t npu2_get_link_state(struct pci_slot *slot __unused, uint8_t *val)
{
	/*
	 * As we're emulating all PCI stuff, the link bandwidth
	 * isn't big deal anyway.
	 */
	*val = OPAL_SHPC_LINK_UP_x1;
	return OPAL_SUCCESS;
}

static int64_t npu2_get_power_state(struct pci_slot *slot __unused, uint8_t *val)
{
	*val = PCI_SLOT_POWER_ON;
	return OPAL_SUCCESS;
}

static int64_t npu2_hreset(struct pci_slot *slot __unused)
{
	return OPAL_SUCCESS;
}

static int64_t npu2_freset(struct pci_slot *slot __unused)
{
	return OPAL_SUCCESS;
}

static struct pci_slot *npu2_slot_create(struct phb *phb)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(phb, NULL);
	if (!slot)
		return slot;

	/* Elementary functions */
	slot->ops.get_presence_state  = NULL;
	slot->ops.get_link_state      = npu2_get_link_state;
	slot->ops.get_power_state     = npu2_get_power_state;
	slot->ops.get_attention_state = NULL;
	slot->ops.get_latch_state     = NULL;
	slot->ops.set_power_state     = NULL;
	slot->ops.set_attention_state = NULL;

	slot->ops.prepare_link_change = NULL;
	slot->ops.poll_link           = NULL;
	slot->ops.hreset              = npu2_hreset;
	slot->ops.freset              = npu2_freset;
	slot->ops.creset              = NULL;

	return slot;
}

static int64_t npu2_freeze_status(struct phb *phb __unused,
				  uint64_t pe_number __unused,
				  uint8_t *freeze_state,
				  uint16_t *pci_error_type __unused,
				  uint16_t *severity __unused,
				  uint64_t *phb_status __unused)
{
	/*
	 * FIXME: When it's called by skiboot PCI config accessor,
	 * the PE number is fixed to 0, which is incorrect. We need
	 * introduce another PHB callback to translate it. For now,
	 * it keeps the skiboot PCI enumeration going.
	 */
	*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	return OPAL_SUCCESS;
}

static int64_t npu2_tce_kill(struct phb *phb, uint32_t kill_type,
			     uint64_t pe_number, uint32_t tce_size,
			     uint64_t dma_addr, uint32_t npages)
{
	struct npu2 *npu = phb_to_npu2(phb);
	uint32_t tce_page_size;
	uint64_t val;

	if (pe_number > NPU2_MAX_PE_NUM)
		return OPAL_PARAMETER;

	sync();
	switch(kill_type) {
	case OPAL_PCI_TCE_KILL_PAGES:
		tce_page_size = GETFIELD(npu->tve_cache[pe_number], NPU2_ATS_IODA_TBL_TVT_PSIZE);
		if (tce_page_size != tce_size) {
			NPU2ERR(npu, "npu2_tce_kill: Unexpected TCE size (got 0x%x expected 0x%x)\n",
				tce_size, tce_page_size);
			return OPAL_PARAMETER;
		}

		while (npages--) {
			val = SETFIELD(NPU2_ATS_TCE_KILL_PENUM, dma_addr, pe_number);
			npu2_write(npu, NPU2_ATS_TCE_KILL, NPU2_ATS_TCE_KILL_ONE | val);
		}
		break;
	case OPAL_PCI_TCE_KILL_PE:
		/*
		 * NPU2 doesn't support killing a PE so fall through
		 * and do a kill all instead.
		 */
	case OPAL_PCI_TCE_KILL:
		npu2_write(npu, NPU2_ATS_TCE_KILL, NPU2_ATS_TCE_KILL_ALL);
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

static const struct phb_ops npu_ops = {
	.cfg_read8		= npu2_cfg_read8,
	.cfg_read16		= npu2_cfg_read16,
	.cfg_read32		= npu2_cfg_read32,
	.cfg_write8		= npu2_cfg_write8,
	.cfg_write16		= npu2_cfg_write16,
	.cfg_write32		= npu2_cfg_write32,
	.choose_bus		= NULL,
	.device_init		= NULL,
	.phb_final_fixup	= npu2_phb_final_fixup,
	.ioda_reset		= npu2_ioda_reset,
	.papr_errinjct_reset	= NULL,
	.pci_reinit		= NULL,
	.set_phb_mem_window	= NULL,
	.phb_mmio_enable	= NULL,
	.map_pe_mmio_window	= NULL,
	.map_pe_dma_window	= npu2_map_pe_dma_window,
	.map_pe_dma_window_real	= npu2_map_pe_dma_window_real,
	.pci_msi_eoi		= NULL,
	.set_xive_pe		= NULL,
	.get_msi_32		= NULL,
	.get_msi_64		= NULL,
	.set_pe			= npu2_set_pe,
	.set_peltv		= NULL,
	.eeh_freeze_status	= npu2_freeze_status,
	.eeh_freeze_clear	= NULL,
	.eeh_freeze_set		= NULL,
	.next_error		= NULL,
	.err_inject		= NULL,
	.get_diag_data		= NULL,
	.get_diag_data2		= NULL,
	.set_capi_mode		= NULL,
	.set_capp_recovery	= NULL,
	.tce_kill		= npu2_tce_kill,
};

static void assign_mmio_bars(uint64_t gcid, uint32_t scom, uint64_t reg[2], uint64_t mm_win[2])
{
	uint32_t i;
	struct npu2_bar *bar;
	struct npu2_bar npu2_bars[] = {
		/* NPU_REGS must be first in this list */
		{ .type = NPU_REGS, .index = 0,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0, 0, NPU2_PHY_BAR),
		  .flags = NPU2_BAR_FLAG_ENABLED },
		{ .type = NPU_PHY, .index = 0,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_1, 0, NPU2_PHY_BAR),
		  .flags = NPU2_BAR_FLAG_ENABLED },
		{ .type = NPU_PHY, .index = 1,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_2, 0, NPU2_PHY_BAR),
		  .flags = NPU2_BAR_FLAG_ENABLED },
		{ .type = NPU_NTL, .index = 0,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0, 0, NPU2_NTL0_BAR) },
		{ .type = NPU_NTL, .index = 1,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0, 0, NPU2_NTL1_BAR) },
		{ .type = NPU_NTL, .index = 2,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_1, 0, NPU2_NTL0_BAR) },
		{ .type = NPU_NTL, .index = 3,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_1, 0, NPU2_NTL1_BAR) },
		{ .type = NPU_NTL, .index = 4,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_2, 0, NPU2_NTL0_BAR) },
		{ .type = NPU_NTL, .index = 5,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_2, 0, NPU2_NTL1_BAR) },
		{ .type = NPU_GENID, .index = 0,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0, 0, NPU2_GENID_BAR) },
		{ .type = NPU_GENID, .index = 1,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_1, 0, NPU2_GENID_BAR) },
		{ .type = NPU_GENID, .index = 2,
		  .reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_2, 0, NPU2_GENID_BAR) },
	};

	/* On DD1, stack 2 was used for NPU_REGS, stack 0/1 for NPU_PHY */
	if (is_p9dd1()) {
		npu2_bars[0].reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_2, 0, NPU2_PHY_BAR);
		npu2_bars[1].reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_0, 0, NPU2_PHY_BAR);
		npu2_bars[2].reg = NPU2_REG_OFFSET(NPU2_STACK_STCK_1, 0, NPU2_PHY_BAR);
	}

	for (i = 0; i < ARRAY_SIZE(npu2_bars); i++) {
		bar = &npu2_bars[i];
		npu2_get_bar(gcid, bar);
		npu2_write_bar(NULL, bar, gcid, scom);
	}

	/* Global MMIO BAR */
	reg[0] = npu2_bars[0].base;
	reg[1] = npu2_bars[0].size;

	/* NTL and GENID BARs are exposed to kernel via the mm
	 * window */
	mm_win[0] = npu2_bars[3].base;
	mm_win[1] = npu2_bars[ARRAY_SIZE(npu2_bars) - 1].base +
		    npu2_bars[ARRAY_SIZE(npu2_bars) - 1].size -
		    mm_win[0];
}

/*
 * Probe NPU2 device node and create PCI root device node
 * accordingly. The NPU2 device node should specify number
 * of links and xscom base address to access links.
 */
static void npu2_probe_phb(struct dt_node *dn)
{
	struct proc_chip *proc_chip;
	struct dt_node *np;
	uint32_t gcid, scom, index, phb_index, links;
	uint64_t reg[2], mm_win[2];
	char *path;

	/* Retrieve chip id */
	path = dt_get_path(dn);
	gcid = dt_get_chip_id(dn);
	assert(proc_chip = get_chip(gcid));
	if ((proc_chip->ec_level & 0xf0) > 0x20) {
		prerror("NPU2: unsupported ec level on Chip 0x%x!\n", gcid);
		return;
	}

	if (!is_p9dd1()) {
		/* TODO: Clean this up with register names, etc. when we get
		 * time. This just turns NVLink mode on in each brick and should
		 * get replaced with a patch from ajd once we've worked out how
		 * things are going to work there.
		 *
		 * Obviously if the year is now 2020 that didn't happen and you
		 * should fix this :-) */
		xscom_write_mask(gcid, 0x5011000, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011030, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011060, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011090, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011200, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011230, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011260, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011290, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011400, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011430, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011460, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));
		xscom_write_mask(gcid, 0x5011490, PPC_BIT(58), PPC_BIT(6) | PPC_BIT(58));

		xscom_write_mask(gcid, 0x50110c0, PPC_BIT(53), PPC_BIT(53));
		xscom_write_mask(gcid, 0x50112c0, PPC_BIT(53), PPC_BIT(53));
		xscom_write_mask(gcid, 0x50114c0, PPC_BIT(53), PPC_BIT(53));
		xscom_write_mask(gcid, 0x50110f1, PPC_BIT(41), PPC_BIT(41));
		xscom_write_mask(gcid, 0x50112f1, PPC_BIT(41), PPC_BIT(41));
		xscom_write_mask(gcid, 0x50114f1, PPC_BIT(41), PPC_BIT(41));

		xscom_write_mask(gcid, 0x5011110, PPC_BIT(0), PPC_BIT(0));
		xscom_write_mask(gcid, 0x5011130, PPC_BIT(0), PPC_BIT(0));
		xscom_write_mask(gcid, 0x5011310, PPC_BIT(0), PPC_BIT(0));
		xscom_write_mask(gcid, 0x5011330, PPC_BIT(0), PPC_BIT(0));
		xscom_write_mask(gcid, 0x5011510, PPC_BIT(0), PPC_BIT(0));
		xscom_write_mask(gcid, 0x5011530, PPC_BIT(0), PPC_BIT(0));
	}

	index = dt_prop_get_u32(dn, "ibm,npu-index");
	phb_index = dt_prop_get_u32(dn, "ibm,phb-index");
	links = dt_prop_get_u32(dn, "ibm,npu-links");
	prlog(PR_INFO, "NPU2: Chip %d Found NPU2#%d (%d links) at %s\n",
	      gcid, index, links, path);
	free(path);

	/* Retrieve scom base address */
	scom = dt_get_address(dn, 0, NULL);
	prlog(PR_INFO, "   SCOM Base:  %08x\n", scom);

	/* Reassign the BARs */
	assign_mmio_bars(gcid, scom, reg, mm_win);

	if (reg[0] && reg[1])
		prlog(PR_INFO, "   Global MMIO BAR:  %016llx (%lldMB)\n",
		      reg[0], reg[1] >> 20);
	else
		prlog(PR_ERR, "    Global MMIO BAR: Disabled\n");

	/* Populate PCI root device node */
	np = dt_new_addr(dt_root, "pciex", reg[0]);
	assert(np);
	dt_add_property_strings(np,
				"compatible",
				"ibm,power9-npu-pciex",
				"ibm,ioda2-npu2-phb");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property(np, "reg", reg, sizeof(reg));
	dt_add_property_cells(np, "ibm,phb-index", phb_index);
	dt_add_property_cells(np, "ibm,npu-index", index);
	dt_add_property_cells(np, "ibm,chip-id", gcid);
	dt_add_property_cells(np, "ibm,xscom-base", scom);
	dt_add_property_cells(np, "ibm,npcq", dn->phandle);
	dt_add_property_cells(np, "ibm,links", links);
	dt_add_property(np, "ibm,mmio-window", mm_win, sizeof(mm_win));
	dt_add_property_cells(np, "ibm,phb-diag-data-size", 0);
}

static uint32_t npu2_populate_pcie_cap(struct npu2_dev *dev,
				       uint32_t start,
				       uint32_t prev_cap)
{
	struct pci_virt_device *pvd = dev->pvd;
	uint32_t val;

	/* Add capability list */
	PCI_VIRT_CFG_INIT_RO(pvd, prev_cap, 1, start);
	PCI_VIRT_CFG_INIT_RO(pvd, start, 1, PCI_CFG_CAP_ID_EXP);

	/* 0x00 - ID/PCIE capability */
	val = PCI_CFG_CAP_ID_EXP;
	val |= ((0x2 << 16) | (PCIE_TYPE_ENDPOINT << 20));
	PCI_VIRT_CFG_INIT_RO(pvd, start, 4, val);

	/* 0x04 - Device capability
	 *
	 * We should support FLR. Otherwise, it might have
	 * problem passing it through to userland via Linux
	 * VFIO infrastructure
	 */
	val = ((PCIE_MPSS_128) |
	       (PCIE_PHANTOM_NONE << 3) |
	       (PCIE_L0SL_MAX_NO_LIMIT << 6) |
	       (PCIE_L1L_MAX_NO_LIMIT << 9) |
	       (PCICAP_EXP_DEVCAP_FUNC_RESET));
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_DEVCAP, 4, val);

	pci_virt_add_filter(pvd, start + PCICAP_EXP_DEVCTL, 2,
			    PCI_REG_FLAG_WRITE,
			    npu2_dev_cfg_exp_devcap, NULL);

	/* 0x08 - Device control and status */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_DEVCTL, 4, 0x00002810,
			  0xffff0000, 0x000f0000);

	/* 0x0c - Link capability */
	val = (PCIE_LSPEED_VECBIT_2 | (PCIE_LWIDTH_1X << 4));
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_LCAP, 4, val);

	/* 0x10 - Link control and status */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_LCTL, 4, 0x00130000,
			 0xfffff000, 0xc0000000);

	/* 0x14 - Slot capability */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SLOTCAP, 4, 0x00000000);

	/* 0x18 - Slot control and status */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SLOTCTL, 4, 0x00000000);

	/* 0x1c - Root control and capability */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_RC, 4, 0x00000000,
			  0xffffffe0, 0x00000000);

	/* 0x20 - Root status */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_RSTAT, 4, 0x00000000,
			 0xffffffff, 0x00010000);

	/* 0x24 - Device capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCIECAP_EXP_DCAP2, 4, 0x00000000);

	/* 0x28 - Device Control and status 2 */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_DCTL2, 4, 0x00070000,
			 0xffff0000, 0x00000000);

	/* 0x2c - Link capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_LCAP2, 4, 0x00000007);

	/* 0x30 - Link control and status 2 */
	PCI_VIRT_CFG_INIT(pvd, start + PCICAP_EXP_LCTL2, 4, 0x00000003,
			 0xffff0000, 0x00200000);

	/* 0x34 - Slot capability 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SCAP2, 4, 0x00000000);

	/* 0x38 - Slot control and status 2 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + PCICAP_EXP_SCTL2, 4, 0x00000000);

	return start + PCICAP_EXP_SCTL2 + 8;
}

static uint32_t npu2_populate_vendor_cap(struct npu2_dev *dev,
					 uint32_t start,
					 uint32_t prev_cap)
{
	struct pci_virt_device *pvd = dev->pvd;

	/* Capbility list */
	PCI_VIRT_CFG_INIT_RO(pvd, prev_cap, 1, start);
	PCI_VIRT_CFG_INIT_RO(pvd, start, 1, PCI_CFG_CAP_ID_VENDOR);
	dev->vendor_cap = start;

	/* Length and version */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 2, 1, VENDOR_CAP_LEN);
	PCI_VIRT_CFG_INIT_RO(pvd, start + 3, 1, VENDOR_CAP_VERSION);

	/*
	 * Defaults when the trap can't handle the read/write (eg. due
	 * to reading/writing less than 4 bytes).
	 */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 4, 4, 0);
	PCI_VIRT_CFG_INIT_RO(pvd, start + 8, 4, 0);

	/* Add NVLink2 PHY procedures trap */
	pci_virt_add_filter(pvd, start + 4, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu2_dev_procedure,
			    NULL);

	/* Link index */
	PCI_VIRT_CFG_INIT_RO(pvd, start + 0xc, 1, dev->index);

	return start + VENDOR_CAP_LEN;
}

static void npu2_populate_cfg(struct npu2_dev *dev)
{
	struct pci_virt_device *pvd = dev->pvd;
	struct npu2_pcie_bar *bar;
	uint32_t pos;

	/* 0x00 - Vendor/Device ID */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_VENDOR_ID, 4, 0x04ea1014);

	/* 0x04 - Command/Status */
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_CMD, 4, 0x00100000, 0xffb802b8,
			  0xf9000000);

	pci_virt_add_filter(pvd, PCI_CFG_CMD, 1, PCI_REG_FLAG_WRITE,
			    npu2_cfg_write_cmd, NULL);

	/* 0x08 - Rev/Class/Cache */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_REV_ID, 4, 0x06800101);

	/* 0x0c - CLS/Latency Timer/Header/BIST */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CACHE_LINE_SIZE, 4, 0x00800000);

	/* 0x10/14 - BAR#0, NTL BAR */
	bar = &dev->bars[0];
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR0, 4,
			  (bar->npu2_bar.base & 0xfffffff0) | (bar->flags & 0xF),
			  0x0000000f, 0x00000000);
	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR1, 4, (bar->npu2_bar.base >> 32),
			  0x00000000, 0x00000000);
	pci_virt_add_filter(pvd, PCI_CFG_BAR0, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu2_dev_cfg_bar, bar);

	/* 0x18/1c - BAR#1, GENID BAR */
	bar = &dev->bars[1];
	if (NPU2DEV_BRICK(dev) == 0)
		PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR2, 4, (bar->npu2_bar.base & 0xfffffff0) |
				  (bar->flags & 0xF),
				  0x0000000f, 0x00000000);
	else
		/* Brick 1 gets the upper portion of the generation id register */
		PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR2, 4, ((bar->npu2_bar.base + 0x10000) & 0xfffffff0) |
				  (bar->flags & 0xF),
				  0x0000000f, 0x00000000);

	PCI_VIRT_CFG_INIT(pvd, PCI_CFG_BAR3, 4, (bar->npu2_bar.base >> 32), 0x00000000,
			  0x00000000);
	pci_virt_add_filter(pvd, PCI_CFG_BAR2, 8,
			    PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
			    npu2_dev_cfg_bar, bar);

	/* 0x20/0x24 - BARs, disabled */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_BAR4, 4, 0x00000000);
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_BAR5, 4, 0x00000000);

	/* 0x28 - Cardbus CIS pointer */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CARDBUS_CIS, 4, 0x00000000);

	/* 0x2c - Subsystem ID */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_SUBSYS_VENDOR_ID, 4, 0x00000000);

	/* 0x30 - ROM BAR, zero sized */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_ROMBAR, 4, 0xffffffff);

	/* 0x34 - PCI Capability */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_CAP, 4, 0x00000000);

	/* 0x38 - Reserved */
	PCI_VIRT_CFG_INIT_RO(pvd, 0x38, 4, 0x00000000);

	/* 0x3c - INT line/pin/Minimal grant/Maximal latency */
	PCI_VIRT_CFG_INIT_RO(pvd, PCI_CFG_INT_LINE, 4, 0x00000100); /* INT A */

	/* PCIE and vendor specific capability */
	pos = npu2_populate_pcie_cap(dev, 0x40, PCI_CFG_CAP);
	pos = npu2_populate_vendor_cap(dev, pos, 0x41);
	PCI_VIRT_CFG_INIT_RO(pvd, pos + 1, 1, 0);
}

static uint32_t npu_allocate_bdfn(struct npu2 *p, uint32_t group)
{
	int i;
	int bdfn = (group << 3);

	for (i = 0; i < p->total_devices; i++) {
		if ((p->devices[i].bdfn & 0xf8) == (bdfn & 0xf8))
			bdfn++;
	}

	return bdfn;
}

static void npu2_populate_devices(struct npu2 *p,
				  struct dt_node *dn)
{
	struct npu2_dev *dev;
	struct dt_node *npu2_dn, *link;
	uint32_t npu_phandle, index = 0;
	int stack;

	/*
	 * Get the npu node which has the links which we expand here
	 * into pci like devices attached to our emulated phb.
	 */
	npu_phandle = dt_prop_get_u32(dn, "ibm,npcq");
	npu2_dn = dt_find_by_phandle(dt_root, npu_phandle);
	assert(npu2_dn);

	/* Walk the link@x nodes to initialize devices */
	p->total_devices = 0;
	p->phb.scan_map = 0;
	dt_for_each_compatible(npu2_dn, link, "ibm,npu-link") {
		uint32_t group_id;
		struct npu2_bar *npu2_bar;

		dev = &p->devices[index];
		dev->npu = p;
		dev->dt_node = link;
		dev->index = dt_prop_get_u32(link, "ibm,npu-link-index");

		group_id = dt_prop_get_u32(link, "ibm,npu-group-id");
		dev->bdfn = npu_allocate_bdfn(p, group_id);

		/* This must be done after calling
		 * npu_allocate_bdfn() */
		p->total_devices++;
		p->phb.scan_map |= 0x1 << ((dev->bdfn & 0xf8) >> 3);

		dev->pl_xscom_base = dt_prop_get_u64(link, "ibm,npu-phy");
		dev->lane_mask = dt_prop_get_u32(link, "ibm,npu-lane-mask");

		/* Populate BARs. BAR0/1 is the NTL bar. */
		stack = NPU2_STACK_STCK_0 + NPU2DEV_STACK(dev);
		npu2_bar = &dev->bars[0].npu2_bar;
		npu2_bar->type = NPU_NTL;
		npu2_bar->index = dev->index;
		npu2_bar->reg = NPU2_REG_OFFSET(stack, 0, NPU2DEV_BRICK(dev) == 0 ?
						NPU2_NTL0_BAR : NPU2_NTL1_BAR);
	        npu2_get_bar(p->chip_id, npu2_bar);

		dev->bars[0].flags = PCI_CFG_BAR_TYPE_MEM | PCI_CFG_BAR_MEM64;

		/* BAR2/3 is the GENID bar. */
		npu2_bar = &dev->bars[1].npu2_bar;
		npu2_bar->type = NPU_GENID;
		npu2_bar->index = NPU2DEV_STACK(dev);
		npu2_bar->reg = NPU2_REG_OFFSET(stack, 0, NPU2_GENID_BAR);
	        npu2_get_bar(p->chip_id, npu2_bar);

		/* The GENID is a single physical BAR that we split
		 * for each emulated device */
		npu2_bar->size = 0x10000;
		if (NPU2DEV_BRICK(dev))
			npu2_bar->base += 0x10000;
		dev->bars[1].flags = PCI_CFG_BAR_TYPE_MEM | PCI_CFG_BAR_MEM64;

		/* Initialize PCI virtual device */
		dev->pvd = pci_virt_add_device(&p->phb, dev->bdfn, 0x100, dev);
		if (dev->pvd) {
			p->phb.scan_map |=
				0x1 << ((dev->pvd->bdfn & 0xf8) >> 3);
			npu2_populate_cfg(dev);
		}

		index++;
	}
}

static void npu2_add_interrupt_map(struct npu2 *p,
				  struct dt_node *dn)
{
	struct dt_node *npu2_dn, *link, *phb_dn;
	uint32_t npu2_phandle, index = 0, i;
	uint32_t icsp = get_ics_phandle();
	uint32_t *map;
	size_t map_size;
	uint32_t mask[] = {0xff00, 0x0, 0x0, 0x7};

	npu2_phandle = dt_prop_get_u32(dn, "ibm,npcq");
	assert((npu2_dn = dt_find_by_phandle(dt_root, npu2_phandle)));
	assert((phb_dn = p->phb.dt_node));
	map_size = 7 * sizeof(*map) * p->total_devices;
	map = malloc(map_size);
	index = 0;
	dt_for_each_compatible(npu2_dn, link, "ibm,npu-link") {
		i = index * 7;
		map[i + 0] = (p->devices[index].bdfn << 8);
		map[i + 1] = 0;
		map[i + 2] = 0;

		map[i + 3] = 1; /* INT A */
		map[i + 4] = icsp; /* interrupt-parent */
		map[i + 5] = p->base_lsi + (index * 2) + 1; /* NDL No-Stall Event */
		map[i + 6] = 0; /* 0 = EDGE, 1 = LEVEL. */
		index++;
	}
	dt_add_property(phb_dn, "interrupt-map", map, map_size);
	free(map);
	dt_add_property(phb_dn, "interrupt-map-mask", mask, sizeof(mask));
}

static void npu2_add_phb_properties(struct npu2 *p)
{
	struct dt_node *np = p->phb.dt_node;
	uint32_t icsp = get_ics_phandle();
	uint64_t mm_base, mm_size, mmio_atsd;

	/*
	 * Add various properties that HB doesn't have to
	 * add, some of them simply because they result from
	 * policy decisions made in skiboot rather than in HB
	 * such as the MMIO windows going to PCI, interrupts,
	 * etc.
	 */
	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);
	dt_add_property_cells(np, "bus-range", 0, 0xff);
	dt_add_property_cells(np, "clock-frequency", 0x200, 0);
        dt_add_property_cells(np, "interrupt-parent", icsp);

	/* NPU2 PHB properties */
	dt_add_property_cells(np, "ibm,opal-num-pes",
			      NPU2_MAX_PE_NUM);
	dt_add_property_cells(np, "ibm,opal-reserved-pe",
			      NPU2_RESERVED_PE_NUM);

	mmio_atsd = (u64) p->regs +
		NPU2_REG_OFFSET(NPU2_STACK_ATSD, NPU2_BLOCK_ATSD0, NPU2_XTS_MMIO_ATSD_LAUNCH);
	dt_add_property_cells(np, "ibm,mmio-atsd", hi32(mmio_atsd),
			      lo32(mmio_atsd));

	/*
	 * Memory window is exposed as 64-bits non-prefetchable
	 * one because 64-bits prefetchable one is kind of special
	 * to kernel.
	 */
	mm_base = p->mm_base;
	mm_size = p->mm_size;
	dt_add_property_cells(np, "ranges", 0x02000000,
			      hi32(mm_base), lo32(mm_base),
			      hi32(mm_base), lo32(mm_base),
			      hi32(mm_size), lo32(mm_size));
}

static uint64_t npu2_ipi_attributes(struct irq_source *is __unused, uint32_t isn __unused)
{
	return IRQ_ATTR_TARGET_LINUX;
}

static char *npu2_ipi_name(struct irq_source *is, uint32_t isn)
{
	struct npu2 *p = is->data;
	uint32_t idx = isn - p->base_lsi;
	const char *name;

	switch (idx) {
	case 0: name = "NDL 0 Stall Event (brick 0)"; break;
	case 1: name = "NDL 0 No-Stall Event (brick 0)"; break;
	case 2: name = "NDL 1 Stall Event (brick 1)"; break;
	case 3: name = "NDL 1 No-Stall Event (brick 1)"; break;
	case 4: name = "NDL 2 Stall Event (brick 2)"; break;
	case 5: name = "NDL 2 No-Stall Event (brick 2)"; break;
	case 6: name = "NDL 5 Stall Event (brick 3)"; break;
	case 7: name = "NDL 5 No-Stall Event (brick 3)"; break;
	case 8: name = "NDL 4 Stall Event (brick 4)"; break;
	case 9: name = "NDL 4 No-Stall Event (brick 4)"; break;
	case 10: name = "NDL 3 Stall Event (brick 5)"; break;
	case 11: name = "NDL 3 No-Stall Event (brick 5)"; break;
	case 12: name = "NTL 0 Event"; break;
	case 13: name = "NTL 1 Event"; break;
	case 14: name = "NTL 2 Event"; break;
	case 15: name = "NTL 3 Event"; break;
	case 16: name = "NTL 4 Event"; break;
	case 17: name = "NTL 5 Event"; break;
	case 18: name = "TCE Event"; break;
	case 19: name = "ATS Event"; break;
	case 20: name = "CQ Event"; break;
	case 21: name = "MISC Event"; break;
	case 22: name = "NMMU Local Xstop"; break;
	default: name = "Unknown";
	}
	return strdup(name);
}

static const struct irq_source_ops npu2_ipi_ops = {
	.attributes	= npu2_ipi_attributes,
	.name = npu2_ipi_name,
};

static void npu2_setup_irqs(struct npu2 *p)
{
	uint64_t reg, val;
	void *tp;

	p->base_lsi = xive_alloc_ipi_irqs(p->chip_id, NPU2_N_DL_IRQS, NPU2_N_DL_IRQS_ALIGN);
	if (p->base_lsi == XIVE_IRQ_ERROR) {
		prlog(PR_ERR, "NPU2: Failed to allocate interrupt sources, IRQs for NDL No-stall events will not be available.\n");
		return;
	}
	xive_register_ipi_source(p->base_lsi, NPU2_N_DL_IRQS, p, &npu2_ipi_ops );

	/* Set IPI configuration */
	reg = NPU2_REG_OFFSET(NPU2_STACK_MISC, NPU2_BLOCK_MISC, NPU2_MISC_CFG);
	val = npu2_read(p, reg);
	val = SETFIELD(NPU2_MISC_CFG_IPI_PS, val, NPU2_MISC_CFG_IPI_PS_64K);
	val = SETFIELD(NPU2_MISC_CFG_IPI_OS, val, NPU2_MISC_CFG_IPI_OS_AIX);
	npu2_write(p, reg, val);

	/* Set IRQ base */
	reg = NPU2_REG_OFFSET(NPU2_STACK_MISC, NPU2_BLOCK_MISC, NPU2_MISC_IRQ_BASE);
	tp = xive_get_trigger_port(p->base_lsi);
	val = ((uint64_t)tp) << NPU2_IRQ_BASE_SHIFT;
	npu2_write(p, reg, val);
}

static void npu2_create_phb(struct dt_node *dn)
{
	const struct dt_property *prop;
	struct npu2 *p;
	struct pci_slot *slot;
	uint32_t links;
	void *pmem;

	/* Retrieve number of devices */
	links = dt_prop_get_u32(dn, "ibm,links");
	pmem = zalloc(sizeof(struct npu2) + links * sizeof(struct npu2_dev));
	assert(pmem);

	/* Populate PHB */
	p = pmem;
	p->index = dt_prop_get_u32(dn, "ibm,phb-index");
	p->chip_id = dt_prop_get_u32(dn, "ibm,chip-id");
	p->xscom_base = dt_prop_get_u32(dn, "ibm,xscom-base");
	p->total_devices = links;
	p->regs = (void *)dt_get_address(dn, 0, NULL);

	prop = dt_require_property(dn, "ibm,mmio-window", -1);
	assert(prop->len >= (2 * sizeof(uint64_t)));
	p->mm_base = ((const uint64_t *)prop->prop)[0];
	p->mm_size = ((const uint64_t *)prop->prop)[1];

	p->devices = pmem + sizeof(struct npu2);

	/* Generic PHB */
	p->phb.dt_node = dn;
	p->phb.ops = &npu_ops;
	p->phb.phb_type = phb_type_npu_v2;
	init_lock(&p->lock);
	init_lock(&p->phb.lock);
	list_head_init(&p->phb.devices);
	list_head_init(&p->phb.virt_devices);

	npu2_setup_irqs(p);
	npu2_populate_devices(p, dn);
	npu2_add_interrupt_map(p, dn);
	npu2_add_phb_properties(p);

	slot = npu2_slot_create(&p->phb);
	if (!slot)
	{
		/**
		 * @fwts-label NPUCannotCreatePHBSlot
		 * @fwts-advice Firmware probably ran out of memory creating
		 * NPU2 slot. NVLink functionality could be broken.
		 */
		prlog(PR_ERR, "NPU2: Cannot create PHB slot\n");
	}

	pci_register_phb(&p->phb, OPAL_DYNAMIC_PHB_ID);

	npu2_init_ioda_cache(p);
	npu2_hw_init(p);
}

void probe_npu2(void)
{
	struct dt_node *np;
	const char *zcal;

	/* Check for a zcal override */
	zcal = nvram_query("nv_zcal_override");
	if (zcal) {
		nv_zcal_nominal = atoi(zcal);
		prlog(PR_WARNING, "NPU2: Using ZCAL impedance override = %d\n", nv_zcal_nominal);
	}

	/* Scan NPU2 XSCOM nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power9-npu")
		npu2_probe_phb(np);

	/* Scan newly created PHB nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power9-npu-pciex")
		npu2_create_phb(np);
}

/*
 * Search a table for an entry with matching value under mask. Returns
 * the index and the current value in *value.
 */
static int npu_table_search(struct npu2 *p, uint64_t table_addr, int stride,
			    int table_size, uint64_t *value, uint64_t mask)
{
	int i;
	uint64_t val;

	assert(value);

	for (i = 0; i < table_size; i++) {
		val = npu2_read(p, table_addr + i*stride);
		if ((val & mask) == *value) {
			*value = val;
			return i;
		}
	}

	return -1;
}

/*
 * Allocate a context ID and initialise the tables with the relevant
 * information. Returns the ID on or error if one couldn't be
 * allocated.
 */
#define NPU2_VALID_ATS_MSR_BITS (MSR_DR | MSR_HV | MSR_PR | MSR_SF)
static int64_t opal_npu_init_context(uint64_t phb_id, int pasid, uint64_t msr,
				     uint64_t bdf)
{
	struct phb *phb = pci_get_phb(phb_id);
	struct npu2 *p = phb_to_npu2(phb);
	uint64_t xts_bdf, xts_bdf_pid = 0;
	int id, lparshort;

	if (!phb || phb->phb_type != phb_type_npu_v2)
		return OPAL_PARAMETER;

	/*
	 * MSR bits should be masked by the caller to allow for future
	 * expansion if required.
	 */
	if (msr & ~NPU2_VALID_ATS_MSR_BITS)
		return OPAL_UNSUPPORTED;

	/*
	 * Need to get LPARSHORT.
	 */
	lock(&p->lock);
	xts_bdf = SETFIELD(NPU2_XTS_BDF_MAP_BDF, 0ul, bdf);
	if (npu_table_search(p, NPU2_XTS_BDF_MAP, 8, NPU2_XTS_BDF_MAP_SIZE,
			     &xts_bdf, NPU2_XTS_BDF_MAP_BDF) < 0) {
		NPU2ERR(p, "LPARID not associated with any GPU\n");
		id = OPAL_PARAMETER;
		goto out;
	}

	lparshort = GETFIELD(NPU2_XTS_BDF_MAP_LPARSHORT, xts_bdf);
	NPU2DBG(p, "Found LPARSHORT = 0x%x for BDF = 0x%03llx\n", lparshort,
		bdf);

	/*
	 * Need to find a free context.
	 */
	id = npu_table_search(p, NPU2_XTS_PID_MAP, 0x20, NPU2_XTS_PID_MAP_SIZE,
			      &xts_bdf_pid, -1UL);
	if (id < 0) {
		NPU2ERR(p, "No XTS contexts available\n");
		id = OPAL_RESOURCE;
		goto out;
	}

	/* Enable this mapping for both real and virtual addresses */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_VALID_ATRGPA0, 0UL, 1);
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_VALID_ATRGPA1, xts_bdf_pid, 1);

	/* Enables TLBIE/MMIOSD forwarding for this entry */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_VALID_ATSD, xts_bdf_pid, 1);
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_LPARSHORT, xts_bdf_pid,
			       lparshort);

	/* Set the relevant MSR bits */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_DR, xts_bdf_pid,
			       !!(msr & MSR_DR));
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_HV, xts_bdf_pid,
			       !!(msr & MSR_HV));
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_PR, xts_bdf_pid,
			       !!(msr & MSR_PR));

	/* We don't support anything other than 64-bit so we can safely hardcode
	 * it here */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_MSR_SF, xts_bdf_pid, 1);

	/* Finally set the PID/PASID */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_PASID, xts_bdf_pid, pasid);

	/* Write the entry */
	NPU2DBG(p, "XTS_PID_MAP[%03d] = 0x%08llx\n", id, xts_bdf_pid);
	npu2_write(p, NPU2_XTS_PID_MAP + id*0x20, xts_bdf_pid);

out:
	unlock(&p->lock);
	return id;
}
opal_call(OPAL_NPU_INIT_CONTEXT, opal_npu_init_context, 4);

static int opal_npu_destroy_context(uint64_t phb_id, uint64_t pid, uint64_t bdf)
{
	struct phb *phb = pci_get_phb(phb_id);
	struct npu2 *p = phb_to_npu2(phb);
	uint64_t xts_bdf, xts_bdf_pid;
	uint64_t lparshort;
	int id, rc = 0;

	if (!phb || phb->phb_type != phb_type_npu_v2)
		return OPAL_PARAMETER;

	lock(&p->lock);

	/* Need to find lparshort for this bdf */
	xts_bdf = SETFIELD(NPU2_XTS_BDF_MAP_BDF, 0ul, bdf);
	if (npu_table_search(p, NPU2_XTS_BDF_MAP, 8, NPU2_XTS_BDF_MAP_SIZE,
			     &xts_bdf, NPU2_XTS_BDF_MAP_BDF) < 0) {
		NPU2ERR(p, "LPARID not associated with any GPU\n");
		rc = OPAL_PARAMETER;
		goto out;
	}

	lparshort = GETFIELD(NPU2_XTS_BDF_MAP_LPARSHORT, xts_bdf);
	NPU2DBG(p, "Found LPARSHORT = 0x%llx destroy context for BDF = 0x%03llx PID = 0x%llx\n",
		lparshort, bdf, pid);

	/* Now find the entry in the bdf/pid table */
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_LPARSHORT, 0ul, lparshort);
	xts_bdf_pid = SETFIELD(NPU2_XTS_PID_MAP_PASID, xts_bdf_pid, pid);
	id = npu_table_search(p, NPU2_XTS_PID_MAP, 0x20, NPU2_XTS_PID_MAP_SIZE, &xts_bdf_pid,
			      NPU2_XTS_PID_MAP_LPARSHORT | NPU2_XTS_PID_MAP_PASID);
	if (id < 0) {
		rc = OPAL_PARAMETER;
		goto out;
	}

	/* And zero the entry */
	npu2_write(p, NPU2_XTS_PID_MAP + id*0x20, 0);
out:
	unlock(&p->lock);
	return rc;
}
opal_call(OPAL_NPU_DESTROY_CONTEXT, opal_npu_destroy_context, 3);

/*
 * Map the given virtual bdf to lparid with given lpcr.
 */
static int opal_npu_map_lpar(uint64_t phb_id, uint64_t bdf, uint64_t lparid,
			     uint64_t lpcr)
{
	struct phb *phb = pci_get_phb(phb_id);
	struct npu2 *p = phb_to_npu2(phb);
	struct npu2_dev *ndev = NULL;
	uint64_t xts_bdf_lpar, rc = OPAL_SUCCESS;
	int i;
	int id;

	if (!phb || phb->phb_type != phb_type_npu_v2)
		return OPAL_PARAMETER;

	if (lpcr)
		/* The LPCR bits are only required for hash based ATS,
		 * which we don't currently support but may need to in
		 * future. */
		return OPAL_UNSUPPORTED;

	lock(&p->lock);

	/* Find any existing entries and update them */
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_VALID, 0UL, 1);
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_BDF, xts_bdf_lpar, bdf);
	id = npu_table_search(p, NPU2_XTS_BDF_MAP, 8, NPU2_XTS_BDF_MAP_SIZE,
			      &xts_bdf_lpar,
			      NPU2_XTS_BDF_MAP_VALID |
			      NPU2_XTS_BDF_MAP_BDF);
	if (id < 0) {
		/* No existing mapping found, find space for a new one */
		xts_bdf_lpar = 0;
		id = npu_table_search(p, NPU2_XTS_BDF_MAP, 8, NPU2_XTS_BDF_MAP_SIZE,
				      &xts_bdf_lpar, -1UL);
	}

	if (id < 0) {
		/* Unable to find a free mapping */
		NPU2ERR(p, "No free XTS_BDF[] entry\n");
		rc = OPAL_RESOURCE;
		goto out;
	}

	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_VALID, 0UL, 1);
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_BDF, xts_bdf_lpar, bdf);

	/* We only support radix for the moment */
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_XLAT, xts_bdf_lpar, 0x3);
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_LPARID, xts_bdf_lpar, lparid);

	/* Need to find an NVLink to send the ATSDs for this device over */
	for (i = 0; i < p->total_devices; i++) {
		if (p->devices[i].gpu_bdfn == bdf) {
			ndev = &p->devices[i];
			break;
		}
	}

	if (!ndev) {
		NPU2ERR(p, "Unable to find nvlink for bdf %llx\n", bdf);
		rc = OPAL_PARAMETER;
		goto out;
	}

	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_STACK, xts_bdf_lpar, 0x4 >> (ndev->index / 2));
	xts_bdf_lpar = SETFIELD(NPU2_XTS_BDF_MAP_BRICK, xts_bdf_lpar, (ndev->index % 2));

	NPU2DBG(p, "XTS_BDF_MAP[%03d] = 0x%08llx\n", id, xts_bdf_lpar);
	npu2_write(p, NPU2_XTS_BDF_MAP + id*8, xts_bdf_lpar);

out:
	unlock(&p->lock);
	return rc;
}
opal_call(OPAL_NPU_MAP_LPAR, opal_npu_map_lpar, 4);
