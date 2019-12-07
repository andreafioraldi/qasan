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

#ifndef __NPU2_H
#define __NPU2_H

#include <phys-map.h>

/* Debugging options */
#define NPU2DBG(p, fmt, a...)	prlog(PR_DEBUG, "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)
#define NPU2INF(p, fmt, a...)	prlog(PR_INFO,  "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)
#define NPU2ERR(p, fmt, a...)	prlog(PR_ERR,   "NPU%d: " fmt, \
				      (p)->phb.opal_id, ##a)

#define NPU2DEVDBG(p, fmt, a...)	NPU2DBG((p)->npu, fmt, ##a)
#define NPU2DEVINF(p, fmt, a...)	NPU2INF((p)->npu, fmt, ##a)
#define NPU2DEVERR(p, fmt, a...)	NPU2ERR((p)->npu, fmt, ##a)

/* Number of PEs supported */
#define NPU2_MAX_PE_NUM		16
#define NPU2_RESERVED_PE_NUM	15

#define NPU2_LINKS_PER_CHIP 6

/* Link flags */
#define NPU2_DEV_PCI_LINKED	0x1
#define NPU2_DEV_DL_RESET	0x2

/* Return the stack (0-2) of a device */
#define NPU2DEV_STACK(ndev) ((ndev)->index / 2)

/* Return the brick number (0-1) within a stack */
#define NPU2DEV_BRICK(ndev) ((ndev)->index % 2)

/* This represents the state of the actual hardware BARs not the
 * emulated PCIe BARs. The is a subtle difference between the two as
 * not all BARs are exposed outside of skiboot. */
struct npu2_bar {
	enum phys_map_type	type;
	int			index;
#define NPU2_BAR_FLAG_ENABLED	0x0010

/* Generation ID's are a single space in the hardware but we split
 * them in two for the emulated PCIe devices so we need to keep track
 * of which one has been enabled/disabled. */
#define NPU2_BAR_FLAG_ENABLED0	0x0080
#define NPU2_BAR_FLAG_ENABLED1  0x0100
	uint32_t		flags;
	uint64_t		base;
	uint64_t		size;
	uint64_t		reg;
};

/* Rpresents a BAR that is exposed via the PCIe emulated
 * devices */
struct npu2_pcie_bar {
#define NPU2_PCIE_BAR_FLAG_SIZE_HI	0x0020
#define NPU2_PCIE_BAR_FLAG_TRAPPED	0x0040
	uint32_t		flags;
	struct npu2_bar		npu2_bar;
};

struct npu2;
struct npu2_dev {
	uint32_t		index;
	uint32_t                flags;
	uint64_t                xscom;
	uint64_t		pl_xscom_base;
	void			*regs;
	struct dt_node		*dt_node;
	struct npu2_pcie_bar	bars[2];
	struct npu2		*npu;

	/* Device and function numbers are allocated based on GPU
	 * association. Links to connected to the same GPU will be
	 * exposed as different functions of the same bus/device. */
	uint32_t		bdfn;
	uint32_t		gpu_bdfn;

	/* PCI virtual device and the associated GPU device */
	struct pci_virt_device	*pvd;
	struct phb		*phb;
	struct pci_device	*pd;

	uint8_t			link_flags;

	/* Vendor specific capability */
	uint32_t		vendor_cap;

	/* Which PHY lanes this device is associated with */
	uint32_t		lane_mask;

	/* Track currently running procedure and step number */
	uint16_t		procedure_number;
	uint16_t		procedure_step;
	uint64_t		procedure_data;
	unsigned long		procedure_tb;
	uint32_t		procedure_status;

	/* Used to associate the NPU device with GPU PCI devices */
	const char		*slot_label;
};

struct npu2 {
	uint32_t	index;
	uint32_t	flags;
	uint32_t	chip_id;
	uint64_t	xscom_base;
	uint64_t	at_xscom;
	void		*regs;
	uint64_t	mm_base;
	uint64_t	mm_size;
	uint32_t	base_lsi;
	uint32_t	total_devices;
	struct npu2_dev	*devices;

	/* IODA cache */
	uint64_t	lxive_cache[8];
	uint64_t	bdf2pe_cache[36];
	uint64_t	tve_cache[16];
	bool		tx_zcal_complete[2];

	/* Used to protect global MMIO space, in particular the XTS
	 * tables. */
	struct lock	lock;

	struct phb	phb;
};

static inline struct npu2 *phb_to_npu2(struct phb *phb)
{
	return container_of(phb, struct npu2, phb);
}

void npu2_write_4b(struct npu2 *p, uint64_t reg, uint32_t val);
uint32_t npu2_read_4b(struct npu2 *p, uint64_t reg);
void npu2_write(struct npu2 *p, uint64_t reg, uint64_t val);
uint64_t npu2_read(struct npu2 *p, uint64_t reg);
void npu2_write_mask(struct npu2 *p, uint64_t reg, uint64_t val, uint64_t mask);
int64_t npu2_dev_procedure(void *dev, struct pci_cfg_reg_filter *pcrf,
			   uint32_t offset, uint32_t len, uint32_t *data,
			   bool write);
void npu2_dev_procedure_reset(struct npu2_dev *dev);
void npu2_set_link_flag(struct npu2_dev *ndev, uint8_t flag);
void npu2_clear_link_flag(struct npu2_dev *ndev, uint8_t flag);
extern int nv_zcal_nominal;
#endif /* __NPU2_H */
