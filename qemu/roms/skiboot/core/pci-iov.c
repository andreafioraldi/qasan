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
#include <pci.h>
#include <pci-cfg.h>
#include <pci-slot.h>
#include <pci-iov.h>

/*
 * Tackle the VF's MPS in PCIe capability. The field is read only.
 * This function caches what is written and returns the cached
 * MPS on read.
 */
static int64_t pci_iov_vf_devctl(void *dev, struct pci_cfg_reg_filter *pcrf,
				 uint32_t offset, uint32_t len,
				 uint32_t *data, bool write)
{
	struct pci_device *vf = (struct pci_device *)dev;
	uint32_t pos = pci_cap(vf, PCI_CFG_CAP_ID_EXP, false);
	uint8_t *pcache;

	if (offset != (pos + PCICAP_EXP_DEVCTL))
		return OPAL_PARTIAL;

	pcache = &pcrf->data[0];
	if (write) {
		*pcache = ((uint8_t)(*data >> (8 * (4 - len)))) &
			   PCICAP_EXP_DEVCTL_MPS;
	} else {
		*data &= ~(PCICAP_EXP_DEVCTL_MPS << (8 * (4 - len)));
		*data |= (((uint32_t)(*pcache & PCICAP_EXP_DEVCTL_MPS))
			  << (8 * (4 - len)));
	}

	return OPAL_SUCCESS;
}

static void pci_iov_vf_quirk(struct phb *phb, struct pci_device *vf)
{
	struct pci_cfg_reg_filter *pcrf;
	uint32_t pos;

	if (!pci_has_cap(vf, PCI_CFG_CAP_ID_EXP, false))
		return;

	/*
	 * On Mellanox MT27500 Family [ConnectX-3], its VF's MPS field in
	 * the corresponding config register is readonly. The MPS for PF/VF
	 * are usually different. We are introducing a quirk to make them
	 * look same to avoid confusion.
	 */
	if (vf->vdid != 0x100315b3)
		return;

	pos = pci_cap(vf, PCI_CFG_CAP_ID_EXP, false);
	pcrf = pci_add_cfg_reg_filter(vf, pos + PCICAP_EXP_DEVCTL, 4,
				      PCI_REG_FLAG_MASK, pci_iov_vf_devctl);
	if (!pcrf)
		prlog(PR_WARNING, "%s: Missed DEVCTL filter on %04x:%02x:%02x.%01x\n",
		      __func__, phb->opal_id, (vf->bdfn >> 8),
		      ((vf->bdfn >> 3) & 0x1f), (vf->bdfn & 0x7));
}

/*
 * Update the SRIOV parameters that change when the number of
 * VFs is configured.
 */
static bool pci_iov_update_parameters(struct pci_iov *iov)
{
	struct phb *phb = iov->phb;
	uint16_t bdfn = iov->pd->bdfn;
	uint32_t pos = iov->pos;
	uint16_t val;
	bool enabled;

	pci_cfg_read16(phb, bdfn, pos + PCIECAP_SRIOV_CTRL, &val);
	enabled = !!(val & PCIECAP_SRIOV_CTRL_VFE);
	if (iov->enabled == enabled)
		return false;

	if (enabled) {
		pci_cfg_read16(phb, bdfn, pos + PCIECAP_SRIOV_INITIAL_VF,
			       &iov->init_VFs);
		pci_cfg_read16(phb, bdfn, pos + PCIECAP_SRIOV_NUM_VF,
			       &iov->num_VFs);
		pci_cfg_read16(phb, bdfn, pos + PCIECAP_SRIOV_VF_OFFSET,
			       &iov->offset);
		pci_cfg_read16(phb, bdfn, pos + PCIECAP_SRIOV_VF_STRIDE,
			       &iov->stride);
	} else {
		iov->init_VFs	= 0;
		iov->num_VFs	= 0;
		iov->offset	= 0;
		iov->stride	= 0;
	}

	iov->enabled = enabled;
	return true;
}

static int64_t pci_iov_change(void *dev __unused,
			      struct pci_cfg_reg_filter *pcrf,
			      uint32_t offset __unused,
			      uint32_t len __unused,
			      uint32_t *data __unused,
			      bool write __unused)
{
	struct pci_iov *iov = (struct pci_iov *)pcrf->data;
	struct phb *phb = iov->phb;
	struct pci_device *pd = iov->pd;
	struct pci_device *vf, *tmp;
	uint32_t i;
	bool changed;

	/* Update SRIOV variable parameters */
	changed = pci_iov_update_parameters(iov);
	if (!changed)
		return OPAL_PARTIAL;

	/* Remove all VFs that have been attached to the parent */
	if (!iov->enabled) {
		list_for_each_safe(&pd->children, vf, tmp, link)
			list_del(&vf->link);
		return OPAL_PARTIAL;
	}

	/* Initialize the VFs and attach them to parent */
	for (changed = false, i = 0; i < iov->num_VFs; i++) {
		vf = &iov->VFs[i];
		vf->bdfn = pd->bdfn + iov->offset + iov->stride * i;
		list_add_tail(&pd->children, &vf->link);

		/*
		 * We don't populate the capabilities again if they have
		 * been existing, to save time. Also, we need delay for
		 * 100ms before the VF's config space becomes ready.
		 */
		if (!pci_has_cap(vf, PCI_CFG_CAP_ID_EXP, false)) {
			if (!changed) {
				changed = !changed;
				time_wait_ms(100);
			}

			pci_init_capabilities(phb, vf);
			pci_iov_vf_quirk(phb, vf);
		}

		/* Call PHB hook */
		if (phb->ops->device_init)
			phb->ops->device_init(phb, pd, NULL);
	}

	return OPAL_PARTIAL;
}

/*
 * This function is called with disabled SRIOV capability. So the VF's
 * config address isn't finalized and its config space isn't accessible.
 */
static void pci_iov_init_VF(struct pci_device *pd, struct pci_device *vf)
{
	vf->is_bridge		= false;
	vf->is_multifunction	= false;
	vf->is_vf		= true;
	vf->dev_type		= PCIE_TYPE_ENDPOINT;
	vf->scan_map		= -1;
	vf->vdid		= pd->vdid;
	vf->sub_vdid		= pd->sub_vdid;
	vf->class		= pd->class;
	vf->dn			= NULL;
	vf->slot		= NULL;
	vf->parent		= pd;
	vf->phb			= pd->phb;
	list_head_init(&vf->pcrf);
	list_head_init(&vf->children);
}

static void pci_free_iov_cap(void *data)
{
	struct pci_iov *iov = data;
	free(iov->VFs);
	free(iov);
}

void pci_init_iov_cap(struct phb *phb, struct pci_device *pd)
{
	int64_t pos;
	struct pci_iov *iov;
	struct pci_cfg_reg_filter *pcrf;
	uint32_t i;

	/* Search for SRIOV capability */
	if (!pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false))
		return;

	pos = pci_find_ecap(phb, pd->bdfn, PCIECAP_ID_SRIOV, NULL);
	if (pos <= 0)
		return;

	/* Allocate IOV */
	iov = zalloc(sizeof(*iov));
	if (!iov) {
		prlog(PR_ERR, "%s: Cannot alloc IOV for %04x:%02x:%02x.%01x\n",
		      __func__, phb->opal_id, (pd->bdfn >> 8),
		      ((pd->bdfn >> 3) & 0x1f), (pd->bdfn & 0x7));
		return;
	}

	/* Allocate VFs */
	pci_cfg_read16(phb, pd->bdfn, pos + PCIECAP_SRIOV_TOTAL_VF,
		       &iov->total_VFs);
	iov->VFs = zalloc(sizeof(*iov->VFs) * iov->total_VFs);
	if (!iov->VFs) {
		prlog(PR_ERR, "%s: Cannot alloc %d VFs for %04x:%02x:%02x.%01x\n",
		      __func__, iov->total_VFs, phb->opal_id,
		      (pd->bdfn >> 8), ((pd->bdfn >> 3) & 0x1f),
		      (pd->bdfn & 0x7));
		free(iov);
		return;
	}

	/* Initialize VFs */
	for (i = 0; i < iov->total_VFs; i++)
		pci_iov_init_VF(pd, &iov->VFs[i]);

	/* Register filter for enabling or disabling SRIOV capability */
	pcrf = pci_add_cfg_reg_filter(pd, pos + PCIECAP_SRIOV_CTRL, 2,
				      PCI_REG_FLAG_WRITE, pci_iov_change);
	if (!pcrf) {
		prlog(PR_ERR, "%s: Cannot set filter on %04x:%02x:%02x.%01x\n",
		      __func__, phb->opal_id, (pd->bdfn >> 8),
		      ((pd->bdfn >> 3) & 0x1f), (pd->bdfn & 0x7));
		free(iov->VFs);
		free(iov);
		return;
	}

	/* Associate filter and IOV capability */
	pcrf->data = (void *)iov;

	/*
	 * Retrieve the number of VFs and other information if applicable.
	 * Register the SRIOV capability in the mean while.
	 */
	iov->phb = phb;
	iov->pd = pd;
	iov->pos = pos;
	iov->enabled = false;
	pci_iov_update_parameters(iov);
	pci_set_cap(pd, PCIECAP_ID_SRIOV, pos, iov, pci_free_iov_cap, true);
}
