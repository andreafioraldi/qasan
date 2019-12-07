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

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include <skiboot.h>
#include <device.h>

#include <pci.h>
#include <pci-cfg.h>
#include <pci-slot.h>
#include <ccan/list/list.h>

#undef pr_fmt
#define pr_fmt(fmt) "DT-SLOT: " fmt

#define PCIDBG(_p, _bdfn, fmt, a...) \
        prlog(PR_DEBUG, "PHB#%04x:%02x:%02x.%x " fmt,   \
              (_p)->opal_id,                            \
              ((_bdfn) >> 8) & 0xff,                    \
              ((_bdfn) >> 3) & 0x1f, (_bdfn) & 0x7, ## a)

struct dt_node *dt_slots;

static struct dt_node *map_phb_to_slot(struct phb *phb)
{
	uint32_t chip_id = dt_get_chip_id(phb->dt_node);
	uint32_t phb_idx = dt_prop_get_u32_def(phb->dt_node,
					       "ibm,phb-index", 0);
	struct dt_node *slot_node;

	if (!dt_slots)
		dt_slots = dt_find_by_path(dt_root, "/ibm,pcie-slots");

	dt_for_each_child(dt_slots, slot_node) {
		u32 reg[2];

		if (!dt_node_is_compatible(slot_node, "ibm,pcie-root-port"))
			continue;

		reg[0] = dt_prop_get_cell(slot_node, "reg", 0);
		reg[1] = dt_prop_get_cell(slot_node, "reg", 1);

		if (reg[0] == chip_id && reg[1] == phb_idx)
			return slot_node;
	}

	return NULL;
}

static struct dt_node *map_downport_to_slot(struct phb *phb,
					    struct pci_device *pd)
{
	struct dt_node *bus_node, *child;
	struct pci_device *cursor;
	uint32_t port_dev_id;

	/*
	 * Downports are a little bit special since we need to figure
	 * out which PCI device corresponds to which down port in the
	 * slot map.
	 *
	 * XXX: I'm assuming the ordering of port IDs and probed
	 * PCIe switch downstream devices is the same. We should
	 * check what we actually get in the HDAT.
	 */

	list_for_each(&pd->parent->children, cursor, link)
		if (cursor == pd)
			break;

	/* the child should always be on the parent's child list */
	assert(cursor);
	port_dev_id = (cursor->bdfn >> 3) & 0x1f;

	bus_node = map_pci_dev_to_slot(phb, pd->parent);
	if (!bus_node)
		return NULL;

	dt_for_each_child(bus_node, child)
		if (dt_prop_get_u32(child, "reg") == port_dev_id)
			return child;

	/* unused downport */
	return NULL;
}

static struct dt_node *__map_pci_dev_to_slot(struct phb *phb,
					   struct pci_device *pd)
{
	struct dt_node *child, *bus_node, *wildcard= NULL;

	if (!pd || !pd->parent || pd->dev_type == PCIE_TYPE_ROOT_PORT)
		return map_phb_to_slot(phb);

	if (pd->dev_type == PCIE_TYPE_SWITCH_DNPORT)
		return map_downport_to_slot(phb, pd);

	/*
	 * For matching against devices always use the 0th function.
	 * This is necessary since some functions may have a different
	 * VDID to the base device. e.g. The DMA engines in PLX switches
	 */
	if (pd->bdfn & 0x7) {
		struct pci_device *cursor;

		PCIDBG(phb, pd->bdfn, "mapping fn %x to 0th fn (%x)\n",
			pd->bdfn, pd->bdfn & (~0x7));

		list_for_each(&pd->parent->children, cursor, link)
			if ((pd->bdfn & ~0x7) == cursor->bdfn)
				return map_pci_dev_to_slot(phb, cursor);

		return NULL;
	}

	/* No slot information for this device. Might be a firmware bug */
	bus_node = map_pci_dev_to_slot(phb, pd->parent);
	if (!bus_node)
		return NULL;

	/*
	 * If this PCI device is mounted on a card the parent "bus"
	 * may actually be a slot or builtin.
	 */
	if (list_empty(&bus_node->children))
		return bus_node;

	/* find the device in the parent bus node */
	dt_for_each_child(bus_node, child) {
		u32 vdid;

		/* "pluggable" and "builtin" without unit addrs are wildcards */
		if (!dt_has_node_property(child, "reg", NULL)) {
			if (wildcard) {
				prerror("Duplicate wildcard entry! Already have %s, found %s",
					wildcard->name, child->name);
				assert(0);
			}

			wildcard = child;
			continue;
		}

		/* NB: the pci_device vdid is did,vid rather than vid,did */
		vdid = dt_prop_get_cell(child, "reg", 1) << 16 |
			dt_prop_get_cell(child, "reg", 0);

		if (vdid == pd->vdid)
			return child;
	}

	if (!wildcard)
		PCIDBG(phb, pd->bdfn,
			"Unable to find a slot for device %.4x:%.4x\n",
			(pd->vdid & 0xffff0000) >> 16, pd->vdid & 0xffff);

	return wildcard;
}

struct dt_node *map_pci_dev_to_slot(struct phb *phb, struct pci_device *pd)
{
	uint32_t bdfn = pd ? pd->bdfn : 0;
	struct dt_node *n;
	char *path;

	if (pd && pd->slot && pd->slot->data)
		return pd->slot->data;

	PCIDBG(phb, bdfn, "Finding slot\n");

	n = __map_pci_dev_to_slot(phb, pd);
	if (!n) {
		PCIDBG(phb, bdfn, "No slot found!\n");
	} else {
		path = dt_get_path(n);
		PCIDBG(phb, bdfn, "Slot found %s\n", path);
		free(path);
	}

	return n;
}

int __print_slot(struct phb *phb, struct pci_device *pd, void *userdata);
int __print_slot(struct phb *phb, struct pci_device *pd,
			void __unused *userdata)
{
	struct dt_node *node;
	struct dt_node *pnode;
	char *c = NULL;
	u32 phandle = 0;

	if (!pd)
		return 0;

	node = map_pci_dev_to_slot(phb, pd);

	/* at this point all node associations should be done */
	if (pd->dn && dt_has_node_property(pd->dn, "ibm,pcie-slot", NULL)) {
		phandle = dt_prop_get_u32(pd->dn, "ibm,pcie-slot");
		pnode = dt_find_by_phandle(dt_root, phandle);

		assert(node == pnode);
	}

	if (node)
		c = dt_get_path(node);

	PCIDBG(phb, pd->bdfn, "Mapped to slot %s (%x)\n",
		c ? c : "<null>", phandle);

	free(c);

	return 0;
}
