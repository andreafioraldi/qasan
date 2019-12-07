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

#ifndef __PCI_IOV_H
#define __PCI_IOV_H

struct pci_iov {
	struct phb			*phb;
	struct pci_device		*pd;
	struct pci_device		*VFs;
	uint32_t			pos;
	bool				enabled;
	struct pci_cfg_reg_filter	pcrf;

	uint16_t			init_VFs;
	uint16_t			total_VFs;
	uint16_t			num_VFs;
	uint16_t			offset;
	uint16_t			stride;
};

extern void pci_init_iov_cap(struct phb *phb, struct pci_device *pd);

#endif
