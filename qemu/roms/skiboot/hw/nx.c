/* Copyright 2013-2015 IBM Corp.
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
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <nx.h>
#include <chip.h>
#include <xscom-p9-regs.h>
#include <phys-map.h>

extern void nx_p9_rng_init(void);

void nx_p9_rng_init(void)
{
	struct proc_chip *chip;
	struct cpu_thread *c;
	uint64_t bar, tmp;

	if (proc_gen != proc_gen_p9)
		return;
	if (chip_quirk(QUIRK_NO_RNG))
		return;

	/*
	 * Two things we need to setup here:
	 *
	 * 1) The per chip BAR for the NX RNG region. The location of
	 *    this is determined by the global MMIO Map.

	 * 2) The per core BAR for the DARN BAR, which points to the
	 *    per chip RNG region set in 1.
	 *
	 */
	for_each_chip(chip) {
		/* 1) NX RNG BAR */
		phys_map_get(chip->id, NX_RNG, 0, &bar, NULL);
		xscom_write(chip->id, P9X_NX_MMIO_BAR,
			    bar | P9X_NX_MMIO_BAR_EN);
		/* Read config register for pace info */
		xscom_read(chip->id, P9X_NX_RNG_CFG, &tmp);
		prlog(PR_INFO, "NX RNG[%x] pace:%lli\n", chip->id,
		      0xffff & (tmp >> 2));

		/* 2) DARN BAR */
		for_each_available_core_in_chip(c, chip->id) {
			uint64_t addr;
			addr = XSCOM_ADDR_P9_EX(pir_to_core_id(c->pir),
						P9X_EX_NCU_DARN_BAR);
			xscom_write(chip->id, addr,
				    bar | P9X_EX_NCU_DARN_BAR_EN);
		}
	}
}

static void nx_init_one(struct dt_node *node)
{
	nx_create_rng_node(node);
	nx_create_crypto_node(node);
	nx_create_compress_node(node);
}

void nx_init(void)
{
	struct dt_node *node;

	nx_p9_rng_init();

	dt_for_each_compatible(dt_root, node, "ibm,power-nx") {
		nx_init_one(node);
	}

	dt_for_each_compatible(dt_root, node, "ibm,power9-nx") {
		nx_init_one(node);
	}
}
