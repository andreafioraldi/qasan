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
#include "rom.h"
#include "drivers/romcode.h"
#include "drivers/sw_driver.h"

static struct rom_driver_ops *rom_driver = NULL;

struct rom_driver_ops* rom_init(const struct dt_node *node __unused)
{
	if (rom_driver)
		goto end;

	/* ROM drivers supported */
	romcode_probe(node);

	if (!rom_driver)
		stb_software_probe(node);

	if (!rom_driver)
		prlog(PR_NOTICE, "ROM: no rom driver found\n");
end:
	return rom_driver;
}

void rom_set_driver(struct rom_driver_ops *driver)
{
	if (rom_driver) {
		/**
		 * @fwts-label ROMAlreadyRegistered
		 * @fwts-advice ibm,secureboot already registered. Check if
		 * rom_init called twice or the same driver is probed twice
		 */
		prlog(PR_WARNING, "ROM: %s driver already registered\n",
		      driver->name);
		return;
	}
	rom_driver = driver;
	prlog(PR_NOTICE, "ROM: %s driver registered\n", driver->name);
}
