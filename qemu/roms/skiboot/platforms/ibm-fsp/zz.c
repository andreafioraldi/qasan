/* Copyright 2016 IBM Corp.
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
#include <fsp.h>
#include <pci.h>
#include <pci-cfg.h>
#include <chip.h>
#include <i2c.h>
#include <timebase.h>
#include <hostservices.h>

#include "ibm-fsp.h"
#include "lxvpd.h"

static bool zz_probe(void)
{
	/* FIXME: make this neater when the dust settles */
	if (dt_node_is_compatible(dt_root, "ibm,zz-1s2u") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-1s4u") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-2s2u") ||
	    dt_node_is_compatible(dt_root, "ibm,zz-2s4u"))
		return true;

	return false;
}

static uint32_t ibm_fsp_occ_timeout(void)
{
	/* Use a fixed 60s value for now */
	return 60;
}

static void zz_init(void)
{
	hservices_init();
	ibm_fsp_init();
}

DECLARE_PLATFORM(zz) = {
	.name			= "ZZ",
	.probe			= zz_probe,
	.init			= zz_init,
	.exit			= ibm_fsp_exit,
	.cec_power_down		= ibm_fsp_cec_power_down,
	.cec_reboot		= ibm_fsp_cec_reboot,
	/* FIXME: correct once PCI slot into is available */
	.pci_setup_phb		= NULL,
	.pci_get_slot_info	= NULL,
	.pci_probe_complete	= NULL,
	.nvram_info		= fsp_nvram_info,
	.nvram_start_read	= fsp_nvram_start_read,
	.nvram_write		= fsp_nvram_write,
	.occ_timeout		= ibm_fsp_occ_timeout,
	.elog_commit		= elog_fsp_commit,
	.start_preload_resource	= fsp_start_preload_resource,
	.resource_loaded	= fsp_resource_loaded,
	.sensor_read		= ibm_fsp_sensor_read,
	.terminate		= ibm_fsp_terminate,
};
