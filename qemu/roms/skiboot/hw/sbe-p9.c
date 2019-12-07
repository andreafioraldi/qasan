/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define pr_fmt(fmt) "SBE: " fmt

#include <chip.h>
#include <errorlog.h>
#include <lock.h>
#include <opal.h>
#include <sbe-p9.h>
#include <skiboot.h>
#include <timebase.h>
#include <timer.h>
#include <trace.h>
#include <xscom.h>

void sbe_interrupt(uint32_t chip_id)
{
	int rc;
	u64 data;
	struct proc_chip *chip;

	chip = get_chip(chip_id);
	if (chip == NULL)
		return;

	/* Read doorbell register */
	rc = xscom_read(chip_id, PSU_HOST_DOORBELL_REG_RW, &data);
	if (rc) {
		prlog(PR_ERR, "Failed to read SBE to Host doorbell register "
		      "[chip id = %x]\n", chip_id);
		goto clr_interrupt;
	}

	/* SBE passtrhough command, call prd handler */
	if (data & SBE_HOST_PASSTHROUGH) {
		prd_sbe_passthrough(chip_id);
	}

clr_interrupt:
	/* Clears all the bits */
	rc = xscom_write(chip_id, PSU_HOST_DOORBELL_REG_AND,
			 SBE_HOST_RESPONSE_CLEAR);
	if (rc) {
		prlog(PR_ERR, "Failed to clear SBE to Host doorbell "
		      "register [chip id = %x]\n", chip_id);
	}
}
