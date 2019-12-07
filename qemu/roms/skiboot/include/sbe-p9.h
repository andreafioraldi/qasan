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

#ifndef __SBE_P9_H
#define __SBE_P9_H

#include <bitutils.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>

#define PSU_HOST_DOORBELL_REG_RW	0x000D0063
#define PSU_HOST_DOORBELL_REG_AND	0x000D0064
#define PSU_HOST_DOORBELL_REG_OR	0x000D0065

#define SBE_HOST_PASSTHROUGH		PPC_BIT(4)
#define SBE_HOST_RESPONSE_CLEAR		0x00

/* SBE interrupt */
extern void sbe_interrupt(uint32_t chip_id);

#endif	/* __SBE_P9_H */
