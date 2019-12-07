/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/import/chips/p9/procedures/utils/stopreg/p9_cpu_reg_restore_instruction.H $ */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2015,2017                        */
/* [+] International Business Machines Corp.                              */
/*                                                                        */
/*                                                                        */
/* Licensed under the Apache License, Version 2.0 (the "License");        */
/* you may not use this file except in compliance with the License.       */
/* You may obtain a copy of the License at                                */
/*                                                                        */
/*     http://www.apache.org/licenses/LICENSE-2.0                         */
/*                                                                        */
/* Unless required by applicable law or agreed to in writing, software    */
/* distributed under the License is distributed on an "AS IS" BASIS,      */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or        */
/* implied. See the License for the specific language governing           */
/* permissions and limitations under the License.                         */
/*                                                                        */
/* IBM_PROLOG_END_TAG                                                     */

///
/// @file   p9_cpu_reg_restore_instruction.H
/// @brief  enumerates all the opcodes used for SPR restoration.
///
// *HWP HW Owner    :  Greg Still <stillgs@us.ibm.com>
// *HWP FW Owner    :  Prem Shanker Jha <premjha2@in.ibm.com>
// *HWP Team        :  PM
// *HWP Level       :  2
// *HWP Consumed by :  HB:HYP

#ifndef __REG_RESTORE_INSTRUCTION_H
#define __REG_RESTORE_INSTRUCTION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {

namespace stopImageSection
{
#endif

/**
 * @brief enumerates opcodes for few instructions.
 */
enum
{
    ORI_OPCODE        = 24,
    RFI_OPCODE        = 19,
    RFI_CONST         = 50,
    ORIS_OPCODE       = 25,
    OPCODE_31         = 31,
    XOR_CONST         = 316,
    RLDICR_OPCODE     = 30,
    RLDICR_CONST      = 1,
    MTSPR_CONST1      = 467,
    MTMSRD_CONST1     = 178,
    MR_R0_TO_R10      = 0x7c0a0378, //mr r10, r0
    MR_R0_TO_R21      = 0x7c150378, //mr r21, r0
    BLR_INST          = 0x4e800020,
    MTSPR_BASE_OPCODE = 0x7c0003a6,
    ATTN_OPCODE       = 0x00000200,
};

#ifdef __cplusplus
} // namespace stopImageSection ends

} // extern "C"
#endif //__cplusplus

#endif //__REG_RESTORE_INSTRUCTION_H
