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

#ifndef __STB_H
#define __STB_H

/**
 * This reads secure mode and trusted mode from device tree and
 * loads drivers accordingly.
 */
extern void stb_init(void);

/**
 * As defined in the TCG Platform Firmware Profile specification, the
 * digest of 0xFFFFFFFF or 0x00000000  must be extended in PCR[0-7] and
 * an EV_SEPARATOR event must be recorded in the event log for PCR[0-7]
 * prior to the first invocation of the first Ready to Boot call.
 *
 * This function should be called before the control is passed to petitboot
 * kernel in order to do the proper PCR extend and event log recording as
 * defined above. This function also deallocates the memory allocated for secure
 * and trusted boot.
 */
extern int stb_final(void);

/**
 * sb_verify - verify a resource
 * @id   : resource id
 * @buf  : data to be verified
 * @len  : buf length
 *
 * This verifies the integrity and authenticity of a resource downloaded from
 * PNOR if secure mode is on. The verification is done by the
 * verification code flashed in the secure ROM.
 *
 * For more information refer to 'doc/stb.rst'
 *
 * returns: 0 otherwise the boot process is aborted
 */
extern int sb_verify(enum resource_id id, void *buf, size_t len);


/**
 * tb_measure - measure a resource
 * @id    : resource id
 * @buf   : data to be measured
 * @len   : buf length
 *
 * This measures a resource downloaded from PNOR if trusted mode is on. That is,
 * an EV_ACTION event is recorded in the event log for the mapped PCR, and the
 * the sha1 and sha256 measurements are extended in the mapped PCR.
 *
 * For more information please refer to 'doc/stb.rst'
 *
 * returns: 0 or an error as defined in status_codes.h
 */
extern int tb_measure(enum resource_id id, void *buf, size_t len);

#endif /* __STB_H */
