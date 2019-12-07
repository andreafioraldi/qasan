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

#ifndef __LPC_MBOX_H
#define __LPC_MBOX_H

#include <opal.h>
#include <ccan/endian/endian.h>

#define BMC_MBOX_ARGS_REGS 11
#define BMC_MBOX_READ_REGS 16
#define BMC_MBOX_WRITE_REGS 13

#define MBOX_C_RESET_STATE 0x01
#define MBOX_C_GET_MBOX_INFO 0x02
#define MBOX_C_GET_FLASH_INFO 0x03
#define MBOX_C_CREATE_READ_WINDOW 0x04
#define MBOX_C_CLOSE_WINDOW 0x05
#define MBOX_C_CREATE_WRITE_WINDOW 0x06
#define MBOX_C_MARK_WRITE_DIRTY 0x07
#define MBOX_C_WRITE_FLUSH 0x08
#define MBOX_C_BMC_EVENT_ACK 0x09
#define MBOX_C_MARK_WRITE_ERASED 0x0a
#define MBOX_COMMAND_COUNT 10

#define MBOX_R_SUCCESS 0x01
#define MBOX_R_PARAM_ERROR 0x02
#define MBOX_R_WRITE_ERROR 0x03
#define MBOX_R_SYSTEM_ERROR 0x04
#define MBOX_R_TIMEOUT 0x05

#define MBOX_ATTN_ACK_MASK 0x3
#define MBOX_ATTN_BMC_REBOOT (1 << 0)
#define MBOX_ATTN_BMC_WINDOW_RESET (1 << 1)
#define MBOX_ATTN_BMC_FLASH_LOST (1 << 6)
#define MBOX_ATTN_BMC_DAEMON_READY (1 << 7)

/* Default poll interval before interrupts are working */
#define MBOX_DEFAULT_POLL_MS	200

struct bmc_mbox_msg {
	uint8_t command;
	uint8_t seq;
	uint8_t args[BMC_MBOX_ARGS_REGS];
	uint8_t response;
	uint8_t host;
	uint8_t bmc;
};

int bmc_mbox_enqueue(struct bmc_mbox_msg *msg);
int bmc_mbox_register_callback(void (*callback)(struct bmc_mbox_msg *msg, void *priv),
		void *drv_data);
int bmc_mbox_register_attn(void (*callback)(uint8_t bits, void *priv),
		void *drv_data);
uint8_t bmc_mbox_get_attn_reg(void);
#endif /* __LPC_MBOX_H */
