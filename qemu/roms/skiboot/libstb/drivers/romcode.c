/* Copyright 2013-2016 IBM Corp.
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

#include <chip.h>
#include <xscom.h>
#include <string.h>
#include <skiboot.h>
#include "../status_codes.h"
#include "../rom.h"
#include "romcode.h"

#define DRIVER_NAME	"romcode"

#define ROMCODE_MEMORY_SIZE	(16 * 1024)
#define ROMCODE_XSCOM_ADDRESS	0x02020017

/*
 *  From the source code of the ROM code
 */
#define ROMCODE_SHA512_OFFSET		0x20
#define ROMCODE_VERIFY_OFFSET		0x30

static const char *compat = "ibm,secureboot-v1";
static void *romcode_base_addr = NULL;
static sha2_hash_t *hw_key_hash = NULL;

/*
 * Assembly interfaces to call into ROM code.
 * func_ptr is the ROM code function address, followed
 * by additional parameters as necessary
 */
ROM_response call_rom_verify(void *func_ptr, ROM_container_raw *container,
			     ROM_hw_params *params);
void call_rom_SHA512(void *func_ptr, const uint8_t *data, size_t len,
		     uint8_t *digest);

static int romcode_verify(void *container)
{
	ROM_hw_params hw_params;
	ROM_response rc;

	memset(&hw_params, 0, sizeof(ROM_hw_params));
	memcpy(&hw_params.hw_key_hash, hw_key_hash, sizeof(sha2_hash_t));
	rc = call_rom_verify(romcode_base_addr + ROMCODE_VERIFY_OFFSET,
			     (ROM_container_raw*) container, &hw_params);
	if (rc != ROM_DONE) {
		/*
		 * Verify failed. hw_params.log indicates what checking has
		 * failed. This will abort the boot process.
		 */
		prlog(PR_ERR, "ROM: %s failed (rc=%d, hw_params.log=0x%llx)\n",
		      __func__, rc, be64_to_cpu(hw_params.log));
		return STB_VERIFY_FAILED;
	}
	return 0;
}

static void romcode_sha512(const uint8_t *data, size_t len, uint8_t *digest)
{
	memset(digest, 0, sizeof(sha2_hash_t));
	call_rom_SHA512(romcode_base_addr + ROMCODE_SHA512_OFFSET,
			data, len, digest);
}

static void romcode_cleanup(void) {
	if (romcode_base_addr)
		free(romcode_base_addr);
	hw_key_hash = NULL;
}

static struct rom_driver_ops romcode_driver = {
	.name    = DRIVER_NAME,
	.verify  = romcode_verify,
	.sha512  = romcode_sha512,
	.cleanup = romcode_cleanup
};

void romcode_probe(const struct dt_node *node)
{
	/* This xscom register has the ROM code base address */
	const uint32_t reg_addr = ROMCODE_XSCOM_ADDRESS;
	uint64_t reg_data;
	struct proc_chip *chip;
	const char* hash_algo;

	if (!dt_node_is_compatible(node, compat)) {
		prlog(PR_DEBUG, "ROM: %s node is not compatible\n",
		      node->name);
		return;
	}
	/*
	 * secureboot-v1 defines containers with sha512 hashes
	 */
	hash_algo = dt_prop_get(node, "hash-algo");
	if (strcmp(hash_algo, "sha512")) {
		/**
		 * @fwts-label ROMHashAlgorithmInvalid
		 * @fwts-advice Hostboot creates the ibm,secureboot node and
		 * the hash-algo property. Check that the ibm,secureboot node
		 * layout has not changed.
		 */
		prlog(PR_ERR, "ROM: hash-algo=%s not expected\n", hash_algo);
		return;
	}
	hw_key_hash = (sha2_hash_t*) dt_prop_get(node, "hw-key-hash");
	romcode_base_addr = malloc(ROMCODE_MEMORY_SIZE);
	assert(romcode_base_addr);
	/*
	 * The logic that contains the ROM within the processor is implemented
	 * in a way that it only responds to CI (cache inhibited) operations.
	 * Due to performance issues we copy the verification code from the
	 * secure ROM to RAM and we use memcpy_from_ci to do that.
	 */
	chip = next_chip(NULL);
	xscom_read(chip->id, reg_addr, &reg_data);
	memcpy_from_ci(romcode_base_addr, (void*) reg_data,
		       ROMCODE_MEMORY_SIZE);
	/*
	 * Skiboot runs with IR (Instruction Relocation) &
	 * DR (Data Relocation) off, so there is no need to either MMIO
	 * the ROM code or set the memory region as executable.
         * skiboot accesses the physical memory directly. Real mode.
	 */
	rom_set_driver(&romcode_driver);
}
