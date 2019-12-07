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
#include <string.h>
#include <skiboot.h>
#include "../rom.h"
#include "sha512.h"
#include "sw_driver.h"

static sha2_hash_t *hw_key_hash = NULL;

static int stb_software_verify(void *container __unused)
{
	return -100;
}

static void stb_software_sha512(const uint8_t *data, size_t len, uint8_t *digest)
{
	mbedtls_sha512_context ctx;
	mbedtls_sha512_init(&ctx);
	memset(digest, 0, sizeof(sha2_hash_t));
	mbedtls_sha512_starts(&ctx, 0); // SHA512 = 0
	mbedtls_sha512_update(&ctx, data, len);
	mbedtls_sha512_finish(&ctx, digest);
	mbedtls_sha512_free(&ctx);
}

static void stb_software_cleanup(void)
{
	return;
}

static struct rom_driver_ops sw_driver = {
	.name    = "software",
	.verify  = stb_software_verify,
	.sha512  = stb_software_sha512,
	.cleanup = stb_software_cleanup
};

void stb_software_probe(const struct dt_node *node)
{
	const char* hash_algo;

	if (!dt_node_is_compatible(node, "ibm,secureboot-v1-softrom")) {
		return;
	}

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

	rom_set_driver(&sw_driver);
}
