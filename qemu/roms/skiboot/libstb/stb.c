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

#include <skiboot.h>
#include <device.h>
#include <platform.h>
#include <string.h>
#include <stdio.h>
#include <nvram.h>
#include "stb.h"
#include "status_codes.h"
#include "container.h"
#include "rom.h"
#include "tpm_chip.h"

/* For debugging only */
//#define STB_DEBUG
//#define STB_FORCE_SECURE_MODE
//#define STB_FORCE_TRUSTED_MODE

static bool secure_mode = false;
static bool trusted_mode = false;

static struct rom_driver_ops *rom_driver = NULL;

#define MAX_RESOURCE_NAME	15

/*
 * This maps a PCR for each resource we can measure. The PCR number is
 * mapped according to the TCG PC Client Platform Firmware Profile
 * specification, Revision 00.21
 * Only resources included in this whitelist can be measured.
 */
static struct {

	/* PNOR partition id */
	enum resource_id id;

	/* PCR mapping for the resource id */
	TPM_Pcr pcr;

	/* Resource name */
	const char name[MAX_RESOURCE_NAME+1];

} resource_map[] = {
	{ RESOURCE_ID_KERNEL, PCR_4, "BOOTKERNEL" },
	{ RESOURCE_ID_CAPP,   PCR_2, "CAPP"},
};

struct event_hash {
	const unsigned char *sha1;
	const unsigned char *sha256;
};

/*
 * Event Separator - digest of 0xFFFFFFFF
 */
static struct event_hash evFF = {
	.sha1   = "\xd9\xbe\x65\x24\xa5\xf5\x04\x7d\xb5\x86"
		  "\x68\x13\xac\xf3\x27\x78\x92\xa7\xa3\x0a",

	.sha256 = "\xad\x95\x13\x1b\xc0\xb7\x99\xc0\xb1\xaf"
		  "\x47\x7f\xb1\x4f\xcf\x26\xa6\xa9\xf7\x60"
		  "\x79\xe4\x8b\xf0\x90\xac\xb7\xe8\x36\x7b"
		  "\xfd\x0e"
};

static int stb_resource_lookup(enum resource_id id)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(resource_map); i++)
		if (resource_map[i].id == id)
			return i;
	return -1;
}

static void sb_enforce(void)
{
	/*
	 * TODO: Ideally, the BMC should decide what security policy to apply
	 * (power off, reboot, switch PNOR sides, etc). We may need
	 * to provide extra info to BMC other than just abort.
	 * Terminate Immediate Attention ? (TI)
	 */
	prlog(PR_EMERG, "STB: Secure mode enforced, aborting.\n");
	abort();
}

void stb_init(void)
{
	struct dt_node *ibm_secureboot;
	/*
	 * The ibm,secureboot device tree properties are documented in
	 * 'doc/device-tree/ibm,secureboot.rst'
	 */
	ibm_secureboot = dt_find_by_path(dt_root, "/ibm,secureboot");
	if (ibm_secureboot == NULL) {
		prlog(PR_NOTICE,"STB: secure and trusted boot not supported\n");
		return;
	}

#ifdef STB_FORCE_SECURE_MODE
	secure_mode = true;
	prlog(PR_NOTICE, "STB: secure mode on (forced!)\n");
#else
	secure_mode = dt_has_node_property(ibm_secureboot, "secure-enabled",
					   NULL);

	if (nvram_query_eq("force-secure-mode", "always")) {
		prlog(PR_NOTICE, "STB: secure mode on (FORCED by nvram)\n");
		secure_mode = true;
	} else if (secure_mode) {
		prlog(PR_NOTICE, "STB: secure mode on.\n");
	} else {
		prlog(PR_NOTICE, "STB: secure mode off\n");
	}
#endif

#ifdef STB_FORCE_TRUSTED_MODE
	trusted_mode = true;
	prlog(PR_NOTICE, "STB: trusted mode on (forced!)\n");
#else
	trusted_mode = dt_has_node_property(ibm_secureboot, "trusted-enabled",
					    NULL);
	if (nvram_query_eq("force-trusted-mode", "true")) {
		prlog(PR_NOTICE, "STB: trusted mode ON (from NVRAM)\n");
		trusted_mode = true;
	}
	prlog(PR_NOTICE, "STB: trusted mode %s\n",
	      trusted_mode ? "on" : "off");
#endif

	if (!secure_mode && !trusted_mode)
		return;
	rom_driver = rom_init(ibm_secureboot);
	if (secure_mode && !rom_driver) {
		prlog(PR_EMERG, "STB: compatible romcode driver not found\n");
		sb_enforce();
	}
	if (trusted_mode)
		tpm_init();
}

int stb_final(void)
{
	uint32_t pcr;
	int rc;
	bool failed;

	rc = 0;
	failed = false;

	if (trusted_mode) {
#ifdef STB_DEBUG
		prlog(PR_NOTICE, "STB: evFF.sha1:\n");
		stb_print_data((uint8_t*) evFF.sha1, TPM_ALG_SHA1_SIZE);
		prlog(PR_NOTICE, "STB: evFF.sha256:\n");
		stb_print_data((uint8_t*) evFF.sha256, TPM_ALG_SHA256_SIZE);
#endif
		/*
		 * We are done. Extending the digest of 0xFFFFFFFF
		 * in PCR[0-7], and recording an EV_SEPARATOR event in
		 * event log as defined in the TCG Platform Firmware Profile
		 * specification, Revision 00.21
		 */
		for (pcr = 0; pcr < 8; pcr++) {
			rc = tpm_extendl(pcr, TPM_ALG_SHA256,
					(uint8_t*) evFF.sha256,
					TPM_ALG_SHA256_SIZE, TPM_ALG_SHA1,
					(uint8_t*) evFF.sha1,
					TPM_ALG_SHA1_SIZE, EV_SEPARATOR,
					"Skiboot Boot");
			if (rc)
				failed = true;
		}
		tpm_add_status_property();
	}
	if (rom_driver) {
		rom_driver->cleanup();
		rom_driver = NULL;
	}
	tpm_cleanup();
	secure_mode = false;
	trusted_mode = false;
	return (failed) ? STB_MEASURE_FAILED : 0;
}

int tb_measure(enum resource_id id, void *buf, size_t len)
{
	int r;
	uint8_t digest[SHA512_DIGEST_LENGTH];
	const uint8_t *digestp;

	digestp = NULL;
	if (!trusted_mode) {
		prlog(PR_INFO, "STB: %s skipped resource %d, "
		      "trusted_mode=0\n", __func__, id);
		return STB_TRUSTED_MODE_DISABLED;
	}
	r = stb_resource_lookup(id);
	if (r == -1) {
		/**
		 * @fwts-label STBMeasureResourceNotMapped
		 * @fwts-advice The resource is not registered in the resource_map[]
		 * array, but it should be otherwise the resource cannot be
		 * measured if trusted mode is on.
		 */
		prlog(PR_ERR, "STB: %s failed, resource %d not mapped\n",
		      __func__, id);
		return STB_ARG_ERROR;
	}
	if (!buf) {
		/**
		 * @fwts-label STBNullResourceReceived
		 * @fwts-advice Null resource passed to tb_measure. This has
		 * come from the resource load framework and likely indicates a
		 * bug in the framework.
		 */
		prlog(PR_ERR, "STB: %s failed: resource %s, buf null\n",
		      __func__, resource_map[r].name);
		return STB_ARG_ERROR;
	}
	memset(digest, 0, SHA512_DIGEST_LENGTH);
	/*
	 * In secure mode we can use the sw-payload-hash from the container
	 * header to measure the container payload. Otherwise we must calculate
	 * the hash of the container payload (if it's a container) or the image
	 * (if it's not a container)
	 */
	if (stb_is_container(buf, len)) {
		digestp = stb_sw_payload_hash(buf, len);
		if(!digestp) {
			prlog(PR_EMERG, "STB Container is corrupt, can't find hash\n");
			abort();
		}

		rom_driver->sha512(
			      (void*)((uint8_t*)buf + SECURE_BOOT_HEADERS_SIZE),
			      len - SECURE_BOOT_HEADERS_SIZE, digest);

		prlog(PR_INFO, "STB: %s sha512 hash re-calculated\n",
		      resource_map[r].name);
		if (memcmp(digestp, digest, TPM_ALG_SHA256_SIZE) != 0) {
			prlog(PR_ALERT, "STB: HASH IN CONTAINER DOESN'T MATCH CONTENT!\n");
			prlog(PR_ALERT, "STB: Container hash:\n");
			stb_print_data(digestp, TPM_ALG_SHA256_SIZE);
			prlog(PR_ALERT, "STB: Computed hash (on %lx bytes):\n", len);
			stb_print_data(digest, TPM_ALG_SHA256_SIZE);

			if (secure_mode)
				abort();
		}
	} else {
		rom_driver->sha512(buf, len, digest);
		prlog(PR_INFO, "STB: %s sha512 hash calculated\n",
		      resource_map[r].name);
	}

#ifdef STB_DEBUG
	/* print the payload/image hash */
	prlog(PR_NOTICE, "STB: %s hash:\n", resource_map[r].name);
	stb_print_data(digest, TPM_ALG_SHA256_SIZE);
#endif
	/*
	 * Measure the resource. Since the ROM code doesn't provide a sha1 hash
	 * algorithm, the sha512 hash is truncated to match the size required
	 * by each PCR bank.
	 */
	return tpm_extendl(resource_map[r].pcr,
			   TPM_ALG_SHA256, digest, TPM_ALG_SHA256_SIZE,
			   TPM_ALG_SHA1,   digest, TPM_ALG_SHA1_SIZE,
			   EV_ACTION, resource_map[r].name);
}

int sb_verify(enum resource_id id, void *buf, size_t len)
{
	int r;
	const char *name = NULL;

	if (!secure_mode) {
		prlog(PR_INFO, "STB: %s skipped resource %d, "
		      "secure_mode=0\n", __func__, id);
		return STB_SECURE_MODE_DISABLED;
	}
	r = stb_resource_lookup(id);
	if (r == -1)
		/**
		 * @fwts-label STBVerifyResourceNotMapped
		 * @fwts-advice Unregistered resources can be verified, but not
		 * measured. The resource should be registered in the
		 * resource_map[] array, otherwise the resource cannot be
		 * measured if trusted mode is on.
		 */
		prlog(PR_WARNING, "STB: verifying the non-expected "
		      "resource %d\n", id);
	else
		name = resource_map[r].name;
	if (!rom_driver || !rom_driver->verify) {
		prlog(PR_EMERG, "STB: secure boot not initialized\n");
		sb_enforce();
	}
	if (!buf || len < SECURE_BOOT_HEADERS_SIZE) {
		prlog(PR_EMERG, "STB: %s arg error: id %d, buf %p, len %zd\n",
		      __func__, id, buf, len);
		sb_enforce();
	}
	if (rom_driver->verify(buf)) {
		prlog(PR_EMERG, "STB: %s failed: resource %s, "
		      "eyecatcher 0x%016llx\n", __func__, name,
		      *((uint64_t*)buf));
		sb_enforce();
	}
	prlog(PR_NOTICE, "STB: %s verified\n", name);
	return 0;
}
