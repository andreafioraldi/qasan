/* Copyright 2013-2017 IBM Corp.
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libflash/blocklevel.h>

#include "../ecc.c"
#include "../blocklevel.c"

#define __unused		__attribute__((unused))

#define ERR(fmt...) fprintf(stderr, fmt)

bool libflash_debug;

static int bl_test_bad_read(struct blocklevel_device *bl __unused, uint64_t pos __unused,
		void *buf __unused, uint64_t len __unused)
{
	return FLASH_ERR_PARM_ERROR;
}

static int bl_test_read(struct blocklevel_device *bl, uint64_t pos, void *buf, uint64_t len)
{
	if (pos + len > 0x1000)
		return FLASH_ERR_PARM_ERROR;

	memcpy(buf, bl->priv + pos, len);

	return 0;
}

static int bl_test_bad_write(struct blocklevel_device *bl __unused, uint64_t pos __unused,
		const void *buf __unused, uint64_t len __unused)
{
	return FLASH_ERR_PARM_ERROR;
}

static int bl_test_write(struct blocklevel_device *bl, uint64_t pos, const void *buf, uint64_t len)
{
	if (pos + len > 0x1000)
		return FLASH_ERR_PARM_ERROR;

	memcpy(bl->priv + pos, buf, len);

	return 0;
}

static int bl_test_erase(struct blocklevel_device *bl, uint64_t pos, uint64_t len)
{
	if (pos + len > 0x1000)
		return FLASH_ERR_PARM_ERROR;

	memset(bl->priv + pos, 0xff, len);

	return 0;
}


static void dump_buf(uint8_t *buf, int start, int end, int miss)
{
	int i;

	printf("pos: value\n");
	for (i = start; i < end; i++)
		printf("%04x: %c%s\n", i, buf[i] == 0xff ? '-' : buf[i], i == miss ? " <- First missmatch" : "");
}

/*
 * Returns zero if the buffer is ok. Otherwise returns the position of
 * the mismatch. If the mismatch is at zero -1 is returned
 */
static int check_buf(uint8_t *buf, int zero_start, int zero_end)
{
	int i;

	for (i = 0; i < 0x1000; i++) {
		if (i >= zero_start && i < zero_end && buf[i] != 0xff)
			return i == 0 ? -1 : i;
		if ((i < zero_start || i >= zero_end) && buf[i] != (i % 26) + 'a')
			return i == 0 ? -1 : i;
	}

	return 0;
}

static void reset_buf(uint8_t *buf)
{
	int i;

	for (i = 0; i < 0x1000; i++) {
		/* This gives repeating a - z which will be nice to visualise */
		buf[i] = (i % 26) + 'a';
	}
}

int main(void)
{
	int i, miss;
	char *buf;
	struct blocklevel_device bl_mem = { 0 };
	struct blocklevel_device *bl = &bl_mem;

	if (blocklevel_ecc_protect(bl, 0, 0x1000)) {
		ERR("Failed to blocklevel_ecc_protect!\n");
		return 1;
	}

	/* 0x1000 -> 0x3000 should remain unprotected */

	if (blocklevel_ecc_protect(bl, 0x3000, 0x1000)) {
		ERR("Failed to blocklevel_ecc_protect(0x3000, 0x1000)\n");
		return 1;
	}
	if (blocklevel_ecc_protect(bl, 0x2f00, 0x1100)) {
		ERR("Failed to blocklevel_ecc_protect(0x2f00, 0x1100)\n");
		return 1;
	}

	/* Zero length protection */
	if (!blocklevel_ecc_protect(bl, 0x4000, 0)) {
		ERR("Shouldn't have succeeded blocklevel_ecc_protect(0x4000, 0)\n");
		return 1;
	}

	/* Minimum creatable size */
	if (blocklevel_ecc_protect(bl, 0x4000, BYTES_PER_ECC)) {
		ERR("Failed to blocklevel_ecc_protect(0x4000, BYTES_PER_ECC)\n");
		return 1;
	}

	/* Deal with overlapping protections */
	if (blocklevel_ecc_protect(bl, 0x100, 0x1000)) {
		ERR("Failed to protect overlaping region blocklevel_ecc_protect(0x100, 0x1000)\n");
		return 1;
	}

	/* Deal with overflow */
	if (!blocklevel_ecc_protect(bl, 1, 0xFFFFFFFF)) {
		ERR("Added an 'overflow' protection blocklevel_ecc_protect(1, 0xFFFFFFFF)\n");
		return 1;
	}

	/* Protect everything */
	if (blocklevel_ecc_protect(bl, 0, 0xFFFFFFFF)) {
		ERR("Couldn't protect everything blocklevel_ecc_protect(0, 0xFFFFFFFF)\n");
		return 1;
	}

	if (ecc_protected(bl, 0, 1) != 1) {
		ERR("Invaid result for ecc_protected(0, 1)\n");
		return 1;
	}

	if (ecc_protected(bl, 0, 0x1000) != 1) {
		ERR("Invalid result for ecc_protected(0, 0x1000)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x100, 0x100) != 1) {
		ERR("Invalid result for ecc_protected(0x0100, 0x100)\n");
		return 1;
	}

	/* Clear the protections */
	bl->ecc_prot.n_prot = 0;
	/* Reprotect */
	if (blocklevel_ecc_protect(bl, 0x3000, 0x1000)) {
		ERR("Failed to blocklevel_ecc_protect(0x3000, 0x1000)\n");
		return 1;
	}
	/* Deal with overlapping protections */
	if (blocklevel_ecc_protect(bl, 0x100, 0x1000)) {
		ERR("Failed to protect overlaping region blocklevel_ecc_protect(0x100, 0x1000)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x1000, 0) != 1) {
		ERR("Invalid result for ecc_protected(0x1000, 0)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x1000, 0x1000) != -1) {
		ERR("Invalid result for ecc_protected(0x1000, 0x1000)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x1000, 0x100) != 1) {
		ERR("Invalid result for ecc_protected(0x1000, 0x100)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x2000, 0) != 0) {
		ERR("Invalid result for ecc_protected(0x2000, 0)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x4000, 1) != 0) {
		ERR("Invalid result for ecc_protected(0x4000, 1)\n");
		return 1;
	}

	/* Check for asking for a region with mixed protection */
	if (ecc_protected(bl, 0x100, 0x2000) != -1) {
		ERR("Invalid result for ecc_protected(0x100, 0x2000)\n");
		return 1;
	}

	/* Test the auto extending of regions */
	if (blocklevel_ecc_protect(bl, 0x5000, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x5000, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x5100, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x5100, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x5200, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x5200, 0x100)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x5120, 0x10) != 1) {
		ERR("Invalid result for ecc_protected(0x5120, 0x10)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x4f00, 0x100)) {
		ERR("Failed to blocklevel_ecc_protected(0x4900, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x4900, 0x100)) {
		ERR("Failed to blocklevel_ecc_protected(0x4900, 0x100)\n");
		return 1;
	}

	if (ecc_protected(bl, 0x4920, 0x10) != 1) {
		ERR("Invalid result for ecc_protected(0x4920, 0x10)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x5290, 0x10)) {
		ERR("Failed to blocklevel_ecc_protect(0x5290, 0x10)\n");
		return 1;
	}

	/* Test the auto extending of regions */
	if (blocklevel_ecc_protect(bl, 0x6000, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x6000, 0x100)\n");
		return 1;
	}

	if (blocklevel_ecc_protect(bl, 0x6200, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x6200, 0x100)\n");
		return 1;
	}
	/*This addition should cause this one to merge the other two together*/
	if (blocklevel_ecc_protect(bl, 0x6100, 0x100)) {
		ERR("Failed to blocklevel_ecc_protect(0x6100, 0x100)\n");
		return 1;
	}
	/* Make sure we trigger the merging code */
	for (i = bl->ecc_prot.n_prot; i < bl->ecc_prot.total_prot; i++)
		blocklevel_ecc_protect(bl, 0x10000 + i * 0x200, 0x10);
	/* Check that the region merging works */
	for (i = 0; i < bl->ecc_prot.n_prot - 1; i++) {
		if (bl->ecc_prot.prot[i].start + bl->ecc_prot.prot[i].len == bl->ecc_prot.prot[i + 1].start ||
			  bl->ecc_prot.prot[i + 1].start + bl->ecc_prot.prot[i + 1].len == bl->ecc_prot.prot[i].start) {
			ERR("Problem with protection range merge code, region starting at 0x%08lx for 0x%08lx appears "
				"to touch region 0x%lx for 0x%lx\n", bl->ecc_prot.prot[i].start, bl->ecc_prot.prot[i].len,
				bl->ecc_prot.prot[i + 1].start, bl->ecc_prot.prot[i + 1].len);
			return 1;
		}
	}

	/*
	 * Test blocklevel_smart_erase()
	 * Probably safe to zero the blocklevel we've got
	 */
	buf = malloc(0x1000);
	if (!buf) {
		ERR("Malloc failed\n");
		return 1;
	}
	memset(bl, 0, sizeof(*bl));
	bl_mem.read = &bl_test_read;
	bl_mem.write = &bl_test_write;
	bl_mem.erase = &bl_test_erase;
	bl_mem.erase_mask = 0xff;
	bl_mem.priv = buf;
	reset_buf(buf);


	/*
	 * Test 1: One full and exact erase block, this shouldn't call
	 * read or write, ensure this fails if it does.
	 */
	bl_mem.write = &bl_test_bad_write;
	bl_mem.read = &bl_test_bad_read;
	if (blocklevel_smart_erase(bl, 0x100, 0x100)) {
		ERR("Failed to blocklevel_smart_erase(0x100, 0x100)\n");
		return 1;
	}
	miss = check_buf(buf, 0x100, 0x200);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x100, 0x100) at 0x%0x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0xfc, 0x105, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x1fc, 0x205, miss == -1 ? 0 : miss);
		return 1;
	}
	bl_mem.read = &bl_test_read;
	bl_mem.write = &bl_test_write;

	reset_buf(buf);
	/* Test 2: Only touch one erase block */
	if (blocklevel_smart_erase(bl, 0x20, 0x40)) {
		ERR("Failed to blocklevel_smart_erase(0x20, 0x40)\n");
		return 1;
	}
	miss = check_buf(buf, 0x20, 0x60);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x20, 0x40) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0x1c, 0x65, miss == -1 ? 0 : miss);
		return 1;
	}

	reset_buf(buf);
	/* Test 3: Start aligned but finish somewhere in it */
	if (blocklevel_smart_erase(bl, 0x100, 0x50)) {
		ERR("Failed to blocklevel_smart_erase(0x100, 0x50)\n");
		return 1;
	}
	miss = check_buf(buf, 0x100, 0x150);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x100, 0x50) at 0x%0x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0xfc, 0x105, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x14c, 0x155, miss == -1 ? 0 : miss);
		return 1;
	}

	reset_buf(buf);
	/* Test 4: Start somewhere in it, finish aligned */
	if (blocklevel_smart_erase(bl, 0x50, 0xb0)) {
		ERR("Failed to blocklevel_smart_erase(0x50, 0xb0)\n");
		return 1;
	}
	miss = check_buf(buf, 0x50, 0x100);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x50, 0xb0) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0x4c, 0x55, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x100, 0x105, miss == -1 ? 0 : miss);
		return 1;
	}

	reset_buf(buf);
	/* Test 5: Cover two erase blocks exactly */
	if (blocklevel_smart_erase(bl, 0x100, 0x200)) {
		ERR("Failed to blocklevel_smart_erase(0x100, 0x200)\n");
		return 1;
	}
	miss = check_buf(buf, 0x100, 0x300);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x100, 0x200) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0xfc, 0x105, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x2fc, 0x305, miss == -1 ? 0 : miss);
		return 1;
	}

	reset_buf(buf);
	/* Test 6: Erase 1.5 blocks (start aligned) */
	if (blocklevel_smart_erase(bl, 0x100, 0x180)) {
		ERR("Failed to blocklevel_smart_erase(0x100, 0x180)\n");
		return 1;
	}
	miss = check_buf(buf, 0x100, 0x280);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x100, 0x180) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0xfc, 0x105, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x27c, 0x285, miss == -1 ? 0 : miss);
		return 1;
	}

	reset_buf(buf);
	/* Test 7: Erase 1.5 blocks (end aligned) */
	if (blocklevel_smart_erase(bl, 0x80, 0x180)) {
		ERR("Failed to blocklevel_smart_erase(0x80, 0x180)\n");
		return 1;
	}
	miss = check_buf(buf, 0x80, 0x200);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x80, 0x180) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0x7c, 0x85, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x1fc, 0x205, miss == -1 ? 0 : miss);
		return 1;
	}

	reset_buf(buf);
	/* Test 8: Erase a big section, not aligned */
	if (blocklevel_smart_erase(bl, 0x120, 0x544)) {
		ERR("Failed to blocklevel_smart_erase(0x120, 0x544)\n");
		return 1;
	}
	miss = check_buf(buf, 0x120, 0x664);
	if (miss) {
		ERR("Buffer mismatch after blocklevel_smart_erase(0x120, 0x544) at 0x%x\n",
				miss == -1 ? 0 : miss);
		dump_buf(buf, 0x11c, 0x125, miss == -1 ? 0 : miss);
		dump_buf(buf, 0x65f, 0x669, miss == -1 ? 0 : miss);
		return 1;
	}

	free(buf);

	return 0;
}
