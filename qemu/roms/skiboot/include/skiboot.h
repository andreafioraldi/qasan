/* Copyright 2013-2014 IBM Corp.
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

#ifndef __SKIBOOT_H
#define __SKIBOOT_H

#include <compiler.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <bitutils.h>
#include <types.h>

#include <ccan/container_of/container_of.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/str/str.h>

#include <libflash/blocklevel.h>

#include <mem-map.h>
#include <op-panel.h>
#include <platform.h>

/* Special ELF sections */
#define __force_data		__section(".force.data")

struct mem_region;
extern struct mem_region *mem_region_next(struct mem_region *region);

#ifndef __TESTING__
/* Readonly section start and end. */
extern char __rodata_start[], __rodata_end[];

static inline bool is_rodata(const void *p)
{
	return ((const char *)p >= __rodata_start && (const char *)p < __rodata_end);
}
#else
static inline bool is_rodata(const void *p)
{
	return false;
}
#endif

#define OPAL_BOOT_COMPLETE 0x1
/* Debug descriptor. This structure is pointed to by the word at offset
 * 0x80 in the sapphire binary
 */
struct debug_descriptor {
	u8	eye_catcher[8];	/* "OPALdbug" */
#define DEBUG_DESC_VERSION	1
	u32	version;
	u8	console_log_levels;	/* high 4 bits in memory,
					 * low 4 bits driver (e.g. uart). */
	u8	state_flags; /* various state flags - OPAL_BOOT_COMPLETE etc */
	u16	reserved2;
	u32	reserved[2];

	/* Memory console */
	u64	memcons_phys;
	u32	memcons_tce;
	u32	memcons_obuf_tce;
	u32	memcons_ibuf_tce;

	/* Traces */
	u64	trace_mask;
	u32	num_traces;
#define DEBUG_DESC_MAX_TRACES	256
	u64	trace_phys[DEBUG_DESC_MAX_TRACES];
	u32	trace_size[DEBUG_DESC_MAX_TRACES];
	u32	trace_tce[DEBUG_DESC_MAX_TRACES];
};
extern struct debug_descriptor debug_descriptor;

static inline bool opal_booting(void)
{
	return !(debug_descriptor.state_flags & OPAL_BOOT_COMPLETE);
}

/* Console logging
 * Update console_get_level() if you add here
 */
#define PR_EMERG	0
#define PR_ALERT	1
#define PR_CRIT		2
#define PR_ERR		3
#define PR_WARNING	4
#define PR_NOTICE	5
#define PR_PRINTF	PR_NOTICE
#define PR_INFO		6
#define PR_DEBUG	7
#define PR_TRACE	8
#define PR_INSANE	9

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

void _prlog(int log_level, const char* fmt, ...) __attribute__((format (printf, 2, 3)));
#define prlog(l, f, ...) do { _prlog(l, pr_fmt(f), ##__VA_ARGS__); } while(0)
#define prerror(fmt...)	do { prlog(PR_ERR, fmt); } while(0)
#define prlog_once(arg, ...)	 		\
({						\
	static bool __prlog_once = false;	\
	if (!__prlog_once) {			\
		__prlog_once = true;		\
		prlog(arg, ##__VA_ARGS__);	\
	}					\
})

/* Location codes  -- at most 80 chars with null termination */
#define LOC_CODE_SIZE	80

/* Processor generation */
enum proc_gen {
	proc_gen_unknown,
	proc_gen_p7,		/* P7 and P7+ */
	proc_gen_p8,
	proc_gen_p9,
};
extern enum proc_gen proc_gen;

extern unsigned int pcie_max_link_speed;

/* Convert a 4-bit number to a hex char */
extern char __attrconst tohex(uint8_t nibble);

/* Bit position of the most significant 1-bit (LSB=0, MSB=63) */
static inline int ilog2(unsigned long val)
{
	int left_zeros;

	asm volatile ("cntlzd %0,%1" : "=r" (left_zeros) : "r" (val));

	return 63 - left_zeros;
}

static inline bool is_pow2(unsigned long val)
{
	return val == (1ul << ilog2(val));
}

#define lo32(x)	((x) & 0xffffffff)
#define hi32(x)	(((x) >> 32) & 0xffffffff)

/* WARNING: _a *MUST* be a power of two */
#define ALIGN_UP(_v, _a)	(((_v) + (_a) - 1) & ~((_a) - 1))
#define ALIGN_DOWN(_v, _a)	((_v) & ~((_a) - 1))

/* TCE alignment */
#define TCE_SHIFT	12
#define TCE_PSIZE	(1ul << 12)
#define TCE_MASK	(TCE_PSIZE - 1)

/* Not the greatest variants but will do for now ... */
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))

/* Clean the stray high bit which the FSP inserts: we only have 52 bits real */
static inline u64 cleanup_addr(u64 addr)
{
	return addr & ((1ULL << 52) - 1);
}

/* Start the kernel */
extern void start_kernel(uint64_t entry, void* fdt,
			 uint64_t mem_top) __noreturn;
extern void start_kernel32(uint64_t entry, void* fdt,
			   uint64_t mem_top) __noreturn;
extern void start_kernel_secondary(uint64_t entry) __noreturn;

/* Get description of machine from HDAT and create device-tree */
extern int parse_hdat(bool is_opal);

/* Root of device tree. */
extern struct dt_node *dt_root;

/* Full skiboot version number (possibly includes gitid). */
extern const char version[];

/* Debug support */
extern char __sym_map_start[];
extern char __sym_map_end[];
extern unsigned long get_symbol(unsigned long addr,
				char **sym, char **sym_end);

/* Direct controls */
extern void direct_controls_init(void);
extern int64_t opal_signal_system_reset(int cpu_nr);

/* Fast reboot support */
extern void disable_fast_reboot(const char *reason);
extern void fast_reboot(void);
extern void __noreturn __secondary_cpu_entry(void);
extern void __noreturn load_and_boot_kernel(bool is_reboot);
extern void cleanup_local_tlb(void);
extern void cleanup_global_tlb(void);
extern void init_shared_sprs(void);
extern void init_replicated_sprs(void);
extern bool start_preload_kernel(void);
extern void copy_exception_vectors(void);
extern void setup_reset_vector(void);

/* Various probe routines, to replace with an initcall system */
extern void probe_p7ioc(void);
extern void probe_phb3(void);
extern void probe_phb4(void);
extern int preload_capp_ucode(void);
extern void preload_io_vpd(void);
extern void probe_npu(void);
extern void probe_npu2(void);
extern void uart_init(void);
extern void mbox_init(void);
extern void early_uart_init(void);
extern void homer_init(void);
extern void occ_pstates_init(void);
extern void slw_init(void);
extern void add_cpu_idle_state_properties(void);
extern void occ_fsp_init(void);
extern void lpc_rtc_init(void);

/* flash support */
struct flash_chip;
extern int flash_register(struct blocklevel_device *bl);
extern int flash_start_preload_resource(enum resource_id id, uint32_t subid,
					void *buf, size_t *len);
extern int flash_resource_loaded(enum resource_id id, uint32_t idx);
extern bool flash_reserve(void);
extern void flash_release(void);
#define FLASH_SUBPART_ALIGNMENT 0x1000
#define FLASH_SUBPART_HEADER_SIZE FLASH_SUBPART_ALIGNMENT
extern int flash_subpart_info(void *part_header, uint32_t header_len,
			      uint32_t part_size, uint32_t *part_actual,
			      uint32_t subid, uint32_t *offset,
			      uint32_t *size);
extern void flash_fw_version_preload(void);
extern void flash_dt_add_fw_version(void);

/* NVRAM support */
extern void nvram_init(void);
extern void nvram_read_complete(bool success);

/* UART stuff */
enum {
	UART_CONSOLE_OPAL,
	UART_CONSOLE_OS
};
extern void uart_set_console_policy(int policy);
extern bool uart_enabled(void);

/* OCC interrupt for P8 */
extern void occ_p8_interrupt(uint32_t chip_id);
extern void occ_send_dummy_interrupt(void);

/* OCC interrupt for P9 */
extern void occ_p9_interrupt(uint32_t chip_id);

/* OCC load support */
extern void occ_poke_load_queue(void);

/* OCC/Host PNOR ownership */
enum pnor_owner {
	PNOR_OWNER_HOST,
	PNOR_OWNER_EXTERNAL,
};
extern void occ_pnor_set_owner(enum pnor_owner owner);

/* PRD */
extern void prd_psi_interrupt(uint32_t proc);
extern void prd_tmgt_interrupt(uint32_t proc);
extern void prd_occ_reset(uint32_t proc);
extern void prd_sbe_passthrough(uint32_t proc);
extern void prd_init(void);
extern void prd_register_reserved_memory(void);

/* Flatten device-tree */
extern void *create_dtb(const struct dt_node *root, bool exclusive);

/* SLW reinit function for switching core settings */
extern int64_t slw_reinit(uint64_t flags);

/* SLW update timer function */
extern void slw_update_timer_expiry(uint64_t new_target);

/* Is SLW timer available ? */
extern bool slw_timer_ok(void);

/* Patch SPR in SLW image */
extern int64_t opal_slw_set_reg(uint64_t cpu_pir, uint64_t sprn, uint64_t val);

extern void fast_sleep_exit(void);

/* Fallback fake RTC */
extern void fake_rtc_init(void);

/* Assembly in head.S */
extern void enter_p8_pm_state(bool winkle);
extern void enter_p9_pm_state(uint64_t psscr);
extern void enter_p9_pm_lite_state(uint64_t psscr);
extern uint32_t reset_patch_start;
extern uint32_t reset_patch_end;

/* Fallback fake NVRAM */
extern int fake_nvram_info(uint32_t *total_size);
extern int fake_nvram_start_read(void *dst, uint32_t src, uint32_t len);
extern int fake_nvram_write(uint32_t offset, void *src, uint32_t size);

/* OCC Inband Sensors */
extern void occ_sensors_init(void);
extern int occ_sensor_read(u32 handle, u32 *data);
extern int occ_sensor_group_clear(u32 group_hndl, int token);
extern void occ_add_sensor_groups(struct dt_node *sg, u32  *phandles,
				  int nr_phandles, int chipid);

#endif /* __SKIBOOT_H */
