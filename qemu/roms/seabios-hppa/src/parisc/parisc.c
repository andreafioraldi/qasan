// Glue code for parisc architecture
//
// Copyright (C) 2017-2018  Helge Deller <deller@gmx.de>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "bregs.h" // struct bregs
#include "hw/pic.h" // enable_hwirq
#include "output.h" // debug_enter
#include "stacks.h" // call16_int
#include "string.h" // memset
#include "util.h" // serial_setup
#include "malloc.h" // malloc
#include "hw/serialio.h" // qemu_debug_port
#include "hw/pcidevice.h" // foreachpci
#include "hw/pci.h" // pci_config_readl
#include "hw/pci_regs.h" // PCI_BASE_ADDRESS_0
#include "hw/ata.h"
#include "hw/blockcmd.h" // scsi_is_ready()
#include "hw/rtc.h"
#include "fw/paravirt.h" // PlatformRunningOn
#include "vgahw.h"
#include "parisc/hppa_hardware.h" // DINO_UART_BASE
#include "parisc/pdc.h"
#include "parisc/b160l.h"

#include "vgabios.h"

/*
 * Various variables which are needed by x86 code.
 * Defined here to be able to link seabios.
 */
int HaveRunPost;
u8 ExtraStack[BUILD_EXTRA_STACK_SIZE+1] __aligned(8);
u8 *StackPos;
u8 __VISIBLE parisc_stack[32*1024] __aligned(64);

u8 BiosChecksum;

char zonefseg_start, zonefseg_end;  // SYMBOLS
char varlow_start, varlow_end, final_varlow_start;
char final_readonly_start;
char code32flat_start, code32flat_end;
char zonelow_base;

struct bios_data_area_s __VISIBLE bios_data_area;
struct vga_bda_s	__VISIBLE vga_bios_data_area;
struct bregs regs;
unsigned long parisc_vga_mem;
unsigned long parisc_vga_mmio;
struct segoff_s ivt_table[256];

void mtrr_setup(void) { }
void mathcp_setup(void) { }
void smp_setup(void) { }
void bios32_init(void) { }
void yield_toirq(void) { }
void farcall16(struct bregs *callregs) { }
void farcall16big(struct bregs *callregs) { }

void cpuid(u32 index, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
	*eax = *ebx = *ecx = *edx = 0;
}

void wrmsr_smp(u32 index, u64 val) { }

/********************************************************
 * PA-RISC specific constants and functions.
 ********************************************************/

/* Pointer to zero-page of PA-RISC */
#define PAGE0 ((volatile struct zeropage *) 0UL)

/* variables provided by qemu */
extern unsigned long boot_args[];
#define ram_size		(boot_args[0])
#define linux_kernel_entry	(boot_args[1])
#define cmdline			(boot_args[2])
#define initrd_start		(boot_args[3])
#define initrd_end		(boot_args[4])
#define smp_cpus		(boot_args[5])
#define pdc_debug		(boot_args[6])

extern char pdc_entry;
extern char pdc_entry_table;
extern char iodc_entry;
extern char iodc_entry_table;

/* args as handed over for firmware calls */
#define ARG0 arg[7-0]
#define ARG1 arg[7-1]
#define ARG2 arg[7-2]
#define ARG3 arg[7-3]
#define ARG4 arg[7-4]
#define ARG5 arg[7-5]
#define ARG6 arg[7-6]
#define ARG7 arg[7-7]

/* size of I/O block used in HP firmware */
#define FW_BLOCKSIZE    2048

#define MIN_RAM_SIZE	(16*1024*1024) // 16 MB

#define MEM_PDC_ENTRY	0x4800	/* as in a B160L */

static unsigned long GoldenMemory = MIN_RAM_SIZE;

static unsigned int chassis_code = 0;

void __VISIBLE __noreturn hlt(void)
{
    if (pdc_debug)
	printf("HALT initiated from %p\n",  __builtin_return_address(0));
    printf("SeaBIOS wants SYSTEM HALT.\n\n");
    asm volatile("\t.word 0xfffdead0": : :"memory");
    while (1);
}

void __noreturn reset(void)
{
    if (pdc_debug)
	printf("RESET initiated from %p\n",  __builtin_return_address(0));
    printf("SeaBIOS wants SYSTEM RESET.\n"
	   "***************************\n");
    PAGE0->imm_soft_boot = 1;
    asm volatile("\t.word 0xfffdead1": : :"memory");
    while (1);
}

#undef BUG_ON
#define BUG_ON(cond) \
	if (unlikely(cond)) \
	{ printf("ERROR in %s:%d\n", __FUNCTION__, __LINE__); hlt(); }

void flush_data_cache(char *start, size_t length)
{
    char *end = start + length;

    do
    {
        asm volatile("fdc 0(%0)" : : "r" (start));
        asm volatile("fic 0(%%sr0,%0)" : : "r" (start));
        start += 16;
    } while (start < end);
    asm volatile("fdc 0(%0)" : : "r" (end));

    asm ("sync");
}

/********************************************************
 * FIRMWARE IO Dependent Code (IODC) HANDLER
 ********************************************************/

typedef struct {
	unsigned long hpa;
	struct pdc_iodc *iodc;
	struct pdc_system_map_mod_info *mod_info;
	struct pdc_module_path *mod_path;
	int num_addr;
	int add_addr[5];
} hppa_device_t;

static hppa_device_t parisc_devices[HPPA_MAX_CPUS+10] = { PARISC_DEVICE_LIST };

#define PARISC_KEEP_LIST \
	GSC_HPA,\
	DINO_HPA,\
	DINO_UART_HPA,\
	/* DINO_SCSI_HPA, */ \
	CPU_HPA,\
	MEMORY_HPA,\
	0

static int keep_this_hpa(unsigned long hpa)
{
	static const unsigned long keep_list[] = { PARISC_KEEP_LIST };
	int i = 0;

	while (keep_list[i]) {
		if (keep_list[i] == hpa)
			return 1;
		i++;
	}
	return 0;
}

/* Rebuild hardware list and drop all devices which are not listed in
 * PARISC_KEEP_LIST. Generate num_cpus CPUs. */
static void remove_parisc_devices(unsigned int num_cpus)
{
	static struct pdc_system_map_mod_info modinfo[HPPA_MAX_CPUS] = { {1,}, };
	static struct pdc_module_path modpath[HPPA_MAX_CPUS] = { {{1,}} };
	hppa_device_t *cpu_dev = NULL;
	unsigned long hpa;
	int i, p, t;

	/* already initialized? */
	static int uninitialized = 1;
	if (!uninitialized)
		return;
	uninitialized = 0;

	p = t = 0;
	while ((hpa = parisc_devices[p].hpa) != 0) {
		if (keep_this_hpa(hpa)) {
			parisc_devices[t] = parisc_devices[p];
			if (hpa == CPU_HPA)
				cpu_dev = &parisc_devices[t];
			t++;
		}
		p++;
	}

	/* Generate CPU list */
	for (i = 1; i < num_cpus; i++) {
		unsigned long hpa = CPU_HPA + i*0x1000;

		parisc_devices[t] = *cpu_dev;
		parisc_devices[t].hpa = hpa;

		modinfo[i] = *cpu_dev->mod_info;
		modinfo[i].mod_addr = hpa;
		parisc_devices[t].mod_info = &modinfo[i];

		modpath[i] = *cpu_dev->mod_path;
		modpath[i].path.mod = 128 + i;
		parisc_devices[t].mod_path = &modpath[i];

		t++;
	}

	BUG_ON(t > ARRAY_SIZE(parisc_devices));

	while (t < ARRAY_SIZE(parisc_devices)) {
		memset(&parisc_devices[t], 0, sizeof(parisc_devices[0]));
		t++;
	}
}

static struct drive_s *boot_drive;

static int find_hpa_index(unsigned long hpa)
{
	int i;
	if (!hpa)
		return -1;
	for (i = 0; i < (ARRAY_SIZE(parisc_devices)-1); i++) {
		if (hpa == parisc_devices[i].hpa)
			return i;
		if (!parisc_devices[i].hpa)
			return -1;
	}
	return -1;
}


#define SERIAL_TIMEOUT 20
static unsigned long parisc_serial_in(char *c, unsigned long maxchars)
{
	const portaddr_t addr = DINO_UART_HPA+0x800;
	unsigned long end = timer_calc(SERIAL_TIMEOUT);
	unsigned long count = 0;
	while (count < maxchars) {
		u8 lsr = inb(addr+SEROFF_LSR);
		if (lsr & 0x01) {
			// Success - can read data
			*c++ = inb(addr+SEROFF_DATA);
			count++;
		}
	        if (timer_check(end))
			break;
	}
	return count;
}

void iodc_log_call(unsigned int *arg, const char *func)
{
	if (pdc_debug) {
		printf("\nIODC %s called: hpa=0x%x option=0x%x arg2=0x%x arg3=0x%x ", func, ARG0, ARG1, ARG2, ARG3);
		printf("result=0x%x arg5=0x%x arg6=0x%x arg7=0x%x\n", ARG4, ARG5, ARG6, ARG7);
	}
}

#define FUNC_MANY_ARGS , \
	int a0, int a1, int a2, int a3,  int a4,  int a5,  int a6, \
	int a7, int a8, int a9, int a10, int a11, int a12


int __VISIBLE parisc_iodc_ENTRY_IO(unsigned int *arg FUNC_MANY_ARGS)
{
	unsigned long hpa = ARG0;
	unsigned long option = ARG1;
	unsigned long *result = (unsigned long *)ARG4;
	int ret, len;
	char *c;
	struct disk_op_s disk_op;

	if (1 &&
	   ((hpa == DINO_UART_HPA && option == ENTRY_IO_COUT) ||
	    (hpa == IDE_HPA       && option == ENTRY_IO_BOOTIN) ||
	    (hpa == DINO_SCSI_HPA && option == ENTRY_IO_BOOTIN)) ) {
		/* avoid debug messages */
	} else {
		iodc_log_call(arg, __FUNCTION__);
	}

	/* console I/O */
	if (hpa == DINO_UART_HPA || hpa == LASI_UART_HPA)
	switch (option) {
	case ENTRY_IO_COUT: /* console output */
		c = (char*)ARG6;
		result[0] = len = ARG7;
		while (len--)
			printf("%c", *c++);
		return PDC_OK;
	case ENTRY_IO_CIN: /* console input, with 5 seconds timeout */
		c = (char*)ARG6;
		result[0] = parisc_serial_in(c, ARG7);
		return PDC_OK;
	}

	/* boot medium I/O */
	if (hpa == DINO_SCSI_HPA || hpa == IDE_HPA)
	switch (option) {
	case ENTRY_IO_BOOTIN: /* boot medium IN */
		disk_op.drive_fl = boot_drive;
		disk_op.buf_fl = (void*)ARG6;
		disk_op.command = CMD_READ;
		disk_op.count = (ARG7 / disk_op.drive_fl->blksize);
		disk_op.lba = (ARG5 / disk_op.drive_fl->blksize);
		// ARG8 = maxsize !!!
		ret = process_op(&disk_op);
		// dprintf(0, "\nBOOT IO res %d count = %d\n", ret, ARG7);
		result[0] = ARG7;
		if (ret)
			return PDC_ERROR;
		return PDC_OK;
	}

	if (option == ENTRY_IO_CLOSE)
		return PDC_OK;

	BUG_ON(1);
	iodc_log_call(arg, __FUNCTION__);

	return PDC_BAD_OPTION;
}


int __VISIBLE parisc_iodc_ENTRY_INIT(unsigned int *arg FUNC_MANY_ARGS)
{
	unsigned long hpa = ARG0;
	unsigned long option = ARG1;
	unsigned long *result = (unsigned long *)ARG4;

	iodc_log_call(arg, __FUNCTION__);
	switch (option) {
	case 4:	/* Init & test mod & dev */
		result[0] = 0; /* module IO_STATUS */
		result[1] = (hpa == DINO_UART_HPA || hpa == LASI_UART_HPA) ? CL_DUPLEX:
			    (hpa == DINO_SCSI_HPA || hpa == IDE_HPA) ? CL_RANDOM : 0;
		result[2] = result[3] = 0; /* TODO?: MAC of network card. */
		return PDC_OK;
	}
	return PDC_BAD_OPTION;
}

int __VISIBLE parisc_iodc_ENTRY_SPA(unsigned int *arg FUNC_MANY_ARGS)
{
	iodc_log_call(arg, __FUNCTION__);
	return PDC_BAD_OPTION;
}

int __VISIBLE parisc_iodc_ENTRY_CONFIG(unsigned int *arg FUNC_MANY_ARGS)
{
	iodc_log_call(arg, __FUNCTION__);
	return PDC_BAD_OPTION;
}

int __VISIBLE parisc_iodc_ENTRY_TEST(unsigned int *arg FUNC_MANY_ARGS)
{
	iodc_log_call(arg, __FUNCTION__);
	return PDC_BAD_OPTION;
}

int __VISIBLE parisc_iodc_ENTRY_TLB(unsigned int *arg FUNC_MANY_ARGS)
{
	unsigned long option = ARG1;
	unsigned long *result = (unsigned long *)ARG4;

	iodc_log_call(arg, __FUNCTION__);

	if (option == 0) {
		*result = 0; /* no TLB */
		return PDC_OK;
	}
	return PDC_BAD_OPTION;
}

/********************************************************
 * FIRMWARE PDC HANDLER
 ********************************************************/

#define STABLE_STORAGE_SIZE	256
static unsigned char stable_storage[STABLE_STORAGE_SIZE];

static void init_stable_storage(void)
{
	/* see ENGINEERING NOTE in PDC2.0 doc */
	memset(&stable_storage, 0, STABLE_STORAGE_SIZE);
	// no intial paths
	stable_storage[0x07] = 0xff;
	stable_storage[0x67] = 0xff;
	stable_storage[0x87] = 0xff;
	stable_storage[0xa7] = 0xff;
	// 0x0e/0x0f => fastsize = all, needed for HPUX
	stable_storage[0x5f] = 0x0f;
}


/*
 * Trivial time conversion helper functions.
 * Not accurate before year 2000 and beyond year 2099.
 * Taken from:
 * https://codereview.stackexchange.com/questions/38275/convert-between-date-time-and-time-stamp-without-using-standard-library-routines
 */

static unsigned short days[4][12] =
{
    {   0,  31,  60,  91, 121, 152, 182, 213, 244, 274, 305, 335},
    { 366, 397, 425, 456, 486, 517, 547, 578, 609, 639, 670, 700},
    { 731, 762, 790, 821, 851, 882, 912, 943, 974,1004,1035,1065},
    {1096,1127,1155,1186,1216,1247,1277,1308,1339,1369,1400,1430},
};

static inline int rtc_from_bcd(int a)
{
	return ((a >> 4) * 10) + (a & 0x0f);
}

#define SECONDS_2000_JAN_1 946684800
/* assumption: only dates between 01/01/2000 and 31/12/2099 */

static unsigned long seconds_since_1970(void)
{
	unsigned long ret;
	unsigned int second = rtc_from_bcd(rtc_read(CMOS_RTC_SECONDS));
	unsigned int minute = rtc_from_bcd(rtc_read(CMOS_RTC_MINUTES));
	unsigned int hour   = rtc_from_bcd(rtc_read(CMOS_RTC_HOURS));
	unsigned int day    = rtc_from_bcd(rtc_read(CMOS_RTC_DAY_MONTH)) - 1;
	unsigned int month  = rtc_from_bcd(rtc_read(CMOS_RTC_MONTH)) - 1;
	unsigned int year   = rtc_from_bcd(rtc_read(CMOS_RTC_YEAR));
	ret = (((year/4*(365*4+1)+days[year%4][month]+day)*24+hour)*60+minute)
			*60+second + SECONDS_2000_JAN_1;

	if (year >= 100)
		printf("\nSeaBIOS WARNING: READ RTC_YEAR=%d is above year 2100.\n", year);

	return ret;
}

static inline int rtc_to_bcd(int a)
{
	return ((a / 10) << 4) | (a % 10);
}

void epoch_to_date_time(unsigned long epoch)
{
    epoch -= SECONDS_2000_JAN_1;

    unsigned int second = epoch%60; epoch /= 60;
    unsigned int minute = epoch%60; epoch /= 60;
    unsigned int hour   = epoch%24; epoch /= 24;

    unsigned int years = epoch/(365*4+1)*4; epoch %= 365*4+1;

    unsigned int year;
    for (year=3; year>0; year--)
    {
        if (epoch >= days[year][0])
            break;
    }

    unsigned int month;
    for (month=11; month>0; month--)
    {
        if (epoch >= days[year][month])
            break;
    }

    unsigned int rtc_year  = years + year;
    unsigned int rtc_month = month + 1;
    unsigned int rtc_day   = epoch - days[year][month] + 1;

    /* set date into RTC */
    rtc_write(CMOS_RTC_SECONDS, rtc_to_bcd(second));
    rtc_write(CMOS_RTC_MINUTES, rtc_to_bcd(minute));
    rtc_write(CMOS_RTC_HOURS, rtc_to_bcd(hour));
    rtc_write(CMOS_RTC_DAY_MONTH, rtc_to_bcd(rtc_day));
    rtc_write(CMOS_RTC_MONTH, rtc_to_bcd(rtc_month));
    rtc_write(CMOS_RTC_YEAR, rtc_to_bcd(rtc_year));

    if (rtc_year >= 100)
	printf("\nSeaBIOS WARNING: WRITE RTC_YEAR=%d above year 2100.\n", rtc_year);
}

/* values in PDC_CHASSIS */
const char * const systat[] =
	{ "Off", "Fault", "Test", "Initialize",
	  "Shutdown", "Warning", "Run", "All On" };

static const char *pdc_name(unsigned long num)
{
	#define DO(x) if (num == x) return #x;
	DO(PDC_POW_FAIL)
	DO(PDC_CHASSIS)
	DO(PDC_PIM)
	DO(PDC_MODEL)
	DO(PDC_CACHE)
	DO(PDC_HPA)
	DO(PDC_COPROC)
	DO(PDC_IODC)
	DO(PDC_TOD)
	DO(PDC_STABLE)
	DO(PDC_NVOLATILE)
	DO(PDC_ADD_VALID)
	DO(PDC_INSTR)
	DO(PDC_PROC)
	DO(PDC_BLOCK_TLB)
	DO(PDC_TLB)
	DO(PDC_MEM)
	DO(PDC_PSW)
	DO(PDC_SYSTEM_MAP)
	DO(PDC_SOFT_POWER)
	DO(PDC_MEM_MAP)
	DO(PDC_EEPROM)
	DO(PDC_NVM)
	DO(PDC_SEED_ERROR)
	DO(PDC_IO)
	DO(PDC_BROADCAST_RESET)
	DO(PDC_LAN_STATION_ID)
	DO(PDC_CHECK_RANGES)
	DO(PDC_NV_SECTIONS)
	DO(PDC_PERFORMANCE)
	DO(PDC_SYSTEM_INFO)
	DO(PDC_RDR)
	DO(PDC_INTRIGUE)
	DO(PDC_STI)
	DO(PDC_PCI_INDEX)
	DO(PDC_INITIATOR)
	DO(PDC_LINK)
	return "UNKNOWN!";
}

int __VISIBLE parisc_pdc_entry(unsigned int *arg FUNC_MANY_ARGS)
{
	static unsigned long psw_defaults = PDC_PSW_ENDIAN_BIT;
	static unsigned long cache_info[] = { PARISC_PDC_CACHE_INFO };
	static struct pdc_cache_info *machine_cache_info
				= (struct pdc_cache_info *) &cache_info;
	static unsigned long model[] = { PARISC_PDC_MODEL };
	static const char model_str[] = PARISC_MODEL;

	unsigned long proc = ARG0;
	unsigned long option = ARG1;
	unsigned long *result = (unsigned long *)ARG2;

	int hpa_index;
	unsigned long hpa;
	struct pdc_iodc *iodc_p;
	unsigned char *c;

	struct pdc_module_path *mod_path;

	if (pdc_debug) {
		printf("\nSeaBIOS: Start PDC proc %s(%d) option %d result=0x%x ARG3=0x%x ", pdc_name(ARG0), ARG0, ARG1, ARG2, ARG3);
		printf("ARG4=0x%x ARG5=0x%x ARG6=0x%x ARG7=0x%x\n", ARG4, ARG5, ARG6, ARG7);
	}

	switch (proc) {
	case PDC_POW_FAIL:
		break;
	case PDC_CHASSIS: /* chassis functions */
		switch (option) {
		case PDC_CHASSIS_DISP:
			ARG3 = ARG2;
			result = (unsigned long *)&ARG4; // do not write to ARG2, use &ARG4 instead
			// fall through
		case PDC_CHASSIS_DISPWARN:
			ARG4 = (ARG3 >> 17) & 7;
			chassis_code = ARG3 & 0xffff;
			printf("\nPDC_CHASSIS: %s (%d), %sCHASSIS  %0x\n",
				systat[ARG4], ARG4, (ARG3>>16)&1 ? "blank display, ":"", chassis_code);
			// fall through
		case PDC_CHASSIS_WARN:
			result[0] = 0;
			return PDC_OK;
		}
		// dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_CHASSIS function %d %x %x %x %x\n", ARG1, ARG2, ARG3, ARG4, ARG5);
		return PDC_BAD_PROC;
	case PDC_PIM:
		switch (option) {
		case PDC_PIM_HPMC:
			break;
		case PDC_PIM_RETURN_SIZE:
			*result = sizeof(struct pdc_hpmc_pim_11); // FIXME 64bit!
			// B160 returns only "2". Why?
			return PDC_OK;
		case PDC_PIM_LPMC:
		case PDC_PIM_SOFT_BOOT:
			return PDC_BAD_OPTION;
		case PDC_PIM_TOC:
			break;
		}
		break;
	case PDC_MODEL: /* model information */
		switch (option) {
		case PDC_MODEL_INFO:
			memcpy(result, model, sizeof(model));
			return PDC_OK;
		case PDC_MODEL_VERSIONS:
			if (ARG3 == 0) {
				result[0] = PARISC_PDC_VERSION;
				return PDC_OK;
			}
			return -4; // invalid c_index
		case PDC_MODEL_SYSMODEL:
			result[0] = sizeof(model_str) - 1;
			strtcpy((char *)ARG4, model_str, sizeof(model_str));
			return PDC_OK;
		case PDC_MODEL_CPU_ID:
			result[0] = PARISC_PDC_CPUID;
			return PDC_OK;
		case PDC_MODEL_CAPABILITIES:
			result[0] = PARISC_PDC_CAPABILITIES;
			return PDC_OK;
		}
		dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_MODEL function %d %x %x %x %x\n", ARG1, ARG2, ARG3, ARG4, ARG5);
		return PDC_BAD_OPTION;
	case PDC_CACHE:
		switch (option) {
		case PDC_CACHE_INFO:
			BUG_ON(sizeof(cache_info) != sizeof(*machine_cache_info));
			// XXX: number of TLB entries should be aligned with qemu
			machine_cache_info->it_size = 256;
			machine_cache_info->dt_size = 256;
			machine_cache_info->it_loop = 1;
			machine_cache_info->dt_loop = 1;

			#if 0
			dprintf(0, "\n\nCACHE  IC: %ld %ld %ld DC: %ld %ld %ld\n",
				machine_cache_info->ic_count, machine_cache_info->ic_loop, machine_cache_info->ic_stride,
				machine_cache_info->dc_count, machine_cache_info->dc_loop, machine_cache_info->dc_stride);
			#endif
			#if 1
                        /* Increase cc_block from 1 to 11. This increases icache_stride
                         * and dcache_stride to 32768 bytes. Revisit for HP-UX. */
			machine_cache_info->dc_conf.cc_block = 11;
			machine_cache_info->ic_conf.cc_block = 11;

			machine_cache_info->ic_size = 0; /* no instruction cache */
			machine_cache_info->ic_count = 0;
			machine_cache_info->ic_loop = 0;
			machine_cache_info->dc_size = 0; /* no data cache */
			machine_cache_info->dc_count = 0;
			machine_cache_info->dc_loop = 0;
			#endif

			memcpy(result, cache_info, sizeof(cache_info));
			return PDC_OK;
		}
		dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_CACHE function %d %x %x %x %x\n", ARG1, ARG2, ARG3, ARG4, ARG5);
		return PDC_BAD_OPTION;
	case PDC_HPA:
		switch (option) {
		case PDC_HPA_PROCESSOR:
			result[0] = CPU_HPA; // XXX: NEED TO FIX FOR SMP?
			result[1] = 0;
			return PDC_OK;
		case PDC_HPA_MODULES:
			return PDC_BAD_OPTION; // all modules on same board as the processor.
		}
		break;
	case PDC_COPROC:
		switch (option) {
		case PDC_COPROC_CFG:
			memset(result, 0, 32 * sizeof(unsigned long));
			/* set bit per cpu in ccr_functional and ccr_present: */
			result[0] = result[1] = (1ULL << smp_cpus) - 1;
			result[17] = 1; // Revision
			result[18] = 19; // Model
			return PDC_OK;
		}
		return PDC_BAD_OPTION;
	case PDC_IODC: /* Call IODC functions */
		// dprintf(0, "\n\nSeaBIOS: Info PDC_IODC function %ld ARG3=%x ARG4=%x ARG5=%x ARG6=%x\n", option, ARG3, ARG4, ARG5, ARG6);
		switch (option) {
		case PDC_IODC_READ:
			hpa = ARG3;
			if (hpa == IDE_HPA /* && chassis_code < 0xcee0 */) {
				iodc_p = &iodc_data_hpa_fff8c000; // workaround for PCI ATA
			} else {
				hpa_index = find_hpa_index(hpa);
				if (hpa_index < 0)
					return -4; // not found
				iodc_p = parisc_devices[hpa_index].iodc;
			}

			if (ARG4 == PDC_IODC_INDEX_DATA) {
				// if (hpa == MEMORY_HPA)
				//	ARG6 = 2; // Memory modules return 2 bytes of IODC memory (result2 ret[0] = 0x6701f41 HI !!)
				memcpy((void*) ARG5, iodc_p, ARG6);
				c = (unsigned char *) ARG5;
				// printf("SeaBIOS: PDC_IODC get: hpa = 0x%lx, HV: 0x%x 0x%x IODC_SPA=0x%x  type 0x%x, \n", hpa, c[0], c[1], c[2], c[3]);
				// c[0] = iodc_p->hversion_model; // FIXME. BROKEN HERE !!!
				// c[1] = iodc_p->hversion_rev || (iodc_p->hversion << 4);
				*result = ARG6;
				return PDC_OK;
			}

			// ARG4 is IODC function to copy.
			if (ARG4 < PDC_IODC_RI_INIT || ARG4 > PDC_IODC_RI_TLB)
				return PDC_IODC_INVALID_INDEX;

			*result = 512; /* max size of function iodc_entry */
			if (ARG6 < *result)
				return PDC_IODC_COUNT;
			memcpy((void*) ARG5, &iodc_entry, *result);
			c = (unsigned char *) &iodc_entry_table;
			/* calculate offset into jump table. */
			c += (ARG4 - PDC_IODC_RI_INIT) * 2 * sizeof(unsigned int);
			memcpy((void*) ARG5, c, 2 * sizeof(unsigned int));
			// dprintf(0, "\n\nSeaBIOS: Info PDC_IODC function OK\n");
			flush_data_cache((char*)ARG5, *result);
			return PDC_OK;
			break;
		case PDC_IODC_NINIT:	/* non-destructive init */
		case PDC_IODC_DINIT:	/* destructive init */
			break;
		case PDC_IODC_MEMERR:
			result[0] = 0; /* IO_STATUS */
			result[1] = 0;
			result[2] = 0;
			result[3] = 0;
			return PDC_OK;
		}
		dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_IODC function %ld ARG3=%x ARG4=%x ARG5=%x ARG6=%x\n", option, ARG3, ARG4, ARG5, ARG6);
		return PDC_BAD_OPTION;
	case PDC_TOD:	/* Time of day */
		switch (option) {
		case PDC_TOD_READ:
			result[0] = seconds_since_1970();
			result[1] = result[2] = result[3] = 0;
			return PDC_OK;
		case PDC_TOD_WRITE:
			/* we ignore the usecs in ARG3 */
			epoch_to_date_time(ARG2);
			return PDC_OK;
		case 2: /* PDC_TOD_CALIBRATE_TIMERS */
			/* double-precision floating-point with frequency of Interval Timer in megahertz: */
			*(double*)&result[0] = (double)CPU_CLOCK_MHZ;
			/* unsigned 64-bit integers representing  clock accuracy in parts per billion: */
			result[2] = 0x5a6c; /* TOD_acc */
			result[3] = 0x5a6c; /* CR_acc (interval timer) */
			return PDC_OK;
		}
		dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_TOD function %ld ARG2=%x ARG3=%x ARG4=%x\n", option, ARG2, ARG3, ARG4);
		return PDC_BAD_OPTION;
	case PDC_STABLE:
		// dprintf(0, "\n\nSeaBIOS: PDC_STABLE function %ld ARG2=%x ARG3=%x ARG4=%x\n", option, ARG2, ARG3, ARG4);
		switch (option) {
		case PDC_STABLE_READ:
			if ((ARG2 + ARG4) > STABLE_STORAGE_SIZE)
				return PDC_INVALID_ARG;
			memcpy((unsigned char *) ARG3, &stable_storage[ARG2], ARG4);
			return PDC_OK;
		case PDC_STABLE_WRITE:
			if ((ARG2 + ARG4) > STABLE_STORAGE_SIZE)
				return PDC_INVALID_ARG;
			memcpy(&stable_storage[ARG2], (unsigned char *) ARG3, ARG4);
			return PDC_OK;
		case PDC_STABLE_RETURN_SIZE:
			result[0] = STABLE_STORAGE_SIZE;
			return PDC_OK;
		case PDC_STABLE_VERIFY_CONTENTS:
			return PDC_OK;
		case PDC_STABLE_INITIALIZE:
			init_stable_storage();
			return PDC_OK;
		}
		return PDC_BAD_OPTION;
	case PDC_NVOLATILE:
		return PDC_BAD_PROC;
	case PDC_ADD_VALID:
		// dprintf(0, "\n\nSeaBIOS: PDC_ADD_VALID function %ld ARG2=%x called.\n", option, ARG2);
		if (option != 0)
			return PDC_BAD_OPTION;
		if (0 && ARG2 == 0) // should PAGE0 be valid?  HP-UX asks for it, but maybe due a bug in our code...
			return 1;
		// if (ARG2 < PAGE_SIZE) return PDC_ERROR;
		if (ARG2 < ram_size)
			return PDC_OK;
		if (ARG2 < FIRMWARE_END)
			return 1;
		if (ARG2 <= 0xffffffff)
			return PDC_OK;
		dprintf(0, "\n\nSeaBIOS: FAILED!!!! PDC_ADD_VALID function %ld ARG2=%x called.\n", option, ARG2);
		return PDC_REQ_ERR_0; /* Operation completed with a requestor bus error. */
	case PDC_INSTR:
		return PDC_BAD_PROC;
	case PDC_CONFIG:	/* Obsolete */
		return PDC_BAD_PROC;
	case PDC_BLOCK_TLB:	/* not needed on virtual machine */
		return PDC_BAD_PROC;
	case PDC_TLB:		/* hardware TLB not used on Linux, but on HP-UX (if available) */
		#if 0
		/* still buggy, let's avoid it to keep things simple. */
		switch (option) {
		case PDC_TLB_INFO:
			result[0] = PAGE_SIZE;
			result[0] = PAGE_SIZE << 2;
			return PDC_OK;
		case PDC_TLB_SETUP:
			result[0] = ARG5 & 1;
			result[1] = 0;
			return PDC_OK;
		}
		#endif
		return PDC_BAD_PROC;
	case PDC_MEM:
		// only implemented on 64bit PDC!
		if (sizeof(unsigned long) == sizeof(unsigned int))
			return PDC_BAD_PROC;

		switch (option) {
		case PDC_MEM_MEMINFO:
			result[0] = 0;	// no PDT entries
			result[1] = 0;	// page entries
			result[2] = 0;	// PDT status
			result[3] = (unsigned long)-1ULL; // dbe_loc
			result[4] = GoldenMemory; // good_mem
			return PDC_OK;
		case PDC_MEM_READ_PDT:
			result[0] = 0;	// no PDT entries
			return PDC_OK;
		case PDC_MEM_GOODMEM:
			GoldenMemory = ARG3;
			return PDC_OK;
		}
		dprintf(0, "\n\nSeaBIOS: Check PDC_MEM option %ld ARG3=%x ARG4=%x ARG5=%x\n", option, ARG3, ARG4, ARG5);
		return PDC_BAD_PROC;
	case PDC_PSW:	/* Get/Set default System Mask  */
		if (option > PDC_PSW_SET_DEFAULTS)
			return PDC_BAD_OPTION;
		/* FIXME: For 64bit support enable PDC_PSW_WIDE_BIT too! */
		if (option == PDC_PSW_MASK)
			*result = PDC_PSW_ENDIAN_BIT;
		if (option == PDC_PSW_GET_DEFAULTS)
			*result = psw_defaults;
		if (option == PDC_PSW_SET_DEFAULTS) {
			psw_defaults = ARG2;
		}
		return PDC_OK;
	case PDC_SYSTEM_MAP:
		// dprintf(0, "\n\nSeaBIOS: Info: PDC_SYSTEM_MAP function %ld ARG3=%x ARG4=%x ARG5=%x\n", option, ARG3, ARG4, ARG5);
		switch (option) {
		case PDC_FIND_MODULE:
			hpa_index = ARG4;
			if (hpa_index >= ARRAY_SIZE(parisc_devices))
				return PDC_NE_MOD; // Module not found
			hpa = parisc_devices[hpa_index].hpa;
			if (!hpa)
				return PDC_NE_MOD; // Module not found

			mod_path = (struct pdc_module_path *)ARG3;
			if (mod_path)
				*mod_path = *parisc_devices[hpa_index].mod_path;

			// *pdc_mod_info = *parisc_devices[hpa_index].mod_info; -> can be dropped.
			memset(result, 0, 32*sizeof(long));
			result[0] = hpa; // .mod_addr for PDC_IODC
			result[1] = 1; // .mod_pgs number of pages (FIXME: only graphics has more, e.g. 0x2000)
			result[2] = 0; // FIXME: additional addresses

			return PDC_OK;
		case PDC_FIND_ADDRESS:
		case PDC_TRANSLATE_PATH:
			break; // return PDC_OK;
		}
		break;
	case PDC_SOFT_POWER: // don't have a soft-power switch
		switch (option) {
		case PDC_SOFT_POWER_ENABLE:
			if (ARG3 == 0) // put soft power button under hardware control.
				hlt();
			return PDC_OK;
		}
		// dprintf(0, "\n\nSeaBIOS: PDC_SOFT_POWER called with ARG2=%x ARG3=%x ARG4=%x\n", ARG2, ARG3, ARG4);
		return PDC_BAD_OPTION;
	case 26: // PDC_SCSI_PARMS is the architected firmware interface to replace the Hversion PDC_INITIATOR procedure.
		return PDC_BAD_PROC;
	case 64: // Unknown function. HP-UX 11 bootcd calls it during boot.
	case 65: // Unknown function. HP-UX 11 bootcd calls it during boot.
		dprintf(0, "\n\nSeaBIOS: UNKNOWN PDC proc %lu OPTION %lu called with ARG2=%x ARG3=%x ARG4=%x\n", proc, option, ARG2, ARG3, ARG4);
		return PDC_BAD_PROC;
	case PDC_IO:
		switch (option) {
		case PDC_IO_READ_AND_CLEAR_ERRORS:
			dprintf(0, "\n\nSeaBIOS: PDC_IO called with ARG2=%x ARG3=%x ARG4=%x\n", ARG2, ARG3, ARG4);
			// return PDC_BAD_OPTION;
		case PDC_IO_RESET:
		case PDC_IO_RESET_DEVICES:
			return PDC_OK;
		}
		break;
	case PDC_BROADCAST_RESET:
		dprintf(0, "\n\nSeaBIOS: PDC_BROADCAST_RESET (reset system) called with ARG3=%x ARG4=%x\n", ARG3, ARG4);
		reset();
		return PDC_OK;
	case PDC_PCI_INDEX: // not needed for Dino PCI bridge
		return PDC_BAD_PROC;
	case PDC_INITIATOR:
		switch (option) {
		case PDC_GET_INITIATOR:
			// ARG3 has hwpath
			result[0] = 7; // host_id: 7 to 15 ?
			result[1] = 40; // 1, 2, 5 or 10 for 5, 10, 20 or 40 MT/s
			result[2] = 0; // ??
			result[3] = 0; // ??
			result[4] = 0; // width: 0:"Narrow, 1:"Wide"
			result[5] = 0; // mode: 0:SMODE_SE, 1:SMODE_HVD, 2:SMODE_LVD
			return PDC_OK;
		case PDC_SET_INITIATOR:
		case PDC_DELETE_INITIATOR:
		case PDC_RETURN_TABLE_SIZE:
		case PDC_RETURN_TABLE:
			break;
		}
		dprintf(0, "\n\nSeaBIOS: Unimplemented PDC_INITIATOR function %ld ARG3=%x ARG4=%x ARG5=%x\n", option, ARG3, ARG4, ARG5);
		return PDC_BAD_OPTION;
	}

	dprintf(0, "\nSeaBIOS: Unimplemented PDC proc %s(%d) option %d result=%x ARG3=%x ",
			pdc_name(ARG0), ARG0, ARG1, ARG2, ARG3);
	dprintf(0, "ARG4=%x ARG5=%x ARG6=%x ARG7=%x\n", ARG4, ARG5, ARG6, ARG7);

	BUG_ON(1);
	return PDC_BAD_PROC;
}


/********************************************************
 * BOOT MENU
 ********************************************************/

extern struct drive_s *select_parisc_boot_drive(char bootdrive);

static int parisc_boot_menu(unsigned long *iplstart, unsigned long *iplend,
		char bootdrive)
{
	int ret;
	unsigned int *target = (void *)(PAGE0->mem_free + 32*1024);
	struct disk_op_s disk_op = {
		.buf_fl = target,
		.command = CMD_SEEK,
		.count = 0,
		.lba = 0,
	};

	boot_drive = select_parisc_boot_drive(bootdrive);
	disk_op.drive_fl = boot_drive;
	if (boot_drive == NULL) {
		printf("SeaBIOS: No boot device.\n");
		return 0;
	}

	/* seek to beginning of disc/CD */
	disk_op.drive_fl = boot_drive;
	ret = process_op(&disk_op);
	// printf("DISK_SEEK returned %d\n", ret);
	if (ret)
		return 0;

	// printf("Boot disc type is 0x%x\n", boot_drive->type);
	disk_op.drive_fl = boot_drive;
	if (boot_drive->type == DTYPE_ATA_ATAPI ||
	    boot_drive->type == DTYPE_ATA) {
		disk_op.command = CMD_ISREADY;
		ret = process_op(&disk_op);
	} else {
		ret = scsi_is_ready(&disk_op);
	}
	// printf("DISK_READY returned %d\n", ret);

	/* read boot sector of disc/CD */
	disk_op.drive_fl = boot_drive;
	disk_op.buf_fl = target;
	disk_op.command = CMD_READ;
	disk_op.count = (FW_BLOCKSIZE / disk_op.drive_fl->blksize);
	disk_op.lba = 0;
	// printf("blocksize is %d, count is %d\n", disk_op.drive_fl->blksize, disk_op.count);
	ret = process_op(&disk_op);
	// printf("DISK_READ(count=%d) = %d\n", disk_op.count, ret);
	if (ret)
		return 0;

	unsigned int ipl_addr = be32_to_cpu(target[0xf0/sizeof(int)]); /* offset 0xf0 in bootblock */
	unsigned int ipl_size = be32_to_cpu(target[0xf4/sizeof(int)]);
	unsigned int ipl_entry= be32_to_cpu(target[0xf8/sizeof(int)]);

	/* check LIF header of bootblock */
	if ((target[0]>>16) != 0x8000) {
		printf("Not a PA-RISC boot image. LIF magic is 0x%x, should be 0x8000.\n", target[0]>>16);
		return 0;
	}
	// printf("ipl start at 0x%x, size %d, entry 0x%x\n", ipl_addr, ipl_size, ipl_entry);
	// TODO: check ipl values for out of range. Rules are:
	// IPL_ADDR - 2 Kbyte aligned, nonzero.
	// IPL_SIZE - Multiple of 2 Kbytes, nonzero, less than or equal to 256 Kbytes.
	// IPL_ENTRY-  Word aligned, less than IPL_SIZE

	/* seek to beginning of IPL */
	disk_op.drive_fl = boot_drive;
	disk_op.command = CMD_SEEK;
	disk_op.count = 0; // (ipl_size / disk_op.drive_fl->blksize);
	disk_op.lba = (ipl_addr / disk_op.drive_fl->blksize);
	ret = process_op(&disk_op);
	// printf("DISK_SEEK to IPL returned %d\n", ret);

	/* read IPL */
	disk_op.drive_fl = boot_drive;
	disk_op.buf_fl = target;
	disk_op.command = CMD_READ;
	disk_op.count = (ipl_size / disk_op.drive_fl->blksize);
	disk_op.lba = (ipl_addr / disk_op.drive_fl->blksize);
	ret = process_op(&disk_op);
	// printf("DISK_READ IPL returned %d\n", ret);

	// printf("First word at %p is 0x%x\n", target, target[0]);

	/* execute IPL */
	// TODO: flush D- and I-cache, not needed in emulation ?
	*iplstart = *iplend = (unsigned long) target;
	*iplstart += ipl_entry;
	*iplend += ALIGN(ipl_size, sizeof(unsigned long));
	return 1;
}


/********************************************************
 * FIRMWARE MAIN ENTRY POINT
 ********************************************************/

static const struct pz_device mem_cons_boot = {
	.hpa = DINO_UART_HPA,
	.iodc_io = (unsigned long) &iodc_entry,
	.cl_class = CL_DUPLEX,
};

static const struct pz_device mem_boot_boot = {
	.dp.flags = PF_AUTOBOOT,
	.hpa = IDE_HPA, // DINO_SCSI_HPA,
	.iodc_io = (unsigned long) &iodc_entry,
	.cl_class = CL_RANDOM,
};

static const struct pz_device mem_kbd_boot = {
	.hpa = DINO_UART_HPA,
	.iodc_io = (unsigned long) &iodc_entry,
	.cl_class = CL_KEYBD,
};

static void parisc_vga_init(void)
{
	extern void vga_post(struct bregs *);
	struct pci_device *pci;

	foreachpci(pci) {
		if (!is_pci_vga(pci))
			continue;

		VgaBDF = pci->bdf;

		parisc_vga_mem = pci_config_readl(pci->bdf, PCI_BASE_ADDRESS_0);
		parisc_vga_mem &= PCI_BASE_ADDRESS_MEM_MASK;
		VBE_framebuffer = parisc_vga_mem;
		parisc_vga_mmio = pci_config_readl(pci->bdf, PCI_BASE_ADDRESS_2);
		parisc_vga_mmio &= PCI_BASE_ADDRESS_MEM_MASK;

		dprintf(1, "\n");

		regs.ax = VgaBDF;
		vga_post(&regs);

		// flag = MF_NOCLEARMEM ?
		//
		// vga_set_mode(0x119, MF_NOCLEARMEM); // bochs: MM_DIRECT, 1280, 1024, 15, 8, 16,
		// vga_set_mode(0x105, 0); // bochs:     { 0x105, { MM_PACKED, 1024, 768,  8,  8, 16, SEG_GRAPH } },
		// vga_set_mode(0x107, 0); // bochs:  { 0x107, { MM_PACKED, 1280, 1024, 8,  8, 16, SEG_GRAPH } },
		// vga_set_mode(0x11c, 0); // bochs:  { 0x11C, { MM_PACKED, 1600, 1200, 8,  8, 16, SEG_GRAPH } },
		// vga_set_mode(0x11f, 0); // bochs:  { 0x11F, { MM_DIRECT, 1600, 1200, 24, 8, 16, SEG_GRAPH } },
		// vga_set_mode(0x101, 0); // bochs:  { 0x101, { MM_PACKED, 640,  480,  8,  8, 16, SEG_GRAPH } },
		vga_set_mode(0x100, 0); // bochs:  { 0x100, { MM_PACKED, 640,  400,  8,  8, 16, SEG_GRAPH } },

		u32 endian = *(u32 *)(parisc_vga_mmio + 0x0604);
		dprintf(1, "parisc: VGA at %pP, mem 0x%lx  mmio 0x%lx endian 0x%x found.\n",
			pci, parisc_vga_mem, parisc_vga_mmio, endian);

		struct vgamode_s *vmode_g = get_current_mode();
		int bpp = vga_bpp(vmode_g);
		int linelength = vgahw_get_linelength(vmode_g);

		dprintf(1, "parisc: VGA resolution: %dx%d-%d  memmodel:%d  bpp:%d  linelength:%d\n",
			    vmode_g->width, vmode_g->height, vmode_g->depth,
			    vmode_g->memmodel, bpp, linelength);
        }
}

/* Prepare boot paths in PAGE0 and stable memory */
static void prepare_boot_path(volatile struct pz_device *dest,
		const struct pz_device *source,
		unsigned int stable_offset)
{
	int hpa_index;
	unsigned long hpa;
	struct pdc_module_path *mod_path;

	*dest = *source;
	hpa = source->hpa;
	hpa_index = find_hpa_index(hpa);

	if (hpa == DINO_SCSI_HPA || hpa == IDE_HPA)
		mod_path = &mod_path_hpa_fff8c000;
	else if (hpa == DINO_UART_HPA || hpa == LASI_UART_HPA)
		mod_path = &mod_path_hpa_fff83000;
	else {
		BUG_ON(hpa_index < 0);
		mod_path = parisc_devices[hpa_index].mod_path;
	}

	/* copy device path to entry in PAGE0 */
	memcpy((void*)&dest->dp, mod_path, sizeof(struct device_path));

	/* copy device path to stable storage */
	memcpy(&stable_storage[stable_offset], mod_path, sizeof(*mod_path));
	BUG_ON(sizeof(*mod_path) != 0x20);
	BUG_ON(sizeof(struct device_path) != 0x20);
}


void __VISIBLE start_parisc_firmware(void)
{
	unsigned int i, cpu_hz;
	unsigned long iplstart, iplend;

	unsigned long interactive = (linux_kernel_entry == 1) ? 1:0;
	char bootdrive = (char)cmdline; // c = hdd, d = CD/DVD

	if (smp_cpus > HPPA_MAX_CPUS)
		smp_cpus = HPPA_MAX_CPUS;

	if (ram_size >= FIRMWARE_START)
		ram_size = FIRMWARE_START;

	/* Initialize device list */
	remove_parisc_devices(smp_cpus);

	/* Show list of HPA devices which are still returned by firmware. */
	if (0) { for (i=0; parisc_devices[i].hpa; i++)
		printf("Kept #%d at 0x%lx\n", i, parisc_devices[i].hpa);
	}

	/* Initialize PAGE0 */
	memset((void*)PAGE0, 0, sizeof(*PAGE0));

	/* copy pdc_entry entry into low memory. */
	memcpy((void*)MEM_PDC_ENTRY, &pdc_entry_table, 3*4);
	flush_data_cache((char*)MEM_PDC_ENTRY, 3*4);

	PAGE0->memc_cont = ram_size;
	PAGE0->memc_phsize = ram_size;
	PAGE0->memc_adsize = ram_size;
	PAGE0->mem_pdc_hi = (MEM_PDC_ENTRY + 0ULL) >> 32;
	PAGE0->mem_free = 0x6000; // min PAGE_SIZE
	PAGE0->mem_hpa = CPU_HPA; // HPA of boot-CPU
	PAGE0->mem_pdc = MEM_PDC_ENTRY;
	PAGE0->mem_10msec = CPU_CLOCK_MHZ*(1000000ULL/100);

	BUG_ON(PAGE0->mem_free <= MEM_PDC_ENTRY);
	BUG_ON(smp_cpus < 1 || smp_cpus > HPPA_MAX_CPUS);

	/* Put QEMU/SeaBIOS marker in PAGE0.
	 * The Linux kernel will search for it. */
	memcpy((char*)&PAGE0->pad0, "SeaBIOS", 8);

	PAGE0->imm_hpa = MEMORY_HPA;
	PAGE0->imm_spa_size = ram_size;
	PAGE0->imm_max_mem = ram_size;

	// Initialize stable storage
	init_stable_storage();

	chassis_code = 0;

	// Initialize boot paths (disc, display & keyboard)
	prepare_boot_path(&(PAGE0->mem_cons), &mem_cons_boot, 0x60);
	prepare_boot_path(&(PAGE0->mem_boot), &mem_boot_boot, 0x0);
	prepare_boot_path(&(PAGE0->mem_kbd),  &mem_kbd_boot, 0xa0);

	malloc_preinit();

	// set Qemu serial debug port
	DebugOutputPort = PORT_SERIAL1;
	// PlatformRunningOn = PF_QEMU;  // emulate runningOnQEMU()

	cpu_hz = 100 * PAGE0->mem_10msec; /* Hz of this PARISC */
	dprintf(1, "\nPARISC SeaBIOS Firmware, %ld x PA7300LC (PCX-L2) at %d.%06d MHz, %lu MB RAM.\n",
		smp_cpus, cpu_hz / 1000000, cpu_hz % 1000000,
		ram_size/1024/1024);

	if (ram_size < MIN_RAM_SIZE) {
		printf("\nSeaBIOS: Machine configured with too little "
			"memory (%ld MB), minimum is %d MB.\n\n",
			ram_size/1024/1024, MIN_RAM_SIZE/1024/1024);
		hlt();
	}

	// handle_post();
	serial_debug_preinit();
	debug_banner();
	// maininit();
	qemu_preinit();
        RamSize = ram_size;
	// coreboot_preinit();

	pci_setup();

	serial_setup();
	block_setup();

	// We don't have VGA BIOS, so init now.
	parisc_vga_init();

	printf("\n");
	printf("Firmware Version 6.1\n"
		"\n"
		"Duplex Console IO Dependent Code (IODC) revision 1\n"
		"\n"
		"Memory Test/Initialization Completed\n\n");
	printf("------------------------------------------------------------------------------\n"
		"  (c) Copyright 2017-2018 Helge Deller <deller@gmx.de> and SeaBIOS developers.\n"
		"------------------------------------------------------------------------------\n\n");
	printf( "  Processor   Speed            State           Coprocessor State  Cache Size\n"
		"  ---------  --------   ---------------------  -----------------  ----------\n");
	for (i = 0; i < smp_cpus; i++)
	  printf("     %s%d      " __stringify(CPU_CLOCK_MHZ)
			" MHz    %s                 Functional            0 KB\n",
			i < 10 ? " ":"", i, i?"Idle  ":"Active");
	printf("\n\n");
	printf("  Available memory:     %llu MB\n"
		"  Good memory required: %d MB\n\n",
		(unsigned long long)ram_size/1024/1024, MIN_RAM_SIZE/1024/1024);
	printf("  Primary boot path:    FWSCSI.6.0\n"
		"  Alternate boot path:  LAN.0.0.0.0.0.0\n"
		"  Console path:         SERIAL_1.9600.8.none\n"
		"  Keyboard path:        PS2\n\n");

	/* directly start Linux kernel if it was given on qemu command line. */
	if (linux_kernel_entry > 1) {
		void (*start_kernel)(unsigned long mem_free, unsigned long cline,
			unsigned long rdstart, unsigned long rdend);

		printf("Autobooting Linux kernel which was loaded by qemu...\n\n");
		start_kernel = (void *) linux_kernel_entry;
		start_kernel(PAGE0->mem_free, cmdline, initrd_start, initrd_end);
		hlt(); /* this ends the emulator */
	}

#if 0
	printf("------- Main Menu -------------------------------------------------------------\n\n"
		"        Command                         Description\n"
		"        -------                         -----------\n"
		"        BOot [PRI|ALT|<path>]           Boot from specified path\n"
		"        PAth [PRI|ALT|CON|KEY] [<path>] Display or modify a path\n"
		"        SEArch [DIsplay|IPL] [<path>]   Search for boot devices\n\n"
		"        COnfiguration [<command>]       Access Configuration menu/commands\n"
		"        INformation [<command>]         Access Information menu/commands\n"
		"        SERvice [<command>]             Access Service menu/commands\n\n"
		"        DIsplay                         Redisplay the current menu\n"
		"        HElp [<menu>|<command>]         Display help for menu or command\n"
		"        RESET                           Restart the system\n"
		"-------\n"
		"Main Menu: Enter command > ");
#endif

	/* check for bootable drives, and load and start IPL bootloader if possible */
	if (parisc_boot_menu(&iplstart, &iplend, bootdrive)) {
		void (*start_ipl)(long interactive, long iplend);

		printf("\nBooting...\n"
			"Boot IO Dependent Code (IODC) revision 153\n\n"
			"%s Booted.\n", PAGE0->imm_soft_boot ? "SOFT":"HARD");
		start_ipl = (void *) iplstart;
		start_ipl(interactive, iplend);
	}

	hlt(); /* this ends the emulator */
}
