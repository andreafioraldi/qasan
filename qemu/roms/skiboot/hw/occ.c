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

#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>
#include <fsp.h>
#include <timebase.h>
#include <hostservices.h>
#include <errorlog.h>
#include <opal-api.h>
#include <opal-msg.h>
#include <timer.h>
#include <i2c.h>
#include <powercap.h>
#include <psr.h>
#include <sensor.h>

/* OCC Communication Area for PStates */

#define P8_HOMER_OPAL_DATA_OFFSET	0x1F8000
#define P9_HOMER_OPAL_DATA_OFFSET	0x0E2000

#define OPAL_DYNAMIC_DATA_OFFSET	0x0B80
/* relative to HOMER_OPAL_DATA_OFFSET */

#define MAX_PSTATES			256
#define MAX_P8_CORES			12
#define MAX_P9_CORES			24

#define MAX_OPAL_CMD_DATA_LENGTH	4090
#define MAX_OCC_RSP_DATA_LENGTH		8698

/**
 * OCC-OPAL Shared Memory Region
 *
 * Reference document :
 * https://github.com/open-power/docs/blob/master/occ/OCC_OpenPwr_FW_Interfaces.pdf
 *
 * Supported layout versions:
 * - 0x01, 0x02 : P8
 * https://github.com/open-power/occ/blob/master_p8/src/occ/proc/proc_pstate.h
 *
 * - 0x90 : P9
 * https://github.com/open-power/occ/blob/master/src/occ_405/proc/proc_pstate.h
 *   In 0x90 the data is separated into :-
 *   -- Static Data (struct occ_pstate_table): Data is written once by OCC
 *   -- Dynamic Data (struct occ_dynamic_data): Data is updated at runtime
 *
 * struct occ_pstate_table -	Pstate table layout
 * @valid:			Indicates if data is valid
 * @version:			Layout version
 * @v2.throttle:		Reason for limiting the max pstate
 * @v9.occ_role:		OCC role (Master/Slave)
 * @v#.pstate_min:		Minimum pstate ever allowed
 * @v#.pstate_nom:		Nominal pstate
 * @v#.pstate_turbo:		Maximum turbo pstate
 * @v#.pstate_ultra_turbo:	Maximum ultra turbo pstate and the maximum
 *				pstate ever allowed
 * @v#.pstates:			Pstate-id and frequency list from Pmax to Pmin
 * @v#.pstates.id:		Pstate-id
 * @v#.pstates.flags:		Pstate-flag(reserved)
 * @v2.pstates.vdd:		Voltage Identifier
 * @v2.pstates.vcs:		Voltage Identifier
 * @v#.pstates.freq_khz:	Frequency in KHz
 * @v#.core_max[1..N]:		Max pstate with N active cores
 * @spare/reserved/pad:		Unused data
 */
struct occ_pstate_table {
	u8 valid;
	u8 version;
	union __packed {
		struct __packed { /* Version 0x01 and 0x02 */
			u8 throttle;
			s8 pstate_min;
			s8 pstate_nom;
			s8 pstate_turbo;
			s8 pstate_ultra_turbo;
			u8 spare;
			u64 reserved;
			struct __packed {
				s8 id;
				u8 flags;
				u8 vdd;
				u8 vcs;
				u32 freq_khz;
			} pstates[MAX_PSTATES];
			s8 core_max[MAX_P8_CORES];
			u8 pad[100];
		} v2;
		struct __packed { /* Version 0x90 */
			u8 occ_role;
			u8 pstate_min;
			u8 pstate_nom;
			u8 pstate_turbo;
			u8 pstate_ultra_turbo;
			u8 spare;
			u64 reserved1;
			u64 reserved2;
			struct __packed {
				u8 id;
				u8 flags;
				u16 reserved;
				u32 freq_khz;
			} pstates[MAX_PSTATES];
			u8 core_max[MAX_P9_CORES];
			u8 pad[56];
		} v9;
	};
} __packed;

/**
 * OPAL-OCC Command Response Interface
 *
 * OPAL-OCC Command Buffer
 *
 * ---------------------------------------------------------------------
 * | OPAL  |  Cmd    | OPAL |	       | Cmd Data | Cmd Data | OPAL    |
 * | Cmd   | Request | OCC  | Reserved | Length   | Length   | Cmd     |
 * | Flags |   ID    | Cmd  |	       | (MSB)    | (LSB)    | Data... |
 * ---------------------------------------------------------------------
 * |  ….OPAL Command Data up to max of Cmd Data Length 4090 bytes      |
 * |								       |
 * ---------------------------------------------------------------------
 *
 * OPAL Command Flag
 *
 * -----------------------------------------------------------------
 * | Bit 7 | Bit 6 | Bit 5 | Bit 4 | Bit 3 | Bit 2 | Bit 1 | Bit 0 |
 * | (msb) |	   |	   |	   |	   |	   |	   | (lsb) |
 * -----------------------------------------------------------------
 * |Cmd    |       |       |       |       |       |       |       |
 * |Ready  |	   |	   |	   |	   |	   |	   |	   |
 * -----------------------------------------------------------------
 *
 * struct opal_command_buffer -	Defines the layout of OPAL command buffer
 * @flag:			Provides general status of the command
 * @request_id:			Token to identify request
 * @cmd:			Command sent
 * @data_size:			Command data length
 * @data:			Command specific data
 * @spare:			Unused byte
 */
struct opal_command_buffer {
	u8 flag;
	u8 request_id;
	u8 cmd;
	u8 spare;
	u16 data_size;
	u8 data[MAX_OPAL_CMD_DATA_LENGTH];
} __packed;

/**
 * OPAL-OCC Response Buffer
 *
 * ---------------------------------------------------------------------
 * | OCC   |  Cmd    | OPAL | Response | Rsp Data | Rsp Data | OPAL    |
 * | Rsp   | Request | OCC  |  Status  | Length   | Length   | Rsp     |
 * | Flags |   ID    | Cmd  |	       | (MSB)    | (LSB)    | Data... |
 * ---------------------------------------------------------------------
 * |  ….OPAL Response Data up to max of Rsp Data Length 8698 bytes     |
 * |								       |
 * ---------------------------------------------------------------------
 *
 * OCC Response Flag
 *
 * -----------------------------------------------------------------
 * | Bit 7 | Bit 6 | Bit 5 | Bit 4 | Bit 3 | Bit 2 | Bit 1 | Bit 0 |
 * | (msb) |	   |	   |	   |	   |	   |	   | (lsb) |
 * -----------------------------------------------------------------
 * |       |       |       |       |       |       |OCC in  | Rsp  |
 * |       |	   |	   |	   |	   |	   |progress|Ready |
 * -----------------------------------------------------------------
 *
 * struct occ_response_buffer -	Defines the layout of OCC response buffer
 * @flag:			Provides general status of the response
 * @request_id:			Token to identify request
 * @cmd:			Command requested
 * @status:			Indicates success/failure status of
 *				the command
 * @data_size:			Response data length
 * @data:			Response specific data
 */
struct occ_response_buffer {
	u8 flag;
	u8 request_id;
	u8 cmd;
	u8 status;
	u16 data_size;
	u8 data[MAX_OCC_RSP_DATA_LENGTH];
} __packed;

/**
 * OCC-OPAL Shared Memory Interface Dynamic Data Vx90
 *
 * struct occ_dynamic_data -	Contains runtime attributes
 * @occ_state:			Current state of OCC
 * @cpu_throttle:		Reason for limiting the max pstate
 * @mem_throttle:		Reason for throttling memory
 * @quick_pwr_drop:		Indicates if QPD is asserted
 * @pwr_shifting_ratio:		Indicates the current percentage of power to
 *				take away from the CPU vs GPU when shifting
 *				power to maintain a power cap. Value of 100
 *				means take all power from CPU.
 * @pwr_cap_type:		Indicates type of power cap in effect
 * @min_pwr_cap:		Minimum allowed system power cap in Watts
 * @max_pwr_cap:		Maximum allowed system power cap in Watts
 * @cur_pwr_cap:		Current system power cap
 * @spare/reserved:		Unused data
 * @cmd:			Opal Command Buffer
 * @rsp:			OCC Response Buffer
 */
struct occ_dynamic_data {
	u8 occ_state;
	u8 spare1;
	u8 spare2;
	u8 spare3;
	u8 spare4;
	u8 cpu_throttle;
	u8 mem_throttle;
	u8 quick_pwr_drop;
	u8 pwr_shifting_ratio;
	u8 pwr_cap_type;
	u16 min_pwr_cap;
	u16 max_pwr_cap;
	u16 cur_pwr_cap;
	u8 pad[112];
	struct opal_command_buffer cmd;
	struct occ_response_buffer rsp;
} __packed;

static bool occ_reset;
static struct lock occ_lock = LOCK_UNLOCKED;
static unsigned long homer_opal_data_offset;

DEFINE_LOG_ENTRY(OPAL_RC_OCC_LOAD, OPAL_PLATFORM_ERR_EVT, OPAL_OCC,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_OCC_RESET, OPAL_PLATFORM_ERR_EVT, OPAL_OCC,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_OCC_PSTATE_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_OCC,
		OPAL_CEC_HARDWARE, OPAL_INFO,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_OCC_TIMEOUT, OPAL_PLATFORM_ERR_EVT, OPAL_OCC,
		OPAL_CEC_HARDWARE, OPAL_UNRECOVERABLE_ERR_GENERAL,
		OPAL_NA);

/*
 * POWER9 and newer platforms have pstate values which are unsigned
 * positive values.  They are continuous set of unsigned integers
 * [0 to +N] where Pmax is 0 and Pmin is N. The linear ordering of
 * pstates for P9 has changed compared to P8.  Where P8 has negative
 * pstate values advertised as [0 to -N] where Pmax is 0 and
 * Pmin is -N.  The following routine helps to abstract pstate
 * comparison with pmax and perform sanity checks on pstate limits.
 */

/**
 * cmp_pstates: Compares the given two pstates and determines which
 *              among them is associated with a higher pstate.
 *
 * @a,@b: The pstate ids of the pstates being compared.
 *
 * Returns: -1 : If pstate associated with @a is smaller than
 *               the pstate associated with @b.
 *	     0 : If pstates associated with @a and @b are equal.
 *	     1 : If pstate associated with @a is greater than
 *               the pstate associated with @b.
 */
static int cmp_pstates(int a, int b)
{
	/* P8 has 0 to -N (pmax to pmin), P9 has 0 to +N (pmax to pmin) */
	if (a > b)
		return (proc_gen == proc_gen_p8)? 1 : -1;
	else if (a < b)
		return (proc_gen == proc_gen_p8)? -1 : 1;

	return 0;
}

static inline
struct occ_pstate_table *get_occ_pstate_table(struct proc_chip *chip)
{
	return (struct occ_pstate_table *)
	       (chip->homer_base + homer_opal_data_offset);
}

static inline
struct occ_dynamic_data *get_occ_dynamic_data(struct proc_chip *chip)
{
	return (struct occ_dynamic_data *)
	       (chip->homer_base + homer_opal_data_offset +
		OPAL_DYNAMIC_DATA_OFFSET);
}

/* Check each chip's HOMER/Sapphire area for PState valid bit */
static bool wait_for_all_occ_init(void)
{
	struct proc_chip *chip;
	struct dt_node *xn;
	struct occ_pstate_table *occ_data;
	int tries;
	uint64_t start_time, end_time;
	uint32_t timeout = 0;

	if (platform.occ_timeout)
		timeout = platform.occ_timeout();

	start_time = mftb();
	for_each_chip(chip) {
		/* Check for valid homer address */
		if (!chip->homer_base) {
			/**
			 * @fwts-label OCCInvalidHomerBase
			 * @fwts-advice The HOMER base address for a chip
			 * was not valid. This means that OCC (On Chip
			 * Controller) will be non-functional and CPU
			 * frequency scaling will not be functional. CPU may
			 * be set to a safe, low frequency. Power savings in
			 * CPU idle or CPU hotplug may be impacted.
			 */
			prlog(PR_ERR,"OCC: Chip: %x homer_base is not valid\n",
				chip->id);
			return false;
		}

		/* Get PState table address */
		occ_data = get_occ_pstate_table(chip);

		/*
		 * Checking for occ_data->valid == 1 is ok because we clear all
		 * homer_base+size before passing memory to host services.
		 * This ensures occ_data->valid == 0 before OCC load
		 */
		tries = timeout * 10;
		while((occ_data->valid != 1) && tries--) {
			time_wait_ms(100);
		}
		if (occ_data->valid != 1) {
			/**
			 * @fwts-label OCCInvalidPStateTable
			 * @fwts-advice The pstate table for a chip
			 * was not valid. This means that OCC (On Chip
			 * Controller) will be non-functional and CPU
			 * frequency scaling will not be functional. CPU may
			 * be set to a low, safe frequency. This means
			 * that CPU idle states and CPU frequency scaling
			 * may not be functional.
			 */
			prlog(PR_ERR, "OCC: Chip: %x PState table is not valid\n",
				chip->id);
			return false;
		}

		if (!chip->occ_functional)
			chip->occ_functional = true;

		prlog(PR_DEBUG, "OCC: Chip %02x Data (%016llx) = %016llx\n",
		      chip->id, (uint64_t)occ_data, *(uint64_t *)occ_data);
	}
	end_time = mftb();
	prlog(PR_NOTICE, "OCC: All Chip Rdy after %lu ms\n",
	      tb_to_msecs(end_time - start_time));

        dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
	        const struct dt_property *p;
		p = dt_find_property(xn, "ibm,occ-functional-state");
		if (!p)
			dt_add_property_cells(xn, "ibm,occ-functional-state",
					      0x1);
	}
	return true;
}

/*
 * OCC provides pstate table entries in continuous descending order.
 * Parse the pstate table to skip pstate_ids that are greater
 * than Pmax. If a pstate_id is equal to Pmin then add it to
 * the list and break from the loop as this is the last valid
 * element in the pstate table.
 */
static void parse_pstates_v2(struct occ_pstate_table *data, u32 *dt_id,
			     u32 *dt_freq, int nr_pstates, int pmax, int pmin)
{
	int i, j;

	for (i = 0, j = 0; i < MAX_PSTATES && j < nr_pstates; i++) {
		if (cmp_pstates(data->v2.pstates[i].id, pmax) > 0)
			continue;

		dt_id[j] = data->v2.pstates[i].id;
		dt_freq[j] = data->v2.pstates[i].freq_khz / 1000;
		j++;

		if (data->v2.pstates[i].id == pmin)
			break;
	}

	if (j != nr_pstates)
		prerror("OCC: Expected pstates(%d) is not equal to parsed pstates(%d)\n",
			nr_pstates, j);
}

static void parse_pstates_v9(struct occ_pstate_table *data, u32 *dt_id,
			     u32 *dt_freq, int nr_pstates, int pmax, int pmin)
{
	int i, j;

	for (i = 0, j = 0; i < MAX_PSTATES && j < nr_pstates; i++) {
		if (cmp_pstates(data->v9.pstates[i].id, pmax) > 0)
			continue;

		dt_id[j] = data->v9.pstates[i].id;
		dt_freq[j] = data->v9.pstates[i].freq_khz / 1000;
		j++;

		if (data->v9.pstates[i].id == pmin)
			break;
	}

	if (j != nr_pstates)
		prerror("OCC: Expected pstates(%d) is not equal to parsed pstates(%d)\n",
			nr_pstates, j);
}

static void parse_vid(struct occ_pstate_table *occ_data,
		      struct dt_node *node, u8 nr_pstates,
		      int pmax, int pmin)
{
	u8 *dt_vdd, *dt_vcs;
	int i, j;

	dt_vdd = malloc(nr_pstates);
	assert(dt_vdd);
	dt_vcs = malloc(nr_pstates);
	assert(dt_vcs);

	for (i = 0, j = 0; i < MAX_PSTATES && j < nr_pstates; i++) {
		if (cmp_pstates(occ_data->v2.pstates[i].id, pmax) > 0)
			continue;

		dt_vdd[j] = occ_data->v2.pstates[i].vdd;
		dt_vcs[j] = occ_data->v2.pstates[i].vcs;
		j++;

		if (occ_data->v2.pstates[i].id == pmin)
			break;
	}

	dt_add_property(node, "ibm,pstate-vdds", dt_vdd, nr_pstates);
	dt_add_property(node, "ibm,pstate-vcss", dt_vcs, nr_pstates);

	free(dt_vdd);
	free(dt_vcs);
}

/* Add device tree properties to describe pstates states */
/* Return nominal pstate to set in each core */
static bool add_cpu_pstate_properties(int *pstate_nom)
{
	struct proc_chip *chip;
	uint64_t occ_data_area;
	struct occ_pstate_table *occ_data;
	struct dt_node *power_mgt;
	/* Arrays for device tree */
	u32 *dt_id, *dt_freq;
	int pmax, pmin, pnom;
	u8 nr_pstates;
	bool ultra_turbo_supported;
	int i;

	prlog(PR_DEBUG, "OCC: CPU pstate state device tree init\n");

	/* Find first chip */
	chip = next_chip(NULL);

	/* Extract PState information from OCC */
	occ_data = get_occ_pstate_table(chip);

	/* Dump first 16 bytes of PState table */
	occ_data_area = (uint64_t)occ_data;
	prlog(PR_DEBUG, "OCC: Data (%16llx) = %16llx %16llx\n",
	      occ_data_area,
	      *(uint64_t *)occ_data_area,
	      *(uint64_t *)(occ_data_area + 8));

	if (!occ_data->valid) {
		/**
		 * @fwts-label OCCInvalidPStateTableDT
		 * @fwts-advice The pstate table for the first chip
		 * was not valid. This means that OCC (On Chip
		 * Controller) will be non-functional. This means
		 * that CPU idle states and CPU frequency scaling
		 * will not be functional as OPAL doesn't populate
		 * the device tree with pstates in this case.
		 */
		prlog(PR_ERR, "OCC: PState table is not valid\n");
		return false;
	}

	/*
	 * Workload-Optimized-Frequency(WOF) or Ultra-Turbo is supported
	 * from version 0x02 onwards. If WOF is disabled then, the max
	 * ultra_turbo pstate will be equal to max turbo pstate.
	 */
	ultra_turbo_supported = true;

	/* Parse Pmax, Pmin and Pnominal */
	switch (occ_data->version) {
	case 0x01:
		ultra_turbo_supported = false;
		/* fallthrough */
	case 0x02:
		if (proc_gen == proc_gen_p9) {
			/**
			 * @fwts-label OCCInvalidVersion02
			 * @fwts-advice The PState table layout version is not
			 * supported in P9. So OPAL will not parse the PState
			 * table. CPU frequency scaling will not be functional
			 * as frequency and pstate-ids are not added to DT.
			 */
			prerror("OCC: Version %x is not supported in P9\n",
				occ_data->version);
			return false;
		}
		pmin = occ_data->v2.pstate_min;
		pnom = occ_data->v2.pstate_nom;
		if (ultra_turbo_supported)
			pmax = occ_data->v2.pstate_ultra_turbo;
		else
			pmax = occ_data->v2.pstate_turbo;
		break;
	case 0x90:
		if (proc_gen == proc_gen_p8) {
			/**
			 * @fwts-label OCCInvalidVersion90
			 * @fwts-advice The PState table layout version is not
			 * supported in P8. So OPAL will not parse the PState
			 * table. CPU frequency scaling will not be functional
			 * as frequency and pstate-ids are not added to DT.
			 */
			prerror("OCC: Version %x is not supported in P8\n",
				occ_data->version);
			return false;
		}
		pmin = occ_data->v9.pstate_min;
		pnom = occ_data->v9.pstate_nom;
		pmax = occ_data->v9.pstate_ultra_turbo;
		break;
	default:
		/**
		 * @fwts-label OCCUnsupportedVersion
		 * @fwts-advice The PState table layout version is not
		 * supported. So OPAL will not parse the PState table.
		 * CPU frequency scaling will not be functional as OPAL
		 * doesn't populate the device tree with pstates.
		 */
		prerror("OCC: Unsupported pstate table layout version %d\n",
			occ_data->version);
		return false;
	}

	/* Sanity check for pstate limits */
	if (cmp_pstates(pmin, pmax) > 0) {
		/**
		 * @fwts-label OCCInvalidPStateLimits
		 * @fwts-advice The min pstate is greater than the
		 * max pstate, this could be due to corrupted/invalid
		 * data in OCC-OPAL shared memory region. So OPAL has
		 * not added pstates to device tree. This means that
		 * CPU Frequency management will not be functional in
		 * the host.
		 */
		prerror("OCC: Invalid pstate limits. Pmin(%d) > Pmax (%d)\n",
			pmin, pmax);
		return false;
	}

	if (cmp_pstates(pnom, pmax) > 0) {
		/**
		 * @fwts-label OCCInvalidNominalPState
		 * @fwts-advice The nominal pstate is greater than the
		 * max pstate, this could be due to corrupted/invalid
		 * data in OCC-OPAL shared memory region. So OPAL has
		 * limited the nominal pstate to max pstate.
		 */
		prerror("OCC: Clipping nominal pstate(%d) to Pmax(%d)\n",
			pnom, pmax);
		pnom = pmax;
	}

	nr_pstates = labs(pmax - pmin) + 1;
	prlog(PR_DEBUG, "OCC: Version %x Min %d Nom %d Max %d Nr States %d\n",
	      occ_data->version, pmin, pnom, pmax, nr_pstates);
	if (nr_pstates <= 1 || nr_pstates > 128) {
		/**
		 * @fwts-label OCCInvalidPStateRange
		 * @fwts-advice The number of pstates is outside the valid
		 * range (currently <=1 or > 128), so OPAL has not added
		 * pstates to the device tree. This means that OCC (On Chip
		 * Controller) will be non-functional. This means
		 * that CPU idle states and CPU frequency scaling
		 * will not be functional.
		 */
		prerror("OCC: OCC range is not valid; No of pstates = %d\n",
			nr_pstates);
		return false;
	}

	power_mgt = dt_find_by_path(dt_root, "/ibm,opal/power-mgt");
	if (!power_mgt) {
		/**
		 * @fwts-label OCCDTNodeNotFound
		 * @fwts-advice Device tree node /ibm,opal/power-mgt not
		 * found. OPAL didn't add pstate information to device tree.
		 * Probably a firmware bug.
		 */
		prlog(PR_ERR, "OCC: dt node /ibm,opal/power-mgt not found\n");
		return false;
	}

	dt_id = malloc(nr_pstates * sizeof(u32));
	assert(dt_id);
	dt_freq = malloc(nr_pstates * sizeof(u32));
	assert(dt_freq);

	switch (occ_data->version) {
	case 0x01:
	case 0x02:
		parse_pstates_v2(occ_data, dt_id, dt_freq, nr_pstates,
				 pmax, pmin);
		break;
	case 0x90:
		parse_pstates_v9(occ_data, dt_id, dt_freq, nr_pstates,
				 pmax, pmin);
		break;
	default:
		return false;
	}

	/* Add the device-tree entries */
	dt_add_property(power_mgt, "ibm,pstate-ids", dt_id,
			nr_pstates * sizeof(u32));
	dt_add_property(power_mgt, "ibm,pstate-frequencies-mhz", dt_freq,
			nr_pstates * sizeof(u32));
	dt_add_property_cells(power_mgt, "ibm,pstate-min", pmin);
	dt_add_property_cells(power_mgt, "ibm,pstate-nominal", pnom);
	dt_add_property_cells(power_mgt, "ibm,pstate-max", pmax);

	free(dt_freq);
	free(dt_id);

	/*
	 * Parse and add WOF properties: turbo, ultra-turbo and core_max array.
	 * core_max[1..n] array provides the max sustainable pstate that can be
	 * achieved with i active cores in the chip.
	 */
	if (ultra_turbo_supported) {
		int pturbo, pultra_turbo;
		u8 nr_cores = get_available_nr_cores_in_chip(chip->id);
		u32 *dt_cmax;

		dt_cmax = malloc(nr_cores * sizeof(u32));
		assert(dt_cmax);
		switch (occ_data->version) {
		case 0x02:
			pturbo = occ_data->v2.pstate_turbo;
			pultra_turbo = occ_data->v2.pstate_ultra_turbo;
			for (i = 0; i < nr_cores; i++)
				dt_cmax[i] = occ_data->v2.core_max[i];
			break;
		case 0x90:
			pturbo = occ_data->v9.pstate_turbo;
			pultra_turbo = occ_data->v9.pstate_ultra_turbo;
			for (i = 0; i < nr_cores; i++)
				dt_cmax[i] = occ_data->v9.core_max[i];
			break;
		default:
			return false;
		}

		if (cmp_pstates(pturbo, pmax) > 0) {
			prerror("OCC: Clipping turbo pstate(%d) to Pmax(%d)\n",
				pturbo, pmax);
			dt_add_property_cells(power_mgt, "ibm,pstate-turbo",
					      pmax);
		} else {
			dt_add_property_cells(power_mgt, "ibm,pstate-turbo",
					      pturbo);
		}

		dt_add_property_cells(power_mgt, "ibm,pstate-ultra-turbo",
				      pultra_turbo);
		dt_add_property(power_mgt, "ibm,pstate-core-max", dt_cmax,
				nr_cores * sizeof(u32));

		free(dt_cmax);
	}

	if (occ_data->version > 0x02)
		goto out;

	dt_add_property_cells(power_mgt, "#address-cells", 2);
	dt_add_property_cells(power_mgt, "#size-cells", 1);

	/* Add chip specific pstate properties */
	for_each_chip(chip) {
		struct dt_node *occ_node;

		occ_data = get_occ_pstate_table(chip);
		occ_node = dt_new_addr(power_mgt, "occ", (uint64_t)occ_data);
		if (!occ_node) {
			/**
			 * @fwts-label OCCDTFailedNodeCreation
			 * @fwts-advice Failed to create
			 * /ibm,opal/power-mgt/occ. Per-chip pstate properties
			 * are not added to Device Tree.
			 */
			prerror("OCC: Failed to create /ibm,opal/power-mgt/occ@%llx\n",
				(uint64_t)occ_data);
			return false;
		}

		dt_add_property_cells(occ_node, "reg",
				      hi32((uint64_t)occ_data),
				      lo32((uint64_t)occ_data),
				      OPAL_DYNAMIC_DATA_OFFSET +
				      sizeof(struct occ_dynamic_data));
		dt_add_property_cells(occ_node, "ibm,chip-id", chip->id);

		/*
		 * Parse and add pstate Voltage Identifiers (VID) to DT which
		 * are provided by OCC in version 0x01 and 0x02
		 */
		parse_vid(occ_data, occ_node, nr_pstates, pmax, pmin);
	}
out:
	/* Return pstate to set for each core */
	*pstate_nom = pnom;
	return true;
}

/*
 * Prepare chip for pstate transitions
 */

static bool cpu_pstates_prepare_core(struct proc_chip *chip,
				     struct cpu_thread *c,
				     int pstate_nom)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp, pstate;
	int rc;

	/*
	 * Currently Fastsleep init clears EX_PM_SPR_OVERRIDE_EN.
	 * Need to ensure only relevant bits are inited
	 */

	/* Init PM GP1 for SCOM based PSTATE control to set nominal freq
	 *
	 * Use the OR SCOM to set the required bits in PM_GP1 register
	 * since the OCC might be mainpulating the PM_GP1 register as well.
	 */ 
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_SET_GP1),
			 EX_PM_SETUP_GP1_PM_SPR_OVERRIDE_EN);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: Failed to write PM_GP1 in pstates init\n");
		return false;
	}

	/* Set new pstate to core */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_PPMCR), &tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: Failed to read from OCC in pstates init\n");
		return false;
	}
	tmp = tmp & ~0xFFFF000000000000ULL;
	pstate = ((uint64_t) pstate_nom) & 0xFF;
	tmp = tmp | (pstate << 56) | (pstate << 48);
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_PPMCR), tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: Failed to write PM_GP1 in pstates init\n");
		return false;
	}
	time_wait_ms(1); /* Wait for PState to change */
	/*
	 * Init PM GP1 for SPR based PSTATE control.
	 * Once OCC is active EX_PM_SETUP_GP1_DPLL_FREQ_OVERRIDE_EN will be
	 * cleared by OCC.  Sapphire need not clear.
	 * However wait for DVFS state machine to become idle after min->nominal
	 * transition initiated above.  If not switch over to SPR control could fail.
	 *
	 * Use the AND SCOM to clear the required bits in PM_GP1 register
	 * since the OCC might be mainpulating the PM_GP1 register as well.
	 */
	tmp = ~EX_PM_SETUP_GP1_PM_SPR_OVERRIDE_EN;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_CLEAR_GP1),
			tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: Failed to write PM_GP1 in pstates init\n");
		return false;
	}

	/* Just debug */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, EX_PM_PPMSR), &tmp);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: Failed to read back setting from OCC"
				 "in pstates init\n");
		return false;
	}
	prlog(PR_DEBUG, "OCC: Chip %x Core %x PPMSR %016llx\n",
	      chip->id, core, tmp);

	/*
	 * If PMSR is still in transition at this point due to PState change
	 * initiated above, then the switchover to SPR may not work.
	 * ToDo: Check for DVFS state machine idle before change.
	 */

	return true;
}

static bool occ_opal_msg_outstanding = false;
static void occ_msg_consumed(void *data __unused)
{
	lock(&occ_lock);
	occ_opal_msg_outstanding = false;
	unlock(&occ_lock);
}

static inline u8 get_cpu_throttle(struct proc_chip *chip)
{
	struct occ_pstate_table *pdata = get_occ_pstate_table(chip);
	struct occ_dynamic_data *data;

	switch (pdata->version) {
	case 0x01:
	case 0x02:
		return pdata->v2.throttle;
	case 0x90:
		data = get_occ_dynamic_data(chip);
		return data->cpu_throttle;
	default:
		return 0;
	};
}

static void occ_throttle_poll(void *data __unused)
{
	struct proc_chip *chip;
	struct occ_pstate_table *occ_data;
	struct opal_occ_msg occ_msg;
	int rc;

	if (!try_lock(&occ_lock))
		return;
	if (occ_reset) {
		int inactive = 0;

		for_each_chip(chip) {
			occ_data = get_occ_pstate_table(chip);
			if (occ_data->valid != 1) {
				inactive = 1;
				break;
			}
		}
		if (!inactive) {
			/*
			 * Queue OCC_THROTTLE with throttle status as 0 to
			 * indicate all OCCs are active after a reset.
			 */
			occ_msg.type = cpu_to_be64(OCC_THROTTLE);
			occ_msg.chip = 0;
			occ_msg.throttle_status = 0;
			rc = _opal_queue_msg(OPAL_MSG_OCC, NULL, NULL, 3,
					     (uint64_t *)&occ_msg);
			if (!rc)
				occ_reset = false;
		}
	} else {
		if (occ_opal_msg_outstanding)
			goto done;
		for_each_chip(chip) {
			u8 throttle;

			occ_data = get_occ_pstate_table(chip);
			throttle = get_cpu_throttle(chip);
			if ((occ_data->valid == 1) &&
			    (chip->throttle != throttle) &&
			    (throttle <= OCC_MAX_THROTTLE_STATUS)) {
				occ_msg.type = cpu_to_be64(OCC_THROTTLE);
				occ_msg.chip = cpu_to_be64(chip->id);
				occ_msg.throttle_status = cpu_to_be64(throttle);
				rc = _opal_queue_msg(OPAL_MSG_OCC, NULL,
						     occ_msg_consumed,
						     3, (uint64_t *)&occ_msg);
				if (!rc) {
					chip->throttle = throttle;
					occ_opal_msg_outstanding = true;
					break;
				}
			}
		}
	}
done:
	unlock(&occ_lock);
}

/* OPAL-OCC Command/Response Interface */

enum occ_state {
	OCC_STATE_NOT_RUNNING		= 0x00,
	OCC_STATE_STANDBY		= 0x01,
	OCC_STATE_OBSERVATION		= 0x02,
	OCC_STATE_ACTIVE		= 0x03,
	OCC_STATE_SAFE			= 0x04,
	OCC_STATE_CHARACTERIZATION	= 0x05,
};

enum occ_role {
	OCC_ROLE_SLAVE		= 0x0,
	OCC_ROLE_MASTER		= 0x1,
};

enum occ_cmd {
	OCC_CMD_CLEAR_SENSOR_DATA,
	OCC_CMD_SET_POWER_CAP,
	OCC_CMD_SET_POWER_SHIFTING_RATIO,
	OCC_CMD_LAST
};

struct opal_occ_cmd_info {
	enum	occ_cmd cmd;
	u8	cmd_value;
	u16	cmd_size;
	u16	rsp_size;
	int	timeout_ms;
	u16	state_mask;
	u8	role_mask;
};

static struct opal_occ_cmd_info occ_cmds[] = {
	{	OCC_CMD_CLEAR_SENSOR_DATA,
		0xD0, 4, 4, 1000,
		PPC_BIT16(OCC_STATE_OBSERVATION) |
		PPC_BIT16(OCC_STATE_ACTIVE) |
		PPC_BIT16(OCC_STATE_CHARACTERIZATION),
		PPC_BIT8(OCC_ROLE_MASTER) | PPC_BIT8(OCC_ROLE_SLAVE)
	},
	{	OCC_CMD_SET_POWER_CAP,
		0xD1, 2, 2, 1000,
		PPC_BIT16(OCC_STATE_OBSERVATION) |
		PPC_BIT16(OCC_STATE_ACTIVE) |
		PPC_BIT16(OCC_STATE_CHARACTERIZATION),
		PPC_BIT8(OCC_ROLE_MASTER)
	},
	{	OCC_CMD_SET_POWER_SHIFTING_RATIO,
		0xD2, 1, 1, 1000,
		PPC_BIT16(OCC_STATE_OBSERVATION) |
		PPC_BIT16(OCC_STATE_ACTIVE) |
		PPC_BIT16(OCC_STATE_CHARACTERIZATION),
		PPC_BIT8(OCC_ROLE_MASTER) | PPC_BIT8(OCC_ROLE_SLAVE)
	},
};

enum occ_response_status {
	OCC_RSP_SUCCESS			= 0x00,
	OCC_RSP_INVALID_COMMAND		= 0x11,
	OCC_RSP_INVALID_CMD_DATA_LENGTH	= 0x12,
	OCC_RSP_INVALID_DATA		= 0x13,
	OCC_RSP_INTERNAL_ERROR		= 0x15,
};

#define OCC_FLAG_RSP_READY		0x01
#define OCC_FLAG_CMD_IN_PROGRESS	0x02
#define OPAL_FLAG_CMD_READY		0x80

struct opal_occ_cmd_data {
	u8 *data;
	enum occ_cmd cmd;
};

static struct cmd_interface {
	struct lock queue_lock;
	struct timer timeout;
	struct opal_occ_cmd_data *cdata;
	struct opal_command_buffer *cmd;
	struct occ_response_buffer *rsp;
	u8 *occ_state;
	u8 *valid;
	u32 chip_id;
	u32 token;
	u8 occ_role;
	u8 request_id;
	bool cmd_in_progress;
	bool retry;
} *chips;

static int nr_occs;

static inline struct cmd_interface *get_chip_cmd_interface(int chip_id)
{
	int i;

	for (i = 0; i < nr_occs; i++)
		if (chips[i].chip_id == chip_id)
			return &chips[i];

	return NULL;
}

static inline bool occ_in_progress(struct cmd_interface *chip)
{
	return (chip->rsp->flag == OCC_FLAG_CMD_IN_PROGRESS);
}

static int write_occ_cmd(struct cmd_interface *chip)
{
	struct opal_command_buffer *cmd = chip->cmd;
	enum occ_cmd ocmd = chip->cdata->cmd;

	if (!chip->retry && occ_in_progress(chip)) {
		chip->cmd_in_progress = false;
		return OPAL_BUSY;
	}

	cmd->flag = chip->rsp->flag = 0;
	cmd->cmd = occ_cmds[ocmd].cmd_value;
	cmd->request_id = chip->request_id++;
	cmd->data_size = occ_cmds[ocmd].cmd_size;
	memcpy(&cmd->data, chip->cdata->data, cmd->data_size);
	cmd->flag = OPAL_FLAG_CMD_READY;

	schedule_timer(&chip->timeout,
		       msecs_to_tb(occ_cmds[ocmd].timeout_ms));

	return OPAL_ASYNC_COMPLETION;
}

static int64_t opal_occ_command(struct cmd_interface *chip, int token,
				struct opal_occ_cmd_data *cdata)
{
	int rc;

	if (!(*chip->valid) ||
	    (!(PPC_BIT16(*chip->occ_state) & occ_cmds[cdata->cmd].state_mask)))
		return OPAL_HARDWARE;

	if (!(PPC_BIT8(chip->occ_role) & occ_cmds[cdata->cmd].role_mask))
		return OPAL_PERMISSION;

	lock(&chip->queue_lock);
	if (chip->cmd_in_progress) {
		rc = OPAL_BUSY;
		goto out;
	}

	chip->cdata = cdata;
	chip->token = token;
	chip->cmd_in_progress = true;
	chip->retry = false;
	rc = write_occ_cmd(chip);
out:
	unlock(&chip->queue_lock);
	return rc;
}

static inline bool sanity_check_opal_cmd(struct opal_command_buffer *cmd,
					 struct cmd_interface *chip)
{
	return ((cmd->cmd == occ_cmds[chip->cdata->cmd].cmd_value) &&
		(cmd->request_id == chip->request_id - 1) &&
		(cmd->data_size == occ_cmds[chip->cdata->cmd].cmd_size));
}

static inline bool check_occ_rsp(struct opal_command_buffer *cmd,
				 struct occ_response_buffer *rsp)
{
	if (cmd->cmd != rsp->cmd) {
		prlog(PR_DEBUG, "OCC: Command value mismatch in OCC response"
		      "rsp->cmd = %d cmd->cmd = %d\n", rsp->cmd, cmd->cmd);
		return false;
	}

	if (cmd->request_id != rsp->request_id) {
		prlog(PR_DEBUG, "OCC: Request ID mismatch in OCC response"
		      "rsp->request_id = %d cmd->request_id = %d\n",
		      rsp->request_id, cmd->request_id);
		return false;
	}

	return true;
}

static inline void queue_occ_rsp_msg(int token, int rc)
{
	int ret;

	ret = opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL, token, rc);
	if (ret)
		prerror("OCC: Failed to queue OCC response status message\n");
}

static void occ_cmd_timeout_handler(struct timer *t __unused, void *data,
				    uint64_t now __unused)
{
	struct cmd_interface *chip = data;

	lock(&chip->queue_lock);
	if (!chip->cmd_in_progress)
		goto exit;

	if (!chip->retry) {
		prlog(PR_DEBUG, "OCC: Command timeout, retrying\n");
		chip->retry = true;
		write_occ_cmd(chip);
	} else {
		chip->cmd_in_progress = false;
		queue_occ_rsp_msg(chip->token, OPAL_TIMEOUT);
		prlog(PR_DEBUG, "OCC: Command timeout after retry\n");
	}
exit:
	unlock(&chip->queue_lock);
}

static int read_occ_rsp(struct occ_response_buffer *rsp)
{
	switch (rsp->status) {
	case OCC_RSP_SUCCESS:
		return OPAL_SUCCESS;
	case OCC_RSP_INVALID_COMMAND:
		prlog(PR_DEBUG, "OCC: Rsp status: Invalid command\n");
		break;
	case OCC_RSP_INVALID_CMD_DATA_LENGTH:
		prlog(PR_DEBUG, "OCC: Rsp status: Invalid command data length\n");
		break;
	case OCC_RSP_INVALID_DATA:
		prlog(PR_DEBUG, "OCC: Rsp status: Invalid command data\n");
		break;
	case OCC_RSP_INTERNAL_ERROR:
		prlog(PR_DEBUG, "OCC: Rsp status: OCC internal error\n");
		break;
	default:
		break;
	}

	/* Clear the OCC response flag */
	rsp->flag = 0;
	return OPAL_INTERNAL_ERROR;
}

static void handle_occ_rsp(uint32_t chip_id)
{
	struct cmd_interface *chip;
	struct opal_command_buffer *cmd;
	struct occ_response_buffer *rsp;

	chip = get_chip_cmd_interface(chip_id);
	if (!chip)
		return;

	cmd = chip->cmd;
	rsp = chip->rsp;

	/*Read rsp*/
	if (rsp->flag != OCC_FLAG_RSP_READY)
		return;
	lock(&chip->queue_lock);
	if (!chip->cmd_in_progress)
		goto exit;

	cancel_timer(&chip->timeout);
	if (!sanity_check_opal_cmd(cmd, chip) ||
	    !check_occ_rsp(cmd, rsp)) {
		if (!chip->retry) {
			prlog(PR_DEBUG, "OCC: Command-response mismatch, retrying\n");
			chip->retry = true;
			write_occ_cmd(chip);
		} else {
			chip->cmd_in_progress = false;
			queue_occ_rsp_msg(chip->token, OPAL_INTERNAL_ERROR);
			prlog(PR_DEBUG, "OCC: Command-response mismatch\n");
		}
		goto exit;
	}

	chip->cmd_in_progress = false;
	queue_occ_rsp_msg(chip->token, read_occ_rsp(chip->rsp));
exit:
	unlock(&chip->queue_lock);
}

static void occ_add_powercap_sensors(struct dt_node *power_mgt);
static void occ_add_psr_sensors(struct dt_node *power_mgt);

static void occ_cmd_interface_init(void)
{
	struct occ_dynamic_data *data;
	struct occ_pstate_table *pdata;
	struct dt_node *power_mgt;
	struct proc_chip *chip;
	int i = 0;

	chip = next_chip(NULL);
	pdata = get_occ_pstate_table(chip);
	if (pdata->version != 0x90)
		return;

	for_each_chip(chip)
		nr_occs++;

	chips = malloc(sizeof(*chips) * nr_occs);
	assert(chips);

	for_each_chip(chip) {
		pdata = get_occ_pstate_table(chip);
		data = get_occ_dynamic_data(chip);
		chips[i].chip_id = chip->id;
		chips[i].occ_role = pdata->v9.occ_role;
		chips[i].occ_state = &data->occ_state;
		chips[i].valid = &pdata->valid;
		chips[i].cmd = &data->cmd;
		chips[i].rsp = &data->rsp;
		init_lock(&chips[i].queue_lock);
		chips[i].cmd_in_progress = false;
		chips[i].request_id = 0;
		init_timer(&chips[i].timeout, occ_cmd_timeout_handler,
			   &chips[i]);
		i++;
	}

	power_mgt = dt_find_by_path(dt_root, "/ibm,opal/power-mgt");
	if (!power_mgt) {
		prerror("OCC: dt node /ibm,opal/power-mgt not found\n");
		return;
	}

	/* Add powercap sensors to DT */
	occ_add_powercap_sensors(power_mgt);

	/* Add power-shifting-ratio CPU-GPU sensors to DT */
	occ_add_psr_sensors(power_mgt);
}

/* Powercap interface */
enum sensor_powercap_occ_attr {
	POWERCAP_OCC_MIN,
	POWERCAP_OCC_MAX,
	POWERCAP_OCC_CUR,
};

static void occ_add_powercap_sensors(struct dt_node *power_mgt)
{
	struct dt_node *pcap, *node;
	u32 handle;

	pcap = dt_new(power_mgt, "powercap");
	if (!pcap) {
		prerror("OCC: Failed to create powercap node\n");
		return;
	}

	dt_add_property_string(pcap, "compatible", "ibm,opal-powercap");
	node = dt_new(pcap, "system-powercap");
	if (!node) {
		prerror("OCC: Failed to create system powercap node\n");
		return;
	}

	handle = powercap_make_handle(POWERCAP_CLASS_OCC, POWERCAP_OCC_CUR);
	dt_add_property_cells(node, "powercap-current", handle);

	handle = powercap_make_handle(POWERCAP_CLASS_OCC, POWERCAP_OCC_MIN);
	dt_add_property_cells(node, "powercap-min", handle);

	handle = powercap_make_handle(POWERCAP_CLASS_OCC, POWERCAP_OCC_MAX);
	dt_add_property_cells(node, "powercap-max", handle);
}

int occ_get_powercap(u32 handle, u32 *pcap)
{
	struct occ_pstate_table *pdata;
	struct occ_dynamic_data *ddata;
	struct proc_chip *chip;

	chip = next_chip(NULL);
	pdata = get_occ_pstate_table(chip);
	ddata = get_occ_dynamic_data(chip);

	if (!pdata->valid)
		return OPAL_HARDWARE;

	switch (powercap_get_attr(handle)) {
	case POWERCAP_OCC_MIN:
		*pcap = ddata->min_pwr_cap;
		break;
	case POWERCAP_OCC_MAX:
		*pcap = ddata->max_pwr_cap;
		break;
	case POWERCAP_OCC_CUR:
		*pcap = ddata->cur_pwr_cap;
		break;
	default:
		*pcap = 0;
		return OPAL_UNSUPPORTED;
	}

	return OPAL_SUCCESS;
}

static u16 pcap_cdata;
static struct opal_occ_cmd_data pcap_data = {
	.data		= (u8 *)&pcap_cdata,
	.cmd		= OCC_CMD_SET_POWER_CAP,
};

int occ_set_powercap(u32 handle, int token, u32 pcap)
{
	struct occ_dynamic_data *ddata;
	struct proc_chip *chip;
	int i;

	if (powercap_get_attr(handle) != POWERCAP_OCC_CUR)
		return OPAL_PERMISSION;

	for (i = 0; i < nr_occs; i++)
		if (chips[i].occ_role == OCC_ROLE_MASTER)
			break;

	if (!(*chips[i].valid))
		return OPAL_HARDWARE;

	chip = get_chip(chips[i].chip_id);
	ddata = get_occ_dynamic_data(chip);

	if (pcap == ddata->cur_pwr_cap)
		return OPAL_SUCCESS;

	if (pcap && (pcap > ddata->max_pwr_cap ||
	    pcap < ddata->min_pwr_cap))
		return OPAL_PARAMETER;

	pcap_cdata = pcap;
	return opal_occ_command(&chips[i], token, &pcap_data);
};

/* Power-Shifting Ratio */
enum psr_type {
	PSR_TYPE_CPU_TO_GPU, /* 0% Cap GPU first, 100% Cap CPU first */
};

int occ_get_psr(u32 handle, u32 *ratio)
{
	struct occ_dynamic_data *ddata;
	struct proc_chip *chip;
	u8 i = psr_get_rid(handle);

	if (psr_get_type(handle) != PSR_TYPE_CPU_TO_GPU)
		return OPAL_UNSUPPORTED;

	if (i > nr_occs)
		return OPAL_UNSUPPORTED;

	if (!(*chips[i].valid))
		return OPAL_HARDWARE;

	chip = get_chip(chips[i].chip_id);
	ddata = get_occ_dynamic_data(chip);
	*ratio = ddata->pwr_shifting_ratio;
	return OPAL_SUCCESS;
}

static u8 psr_cdata;
static struct opal_occ_cmd_data psr_data = {
	.data		= &psr_cdata,
	.cmd		= OCC_CMD_SET_POWER_SHIFTING_RATIO,
};

int occ_set_psr(u32 handle, int token, u32 ratio)
{
	struct occ_dynamic_data *ddata;
	struct proc_chip *chip;
	u8 i = psr_get_rid(handle);

	if (psr_get_type(handle) != PSR_TYPE_CPU_TO_GPU)
		return OPAL_UNSUPPORTED;

	if (ratio > 100)
		return OPAL_PARAMETER;

	if (i > nr_occs)
		return OPAL_UNSUPPORTED;

	if (!(*chips[i].valid))
		return OPAL_HARDWARE;

	chip = get_chip(chips[i].chip_id);
	ddata = get_occ_dynamic_data(chip);
	if (ratio == ddata->pwr_shifting_ratio)
		return OPAL_SUCCESS;

	psr_cdata = ratio;
	return opal_occ_command(&chips[i], token, &psr_data);
}

static void occ_add_psr_sensors(struct dt_node *power_mgt)
{
	struct dt_node *node;
	int i;

	node = dt_new(power_mgt, "psr");
	if (!node) {
		prerror("OCC: Failed to create power-shifting-ratio node\n");
		return;
	}

	dt_add_property_string(node, "compatible",
			       "ibm,opal-power-shift-ratio");
	for (i = 0; i < nr_occs; i++) {
		struct dt_node *cnode;
		char name[20];
		u32 handle = psr_make_handle(PSR_CLASS_OCC, i,
					     PSR_TYPE_CPU_TO_GPU);

		cnode = dt_new_addr(node, "cpu-to-gpu", handle);
		if (!cnode) {
			prerror("OCC: Failed to create power-shifting-ratio node\n");
			return;
		}

		snprintf(name, 20, "cpu_to_gpu_%d", chips[i].chip_id);
		dt_add_property_string(cnode, "label", name);
		dt_add_property_cells(cnode, "handle", handle);
	}
}

/* OCC clear sensor limits CSM/Profiler/Job-scheduler */

enum occ_sensor_limit_group {
	OCC_SENSOR_LIMIT_GROUP_CSM		= 0x10,
	OCC_SENSOR_LIMIT_GROUP_PROFILER		= 0x20,
	OCC_SENSOR_LIMIT_GROUP_JOB_SCHED	= 0x40,
};

static u32 sensor_limit;
static struct opal_occ_cmd_data slimit_data = {
	.data		= (u8 *)&sensor_limit,
	.cmd		= OCC_CMD_CLEAR_SENSOR_DATA,
};

int occ_sensor_group_clear(u32 group_hndl, int token)
{
	u32 limit = sensor_get_rid(group_hndl);
	u8 i = sensor_get_attr(group_hndl);

	if (i > nr_occs)
		return OPAL_UNSUPPORTED;

	switch (limit) {
	case OCC_SENSOR_LIMIT_GROUP_CSM:
	case OCC_SENSOR_LIMIT_GROUP_PROFILER:
	case OCC_SENSOR_LIMIT_GROUP_JOB_SCHED:
		break;
	default:
		return OPAL_UNSUPPORTED;
	}

	if (!(*chips[i].valid))
		return OPAL_HARDWARE;

	sensor_limit = limit << 24;
	return opal_occ_command(&chips[i], token, &slimit_data);
}

void occ_add_sensor_groups(struct dt_node *sg, u32 *phandles, int nr_phandles,
			   int chipid)
{
	struct limit_group_info {
		int limit;
		const char *str;
	} limits[] = {
		{ OCC_SENSOR_LIMIT_GROUP_CSM, "csm" },
		{ OCC_SENSOR_LIMIT_GROUP_PROFILER, "profiler" },
		{ OCC_SENSOR_LIMIT_GROUP_JOB_SCHED, "js" },
	};
	int i, j;

	for (i = 0; i < nr_occs; i++)
		if (chips[i].chip_id == chipid)
			break;

	for (j = 0; j < ARRAY_SIZE(limits); j++) {
		struct dt_node *node;
		char name[20];
		u32 handle;

		snprintf(name, 20, "occ-%s", limits[j].str);
		handle = sensor_make_handler(SENSOR_OCC, 0,
					     limits[j].limit, i);
		node = dt_new_addr(sg, name, handle);
		if (!node) {
			prerror("Failed to create sensor group nodes\n");
			return;
		}

		dt_add_property_cells(node, "sensor-group-id", handle);
		dt_add_property_string(node, "type", limits[j].str);
		dt_add_property_cells(node, "ibm,chip-id", chipid);
		dt_add_property(node, "sensors", phandles, nr_phandles);
		dt_add_property_cells(node, "ops", OPAL_SENSOR_GROUP_CLEAR);
	}
}

/* CPU-OCC PState init */
/* Called after OCC init on P8 and P9 */
void occ_pstates_init(void)
{
	struct proc_chip *chip;
	struct cpu_thread *c;
	int pstate_nom;
	static bool occ_pstates_initialized;

	/* OCC is supported in P8 and P9 */
	if (proc_gen < proc_gen_p8)
		return;
	/* Handle fast reboots */
	if (occ_pstates_initialized)
		return;

	switch (proc_gen) {
	case proc_gen_p8:
		homer_opal_data_offset = P8_HOMER_OPAL_DATA_OFFSET;
		break;
	case proc_gen_p9:
		homer_opal_data_offset = P9_HOMER_OPAL_DATA_OFFSET;
		break;
	default:
		return;
	}

	chip = next_chip(NULL);
	if (!chip->homer_base) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"OCC: No HOMER detected, assuming no pstates\n");
		return;
	}

	/* Wait for all OCC to boot up */
	if(!wait_for_all_occ_init()) {
		log_simple_error(&e_info(OPAL_RC_OCC_TIMEOUT),
			 "OCC: Initialization on all chips did not complete"
			 "(timed out)\n");
		return;
	}

	/*
	 * Check boundary conditions and add device tree nodes
	 * and return nominal pstate to set for the core
	 */
	if (!add_cpu_pstate_properties(&pstate_nom)) {
		log_simple_error(&e_info(OPAL_RC_OCC_PSTATE_INIT),
			"Skiping core cpufreq init due to OCC error\n");
		return;
	}

	/*
	 * Setup host based pstates and set nominal frequency only in
	 * P8.
	 */
	if (proc_gen == proc_gen_p8) {
		for_each_chip(chip)
			for_each_available_core_in_chip(c, chip->id)
				cpu_pstates_prepare_core(chip, c, pstate_nom);
	}

	/* Add opal_poller to poll OCC throttle status of each chip */
	for_each_chip(chip)
		chip->throttle = 0;
	opal_add_poller(occ_throttle_poll, NULL);
	occ_pstates_initialized = true;

	/* Init OPAL-OCC command-response interface */
	occ_cmd_interface_init();
}

struct occ_load_req {
	u8 scope;
	u32 dbob_id;
	u32 seq_id;
	struct list_node link;
};
static LIST_HEAD(occ_load_req_list);

int find_master_and_slave_occ(uint64_t **master, uint64_t **slave,
			      int *nr_masters, int *nr_slaves)
{
	struct proc_chip *chip;
	int nr_chips = 0, i;
	uint64_t chipids[MAX_CHIPS];

	for_each_chip(chip) {
		chipids[nr_chips++] = chip->id;
	}

	chip = next_chip(NULL);
	/*
	 * Proc0 is the master OCC for Tuleta/Alpine boxes.
	 * Hostboot expects the pair of chips for MURANO, so pass the sibling
	 * chip id along with proc0 to hostboot.
	 */
	*nr_masters = (chip->type == PROC_CHIP_P8_MURANO) ? 2 : 1;
	*master = (uint64_t *)malloc(*nr_masters * sizeof(uint64_t));

	if (!*master) {
		printf("OCC: master array alloc failure\n");
		return -ENOMEM;
	}

	if (nr_chips - *nr_masters > 0) {
		*nr_slaves = nr_chips - *nr_masters;
		*slave = (uint64_t *)malloc(*nr_slaves * sizeof(uint64_t));
		if (!*slave) {
			printf("OCC: slave array alloc failure\n");
			return -ENOMEM;
		}
	}

	for (i = 0; i < nr_chips; i++) {
		if (i < *nr_masters) {
			*(*master + i) = chipids[i];
			continue;
		}
		*(*slave + i - *nr_masters) = chipids[i];
	}
	return 0;
}

static void occ_queue_load(u8 scope, u32 dbob_id, u32 seq_id)
{
	struct occ_load_req *occ_req;

	occ_req = zalloc(sizeof(struct occ_load_req));
	if (!occ_req) {
		/**
		 * @fwts-label OCCload_reqENOMEM
		 * @fwts-advice ENOMEM while allocating OCC load message.
		 * OCCs not started, consequently no power/frequency scaling
		 * will be functional.
		 */
		prlog(PR_ERR, "OCC: Could not allocate occ_load_req\n");
		return;
	}

	occ_req->scope = scope;
	occ_req->dbob_id = dbob_id;
	occ_req->seq_id = seq_id;
	list_add_tail(&occ_load_req_list, &occ_req->link);
}

static void __occ_do_load(u8 scope, u32 dbob_id __unused, u32 seq_id)
{
	struct fsp_msg *stat;
	int rc = -ENOMEM;
	int status_word = 0;
	struct proc_chip *chip = next_chip(NULL);

	/* Call HBRT... */
	rc = host_services_occ_load();

	/* Handle fallback to preload */
	if (rc == -ENOENT && chip->homer_base) {
		prlog(PR_INFO, "OCC: Load: Fallback to preloaded image\n");
		rc = 0;
	} else if (!rc) {
		struct opal_occ_msg occ_msg = { CPU_TO_BE64(OCC_LOAD), 0, 0 };

		rc = _opal_queue_msg(OPAL_MSG_OCC, NULL, NULL, 3,
				     (uint64_t *)&occ_msg);
		if (rc)
			prlog(PR_INFO, "OCC: Failed to queue message %d\n",
			      OCC_LOAD);

		/* Success, start OCC */
		rc = host_services_occ_start();
	}
	if (rc) {
		/* If either of hostservices call fail, send fail to FSP */
		/* Find a chip ID to send failure */
		for_each_chip(chip) {
			if (scope == 0x01 && dbob_id != chip->dbob_id)
				continue;
			status_word = 0xB500 | (chip->pcid & 0xff);
			break;
		}
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
			"OCC: Error %d in load/start OCC\n", rc);
	}

	/* Send a single response for all chips */
	stat = fsp_mkmsg(FSP_CMD_LOAD_OCC_STAT, 2, status_word, seq_id);
	if (stat)
		rc = fsp_queue_msg(stat, fsp_freemsg);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
			"OCC: Error %d queueing FSP OCC LOAD STATUS msg", rc);
		fsp_freemsg(stat);
	}
}

void occ_poke_load_queue(void)
{
	struct occ_load_req *occ_req, *next;

	if (list_empty(&occ_load_req_list))
		return;

	list_for_each_safe(&occ_load_req_list, occ_req, next, link) {
		__occ_do_load(occ_req->scope, occ_req->dbob_id,
				occ_req->seq_id);
		list_del(&occ_req->link);
		free(occ_req);
	}
}

static void occ_do_load(u8 scope, u32 dbob_id __unused, u32 seq_id)
{
	struct fsp_msg *rsp;
	int rc = -ENOMEM;
	u8 err = 0;

	if (scope != 0x01 && scope != 0x02) {
		/**
		 * @fwts-label OCCLoadInvalidScope
		 * @fwts-advice Invalid request for loading OCCs. Power and
		 * frequency management not functional
		 */
		prlog(PR_ERR, "OCC: Load message with invalid scope 0x%x\n",
		      scope);
		err = 0x22;
	}

	/* First queue up an OK response to the load message itself */
	rsp = fsp_mkmsg(FSP_RSP_LOAD_OCC | err, 0);
	if (rsp)
		rc = fsp_queue_msg(rsp, fsp_freemsg);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
			"OCC: Error %d queueing FSP OCC LOAD reply\n", rc);
		fsp_freemsg(rsp);
		return;
	}

	if (err)
		return;

	if (proc_gen == proc_gen_p9) {
		rc = -ENOMEM;
		/* OCC is pre-loaded in P9, so send SUCCESS to FSP */
		rsp = fsp_mkmsg(FSP_CMD_LOAD_OCC_STAT, 2, 0, seq_id);
		if (rsp)
			rc = fsp_queue_msg(rsp, fsp_freemsg);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
				"OCC: Error %d queueing FSP OCC LOAD STATUS msg", rc);
			fsp_freemsg(rsp);
		}
		return;
	}

	/*
	 * Check if hostservices lid caching is complete. If not, queue
	 * the load request.
	 */
	if (!hservices_lid_preload_complete()) {
		occ_queue_load(scope, dbob_id, seq_id);
		return;
	}

	__occ_do_load(scope, dbob_id, seq_id);
}

int occ_msg_queue_occ_reset(void)
{
	struct opal_occ_msg occ_msg = { OCC_RESET, 0, 0 };
	struct proc_chip *chip;
	int rc;

	lock(&occ_lock);
	rc = _opal_queue_msg(OPAL_MSG_OCC, NULL, NULL, 3,
			     (uint64_t *)&occ_msg);
	if (rc) {
		prlog(PR_INFO, "OCC: Failed to queue OCC_RESET message\n");
		goto out;
	}
	/*
	 * Set 'valid' byte of occ_pstate_table to 0 since OCC
	 * may not clear this byte on a reset.
	 * OCC will set the 'valid' byte to 1 when it becomes
	 * active again.
	 */
	for_each_chip(chip) {
		struct occ_pstate_table *occ_data;

		occ_data = get_occ_pstate_table(chip);
		occ_data->valid = 0;
		chip->throttle = 0;
	}
	occ_reset = true;
out:
	unlock(&occ_lock);
	return rc;
}

static void occ_do_reset(u8 scope, u32 dbob_id, u32 seq_id)
{
	struct fsp_msg *rsp, *stat;
	struct proc_chip *chip = next_chip(NULL);
	int rc = -ENOMEM;
	u8 err = 0;

	/* Check arguments */
	if (scope != 0x01 && scope != 0x02) {
		/**
		 * @fwts-label OCCResetInvalidScope
		 * @fwts-advice Invalid request for resetting OCCs. Power and
		 * frequency management not functional
		 */
		prlog(PR_ERR, "OCC: Reset message with invalid scope 0x%x\n",
		      scope);
		err = 0x22;
	}

	/* First queue up an OK response to the reset message itself */
	rsp = fsp_mkmsg(FSP_RSP_RESET_OCC | err, 0);
	if (rsp)
		rc = fsp_queue_msg(rsp, fsp_freemsg);
	if (rc) {
		fsp_freemsg(rsp);
		log_simple_error(&e_info(OPAL_RC_OCC_RESET),
			"OCC: Error %d queueing FSP OCC RESET reply\n", rc);
		return;
	}

	/* If we had an error, return */
	if (err)
		return;

	/*
	 * Call HBRT to stop OCC and leave it stopped.  FSP will send load/start
	 * request subsequently.  Also after few runtime restarts (currently 3),
	 * FSP will request OCC to left in stopped state.
	 */

	rc = host_services_occ_stop();

	/* Handle fallback to preload */
	if (rc == -ENOENT && chip->homer_base) {
		prlog(PR_INFO, "OCC: Reset: Fallback to preloaded image\n");
		rc = 0;
	}
	if (!rc) {
		/* Send a single success response for all chips */
		stat = fsp_mkmsg(FSP_CMD_RESET_OCC_STAT, 2, 0, seq_id);
		if (stat)
			rc = fsp_queue_msg(stat, fsp_freemsg);
		if (rc) {
			fsp_freemsg(stat);
			log_simple_error(&e_info(OPAL_RC_OCC_RESET),
				"OCC: Error %d queueing FSP OCC RESET"
					" STATUS message\n", rc);
		}
		occ_msg_queue_occ_reset();
	} else {

		/*
		 * Then send a matching OCC Reset Status message with an 0xFE
		 * (fail) response code as well to the first matching chip
		 */
		for_each_chip(chip) {
			if (scope == 0x01 && dbob_id != chip->dbob_id)
				continue;
			rc = -ENOMEM;
			stat = fsp_mkmsg(FSP_CMD_RESET_OCC_STAT, 2,
					 0xfe00 | (chip->pcid & 0xff), seq_id);
			if (stat)
				rc = fsp_queue_msg(stat, fsp_freemsg);
			if (rc) {
				fsp_freemsg(stat);
				log_simple_error(&e_info(OPAL_RC_OCC_RESET),
					"OCC: Error %d queueing FSP OCC RESET"
						" STATUS message\n", rc);
			}
			break;
		}
	}
}

#define PV_OCC_GP0		0x01000000
#define PV_OCC_GP0_AND		0x01000004
#define PV_OCC_GP0_OR		0x01000005
#define PV_OCC_GP0_PNOR_OWNER	PPC_BIT(18) /* 1 = OCC / Host, 0 = BMC */

static void occ_pnor_set_one_owner(uint32_t chip_id, enum pnor_owner owner)
{
	uint64_t reg, mask;

	if (owner == PNOR_OWNER_HOST) {
		reg = PV_OCC_GP0_OR;
		mask = PV_OCC_GP0_PNOR_OWNER;
	} else {
		reg = PV_OCC_GP0_AND;
		mask = ~PV_OCC_GP0_PNOR_OWNER;
	}

	xscom_write(chip_id, reg, mask);
}

void occ_pnor_set_owner(enum pnor_owner owner)
{
	struct proc_chip *chip;

	for_each_chip(chip)
		occ_pnor_set_one_owner(chip->id, owner);
}

static bool fsp_occ_msg(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	u32 dbob_id, seq_id;
	u8 scope;

	switch (cmd_sub_mod) {
	case FSP_CMD_LOAD_OCC:
		/*
		 * We get the "Load OCC" command at boot. We don't currently
		 * support loading it ourselves (we don't have the procedures,
		 * they will come with Host Services). For now HostBoot will
		 * have loaded a OCC firmware for us, but we still need to
		 * be nice and respond to OCC.
		 */
		scope = msg->data.bytes[3];
		dbob_id = msg->data.words[1];
		seq_id = msg->data.words[2];
		prlog(PR_INFO, "OCC: Got OCC Load message, scope=0x%x"
		      " dbob=0x%x seq=0x%x\n", scope, dbob_id, seq_id);
		occ_do_load(scope, dbob_id, seq_id);
		return true;

	case FSP_CMD_RESET_OCC:
		/*
		 * We shouldn't be getting this one, but if we do, we have
		 * to reply something sensible or the FSP will get upset
		 */
		scope = msg->data.bytes[3];
		dbob_id = msg->data.words[1];
		seq_id = msg->data.words[2];
		prlog(PR_INFO, "OCC: Got OCC Reset message, scope=0x%x"
		      " dbob=0x%x seq=0x%x\n", scope, dbob_id, seq_id);
		occ_do_reset(scope, dbob_id, seq_id);
		return true;
	}
	return false;
}

static struct fsp_client fsp_occ_client = {
	.message = fsp_occ_msg,
};

#define P8_OCB_OCI_OCCMISC		0x6a020
#define P8_OCB_OCI_OCCMISC_AND		0x6a021
#define P8_OCB_OCI_OCCMISC_OR		0x6a022

#define P9_OCB_OCI_OCCMISC		0x6c080
#define P9_OCB_OCI_OCCMISC_CLEAR	0x6c081
#define P9_OCB_OCI_OCCMISC_OR		0x6c082

#define OCB_OCI_OCIMISC_IRQ		PPC_BIT(0)
#define OCB_OCI_OCIMISC_IRQ_TMGT	PPC_BIT(1)
#define OCB_OCI_OCIMISC_IRQ_SLW_TMR	PPC_BIT(14)
#define OCB_OCI_OCIMISC_IRQ_OPAL_DUMMY	PPC_BIT(15)

#define P8_OCB_OCI_OCIMISC_MASK		(OCB_OCI_OCIMISC_IRQ_TMGT | \
					 OCB_OCI_OCIMISC_IRQ_OPAL_DUMMY | \
					 OCB_OCI_OCIMISC_IRQ_SLW_TMR)

#define OCB_OCI_OCIMISC_IRQ_I2C		PPC_BIT(2)
#define OCB_OCI_OCIMISC_IRQ_SHMEM	PPC_BIT(3)
#define P9_OCB_OCI_OCIMISC_MASK		(OCB_OCI_OCIMISC_IRQ_TMGT | \
					 OCB_OCI_OCIMISC_IRQ_I2C | \
					 OCB_OCI_OCIMISC_IRQ_SHMEM | \
					 OCB_OCI_OCIMISC_IRQ_OPAL_DUMMY)

void occ_send_dummy_interrupt(void)
{
	struct psi *psi;
	struct proc_chip *chip = get_chip(this_cpu()->chip_id);

	/* Emulators and P7 doesn't do this */
	if (proc_gen < proc_gen_p8 || chip_quirk(QUIRK_NO_OCC_IRQ))
		return;

	/* Find a functional PSI. This ensures an interrupt even if
	 * the psihb on the current chip is not configured */
	if (chip->psi)
		psi = chip->psi;
	else
		psi = psi_find_functional_chip();

	if (!psi) {
		prlog_once(PR_WARNING, "PSI: no functional PSI HB found, "
				       "no self interrupts delivered\n");
		return;
	}

	switch (proc_gen) {
	case proc_gen_p8:
		xscom_write(psi->chip_id, P8_OCB_OCI_OCCMISC_OR,
			    OCB_OCI_OCIMISC_IRQ |
			    OCB_OCI_OCIMISC_IRQ_OPAL_DUMMY);
		break;
	case proc_gen_p9:
		xscom_write(psi->chip_id, P9_OCB_OCI_OCCMISC_OR,
			    OCB_OCI_OCIMISC_IRQ |
			    OCB_OCI_OCIMISC_IRQ_OPAL_DUMMY);
		break;
	default:
		break;
	}
}

void occ_p8_interrupt(uint32_t chip_id)
{
	uint64_t ireg;
	int64_t rc;

	/* The OCC interrupt is used to mux up to 15 different sources */
	rc = xscom_read(chip_id, P8_OCB_OCI_OCCMISC, &ireg);
	if (rc) {
		prerror("OCC: Failed to read interrupt status !\n");
		/* Should we mask it in the XIVR ? */
		return;
	}
	prlog(PR_TRACE, "OCC: IRQ received: %04llx\n", ireg >> 48);

	/* Clear the bits */
	xscom_write(chip_id, P8_OCB_OCI_OCCMISC_AND, ~ireg);

	/* Dispatch */
	if (ireg & OCB_OCI_OCIMISC_IRQ_TMGT)
		prd_tmgt_interrupt(chip_id);
	if (ireg & OCB_OCI_OCIMISC_IRQ_SLW_TMR)
		check_timers(true);

	/* We may have masked-out OCB_OCI_OCIMISC_IRQ in the previous
	 * OCCMISC_AND write. Check if there are any new source bits set,
	 * and trigger another interrupt if so.
	 */
	rc = xscom_read(chip_id, P8_OCB_OCI_OCCMISC, &ireg);
	if (!rc && (ireg & P8_OCB_OCI_OCIMISC_MASK))
		xscom_write(chip_id, P8_OCB_OCI_OCCMISC_OR,
			    OCB_OCI_OCIMISC_IRQ);
}

void occ_p9_interrupt(uint32_t chip_id)
{
	u64 ireg;
	s64 rc;

	/* The OCC interrupt is used to mux up to 15 different sources */
	rc = xscom_read(chip_id, P9_OCB_OCI_OCCMISC, &ireg);
	if (rc) {
		prerror("OCC: Failed to read interrupt status !\n");
		return;
	}
	prlog(PR_TRACE, "OCC: IRQ received: %04llx\n", ireg >> 48);

	/* Clear the bits */
	xscom_write(chip_id, P9_OCB_OCI_OCCMISC_CLEAR, ireg);

	/* Dispatch */
	if (ireg & OCB_OCI_OCIMISC_IRQ_TMGT)
		prd_tmgt_interrupt(chip_id);

	if (ireg & OCB_OCI_OCIMISC_IRQ_SHMEM) {
		occ_throttle_poll(NULL);
		handle_occ_rsp(chip_id);
	}

	if (ireg & OCB_OCI_OCIMISC_IRQ_I2C)
		p9_i2c_bus_owner_change(chip_id);

	/* We may have masked-out OCB_OCI_OCIMISC_IRQ in the previous
	 * OCCMISC_AND write. Check if there are any new source bits set,
	 * and trigger another interrupt if so.
	 */
	rc = xscom_read(chip_id, P9_OCB_OCI_OCCMISC, &ireg);
	if (!rc && (ireg & P9_OCB_OCI_OCIMISC_MASK))
		xscom_write(chip_id, P9_OCB_OCI_OCCMISC_OR,
			    OCB_OCI_OCIMISC_IRQ);
}

void occ_fsp_init(void)
{
	/* OCC is  supported in P8 and P9 */
	if (proc_gen < proc_gen_p8)
		return;

	/* If we have an FSP, register for notifications */
	if (fsp_present())
		fsp_register_client(&fsp_occ_client, FSP_MCLASS_OCC);
}
