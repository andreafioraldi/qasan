// Internal timer
//
// Copyright (C) 2008-2013  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_LOW
#include "config.h" // CONFIG_*
#include "output.h" // dprintf
#include "stacks.h" // yield
#include "util.h" // timer_setup
#include "x86.h" // cpuid
#include "parisc/pdc.h"

#define PAGE0 ((volatile struct zeropage *) 0UL)

#define NANOSECONDS_PER_SECOND 1000000000LL
#define SCALE_MS 1000000
#define SCALE_US 1000
#define SCALE_NS 1


// Setup internal timers.
void
timer_setup(void)
{
}

void
pmtimer_setup(u16 ioport)
{
}

u32 ticks_from_ms(u32 ms)
{
    return 0;
}


/****************************************************************
 * Internal timer reading
 ****************************************************************/

u32 TimerLast VARLOW;

// Sample the current timer value.
static u32
timer_read(void)
{
    return rdtscll();
}

// Check if the current time is past a previously calculated end time.
int
timer_check(u32 end)
{
    return (s32)(timer_read() - end) > 0;
}

static void
timer_sleep(u32 diff)
{
    u32 start = timer_read();
    u32 end = start + diff;
    while (!timer_check(end))
        yield();
}

void ndelay(u32 count) {
    timer_sleep((count * PAGE0->mem_10msec / 10) / 1000 / 1000);
}
void udelay(u32 count) {
    timer_sleep((count * PAGE0->mem_10msec / 10) / 1000);
}
void mdelay(u32 count) {
    timer_sleep((count * PAGE0->mem_10msec / 10));
}

void nsleep(u32 count) {
    ndelay(count);
}
void usleep(u32 count) {
    udelay(count);
}
void msleep(u32 count) {
    mdelay(count);
}

// Return the TSC value that is 'msecs' time in the future.
u32
timer_calc(u32 msecs)
{
    return (msecs * PAGE0->mem_10msec / 10) + timer_read();
}
u32
timer_calc_usec(u32 usecs)
{
    return ((usecs * PAGE0->mem_10msec / 10) / 1000) + timer_read();
}


void
pit_setup(void)
{
}
