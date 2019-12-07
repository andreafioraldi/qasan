.. _imc:

OPAL/Skiboot In-Memory Collection (IMC) interface Documentation
===============================================================

Overview:
---------

In-Memory-Collection (IMC) is performance monitoring infrastrcuture
for counters that (once started) can be read from memory at any time by
an operating system. Such counters include those for the Nest and Core
units, enabling continuous monitoring of resource utilisation on the chip.

The API is agnostic as to how these counters are implemented. For the
Nest units, they're implemented by having microcode in an on-chip
microcontroller and for core units, they are implemented as part of core logic
to gather data and periodically write it to the memory locations.

Nest (On-Chip, Off-Core) unit:
------------------------------

Nest units have dedicated hardware counters which can be programmed
to monitor various chip resources such as memory bandwidth,
xlink bandwidth, alink bandwidth, PCI, NVlink and so on. These Nest
unit PMU counters can be programmed in-band via scom. But alternatively,
programming of these counters and periodically moving the counter data
to memory are offloaded to a hardware engine part of OCC (On-Chip Controller).

Microcode, starts to run at system boot in OCC complex, initialize these
Nest unit PMUs and periodically accumulate the nest pmu counter values
to memory. List of supported events by the microcode is packages as a DTS
and stored in IMA_CATALOG partition.

Core unit:
----------

Core IMC PMU counters are handled in the core-imc unit. Each core has
4 Core Performance Monitoring Counters (CPMCs) which are used by Core-IMC logic.
Two of these are dedicated to count core cycles and instructions.
The 2 remaining CPMCs have to multiplex 128 events each.

Core IMC hardware does not support interrupts and it peridocially (based on
sampling duration) fetches the counter data and accumulate to main memory.
Memory to accumulate counter data are refered from "PDBAR" (per-core scom)
and "LDBAR" per-thread spr.

OPAL APIs:
----------

The OPAL API is simple: a call to init a counter type, and calls to
start and stop collection. The memory locations are described in the
device tree.

See :ref:`opal-imc-counters` and :ref:`device-tree/imc`
