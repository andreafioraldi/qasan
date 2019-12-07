ibm,opal/power-mgt/occ device tree entries
==========================================

This node exports the per-chip pstate table properties to kernel.

Example:

.. code-block:: dts

 occ@7ffddf8000 {
        ibm,pstate-vdds = [45 45 46 46 46 47 48 49 4a 4b 4c 4d 4f 50 51 52 53 54 55 57 58 59 5a 5b 5c 5d 5e 5f 5f 60 61 62 63 64 65 65 66 67 68 69 6a 6a 6b 6c 6d 6e 6f 70 70 71];
        ibm,chip-id = <0x1>;
        phandle = <0x100003b8>;
        ibm,pstate-vcss = [3b 3d 3f 41 42 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 50 51 52 53 54 55 56 56 57 57 58 58 59 59 5a 5a 5b 5b 5c 5c 5d 5d 5e 5e 5f 5f 60 60 61 61 62 62];
        reg = <0x7f 0xfddf8000 0xb98>;
 };

ibm,chip-id
-----------

This property denotes the ID of chip to which OCC belongs to.

reg
---

This tuple gives the statring address of the OPAL data in HOMER and
the size of the OPAL data.

The top-level /ibm,opal/power-mgt contains : ::

 #size-cells = <1>
 #address-cells = <2>

ibm,pstate-vcss ibm,pstate-vdds
-------------------------------

These properties list a voltage-identifier of each of the pstates listed in
ibm,pstate-ids for the Vcs and Vdd values used for that pstate in that chip.
Each VID is a single byte.
