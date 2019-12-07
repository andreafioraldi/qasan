.. _device-tree/imc:

===========================
IMC Device Tree Bindings
===========================

See :ref:`imc` for general In-Memory Collection (IMC) counter information.

imc-counters top-level node
----------------------------
.. code-block:: dts

      imc-counters {
        compatible = "ibm,opal-in-memory-counters";
        #address-cells = <0x1>;
        #size-cells = <0x1>;
        phandle = <0x1000023a>;
        version-id = <0xd>;
	/* Denote IMC Events Catalog version used to build this DTS file. */

      };

IMC device/units bindings
-------------------------

.. code-block:: dts

        mcs3 {
                compatible = "ibm,imc-counters";
                events-prefix = "PM_MCS3_"; /* denotes event name to be prefixed to get complete event name supported by this device */

                phandle = <0x10000241>;
                events = <0x10000242>; /* phandle of the events node supported by this device */

                unit = "MiB";
                scale = "4"; /* unit and scale for all the events for this device */

                reg = <0x118 0x8>; /* denotes base address for device event updates */
                type = <0x10>;
                size = 0x40000;
                offset = 0x180000;
                base_addr = <Base address of the counter in reserve memory>
                /* This is per-chip memory field and OPAL files it based on the no of chip in the system */
                /* base_addr property also indicates (or hints) kernel whether to memory */
                /* should be mmapped or allocated at system start for the counters */
                chipids = <chip-id for the base_addr >
        };


IMC device event bindings
-------------------------

.. code-block:: dts

        nest-mcs-events {
                #address-cells = <0x1>;
                #size-cells = <0x1>;
                phandle = <0x10000242>;

                event@98 {
                      desc = "Total Write Bandwidth seen on both MCS"; /* event description */

                      phandle = <0x1000023d>;
                      reg = <0x98 0x8>; /* event offset,when added with (nest-offset-address + device reg) will point to actual counter memory */

                      event-name = "DOWN_128B_DATA_XFER"; /* denotes the actual event name */

                };

		/* List of events supported */

        };
