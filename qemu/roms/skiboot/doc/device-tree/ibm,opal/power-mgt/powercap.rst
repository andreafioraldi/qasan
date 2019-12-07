power-mgt/powercap
------------------

The powercap sensors are populated in this node. Each child node in
the "powercap" node represents a power-cappable component.

For example : ::

        system-powercap/

The OPAL_GET_POWERCAP and OPAL_SET_POWERCAP calls take a handle for
what powercap property to get/set which is defined in the child node.

The compatible property for the linux driver which will be
"ibm,opal-powercap"

Each child node has below properties:

`powercap-current`
  Handle to indicate the current powercap

`powercap-min`
  Minimum possible powercap

`powercap-max`
  Maximum possible powercap

Powercap handle uses the following encoding: ::

        | Class |    Reserved   | Attribute |
        |-------|---------------|-----------|

Note: The format of the powercap handle is ``NOT`` ABI and may change in
the future.

.. code-block:: dts

   power-mgt {
     powercap {
        compatible = "ibm,opal-powercap";

        system-powercap {
                name = "system-powercap";
                powercap-current = <0x00000002>;
                powercap-min = <0x00000000>;
                powercap-max = <0x00000001>;
        };
     };
    };
