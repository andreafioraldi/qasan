.. _device-tree/ibm,secureboot:

ibm,secureboot
==============

Secure boot and trusted boot relies on a code stored in the secure ROM at
manufacture time to verify and measure other codes before they are executed.
This ROM code is also referred to as ROM verification code.

On POWER8, the presence of the ROM code is announced to skiboot (by Hostboot)
by the ``ibm,secureboot`` device tree node.

If the system is booting up in secure mode, the ROM code is called for secure
boot to verify the integrity and authenticity of an image before it is executed.

If the system is booting up in trusted mode, the ROM code is called for trusted
boot to calculate the SHA512 hash of an image only if the image is not a secure boot
container or the system is not booting up in secure mode.

For further information about secure boot and trusted boot please refer to
:ref:`stb-overview`.


Required properties
-------------------

.. code-block:: none

    compatible:         ibm,secureboot version. It is related to the ROM code version.
                
    hash-algo:          hash algorithm used for the hw-key-hash. Aspects such as the size
                        of the hw-key-hash can be infered from this property.

    secure-enabled:     this property exists if the system is booting in secure mode.

    trusted-enabled:    this property exists if the system is booting in trusted mode.

    hw-key-hash:        hash of three concatenated hardware public key. This is required
                        by the ROM code to verify images.

Example
-------

For the first version ``ibm,secureboot-v1``, the ROM code expects the *hw-key-hash*
to be a SHA512 hash.

.. code-block:: dts

    ibm,secureboot {
        compatible = "ibm,secureboot-v1";
        hash-algo = "sha512";
        secure-enabled;
        trusted-enabled;
        hw-key-hash = <0x40d487ff 0x7380ed6a 0xd54775d5 0x795fea0d 0xe2f541fe
                       0xa9db06b8 0x466a42a3 0x20e65f75 0xb4866546 0x17d907
                       0x515dc2a5 0xf9fc5095 0x4d6ee0c9 0xb67d219d 0xfb708535
                       0x1d01d6d1>;
        phandle = <0x100000fd>;
        linux,phandle = <0x100000fd>;
    };
