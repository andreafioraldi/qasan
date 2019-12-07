.. _stb-overview:

================================
Secure and Trusted Boot Overview
================================

Just as a quick reference::

  Secure boot:  verify and enforce.
  Trusted boot: measure and record.

Secure boot seeks to protect system integrity from execution of malicious
code during boot. The authenticity and integrity of every code is verified
by its predecessor code before it is executed. If the verification fails, the
boot process is aborted.

Trusted boot does not perform enforcement. Instead it creates artifacts during
system boot to prove that a particular chain of events have happened during
boot. Interested parties can subsequently assess the artifacts to check whether
or not only trusted events happened and then make security decisions. These
artifacts comprise a log of measurements and the digests extended into the TPM PCRs.
Platform Configuration Registers (PCRs) are registers in the Trusted Platform
Module (TPM) that are shielded from direct access by the CPU.

Trusted boot measures and maintains in an Event Log a record of all boot
events that may affect the security state of the platform. A measurement is
calculated by hashing the data of a given event. When a new measurement is
added to the Event Log, the same measurement is also sent to the TPM, which
performs an extend operation to incrementally update the existing digest stored
in a PCR.

PCR extend is an operation that uses a hash function to combine a new
measurement with the existing digest saved in the PCR. Basically, it
concatenates the existing PCR value with the received measurement, and then
stores the hash of this string in the PCR.

The TPM may maintain multiple banks of PCRs, where a PCR bank is a collection of
PCRs that are extended with the same hash algorithm. TPM 2.0 has a SHA1 bank
and a SHA256 bank with 24 PCRs each.

When the system boot is complete, each non-zero PCR value represents one or more
events measured during the boot in chronological order. Interested parties
can make inferences about the system's state by using an attestation tool to
remotely compare the PCR values of a TPM against known good values, and also
identify unexpected events by replaying the Event Log against known good Event
Log entries.


Implementation in skiboot
-------------------------

Libstb implements an API for secure and trusted boot, which is used to verify
and measure images retrieved from PNOR. The libstb interface is documented
in ``libstb/stb.h``

The example below shows how libstb can be used to add secure and trusted
boot support for a platform:

::

    stb_init();
        start_preload_resource(RESOURCE_ID_CAPP, 0, capp_ucode_info.lid, &capp_ucode_info.size);
            sb_verify(id, buf, len);
            tb_measure(id, buf, len);
        start_preload_resource(RESOURCE_ID_KERNEL, 0, KERNEL_LOAD_BASE, &kernel_size);
            sb_verify(id, buf, len);
            tb_measure(id, buf, len);
    stb_final();

First, ``stb_init()`` must be called to initialize libstb. Basically, it reads both
secure mode and trusted mode flags and loads drivers accordingly. In P8, secure
mode and trusted mode are read from the *ibm,secureboot* device tree node (see
:ref:`device-tree/ibm,secureboot`).

If either secure mode or trusted mode is on, ``stb_init()`` loads a driver (romcode
driver) to access the verification and SHA512 functions provided by the code
stored in the secure ROM at manufacture time. Both secure boot and trusted boot
depends on the romcode driver to access the ROM code. If trusted mode is on,
``stb_init()`` loads a TPM device driver compatible with the tpm device tree node
and also initializes the existing event log in skiboot. For device tree bindings
for the TPM, see :ref:`device-tree/tpm`.

Once libstb is initialized in the platform, ``sb_verify()`` and ``tb_measure()`` can
used as shown in the example above to respectively verify and measure images
retrieved from PNOR. If a platform claims secure and trusted boot support, then
``sb_verify()`` and ``tb_measure()`` is called for all images retrieved from PNOR. 

``sb_verify()`` and ``tb_measure()`` do nothing if libstb is not initialized in the
platform since both secure mode and trusted mode are off by default.

Finally, ``stb_final()`` must be called when no more images need to be retrieved
from PNOR in order to indicate that secure boot and trusted boot have completed
in skiboot. When stb_final() is called, basically it records eight *EV_SEPARATOR*
events in the event log (one for each PCR through 0 to 7) and extends the PCR
through 0 to 7 of both SHA1 and SHA256 PCR banks with the digest of *0xFFFFFFFF*.
Additionally, ``stb_final()`` also frees resources allocated for secure boot and
trusted boot.


Verifying an image
~~~~~~~~~~~~~~~~~~

If secure mode is on, ``sb_verify()`` verifies the integrity and authenticity of an
image by calling the ``ROM_verify()`` function from the ROM code via romcode driver. In
general terms, this verification will pass only if the following conditions are
satisfied. Otherwise the boot process is aborted.

1. Secure boot header is properly built and attached to the image.  When
   ``sb_verify()`` is called, the ROM code verifies all the secure boot header
   fields, including the keys, hashes and signatures.  The secure boot header
   and the image are also collectively referred to as secure boot container, or
   just container. As the secure boot header is the container header and the
   image is the container payload.

2. The public hardware keys of the container header match with the hw-key-hash
   read from the device tree. The way that secure boot is designed, this
   assertion ensures that only images signed by the owner of the hw-key-hash
   will pass the verification.  The hw-key-hash is a hash of three hardware
   public keys stored in *SEEPROM* at manufacture time and written to the device
   tree at boot time.


Measuring an image
~~~~~~~~~~~~~~~~~~

``tb_measure()`` measures an image retrieved from PNOR if trusted mode is on, but
only if the provided image is included in the *resource_map* whitelist. This
whitelist defines for each expected image to what PCR the measurement must be
recorded and extended. ``tb_measure()`` returns an error if the provided image is
not included in the *resource_map* whitelist.

For the sake of simplicity we say that ``tb_measure()`` measures an image, but
calculating the digest of a given image is just one of the steps performed by
``tb_measure()``.

Steps performed by ``tb_measure()`` if trusted mode is on:

1. Measure the provided image for each PCR bank: SHA1 and SHA256. If secure
   mode is on and the image is a container, parse the container header to get
   the SHA512 hash of the container payload (*sw-payload-hash* field). Otherwise,
   call the ROM code via romcode driver to calculate the SHA512 hash of the
   image at boot time. In both cases, the SHA512 hash is truncated to match the
   size required by each PCR bank: SHA1 bank PCRs are 20 bytes and SHA256 bank
   PCRs are 32 bytes.

2. Record a new event in the event log for the mapped PCR. Call the tpmLogMgr
   API to generate a new event and record it in the event log. The new event is
   generated for the mapped PCR and it also contains a digest list with both
   SHA1 and SHA256 measurements obtained in step 1.

3. Extend the measurements into the mapped PCR. Call the TCG Software Stack
   (TSS) API to extend both measurements obtained in step 1 into the mapped PCR
   number. The SHA1 measurement is extended to the SHA1 PCR bank and the SHA256
   measurement is extended to the SHA256 PCR bank. However, they are extended
   to the same PCR number on each bank.
   Since this TSS implementation supports multibank, it does the marshalling of
   both SHA1 and SHA256 measurements into a single TPM extend command and then
   it sends the command to the TPM device via TPM device driver.

Both TSS and tpmLogMgr APIs are implemented by hostboot, but their source code
are added to skiboot. The TSS and tpmLogMgr interfaces are defined in
``libstb/tss/trustedbootCmds.H`` and ``libstb/tss/tpmLogMgr.H``, respectively.
