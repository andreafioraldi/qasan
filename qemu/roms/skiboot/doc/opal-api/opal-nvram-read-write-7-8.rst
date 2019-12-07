OPAL_READ_NVRAM
===============
::

   #define OPAL_READ_NVRAM                         7

``OPAL_READ_NVRAM`` call requests OPAL to read the data from system NVRAM
memory into a memory buffer. The data at ``offset`` from nvram_image
will be copied to memory ``buffer`` of size ``size``.

Parameters
----------
::

   uint64_t buffer
   uint64_t size
   uint64_t offset

``buffer``
   the data from nvram will be copied to ``buffer``

``size``
   the data of size ``size`` will be copied

``offset``
   the data will be copied from address equal to base ``nvram_image`` plus ``offset``

Return Values
-------------

``OPAL_SUCCESS``
  data from nvram to memory ``buffer`` copied successfully

``OPAL_PARAMETER``
  a parameter ``offset`` or ``size`` was incorrect

``OPAL_HARDWARE``
  either nvram is not initialized or permanent error related to nvram hardware.

OPAL_WRITE_NVRAM
================
::

   #define OPAL_WRITE_NVRAM                        8

``OPAL_WRITE_NVRAM`` call requests OPAL to write the data to actual system NVRAM memory
 from memory ``buffer`` at ``offset``, of size ``size``

Parameters
----------
::

   uint64_t buffer
   uint64_t size
   uint64_t offset

``buffer``
   data from ``buffer`` will be copied to nvram

``size``
   the data of size ``size`` will be copied

``offset``
   the data will be copied to address which is equal to base ``nvram_image`` plus ``offset``

Return Values
-------------

``OPAL_SUCCESS``
  data from memory ``buffer`` to actual nvram_image copied successfully

``OPAL_PARAMETER``
  a parameter ``offset`` or ``size`` was incorrect

``OPAL_HARDWARE``
  either nvram is not initialized or permanent error related to nvram hardware.
