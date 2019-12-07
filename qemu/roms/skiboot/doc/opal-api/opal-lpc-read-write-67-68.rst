OPAL_LPC_READ
=============
::

  This function related to Low Pin Count (LPC) bus. This function reads the
  data from IDSEL register for ``chip_id``, which has LPC information.
  From ``addr`` for ``addr_type`` with read size ``sz`` bytes in to a
  variable named ``data``.

Parameters
----------

``chip_id``
  The ``chip_id`` parameter contains value of the chip number identified at
  boot time.

``addr_type``
  The ``addr_type`` is one of the LPC supported address types.
  Supported address types are -
  LPC memory,
  LPC IO and
  LPC firmware.

``addr``
  The ``addr`` from which the data has to be read.

``data``
  The ``data`` will be used to store the read data.

``sz``
   How many ``sz`` bytes to be read in to ``data``.

Return Codes
------------

``OPAL_PARAMETER``
   Indicates either ``chip_id`` not found or ``chip_id`` doesn’t contain
   LPC information.

``OPAL_SUCCESS``
  Indicates Success!

OPAL_LPC_WRITE
==============
::

  This function related to Low Pin Count (LPC) bus. This function writes the
  ``data`` in to  ECCB register for ``chip_id``, which has LPC information.
  From ``addr`` for ``addr_type`` with write size ``sz`` bytes.

Parameters
----------

``chip_id``
  The ``chip_id`` parameter contains value of the chip number identified at
  boot time.

``addr_type``
  The ``addr_type`` is one of the address types LPC supported.
  Supported address types are -
  LPC memory,
  LPC IO and
  LPC firmware.

``addr``
  The ``addr`` to where the ``data`` need to be written.

``data``
  The ``data`` for writing.

``sz``
   How many ``sz`` bytes to write.

Return Codes
------------

``OPAL_PARAMETER``
   Indicates either ``chip_id`` not found or ``chip_id`` doesn’t contain LPC
   information.

``OPAL_SUCCESS``
  Indicates Success!
