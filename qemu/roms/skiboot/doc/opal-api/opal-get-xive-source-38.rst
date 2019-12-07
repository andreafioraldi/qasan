OPAL_GET_XIVE_SOURCE
====================
::

  This function validates the given ``xive_num`` and sets the 
  ``interrupt_source_number``. Then returns the proper return code.

Parameters
----------

``phb_id``
  The ``phb_id`` parameter is the value from the PHB node ``ibm,opal-phbid``
  property.

``xive_num``
  The ``xive_num`` is the index of an XIVE that corresponds to a particular
  interrupt.

``interrupt_source_number``
  The ``interrupt_source_number`` is a value formed by the combination of the
  device tree MSI property base BUID and ``xive_num``

Return Codes
------------
``OPAL_PARAMETER``
  The indicated ``phb_id`` not found

``OPAL_UNSUPPORTED``
  Presence retrieval not supported on the ``phb_id``

``OPAL_SUCCESS``
  Indicates Success!
