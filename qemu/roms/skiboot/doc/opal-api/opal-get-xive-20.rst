OPAL_GET_XIVE
=============
::

   #define OPAL_GET_XIVE				20

The host calls this function to return the configuration of an
interrupt source. See OPAL_SET_XIVE for details.

Parameters
----------

``isn``
  The ``isn`` is the global interrupt number being queried

``server_number``
  the ``server_number`` returns the mangled server (processor)
  that is set to receive that interrupt.

``priority``
  the ``priority`` returns the current interrupt priority setting
  for that interrupt.

