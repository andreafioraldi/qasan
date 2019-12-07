.. _opal-psr:

OPAL_GET_POWER_SHIFT_RATIO
==============================
OPAL call to read the power-shifting-ratio using a handle to identify
the type (e.g CPU vs. GPU, CPU vs. MEM) which is exported via
device-tree.

The call can be asynchronus, where the token parameter is used to wait
for the completion.

Parameters
----------

=== =======
=== =======
u32 handle
int token
u32 \*ratio
=== =======

Returns
-------
OPAL_SUCCESS
  Success

OPAL_PARAMETER
  Invalid ratio pointer

OPAL_UNSUPPORTED
  No support for reading psr

OPAL_HARDWARE
  Unable to procced due to the current hardware state

OPAL_ASYNC_COMPLETION
  Request was sent and an async completion message will be sent with
  token and status of the request.

OPAL_SET_POWER_SHIFT_RATIO
==============================
OPAL call to set power-shifting-ratio using a handle to identify
the type of PSR which is exported in device-tree. This call can be
asynchronus where the token parameter is used to wait for the
completion.

Parameters
----------
::
        u32 handle
        int token
        u32 ratio

Returns
-------
OPAL_SUCCESS
  Success

OPAL_PARAMETER
  Invalid ratio requested

OPAL_UNSUPPORTED
  No support for changing the ratio

OPAL_PERMISSION
  Hardware cannot take the request

OPAL_ASYNC_COMPLETION
  Request was sent and an async completion message will be sent with
  token and status of the request.

OPAL_HARDWARE
  Unable to procced due to the current hardware state

OPAL_BUSY
  Previous request in progress

OPAL_INTERNAL_ERROR
  Error in request response

OPAL_TIMEOUT
  Timeout in request completion
