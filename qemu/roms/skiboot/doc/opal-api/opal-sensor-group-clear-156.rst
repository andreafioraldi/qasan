.. _opal-sensor-groups-clear:

OPAL_SENSOR_GROUP_CLEAR
==============================
OPAL call to clear the sensor groups data using a handle to identify
the type of sensor group which is exported via DT.

The call can be asynchronus, where the token parameter is used to wait
for the completion.

Parameters
----------
::
        u32 handle
        int token

Returns
-------
OPAL_SUCCESS
  Success

OPAL_UNSUPPORTED
  No support for clearing the sensor group

OPAL_HARDWARE
  Unable to procced due to the current hardware state

OPAL_PERMISSION
  Hardware cannot take the request

OPAL_ASYNC_COMPLETION
  Request was sent and an async completion message will be sent with
  token and status of the request.

OPAL_BUSY
  Previous request in progress

OPAL_INTERNAL_ERROR
  Error in request response

OPAL_TIMEOUT
  Timeout in request completion
