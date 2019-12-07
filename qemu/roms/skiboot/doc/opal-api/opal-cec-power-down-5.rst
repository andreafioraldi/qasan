OPAL_CEC_POWER_DOWN
===================
::

   #define OPAL_CEC_POWER_DOWN			5

   int64 opal_cec_power_down(uint64 request)

Arguments
---------
::

   uint64 request values as follows:
    0 - Power down normally
    1 - Power down immediately

This OPAL call requests OPAL to power down the system. The exact difference
between a normal and immediate shutdown is platform specific.

Current Linux kernels just use power down normally (0). It is valid for a
platform to only support some types of power down operations.

Return Values
-------------

``OPAL_SUCCESS``
  the power down request was successful.
  This may/may not result in immediate power down. An OS should
  spin in a loop after getting `OPAL_SUCCESS` as it is likely that there
  will be a delay before instructions stop being executed.

``OPAL_BUSY``
  unable to power down, try again later.

``OPAL_BUSY_EVENT``
  Unable to power down, call `opal_run_pollers` and try again.

``OPAL_PARAMETER``
  a parameter was incorrect

``OPAL_INTERNAL_ERROR``
  Something went wrong, and waiting and trying again is unlikely to be
  successful. Although, considering that in a shutdown code path, there's
  unlikely to be any other valid option to take, retrying is perfectly valid.

  In older OPAL versions (prior to skiboot v5.9), on IBM FSP systems, this
  return code was returned erroneously instead of OPAL_BUSY_EVENT during an
  FSP Reset/Reload.

``OPAL_UNSUPPORTED``
  this platform does not support being powered off.
