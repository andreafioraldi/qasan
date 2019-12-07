OPAL API Return Codes
=====================

All OPAL calls return an integer relaying the success/failure of the OPAL
call.

Success is typically indicated by OPAL_SUCCESS. Failure is always indicated
by a negative return code.

Conforming host Operating Systems MUST handle return codes other than those
listed here. In future OPAL versions, additional return codes may be added.

In the reference implementation (skiboot) these are all in include/opal.h.


The core set of return codes are:

OPAL_SUCCESS
------------
::

 #define OPAL_SUCCESS		0

Success!

OPAL_PARAMETER
--------------
::

 #define OPAL_PARAMETER		-1

A parameter was invalid. This will also be returned if you call an
invalid OPAL call. To determine if a specific OPAL call is supported
or not, OPAL_CHECK_TOKEN should be called rather than relying on
OPAL_PARAMETER being returned for an invalid token.

OPAL_BUSY
---------
::

   #define OPAL_BUSY		-2

Try again later. Related to `OPAL_BUSY_EVENT`, but `OPAL_BUSY` indicates that the
caller need not call `OPAL_POLL_EVENTS` itself. **TODO** Clarify current situation.

OPAL_PARTIAL
------------
::

   #define OPAL_PARTIAL		-3

The operation partially succeeded.

OPAL_CONSTRAINED
----------------
::

   #define OPAL_CONSTRAINED	-4

**FIXME**

OPAL_CLOSED
-----------
::

   #define OPAL_CLOSED		-5

**FIXME** document these

OPAL_HARDWARE
-------------
::

   #define OPAL_HARDWARE		-6

**FIXME** document these

OPAL_UNSUPPORTED
----------------
::

   #define OPAL_UNSUPPORTED	-7

Unsupported operation. Non-fatal.

OPAL_PERMISSION
---------------
::

   #define OPAL_PERMISSION		-8

Inadequate permission to perform the operation.

OPAL_NO_MEM
-----------
::

   #define OPAL_NO_MEM		-9

Indicates a temporary or permanent lack of adequate memory to perform the
operation. Ideally, this should never happen. Skiboot reserves a small amount
of memory for its heap and some operations (such as I2C requests) are allocated
from this heap.

If this is ever hit, you should likely file a bug.


OPAL_RESOURCE
-------------
::

   #define OPAL_RESOURCE		-10

**FIXME**

OPAL_INTERNAL_ERROR
-------------------
::

   #define OPAL_INTERNAL_ERROR	-11

**FIXME**

OPAL_BUSY_EVENT
---------------
::

   #define OPAL_BUSY_EVENT		-12

The same as `OPAL_BUSY` but signals that the OS should call `OPAL_POLL_EVENTS` as
that may be required to get into a state where the call will succeed.

OPAL_HARDWARE_FROZEN
--------------------
::

   #define OPAL_HARDWARE_FROZEN	-13

OPAL_WRONG_STATE
----------------
::

   #define OPAL_WRONG_STATE	-14

OPAL_ASYNC_COMPLETION
---------------------
::

   #define OPAL_ASYNC_COMPLETION	-15

For asynchronous calls, successfully queueing/starting executing the
command is indicated by the OPAL_ASYNC_COMPLETION return code.
pseudo-code for an async call: ::

  token = opal_async_get_token();
  rc = opal_async_example(foo, token);
  if (rc != OPAL_ASYNC_COMPLETION)
      handle_error(rc);
  rc = opal_async_wait(token);
  // handle result here

OPAL_EMPTY
----------
::

   #define OPAL_EMPTY		-16

I2C Calls
---------
Added for I2C, only applicable to I2C calls: ::

  #define OPAL_I2C_TIMEOUT	-17
  #define OPAL_I2C_INVALID_CMD	-18
  #define OPAL_I2C_LBUS_PARITY	-19
  #define OPAL_I2C_BKEND_OVERRUN	-20
  #define OPAL_I2C_BKEND_ACCESS	-21
  #define OPAL_I2C_ARBT_LOST	-22
  #define OPAL_I2C_NACK_RCVD	-23
  #define OPAL_I2C_STOP_ERR	-24


