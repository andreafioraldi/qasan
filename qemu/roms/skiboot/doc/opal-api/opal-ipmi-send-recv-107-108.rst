OPAL_IPMI_SEND
==============
::

   #define OPAL_IPMI_SEND                          107

``OPAL_IPMI_SEND`` call will send an IPMI message to the service processor.

Parameters
----------
::

   uint64_t interface
   struct opal_ipmi_msg *opal_ipmi_msg
   uint64_t msg_len

``interface``
   ``interface`` parameter is the value from the ipmi interface node ``ibm,ipmi-interface-id``

``opal_ipmi_msg``
   ``opal_ipmi_msg`` is the pointer to below structure ``opal_ipmi_msg``

::

   struct opal_ipmi_msg {
        uint8_t version;
        uint8_t netfn;
        uint8_t cmd;
        uint8_t data[];
   };

``msg_len``
   ipmi message request size

Return Values
-------------

``OPAL_SUCCESS``
  ``msg`` queued successfully

``OPAL_PARAMETER``
  invalid ipmi message request length ``msg_len``

``OPAL_HARDWARE``
  backend support is not present as block transfer/service processor ipmi routines are not
  initialized which are used for communication

``OPAL_UNSUPPORTED``
  in-correct opal ipmi message format version ``opal_ipmi_msg->version``

``OPAL_RESOURCE``
  insufficient resources to create ``ipmi_msg`` structure

OPAL_IPMI_RECV
==============
::

   #define OPAL_IPMI_RECV                          108

``OPAL_IPMI_RECV`` call reads an ipmi message of type ``ipmi_msg`` from ipmi message
queue ``msgq`` into host OS structure ``opal_ipmi_msg``.

Parameters
----------
::

   uint64_t interface
   struct opal_ipmi_msg *opal_ipmi_msg
   uint64_t *msg_len

``interface``
   ``interface`` parameter is the value from the ipmi interface node ``ibm,ipmi-interface-id``

``opal_ipmi_msg``
   ``opal_ipmi_msg`` is the pointer to below structure ``opal_ipmi_msg``

::

   struct opal_ipmi_msg {
        uint8_t version;
        uint8_t netfn;
        uint8_t cmd;
        uint8_t data[];
   };

``msg_len``
   ``msg_len`` is the pointer to ipmi message response size

Return Values
-------------

``OPAL_SUCCESS``
  ipmi message dequeued from ``msgq`` queue and memory taken by it got released successfully

``OPAL_EMPTY``
  ``msgq`` list is empty

``OPAL_PARAMETER``
  invalid ipmi ``interface`` value

``OPAL_UNSUPPORTED``
  in-correct opal ipmi message format version ``opal_ipmi_msg->version``
