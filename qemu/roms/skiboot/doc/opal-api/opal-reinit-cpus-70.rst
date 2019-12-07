OPAL_REINIT_CPUS
================
::

   static int64_t opal_reinit_cpus(uint64_t flags);

This OPAL call reinitializes some bit of CPU state across *ALL* CPUs.
Consequently, all CPUs must be in OPAL for this call to succeed (either
at boot time or after OPAL_RETURN_CPU is called)

Arguments
---------
Currently, possible flags are: ::

  enum {
	OPAL_REINIT_CPUS_HILE_BE	= (1 << 0),
	OPAL_REINIT_CPUS_HILE_LE	= (1 << 1),
	OPAL_REINIT_CPUS_MMU_HASH	= (1 << 2),
	OPAL_REINIT_CPUS_MMU_RADIX	= (1 << 3),
	OPAL_REINIT_CPUS_TM_SUSPEND_DISABLED = (1 << 4),
  };

Extra flags may be added in the future, so other bits *must* be 0.

On POWER7 CPUs, only OPAL_REINIT_CPUS_HILE_BE is supported. All other
flags will return OPAL_UNSUPPORTED.

On POWER8 CPUs, only OPAL_REINIT_CPUS_HILE_BE and OPAL_REINIT_CPUS_HILE_LE
are support and other bits *MUST NOT* be set.

On POWER9 CPUs, all options including OPAL_REINIT_CPUS_MMU_HASH and
OPAL_REINIT_CPUS_MMU_RADIX.

OPAL_REINIT_CPUS_TM_SUSPEND_DISABLED
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This flag requests that CPUs be configured with TM (Transactional Memory)
suspend mode disabled. This may only be supported on some CPU versions.


Returns
-------

``OPAL_SUCCESS``
  Success!

``OPAL_UNSUPPORTED``
  Processor does not suport reinit flags.
