#ifndef __QASAN_H__
#define __QASAN_H__

#include <stdio.h>

#ifdef DEBUG
#define QASAN_LOG(msg...) fprintf(stderr, "[QASAN] " msg) 
#else
#define QASAN_LOG(msg...) do {} while (0)
#endif

#define QASAN_HYPER_NR 0xa2a11

enum {
  QASAN_HYPER_MALLOC_USABLE_SIZE,
  QASAN_HYPER_MALLOC,
  QASAN_HYPER_CALLOC,
  QASAN_HYPER_REALLOC,
  QASAN_HYPER_FREE,
  QASAN_HYPER_MEMALIGN,
  QASAN_HYPER_MEMCPY,
  QASAN_HYPER_MEMSET,
};

#endif
