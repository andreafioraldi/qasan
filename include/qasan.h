#ifndef __QASAN_H__
#define __QASAN_H__

#include <stdio.h>

#ifdef DEBUG
#define QASAN_LOG(msg...) fprintf(stderr, "[QASAN] " msg) 
#else
#define QASAN_LOG(msg...) do {} while (0)
#endif

#define ASAN_OFFSET 0x7FFF8000

#define QASAN_HYPER_NR 0xa2a11

#define QASAN_HYPER_MALLOC_USABLE_SIZE 0
#define QASAN_HYPER_MALLOC 1
#define QASAN_HYPER_CALLOC 2
#define QASAN_HYPER_REALLOC 3
#define QASAN_HYPER_FREE 4
#define QASAN_HYPER_MEMALIGN 5

#endif
