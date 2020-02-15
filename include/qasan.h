/*******************************************************************************
Copyright (c) 2019-2020, Andrea Fioraldi


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#ifndef __QASAN_H__
#define __QASAN_H__

#include <stdio.h>
#include <unistd.h>

#define QASAN_VERSTR "0.1"

#ifdef DEBUG
#define QASAN_LOG(msg...) do { \
  if (__qasan_debug) { \
    fprintf(stderr, "==%d== ", getpid()); \
    fprintf(stderr, msg); \
  } \
} while (0)
#else
#define QASAN_LOG(msg...) do {} while (0)
#endif

#define QASAN_FAKEINSTR_X86 { 0x0f, 0x3a, 0xf2 }

#define QASAN_FAKESYS_NR 0xa2a4

enum {
  QASAN_ACTION_CHECK_LOAD,
  QASAN_ACTION_CHECK_STORE,
  QASAN_ACTION_POISON,
  QASAN_ACTION_USER_POISON,
  QASAN_ACTION_UNPOISON,
  QASAN_ACTION_ALLOC,
  QASAN_ACTION_DEALLOC,
  QASAN_ACTION_ENABLE,
  QASAN_ACTION_DISABLE,
  QASAN_ACTION_SWAP_STATE,
};

extern int __qasan_debug;

/* shadow map byte values */
#define ASAN_VALID 0x00
#define ASAN_PARTIAL1 0x01
#define ASAN_PARTIAL2 0x02
#define ASAN_PARTIAL3 0x03
#define ASAN_PARTIAL4 0x04
#define ASAN_PARTIAL5 0x05
#define ASAN_PARTIAL6 0x06
#define ASAN_PARTIAL7 0x07
#define ASAN_ARRAY_COOKIE 0xac
#define ASAN_STACK_RZ 0xf0
#define ASAN_STACK_LEFT_RZ 0xf1
#define ASAN_STACK_MID_RZ 0xf2
#define ASAN_STACK_RIGHT_RZ 0xf3
#define ASAN_STACK_FREED 0xf5
#define ASAN_STACK_OOSCOPE 0xf8
#define ASAN_GLOBAL_RZ 0xf9
#define ASAN_HEAP_RZ 0xe9
#define ASAN_USER 0xf7
#define ASAN_HEAP_LEFT_RZ 0xfa
#define ASAN_HEAP_RIGHT_RZ 0xfb
#define ASAN_HEAP_FREED 0xfd

#endif
