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

#ifndef __LIBQASAN_H__
#define __LIBQASAN_H__

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <inttypes.h>
#include <dlfcn.h>

#include "qasan.h"

#define QASAN_ENABLED (0)
#define QASAN_DISABLED (1)

#define QASAN_LOG(msg...) do { \
  if (__qasan_log) { \
    fprintf(stderr, "==%d== ", getpid()); \
    fprintf(stderr, msg); \
  } \
} while (0)

#if __x86_64__

// The backdoor is more performant than the fake syscall
#define QASAN_CALL0(action) \
({ \
  uintptr_t __libqasan__ret__; \
  asm volatile ( \
    "movq %1, %%rax\n" \
    ".byte 0x0f\n" \
    ".byte 0x3a\n" \
    ".byte 0xf2\n" \
    "movq %%rax, %0\n" \
    : "=g"(__libqasan__ret__) \
    : "g"((uintptr_t)(action)) \
    : "%rax", "memory" \
  ); \
  __libqasan__ret__; \
})

#define QASAN_CALL1(action, arg1) \
({ \
  uintptr_t __libqasan__ret__; \
  asm volatile ( \
    "movq %1, %%rax\n" \
    "movq %2, %%rdi\n" \
    ".byte 0x0f\n" \
    ".byte 0x3a\n" \
    ".byte 0xf2\n" \
    "movq %%rax, %0\n" \
    : "=g"(__libqasan__ret__) \
    : "g"((uintptr_t)(action)), "g"((uintptr_t)(arg1)) \
    : "%rax", "%rdi", "memory" \
  ); \
  __libqasan__ret__; \
})

#define QASAN_CALL2(action, arg1, arg2) \
({ \
  uintptr_t __libqasan__ret__; \
  asm volatile ( \
    "movq %1, %%rax\n" \
    "movq %2, %%rdi\n" \
    "movq %3, %%rsi\n" \
    ".byte 0x0f\n" \
    ".byte 0x3a\n" \
    ".byte 0xf2\n" \
    "movq %%rax, %0\n" \
    : "=g"(__libqasan__ret__) \
    : "g"((uintptr_t)(action)), "g"((uintptr_t)(arg1)), "g"((uintptr_t)(arg2)) \
    : "%rax", "%rdi", "%rsi", "memory" \
  ); \
  __libqasan__ret__; \
})

#define QASAN_CALL3(action, arg1, arg2, arg3) \
({ \
  uintptr_t __libqasan__ret__; \
  asm volatile ( \
    "movq %1, %%rax\n" \
    "movq %2, %%rdi\n" \
    "movq %3, %%rsi\n" \
    "movq %4, %%rdx\n" \
    ".byte 0x0f\n" \
    ".byte 0x3a\n" \
    ".byte 0xf2\n" \
    "movq %%rax, %0\n" \
    : "=g"(__libqasan__ret__) \
    : "g"((uintptr_t)(action)), "g"((uintptr_t)(arg1)), "g"((uintptr_t)(arg2)), "g"((uintptr_t)(arg3)) \
    : "%rax", "%rdi", "%rsi", "%rdx", "memory" \
  ); \
  __libqasan__ret__; \
})

#elif __i386__

// The backdoor is more performant than the fake syscall
#define QASAN_CALL0(action) \
({ \
  uintptr_t __libqasan__ret__; \
  asm volatile ( \
    "movl %1, %%eax\n" \
    ".byte 0x0f\n" \
    ".byte 0x3a\n" \
    ".byte 0xf2\n" \
    "movl %%eax, %0\n" \
    : "=g"(__libqasan__ret__) \
    : "g"((uintptr_t)(action)) \
    : "%eax", "memory" \
  ); \
  __libqasan__ret__; \
})

#define QASAN_CALL1(action, arg1) \
({ \
  uintptr_t __libqasan__ret__; \
  asm volatile ( \
    "movl %1, %%eax\n" \
    "movl %2, %%edi\n" \
    ".byte 0x0f\n" \
    ".byte 0x3a\n" \
    ".byte 0xf2\n" \
    "movl %%eax, %0\n" \
    : "=g"(__libqasan__ret__) \
    : "g"((uintptr_t)(action)), "g"((uintptr_t)(arg1)) \
    : "%eax", "%edi", "memory" \
  ); \
  __libqasan__ret__; \
})

#define QASAN_CALL2(action, arg1, arg2) \
({ \
  uintptr_t __libqasan__ret__; \
  asm volatile ( \
    "movl %1, %%eax\n" \
    "movl %2, %%edi\n" \
    "movl %3, %%esi\n" \
    ".byte 0x0f\n" \
    ".byte 0x3a\n" \
    ".byte 0xf2\n" \
    "movl %%eax, %0\n" \
    : "=g"(__libqasan__ret__) \
    : "g"((uintptr_t)(action)), "g"((uintptr_t)(arg1)), "g"((uintptr_t)(arg2)) \
    : "%eax", "%edi", "%esi", "memory" \
  ); \
  __libqasan__ret__; \
})

#define QASAN_CALL3(action, arg1, arg2, arg3) \
({ \
  uintptr_t __libqasan__ret__; \
  asm volatile ( \
    "movl %1, %%eax\n" \
    "movl %2, %%edi\n" \
    "movl %3, %%esi\n" \
    "movl %4, %%edx\n" \
    ".byte 0x0f\n" \
    ".byte 0x3a\n" \
    ".byte 0xf2\n" \
    "movl %%eax, %0\n" \
    : "=g"(__libqasan__ret__) \
    : "g"((uintptr_t)(action)), "g"((uintptr_t)(arg1)), "g"((uintptr_t)(arg2)), "g"((uintptr_t)(arg3)) \
    : "%eax", "%edi", "%esi", "%edx", "memory" \
  ); \
  __libqasan__ret__; \
})


#else

#define QASAN_CALL0(action) \
  syscall(QASAN_FAKESYS_NR, action, NULL, NULL, NULL)
#define QASAN_CALL1(action, arg1) \
  syscall(QASAN_FAKESYS_NR, action, arg1, NULL, NULL)
#define QASAN_CALL2(action, arg1, arg2) \
  syscall(QASAN_FAKESYS_NR, action, arg1, arg2, NULL)
#define QASAN_CALL3(action, arg1, arg2, arg3) \
  syscall(QASAN_FAKESYS_NR, action, arg1, arg2, arg3)

#endif

#define QASAN_LOAD(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_CHECK_LOAD, ptr, len)
#define QASAN_STORE(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_CHECK_STORE, ptr, len)

#define QASAN_POISON(ptr, len, poison_byte) \
  QASAN_CALL3(QASAN_ACTION_POISON, ptr, len, poison_byte)
#define QASAN_UNPOISON(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_UNPOISON, ptr, len)

#define QASAN_ALLOC(start, end) \
  QASAN_CALL2(QASAN_ACTION_ALLOC, start, end)
#define QASAN_DEALLOC(ptr) \
  QASAN_CALL1(QASAN_ACTION_DEALLOC, ptr)

#define QASAN_SWAP(state) \
  QASAN_CALL1(QASAN_ACTION_SWAP_STATE, state)

#define ASSERT_DLSYM(name) \
({ \
  void* a = (void*)dlsym(RTLD_NEXT, # name); \
  if (!a) { \
    fprintf(stderr, "FATAL ERROR: failed dlsym of " # name " in libqasan!\n"); \
    abort(); \
  } \
  a; \
})

extern int __qasan_log;

void __libqasan_init_hooks(void);
void __libqasan_init_malloc(void);

void __libqasan_hotpatch(void);

size_t __libqasan_malloc_usable_size(void * ptr);
void*  __libqasan_malloc(size_t size);
void   __libqasan_free(void * ptr);
void*  __libqasan_calloc(size_t nmemb, size_t size);
void*  __libqasan_realloc(void* ptr, size_t size);
int    __libqasan_posix_memalign(void** ptr, size_t align, size_t len);
void*  __libqasan_memalign(size_t align, size_t len);
void*  __libqasan_aligned_alloc(size_t align, size_t len);

void *__libqasan_memcpy(void *dest, const void *src, size_t n);
void *__libqasan_memmove(void *dest, const void *src, size_t n);
void *__libqasan_memset(void *s, int c, size_t n);
void *__libqasan_memchr(const void *s, int c, size_t n);
void *__libqasan_memrchr(const void *s, int c, size_t n);
size_t __libqasan_strlen(const char* s);
size_t __libqasan_strnlen(const char* s, size_t len);
int __libqasan_strcmp(const char* str1, const char* str2);
int __libqasan_strncmp(const char* str1, const char* str2, size_t len);
int __libqasan_strcasecmp(const char* str1, const char* str2);
int __libqasan_strncasecmp(const char* str1, const char* str2, size_t len);
int __libqasan_memcmp(const void* mem1, const void* mem2, size_t len);
int __libqasan_bcmp(const void* mem1, const void* mem2, size_t len);
char* __libqasan_strstr(const char* haystack, const char* needle);
char* __libqasan_strcasestr(const char* haystack, const char* needle);
void* __libqasan_memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len);
char *__libqasan_strchr(const char *s, int c);
char *__libqasan_strrchr(const char *s, int c);

#endif
