/*
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
*/

#include "libqasan.h"
#include <errno.h>
#include <assert.h>

#define REDZONE_SIZE 32

// TODO quarantine

struct chunk_begin {
  void* fd; // do not overlap these ptmalloc ptrs
  void* bk;
  size_t requested_size;
  char redzone[REDZONE_SIZE];
};

struct chunk_struct {

  struct chunk_begin begin;
  char redzone[REDZONE_SIZE];
  size_t prev_size_padding;

};

size_t (*__lq_libc_malloc_usable_size)(void *);
void * (*__lq_libc_malloc)(size_t);
void (*__lq_libc_free)(void *);

int __libqasan_malloc_initialized;
int __tmp_alloc_zone_idx;
unsigned char __tmp_alloc_zone[2048];


void __libqasan_init_malloc(void) {

  __lq_libc_malloc = dlsym(RTLD_NEXT, "malloc");
  __lq_libc_malloc_usable_size = dlsym(RTLD_NEXT, "malloc_usable_size");
  __lq_libc_free = dlsym(RTLD_NEXT, "free");

  assert(__lq_libc_malloc_usable_size && __lq_libc_malloc && __lq_libc_free);
  
  __libqasan_malloc_initialized = 1;
  QASAN_LOG("\n");
  QASAN_LOG("Allocator initialization done.\n");
  QASAN_LOG("\n");

}

size_t __libqasan_malloc_usable_size(void * ptr) {

  // if (!__libqasan_malloc_initialized) __libqasan_init_malloc();
  
  char* p = ptr;
  p -= sizeof(struct chunk_begin);
  
  // return __lq_libc_malloc_usable_size(p) - sizeof(struct chunk_struct);
  return ((struct chunk_begin*)p)->requested_size;

}

void * __libqasan_malloc(size_t size) {

  if (!__libqasan_malloc_initialized) {
  
    void* r = &__tmp_alloc_zone[__tmp_alloc_zone_idx];
    __tmp_alloc_zone_idx += size;
    return r;

  }

  struct chunk_begin* p = __lq_libc_malloc(sizeof(struct chunk_struct) +size);
  if (!p) return NULL;
  
  p->requested_size = size;
  
  QASAN_UNPOISON(&p[1], size);
  QASAN_ALLOC(&p[1], (char*)&p[1] + size);
  QASAN_POISON(p->redzone, REDZONE_SIZE, ASAN_HEAP_LEFT_RZ);
  QASAN_POISON((char*)&p[1] + size, (size & ~7) +8 - size + REDZONE_SIZE, ASAN_HEAP_RIGHT_RZ);
  
  __builtin_memset(&p[1], 0xff, size);
  
  return &p[1]; 

}

void __libqasan_free(void * ptr) {

  if (!__libqasan_malloc_initialized) return;
  
  if (!ptr) return;

  char* p = ptr;
  p -= sizeof(struct chunk_begin);
  
  size_t n = ((struct chunk_begin*)p)->requested_size;

  QASAN_STORE(ptr, n);

  __lq_libc_free(p);
  
  if (n & -7)
    n = (n & -7) +8;
  
  QASAN_POISON(ptr, n, ASAN_HEAP_FREED);
  QASAN_DEALLOC(ptr);

}

void * __libqasan_calloc(size_t nmemb, size_t size) {

  size *= nmemb;
  char* p = __libqasan_malloc(size);
  if (!p) return NULL;
  
  __builtin_memset(p, 0, size);

  return p;

}

void * __libqasan_realloc(void* ptr, size_t size) {

  char* p = __libqasan_malloc(size);
  if (!p) return NULL;
  
  if (!ptr) return p;
  
  size_t n = ((struct chunk_begin*)p)[-1].requested_size;
  if (size < n) n = size;

  __builtin_memcpy(p, ptr, n);
  
  __libqasan_free(ptr);
  return p;

}

int __libqasan_posix_memalign(void** ptr, size_t align, size_t len) {

  if ((align % 2) || (align % sizeof(void*)))
    return EINVAL;
  if (len == 0) {

    *ptr = NULL;
    return 0;

  }

  size_t rem = len % align;
  if (rem) len += align - rem;

  *ptr = __libqasan_malloc(len);

  return 0;

}

void* __libqasan_memalign(size_t align, size_t len) {

  void* ret = NULL;

  posix_memalign(&ret, align, len);

  return ret;

}

void* __libqasan_aligned_alloc(size_t align, size_t len) {

  void* ret = NULL;

  if ((len % align)) return NULL;

  posix_memalign(&ret, align, len);

  return ret;

}

