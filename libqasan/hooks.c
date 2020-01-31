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

char *(*__lq_libc_fgets)(char *, int, FILE *);
int (*__lq_libc_memcmp)(const void *, const void *, size_t);
void *(*__lq_libc_memcpy)(void *, const void *, size_t);
void *(*__lq_libc_memmove)(void *, const void *, size_t);
void *(*__lq_libc_memset)(void *, int, size_t);

void __libqasan_init_hooks(void) {

  __libqasan_init_malloc();

  __lq_libc_fgets = (void*)dlsym(RTLD_NEXT, "fgets");
  __lq_libc_memcmp = (void*)dlsym(RTLD_NEXT, "memcmp");
  __lq_libc_memcpy = (void*)dlsym(RTLD_NEXT, "memcpy");
  __lq_libc_memmove = (void*)dlsym(RTLD_NEXT, "memmove");
  __lq_libc_memset = (void*)dlsym(RTLD_NEXT, "memset");

}

size_t malloc_usable_size (void * ptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: malloc_usable_size(%p)\n", rtv, ptr);
  size_t r = __libqasan_malloc_usable_size(ptr);
  QASAN_LOG("\t\t = %ld\n", r);

  return r;

}

void * malloc(size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: malloc(%ld)\n", rtv, size);
  void * r = __libqasan_malloc(size);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

void * calloc(size_t nmemb, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: calloc(%ld, %ld)\n", rtv, nmemb, size);
  void * r = __libqasan_calloc(nmemb, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void *realloc(void *ptr, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: realloc(%p, %ld)\n", rtv, ptr, size);
  void * r = __libqasan_realloc(ptr, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

int posix_memalign(void **memptr, size_t alignment, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: posix_memalign(%p, %ld, %ld)\n", rtv, memptr, alignment, size);
  int r = __libqasan_posix_memalign(memptr, alignment, size);
  QASAN_LOG("\t\t = %d [*memptr = %p]\n", r, *memptr);

  return r;

}

void *memalign(size_t alignment, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memalign(%ld, %ld)\n", rtv, alignment, size);
  void * r = __libqasan_memalign(alignment, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void *aligned_alloc(size_t alignment, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: aligned_alloc(%ld, %ld)\n", rtv, alignment, size);
  void * r = __libqasan_aligned_alloc(alignment, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void * valloc(size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: valloc(%ld)\n", rtv, size);
  void * r = __libqasan_memalign(sysconf(_SC_PAGESIZE), size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void * pvalloc(size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: pvalloc(%ld)\n", rtv, size);
  size_t page_size = sysconf(_SC_PAGESIZE);
  size = (size & (page_size -1)) + page_size;
  void * r = __libqasan_memalign(page_size, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void free(void * ptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: free(%p)\n", rtv, ptr);
  __libqasan_free(ptr);

}

char *fgets(char *s, int size, FILE *stream) {

 QASAN_STORE(s, size);
 QASAN_LOAD(stream, sizeof(FILE));
 return __lq_libc_fgets(s, size, stream);

}

int memcmp(const void *s1, const void *s2, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memcmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  QASAN_LOAD(s1, n);
  QASAN_LOAD(s2, n);
  int r = __lq_libc_memcmp(s1, s2, n);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

void *memcpy(void *dest, const void *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memcpy(%p, %p, %ld)\n", rtv, dest, src, n);
  QASAN_LOAD(src, n);
  QASAN_STORE(dest, n);
  void * r = __lq_libc_memcpy(dest, src, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

void *memmove(void *dest, const void *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memmove(%p, %p, %ld)\n", rtv, dest, src, n);
  QASAN_LOAD(src, n);
  QASAN_STORE(dest, n);
  void * r = __lq_libc_memmove(dest, src, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

void *memset(void *s, int c, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memcpy(%p, %d, %ld)\n", rtv, s, c, n);
  QASAN_STORE(s, n);
  void * r = __lq_libc_memset(s, c, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

/*

char *strchr(const char *s, int c) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strchr(%p, %d)\n", rtv, s, c);
  void * r = (void*)QASAN_CALL2(QASAN_ACTION_STRCHR, s, c);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

int strcasecmp(const char *s1, const char *s2) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcasecmp(%p, %p)\n", rtv, s1, s2);
  int r = QASAN_CALL2(QASAN_ACTION_STRCASECMP, s1, s2);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}*/
/*
char *strcat(char *dest, const char *src) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcat(%p, %p)\n", rtv, dest, src);
  void * r = (void*)QASAN_CALL2(QASAN_ACTION_STRCAT, dest, src);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}
*/
/*
int strcmp(const char *s1, const char *s2) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcmp(%p, %p)\n", rtv, s1, s2);
  int r = QASAN_CALL2(QASAN_ACTION_STRCMP, s1, s2);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

char *strcpy(char *dest, const char *src) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcpy(%p, %p)\n", rtv, dest, src);
  void * r = (void*)QASAN_CALL2(QASAN_ACTION_STRCPY, dest, src);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

char *strdup(const char *s) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strdup(%p)\n", rtv, s);
  void * r = (void*)QASAN_CALL1(QASAN_ACTION_STRDUP, s);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

size_t strlen(const char *s) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strlen(%p)\n", rtv, s);
  size_t r = QASAN_CALL1(QASAN_ACTION_STRLEN, s);
  QASAN_LOG("\t\t = %ld\n", r);
  
  return r;

}

int strncasecmp(const char *s1, const char *s2, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strncasecmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  int r = QASAN_CALL3(QASAN_ACTION_STRNCASECMP, s1, s2, n);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

int strncmp(const char *s1, const char *s2, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strncmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  int r = QASAN_CALL3(QASAN_ACTION_STRNCMP, s1, s2, n);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

char *strncat(char *dest, const char *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strncat(%p, %p, %ld)\n", rtv, dest, src, n);
  void * r = (void*)QASAN_CALL3(QASAN_ACTION_STRNCAT, dest, src, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

char *strncpy(char *dest, const char *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strncpy(%p, %p, %ld)\n", rtv, dest, src, n);
  void * r = (void*)QASAN_CALL3(QASAN_ACTION_STRNCPY, dest, src, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

size_t strnlen(const char *s, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strnlen(%p, %ld)\n", rtv, s, n);
  size_t r = QASAN_CALL2(QASAN_ACTION_STRNLEN, s, n);
  QASAN_LOG("\t\t = %ld\n", r);
  
  return r;

}

char *strrchr(const char *s, int c) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strrchr(%p, %d)\n", rtv, s, c);
  void * r = (void*)QASAN_CALL2(QASAN_ACTION_STRRCHR, s, c);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

int atoi(const char *nptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: atoi(%p)\n", rtv, nptr);
  int r = QASAN_CALL1(QASAN_ACTION_ATOI, nptr);
  QASAN_LOG("\t\t = %d\n", r);

  return r;

}

long atol(const char *nptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: atol(%p)\n", rtv, nptr);
  long r = QASAN_CALL1(QASAN_ACTION_ATOL, nptr);
  QASAN_LOG("\t\t = %ld\n", r);

  return r;

}

long long atoll(const char *nptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: atoll(%p)\n", rtv, nptr);
  long long r = QASAN_CALL1(QASAN_ACTION_ATOLL, nptr);
  QASAN_LOG("\t\t = %lld\n", r);

  return r;

}*/
