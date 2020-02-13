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

#include "libqasan.h"
#include "map_macro.h"

char *(*__lq_libc_fgets)(char *, int, FILE *);
int (*__lq_libc_atoi)(const char *);
long (*__lq_libc_atol)(const char *);
long long (*__lq_libc_atoll)(const char *);

void __libqasan_init_hooks(void) {

  __libqasan_init_malloc();

  __lq_libc_fgets = ASSERT_DLSYM(fgets);
  __lq_libc_atoi = ASSERT_DLSYM(atoi);
  __lq_libc_atol = ASSERT_DLSYM(atol);
  __lq_libc_atoll = ASSERT_DLSYM(atoll);

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
  int r = __libqasan_memcmp(s1, s2, n);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

void *memcpy(void *dest, const void *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memcpy(%p, %p, %ld)\n", rtv, dest, src, n);
  QASAN_LOAD(src, n);
  QASAN_STORE(dest, n);
  void * r = __libqasan_memcpy(dest, src, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

void *memmove(void *dest, const void *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memmove(%p, %p, %ld)\n", rtv, dest, src, n);
  QASAN_LOAD(src, n);
  QASAN_STORE(dest, n);
  void * r = __libqasan_memmove(dest, src, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

void *memset(void *s, int c, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memset(%p, %d, %ld)\n", rtv, s, c, n);
  QASAN_STORE(s, n);
  void * r = __libqasan_memset(s, c, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memmem(%p, %ld, %p, %ld)\n", rtv, haystack, haystacklen, needle, needlelen);
  QASAN_LOAD(haystack, haystacklen);
  QASAN_LOAD(needle, needlelen);
  void * r = __libqasan_memmem(haystack, haystacklen, needle, needlelen);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

void bzero(void *s, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: bzero(%p, %ld)\n", rtv, s, n);
  QASAN_STORE(s, n);
  __libqasan_memset(s, 0, n);
  
}

void explicit_bzero(void *s, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: bzero(%p, %ld)\n", rtv, s, n);
  QASAN_STORE(s, n);
  __libqasan_memset(s, 0, n);
  
}

int bcmp(const void *s1, const void *s2, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: bcmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  QASAN_LOAD(s1, n);
  QASAN_LOAD(s2, n);
  int r = __libqasan_bcmp(s1, s2, n);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;
  
}

char *strchr(const char *s, int c) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strchr(%p, %d)\n", rtv, s, c);
  size_t l = __libqasan_strlen(s);
  QASAN_LOAD(s, l+1);
  void * r = __libqasan_strchr(s, c);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

char *strrchr(const char *s, int c) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strrchr(%p, %d)\n", rtv, s, c);
  size_t l = __libqasan_strlen(s);
  QASAN_LOAD(s, l+1);
  void * r = __libqasan_strrchr(s, c);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

int strcasecmp(const char *s1, const char *s2) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcasecmp(%p, %p)\n", rtv, s1, s2);
  size_t l1 = __libqasan_strlen(s1);
  QASAN_LOAD(s1, l1+1);
  size_t l2 = __libqasan_strlen(s2);
  QASAN_LOAD(s2, l2+1);
  int r = __libqasan_strcasecmp(s1, s2);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

int strncasecmp(const char *s1, const char *s2, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strncasecmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  size_t l1 = __libqasan_strnlen(s1, n);
  QASAN_LOAD(s1, l1);
  size_t l2 = __libqasan_strnlen(s2, n);
  QASAN_LOAD(s2, l2);
  int r = __libqasan_strncasecmp(s1, s2, n);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

char *strcat(char *dest, const char *src) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcat(%p, %p)\n", rtv, dest, src);
  size_t l2 = __libqasan_strlen(src);
  QASAN_LOAD(src, l2+1);
  size_t l1 = __libqasan_strlen(dest);
  QASAN_STORE(dest, l1+l2+1);
  __libqasan_memcpy(dest +l1, src, l2);
  dest[l1 + l2] = 0;
  void * r = dest;
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

int strcmp(const char *s1, const char *s2) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcmp(%p, %p)\n", rtv, s1, s2);
  size_t l1 = __libqasan_strlen(s1);
  QASAN_LOAD(s1, l1+1);
  size_t l2 = __libqasan_strlen(s2);
  QASAN_LOAD(s2, l2+1);
  int r = __libqasan_strcmp(s1, s2);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

int strncmp(const char *s1, const char *s2, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strncmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  size_t l1 = __libqasan_strnlen(s1, n);
  QASAN_LOAD(s1, l1);
  size_t l2 = __libqasan_strnlen(s2, n);
  QASAN_LOAD(s2, l2);
  int r = __libqasan_strncmp(s1, s2, n);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

char *strcpy(char *dest, const char *src) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcpy(%p, %p)\n", rtv, dest, src);
  size_t l = __libqasan_strlen(src) +1;
  QASAN_LOAD(src, l);
  QASAN_STORE(dest, l);
  void * r = __libqasan_memcpy(dest, src, l);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

char *strncpy(char *dest, const char *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strncpy(%p, %p, %ld)\n", rtv, dest, src, n);
  size_t l = __libqasan_strnlen(src, n);
  QASAN_STORE(dest, n);
  void * r;
  if (l < n) {
    QASAN_LOAD(src, l+1);
    r = __libqasan_memcpy(dest, src, l+1);
  } else {
    QASAN_LOAD(src, n);
    r = __libqasan_memcpy(dest, src, n);
  }
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

char *stpcpy(char *dest, const char *src) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: stpcpy(%p, %p)\n", rtv, dest, src);
  size_t l = __libqasan_strlen(src) +1;
  QASAN_LOAD(src, l);
  QASAN_STORE(dest, l);
  char * r = __libqasan_memcpy(dest, src, l) + (l-1);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;


}

char *strdup(const char *s) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strdup(%p)\n", rtv, s);
  size_t l = __libqasan_strlen(s);
  QASAN_LOAD(s, l+1);
  void * r = __libqasan_malloc(l +1);
  __libqasan_memcpy(r, s, l+1);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

size_t strlen(const char *s) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strlen(%p)\n", rtv, s);
  size_t r = __libqasan_strlen(s);
  QASAN_LOAD(s, r+1);
  QASAN_LOG("\t\t = %ld\n", r);
  
  return r;

}

size_t strnlen(const char *s, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strnlen(%p, %ld)\n", rtv, s, n);
  size_t r = __libqasan_strnlen(s, n);
  QASAN_LOAD(s, r);
  QASAN_LOG("\t\t = %ld\n", r);
  
  return r;

}

char* strstr(const char* haystack, const char* needle) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strstr(%p, %p)\n", rtv, haystack, needle);
  size_t l = __libqasan_strlen(haystack) +1;
  QASAN_LOAD(haystack, l);
  l = __libqasan_strlen(needle) +1;
  QASAN_LOAD(needle, l);
  void * r = __libqasan_strstr(haystack, needle);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

char* strcasestr(const char* haystack, const char* needle) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcasestr(%p, %p)\n", rtv, haystack, needle);
  size_t l = __libqasan_strlen(haystack) +1;
  QASAN_LOAD(haystack, l);
  l = __libqasan_strlen(needle) +1;
  QASAN_LOAD(needle, l);
  void * r = __libqasan_strcasestr(haystack, needle);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

int atoi(const char *nptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: atoi(%p)\n", rtv, nptr);
  size_t l = __libqasan_strlen(nptr);
  QASAN_LOAD(nptr, l);
  int r = __lq_libc_atoi(nptr);
  QASAN_LOG("\t\t = %d\n", r);

  return r;

}

long atol(const char *nptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: atol(%p)\n", rtv, nptr);
  size_t l = __libqasan_strlen(nptr);
  QASAN_LOAD(nptr, l);
  long r = __lq_libc_atol(nptr);
  QASAN_LOG("\t\t = %ld\n", r);

  return r;

}

long long atoll(const char *nptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: atoll(%p)\n", rtv, nptr);
  size_t l = __libqasan_strlen(nptr);
  QASAN_LOAD(nptr, l);
  long long r = __lq_libc_atoll(nptr);
  QASAN_LOG("\t\t = %lld\n", r);

  return r;

}

