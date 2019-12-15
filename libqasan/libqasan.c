#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <inttypes.h>

#define DEBUG
#include "qasan.h"

#define CHECK_LOAD(ptr, len) syscall(QASAN_FAKESYS_NR, QASAN_ACTION_CHECK_LOAD, ptr, len)
#define CHECK_STORE(ptr, len) syscall(QASAN_FAKESYS_NR, QASAN_ACTION_CHECK_STORE, ptr, len)

int __qasan_debug;

void print_maps(void) {

  int fd = open("/proc/self/maps", O_RDONLY);
  char buf[4096] = {0};
  
  read(fd, buf, 4095);
  close(fd);

  size_t len = strlen(buf);

  QASAN_LOG("\n");
  QASAN_LOG("Guest process maps:\n");
  int i;
  char * line = NULL;
  for (i = 0; i < len; i++) {
    if (!line) line = &buf[i];
    if (buf[i] == '\n') {
      buf[i] = 0;
      QASAN_LOG("%s\n", line);
      line = NULL;
    }
  }
  if (line) QASAN_LOG("%s\n", line);
  QASAN_LOG("\n");

}

void posix_signal_handler(int sig, siginfo_t *siginfo, void *context) {

  char * strex = NULL;
  switch(sig) {
    case SIGSEGV:
      strex = "SIGSEGV";
      break;
    case SIGINT:
      strex = "SIGINT";
      break;
    case SIGFPE:
      strex = "SIGFPE";
      break;
    case SIGILL:
      strex = "SIGILL";
      break;
    case SIGTERM:
      strex = "SIGTERM";
      break;
    case SIGABRT:
      strex = "SIGABRT";
      break;
    default:
      strex = "<unknown>";
      break;
  }
  
  ucontext_t *ctx = (ucontext_t *)context;
  void * pc;
#ifdef __x86_64__
  pc = (void*)ctx->uc_mcontext.gregs[REG_RIP];
#else
  pc = (void*)ctx->uc_mcontext.gregs[REG_EIP];
#endif
  QASAN_LOG("\n");
  QASAN_LOG("Caught %s: pc=%p addr=%p\n", strex, pc, siginfo->si_addr);
  QASAN_LOG("\n");

  _exit(siginfo->si_status);

}

__attribute__((constructor)) void __libqasan_init() {

  __qasan_debug = getenv("QASAN_DEBUG") != NULL;

  QASAN_LOG("QEMU-AddressSanitizer (v%s)\n", QASAN_VERSTR);
  QASAN_LOG("Copyright (C) 2019 Andrea Fioraldi <andreafioraldi@gmail.com>\n");
  QASAN_LOG("\n");

  if (__qasan_debug) {

    print_maps();

    struct sigaction sig_action = {};
    sig_action.sa_sigaction = posix_signal_handler;
    sigemptyset(&sig_action.sa_mask);

    sig_action.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &sig_action, NULL);
    sigaction(SIGFPE,  &sig_action, NULL);
    sigaction(SIGINT,  &sig_action, NULL);
    sigaction(SIGILL,  &sig_action, NULL);
    sigaction(SIGTERM, &sig_action, NULL);
    sigaction(SIGABRT, &sig_action, NULL);
  
  }

}


size_t malloc_usable_size (void * ptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: malloc_usable_size(%p)\n", rtv, ptr);
  size_t r = syscall(QASAN_FAKESYS_NR, QASAN_ACTION_MALLOC_USABLE_SIZE, ptr);
  QASAN_LOG("\t\t = %ld\n", r);

  return r;

}

void * malloc(size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: malloc(%ld)\n", rtv, size);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_MALLOC, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void * calloc(size_t nmemb, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: calloc(%ld, %ld)\n", rtv, nmemb, size);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_CALLOC, nmemb, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void *realloc(void *ptr, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: realloc(%p, %ld)\n", rtv, ptr, size);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_REALLOC, ptr, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

int posix_memalign(void **memptr, size_t alignment, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: posix_memalign(%p, %ld, %ld)\n", rtv, memptr, alignment, size);
  int r = syscall(QASAN_FAKESYS_NR, QASAN_ACTION_POSIX_MEMALIGN, memptr, alignment, size);
  QASAN_LOG("\t\t = %d [*memptr = %p]\n", r, *memptr);

  return r;

}

void *memalign(size_t alignment, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memalign(%ld, %ld)\n", rtv, alignment, size);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_MEMALIGN, alignment, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void *aligned_alloc(size_t alignment, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: aligned_alloc(%ld, %ld)\n", rtv, alignment, size);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_ALIGNED_ALLOC, alignment, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void * valloc(size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: valloc(%ld)\n", rtv, size);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_VALLOC, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void * pvalloc(size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: pvalloc(%ld)\n", rtv, size);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_PVALLOC, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void free(void * ptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: free(%p)\n", rtv, ptr);
  syscall(QASAN_FAKESYS_NR, QASAN_ACTION_FREE, ptr);

}


int memcmp(const void *s1, const void *s2, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memcmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  int r = syscall(QASAN_FAKESYS_NR, QASAN_ACTION_MEMCMP, s1, s2, n);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

void *memcpy(void *dest, const void *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memcpy(%p, %p, %ld)\n", rtv, dest, src, n);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_MEMCPY, dest, src, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

/* For a strange reason memmove is broken so we provide this homemode version */
void * __homemade_asan_memmove(void *dest, const void *src, size_t n) {

   char *csrc = (char *)src; 
   char *cdest = (char *)dest;
   
   CHECK_LOAD(src, n);
   CHECK_STORE(dest, n);
  
   char *temp = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_MALLOC, n); 
  
   for (int i=0; i<n; i++) 
       temp[i] = csrc[i];
  
   for (int i=0; i<n; i++) 
       cdest[i] = temp[i];
  
   syscall(QASAN_FAKESYS_NR, QASAN_ACTION_FREE, temp);
   
   return dest;

}

void *memmove(void *dest, const void *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memmove(%p, %p, %ld)\n", rtv, dest, src, n);
  void * r = __homemade_asan_memmove(dest, src, n);
  //void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_MEMMOVE, dest, src, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

void *memset(void *s, int c, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memcpy(%p, %d, %ld)\n", rtv, s, c, n);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_MEMSET, s, c, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

char *strchr(const char *s, int c) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strchr(%p, %d)\n", rtv, s, c);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRCHR, s, c);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

int strcasecmp(const char *s1, const char *s2) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcasecmp(%p, %p)\n", rtv, s1, s2);
  int r = syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRCASECMP, s1, s2);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

char *strcat(char *dest, const char *src) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcat(%p, %p)\n", rtv, dest, src);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRCAT, dest, src);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

int strcmp(const char *s1, const char *s2) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcmp(%p, %p)\n", rtv, s1, s2);
  int r = syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRCMP, s1, s2);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

char *strcpy(char *dest, const char *src) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strcpy(%p, %p)\n", rtv, dest, src);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRCPY, dest, src);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

char *strdup(const char *s) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strdup(%p)\n", rtv, s);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRDUP, s);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

size_t strlen(const char *s) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strlen(%p)\n", rtv, s);
  size_t r = syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRLEN, s);
  QASAN_LOG("\t\t = %ld\n", r);
  
  return r;

}

int strncasecmp(const char *s1, const char *s2, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strncasecmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  int r = syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRNCASECMP, s1, s2, n);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

int strncmp(const char *s1, const char *s2, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strncmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  int r = syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRNCMP, s1, s2, n);
  QASAN_LOG("\t\t = %d\n", r);
  
  return r;

}

char *strncpy(char *dest, const char *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strncpy(%p, %p, %ld)\n", rtv, dest, src, n);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRNCPY, dest, src, n);
  QASAN_LOG("\t\t = %p\n", r);
  
  return r;

}

size_t strnlen(const char *s, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: strnlen(%p, %ld)\n", rtv, s, n);
  size_t r = syscall(QASAN_FAKESYS_NR, QASAN_ACTION_STRNLEN, s, n);
  QASAN_LOG("\t\t = %ld\n", r);
  
  return r;

}
