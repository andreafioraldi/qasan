#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define DEBUG
#include "qasan.h"

#include <signal.h>
#include <ucontext.h>

int __qasan_debug;

void print_maps(void) {

  int fd = open("/proc/self/maps", O_RDONLY);
  char buf[4096] = {0};
  
  read(fd, buf, 4095);
  close(fd);

  size_t len = strlen(buf);

  QASAN_LOG("Process maps:\n");
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
  QASAN_LOG("Caught %s\n\tPC = %p\n\tADDR = %p\n", strex, pc, siginfo->si_addr);
  
  _exit(86);

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

void *memcpy(void *dest, const void *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%14p: memcpy(%p, %p, %ld)\n", rtv, dest, src, n);
  void * r = (void*)syscall(QASAN_FAKESYS_NR, QASAN_ACTION_MEMCPY, dest, src, n);
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


