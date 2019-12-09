#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

#define DEBUG
#include "qasan.h"

#include <signal.h>
#include <ucontext.h>

#ifdef DEBUG
void print_maps(void) {

  FILE *f = fopen("/proc/self/maps", "rb");
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *string = malloc(fsize +1);
  fread(string, 1, fsize, f);
  fclose(f);

  string[fsize] = 0;
  
  fprintf(stderr, "%s\n", string);

}

void posix_signal_handler(int sig, siginfo_t *siginfo, void *context) {

  ucontext_t *ctx = (ucontext_t *)context;
  printf("PC = %p \n", ctx->uc_mcontext.gregs[REG_RIP]);
  printf("ADDR = %p \n", siginfo->si_addr);

  switch(sig)
  {
    case SIGSEGV:
      fputs("Caught SIGSEGV: Segmentation Fault\n", stderr);
      break;
    case SIGINT:
      fputs("Caught SIGINT: Interactive attention signal, (usually ctrl+c)\n", stderr);
      break;
    case SIGFPE:
      switch(siginfo->si_code)
      {
        case FPE_INTDIV:
          fputs("Caught SIGFPE: (integer divide by zero)\n", stderr);
          break;
        case FPE_INTOVF:
          fputs("Caught SIGFPE: (integer overflow)\n", stderr);
          break;
        case FPE_FLTDIV:
          fputs("Caught SIGFPE: (floating-point divide by zero)\n", stderr);
          break;
        case FPE_FLTOVF:
          fputs("Caught SIGFPE: (floating-point overflow)\n", stderr);
          break;
        case FPE_FLTUND:
          fputs("Caught SIGFPE: (floating-point underflow)\n", stderr);
          break;
        case FPE_FLTRES:
          fputs("Caught SIGFPE: (floating-point inexact result)\n", stderr);
          break;
        case FPE_FLTINV:
          fputs("Caught SIGFPE: (floating-point invalid operation)\n", stderr);
          break;
        case FPE_FLTSUB:
          fputs("Caught SIGFPE: (subscript out of range)\n", stderr);
          break;
        default:
          fputs("Caught SIGFPE: Arithmetic Exception\n", stderr);
          break;
      }
    case SIGILL:
      switch(siginfo->si_code)
      {
        case ILL_ILLOPC:
          fputs("Caught SIGILL: (illegal opcode)\n", stderr);
          break;
        case ILL_ILLOPN:
          fputs("Caught SIGILL: (illegal operand)\n", stderr);
          break;
        case ILL_ILLADR:
          fputs("Caught SIGILL: (illegal addressing mode)\n", stderr);
          break;
        case ILL_ILLTRP:
          fputs("Caught SIGILL: (illegal trap)\n", stderr);
          break;
        case ILL_PRVOPC:
          fputs("Caught SIGILL: (privileged opcode)\n", stderr);
          break;
        case ILL_PRVREG:
          fputs("Caught SIGILL: (privileged register)\n", stderr);
          break;
        case ILL_COPROC:
          fputs("Caught SIGILL: (coprocessor error)\n", stderr);
          break;
        case ILL_BADSTK:
          fputs("Caught SIGILL: (internal stack error)\n", stderr);
          break;
        default:
          fputs("Caught SIGILL: Illegal Instruction\n", stderr);
          break;
      }
      break;
    case SIGTERM:
      fputs("Caught SIGTERM: a termination request was sent to the program\n", stderr);
      break;
    case SIGABRT:
      fputs("Caught SIGABRT: usually caused by an abort() or assert()\n", stderr);
      break;
    default:
      break;
  }
  
  exit(1);
}

__attribute__((constructor)) void set_signal_handler()
{
  //print_maps();
  /* register our signal handlers */
  {
    struct sigaction sig_action = {};
    sig_action.sa_sigaction = posix_signal_handler;
    sigemptyset(&sig_action.sa_mask);

    sig_action.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSEGV, &sig_action, NULL) != 0) { err(1, "sigaction"); }
    if (sigaction(SIGFPE,  &sig_action, NULL) != 0) { err(1, "sigaction"); }
    if (sigaction(SIGINT,  &sig_action, NULL) != 0) { err(1, "sigaction"); }
    if (sigaction(SIGILL,  &sig_action, NULL) != 0) { err(1, "sigaction"); }
    if (sigaction(SIGTERM, &sig_action, NULL) != 0) { err(1, "sigaction"); }
    if (sigaction(SIGABRT, &sig_action, NULL) != 0) { err(1, "sigaction"); }
  }
}
#endif

size_t malloc_usable_size (void * ptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%p:\tmalloc_usable_size(%p)\n", rtv, ptr);
  size_t r = syscall(QASAN_HYPER_NR, QASAN_HYPER_MALLOC_USABLE_SIZE, ptr);
  QASAN_LOG("\t\t = %ld\n", r);

  return r;

}

void * malloc(size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%p:\tmalloc(%ld)\n", rtv, size);
  void * r = (void*)syscall(QASAN_HYPER_NR, QASAN_HYPER_MALLOC, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void * calloc(size_t nmemb, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%p:\tcalloc(%ld, %ld)\n", rtv, nmemb, size);
  void * r = (void*)syscall(QASAN_HYPER_NR, QASAN_HYPER_CALLOC, nmemb, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void *realloc(void *ptr, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%p:\trealloc(%p, %ld)\n", rtv, ptr, size);
  void * r = (void*)syscall(QASAN_HYPER_NR, QASAN_HYPER_REALLOC, ptr, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void free(void * ptr) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%p:\tfree(%p)\n", rtv, ptr);
  syscall(QASAN_HYPER_NR, QASAN_HYPER_FREE, ptr);

}

void *memalign(size_t alignment, size_t size) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%p:\tmemalign(%ld, %ld)\n", rtv, alignment, size);
  void * r = (void*)syscall(QASAN_HYPER_NR, QASAN_HYPER_MEMALIGN, alignment, size);
  QASAN_LOG("\t\t = %p\n", r);

  return r;

}

void *memcpy(void *dest, const void *src, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%p:\tmemcpy(%p, %p, %ld)\n", rtv, dest, src, n);
  syscall(QASAN_HYPER_NR, QASAN_HYPER_MEMCPY, dest, src, n);

}

void *memset(void *s, int c, size_t n) {

  void * rtv = __builtin_return_address(0);

  QASAN_LOG("%p:\tmemcpy(%p, %d, %ld)\n", rtv, s, c, n);
  syscall(QASAN_HYPER_NR, QASAN_HYPER_MEMSET, s, c, n);

}

