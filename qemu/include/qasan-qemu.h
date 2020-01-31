#ifndef __QASAN_QEMU_H__
#define __QASAN_QEMU_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <malloc.h>
#include "../../include/qasan.h"
#include "tcg.h"

#define HEAP_PAD 16

#define SHADOW_BK_SIZE (4096*8)

struct shadow_stack_block {

  int index;
  target_ulong buf[SHADOW_BK_SIZE];
  
  struct shadow_stack_block* next;

};

struct shadow_stack {

  int size;
  struct shadow_stack_block* first;

};

extern __thread struct shadow_stack qasan_shadow_stack;

#ifdef ASAN_GIOVESE

#define ASAN_NAME_STR "QEMU-AddressSanitizer"
#include "../../asan-giovese/asan-giovese.h"

#if defined(TARGET_X86_64) || defined(TARGET_I386)

#define GET_PC(env) ((env)->eip)
#define GET_BP(env) ((env)->regs[R_EBP])
#define GET_SP(env) ((env)->regs[R_ESP])

#else
#error "Target not supported by asan-giovese"
#endif

#else

void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);

void __asan_load1(void*);
void __asan_load2(void*);
void __asan_load4(void*);
void __asan_load8(void*);
void __asan_store1(void*);
void __asan_store2(void*);
void __asan_store4(void*);
void __asan_store8(void*);
void __asan_loadN(void*, size_t);
void __asan_storeN(void*, size_t);

#endif

extern __thread int cur_block_is_good;

target_long qasan_actions_dispatcher(void *cpu_env, target_long action,
                                     target_long arg1, target_long arg2,
                                     target_long arg3);

void qasan_gen_load1(TCGv ptr, int off);
void qasan_gen_load2(TCGv ptr, int off);
void qasan_gen_load4(TCGv ptr, int off);
void qasan_gen_load8(TCGv ptr, int off);
void qasan_gen_store1(TCGv ptr, int off);
void qasan_gen_store2(TCGv ptr, int off);
void qasan_gen_store4(TCGv ptr, int off);
void qasan_gen_store8(TCGv ptr, int off);

#endif
