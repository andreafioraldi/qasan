/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "exec/tb-lookup.h"
#include "disas/disas.h"
#include "exec/log.h"

/* 32-bit helpers */

int32_t HELPER(div_i32)(int32_t arg1, int32_t arg2)
{
    return arg1 / arg2;
}

int32_t HELPER(rem_i32)(int32_t arg1, int32_t arg2)
{
    return arg1 % arg2;
}

uint32_t HELPER(divu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 / arg2;
}

uint32_t HELPER(remu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 % arg2;
}

/* 64-bit helpers */

uint64_t HELPER(shl_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 << arg2;
}

uint64_t HELPER(shr_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 >> arg2;
}

int64_t HELPER(sar_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 >> arg2;
}

int64_t HELPER(div_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 / arg2;
}

int64_t HELPER(rem_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 % arg2;
}

uint64_t HELPER(divu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 / arg2;
}

uint64_t HELPER(remu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 % arg2;
}

uint64_t HELPER(muluh_i64)(uint64_t arg1, uint64_t arg2)
{
    uint64_t l, h;
    mulu64(&l, &h, arg1, arg2);
    return h;
}

int64_t HELPER(mulsh_i64)(int64_t arg1, int64_t arg2)
{
    uint64_t l, h;
    muls64(&l, &h, arg1, arg2);
    return h;
}

uint32_t HELPER(clz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? clz32(arg) : zero_val;
}

uint32_t HELPER(ctz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? ctz32(arg) : zero_val;
}

uint64_t HELPER(clz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? clz64(arg) : zero_val;
}

uint64_t HELPER(ctz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? ctz64(arg) : zero_val;
}

uint32_t HELPER(clrsb_i32)(uint32_t arg)
{
    return clrsb32(arg);
}

uint64_t HELPER(clrsb_i64)(uint64_t arg)
{
    return clrsb64(arg);
}

uint32_t HELPER(ctpop_i32)(uint32_t arg)
{
    return ctpop32(arg);
}

uint64_t HELPER(ctpop_i64)(uint64_t arg)
{
    return ctpop64(arg);
}

void *HELPER(lookup_tb_ptr)(CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    tb = tb_lookup__cpu_state(cpu, &pc, &cs_base, &flags, curr_cflags());
    if (tb == NULL) {
        return tcg_ctx->code_gen_epilogue;
    }
    qemu_log_mask_and_addr(CPU_LOG_EXEC, pc,
                           "Chain %d: %p ["
                           TARGET_FMT_lx "/" TARGET_FMT_lx "/%#x] %s\n",
                           cpu->cpu_index, tb->tc.ptr, cs_base, pc, flags,
                           lookup_symbol(pc));
    return tb->tc.ptr;
}

void HELPER(exit_atomic)(CPUArchState *env)
{
    cpu_loop_exit_atomic(ENV_GET_CPU(env), GETPC());
}

/////////////////////////////////////////////////
//                   QASAN
/////////////////////////////////////////////////

#include "qasan-qemu.h"

#ifndef CONFIG_USER_ONLY
#define g2h(x) \
  ({ \
    void *_a; \
    if (!qasan_addr_to_host(cpu, (x), &_a)) \
      return (target_ulong)-1; \
    _a; \
  })
// h2g must not be defined
// #define h2g(x) (x)
#endif

int qasan_addr_to_host(CPUState* cpu, target_ulong addr, void** host_addr);

int __qasan_debug;

#ifdef ASAN_GIOVESE

__thread struct shadow_stack qasan_shadow_stack;

void asan_giovese_populate_context(struct call_context* ctx) {

  ctx->addresses = calloc(sizeof(void*), qasan_shadow_stack.size);
  ctx->size = qasan_shadow_stack.size;
  ctx->tid = 0; // TODO
  if (qasan_shadow_stack.size == 0) return;
  
  int i, j = 0;
  for (i = 0; i < qasan_shadow_stack.first->index; ++i)
    ctx->addresses[j++] = qasan_shadow_stack.first->buf[i];

  struct shadow_stack_block* b = qasan_shadow_stack.first->next;
  while (b) {
  
    for (i = 0; i < SHADOW_BK_SIZE; ++i)
      ctx->addresses[j++] = b->buf[i];
  
  }

}

char* asan_giovese_printaddr(TARGET_ULONG guest_addr) {

  return NULL;

}

#if defined(TARGET_X86_64) || defined(TARGET_I386)
static void qasan_get_pc_bp_sp(CPUArchState *env, target_ulong* pc, target_ulong* bp, target_ulong* sp) {

  *pc = env->eip;
  *bp = env->regs[R_EBP];
  *bp = env->regs[R_ESP];

}
#else
#error "Target not supported by asan-giovese"
#endif

#endif


target_long qasan_actions_dispatcher(void *cpu_env,
                                     target_long action, target_long arg1,
                                     target_long arg2, target_long arg3) {

    /* TODO hack return address and AsanThread stack_top/bottom to get
       meaningful stacktraces in report.
       
    */
    /*
    uintptr_t fp = __builtin_frame_address(0);
    uintptr_t* parent_fp_ptr;
    uintptr_t saved_parent_fp;
    if (fp) {
        parent_fp_ptr = (uintptr_t*)(fp - sizeof(uintptr_t));
        saved_parent_fp = *parent_fp_ptr;
        
    }
    */
    
    CPUArchState *env = cpu_env;
    CPUState *cpu = ENV_GET_CPU(env);

    switch(action) {
#ifdef ASAN_GIOVESE
        case QASAN_ACTION_CHECK_LOAD:
        if (asan_giovese_loadN(g2h(arg1), arg2)) {
          target_ulong saved_pc, saved_bp, saved_sp;
          qasan_get_pc_bp_sp(env, &saved_pc, &saved_bp, &saved_sp);
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, g2h(arg1), arg2,
                                        arg1, saved_pc, saved_bp, saved_sp);
        }
        break;
        
        case QASAN_ACTION_CHECK_STORE:
        if (asan_giovese_storeN(g2h(arg1), arg2)) {
          target_ulong saved_pc, saved_bp, saved_sp;
          qasan_get_pc_bp_sp(env, &saved_pc, &saved_bp, &saved_sp);
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, g2h(arg1), arg2,
                                        arg1, saved_pc, saved_bp, saved_sp);
        }
        break;
        
        case QASAN_ACTION_POISON:
        asan_giovese_user_poison_region(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_UNPOISON:
        asan_giovese_unpoison_region(g2h(arg1), arg2);
        break;
#else
        case QASAN_ACTION_CHECK_LOAD:
        __asan_loadN(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_CHECK_STORE:
        __asan_storeN(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_POISON:
        __asan_poison_memory_region(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_UNPOISON:
        __asan_unpoison_memory_region(g2h(arg1), arg2);
        break;

#if defined(CONFIG_USER_ONLY)        
        case QASAN_ACTION_MALLOC_USABLE_SIZE:
        return __interceptor_malloc_usable_size(g2h(arg1));
        
        case QASAN_ACTION_MALLOC: {
            target_long r = h2g(__interceptor_malloc(arg1));
            if (r) page_set_flags(r - HEAP_PAD, r + arg1 + HEAP_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_CALLOC: {
            target_long r = h2g(__interceptor_calloc(arg1, arg2));
            if (r) page_set_flags(r - HEAP_PAD, r + (arg1 * arg2) + HEAP_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_REALLOC: {
            target_long r = h2g(__interceptor_malloc(arg2));
            if (r) {
              page_set_flags(r - HEAP_PAD, r + arg2 + HEAP_PAD,
                             PROT_READ | PROT_WRITE | PAGE_VALID);
              size_t l = __interceptor_malloc_usable_size(g2h(arg1));
              if (arg2 < l) l = arg2;
              __asan_memcpy(g2h(r), g2h(arg1), l);
            }
            __interceptor_free(g2h(arg1));
            /*target_long r = h2g(__interceptor_realloc(g2h(arg1), arg2));
            if (r) page_set_flags(r - HEAP_PAD, r + arg1 + HEAP_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);*/
            return r;
        }
        
        case QASAN_ACTION_POSIX_MEMALIGN: {
            void ** memptr = (void **)g2h(arg1);
            target_long r = __interceptor_posix_memalign(memptr, arg2, arg3);
            if (*memptr) {
              *memptr = h2g(*memptr);
              page_set_flags(*memptr - HEAP_PAD, *memptr + arg2 + HEAP_PAD,
                             PROT_READ | PROT_WRITE | PAGE_VALID);
            }
            return r;
        }
        
        case QASAN_ACTION_MEMALIGN: {
            target_long r = h2g(__interceptor_memalign(arg1, arg2));
            if (r) page_set_flags(r - HEAP_PAD, r + arg2 + HEAP_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_ALIGNED_ALLOC: {
            target_long r = h2g(__interceptor_aligned_alloc(arg1, arg2));
            if (r) page_set_flags(r - HEAP_PAD, r + arg2 + HEAP_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_VALLOC: {
            target_long r = h2g(__interceptor_valloc(arg1));
            if (r) page_set_flags(r - HEAP_PAD, r + arg1 + HEAP_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_PVALLOC: {
            target_long r = h2g(__interceptor_pvalloc(arg1));
            if (r) page_set_flags(r - HEAP_PAD, r + arg1 + HEAP_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_FREE:
        __interceptor_free(g2h(arg1));
        break;
        
        case QASAN_ACTION_MEMCMP:
        return __interceptor_memcmp(g2h(arg1), g2h(arg2), arg3);
        
        case QASAN_ACTION_MEMCPY:
        return h2g(__asan_memcpy(g2h(arg1), g2h(arg2), arg3));
        
        case QASAN_ACTION_MEMMOVE:
        return h2g(__interceptor_memmove(g2h(arg1), g2h(arg2), arg3));
        
        case QASAN_ACTION_MEMSET:
        return h2g(__asan_memset(g2h(arg1), arg2, arg3));
        
        case QASAN_ACTION_STRCHR:
        return h2g(__interceptor_strchr(g2h(arg1), arg2));
        
        case QASAN_ACTION_STRCASECMP:
        return __interceptor_strcasecmp(g2h(arg1), g2h(arg2));
        
        case QASAN_ACTION_STRCAT: {
          // TODO fixme: strange stuffs happens when using ASan strcat...
          // return h2g(__interceptor_strcat(g2h(arg1), g2h(arg2)));
          size_t l1 = strlen(g2h(arg1));
          size_t l2 = strlen(g2h(arg2));
          __asan_loadN(g2h(arg2), l2);
          if (l2) {
            __asan_loadN(g2h(arg1), l1);
            __asan_storeN(g2h(arg1) +l1, l2 +1);
          }
          return h2g(strcat(g2h(arg1), g2h(arg2)));
        }
        
        case QASAN_ACTION_STRCMP:
        return __interceptor_strcmp(g2h(arg1), g2h(arg2));
        
        case QASAN_ACTION_STRCPY:
        return h2g(__interceptor_strcpy(g2h(arg1), g2h(arg2)));
        
        case QASAN_ACTION_STRDUP: {
            size_t l = __interceptor_strlen(g2h(arg1));
            target_long r = h2g(__interceptor_strdup(g2h(arg1)));
            if (r) page_set_flags(r - HEAP_PAD, r + l + HEAP_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_STRLEN:
        return __interceptor_strlen(g2h(arg1));
        
        case QASAN_ACTION_STRNCASECMP:
        return __interceptor_strncasecmp(g2h(arg1), g2h(arg2), arg3);
        
        case QASAN_ACTION_STRNCMP:
        return __interceptor_strncmp(g2h(arg1), g2h(arg2), arg3);
       
        case QASAN_ACTION_STRNCAT:
        return __interceptor_strncat(g2h(arg1), g2h(arg2), arg3);

        case QASAN_ACTION_STRNCPY:
        return h2g(__interceptor_strncpy(g2h(arg1), g2h(arg2), arg3));
        
        case QASAN_ACTION_STRNLEN:
        return __interceptor_strnlen(g2h(arg1), arg2);
        
        case QASAN_ACTION_STRRCHR:
        return h2g(__interceptor_strrchr(g2h(arg1), arg2));
        
        case QASAN_ACTION_ATOI:
        return __interceptor_atoi(g2h(arg1));
        
        case QASAN_ACTION_ATOL:
        return __interceptor_atol(g2h(arg1));
        
        case QASAN_ACTION_ATOLL:
        return __interceptor_atoll(g2h(arg1));
#endif
#endif
        default:
        QASAN_LOG("Invalid QASAN action %d\n", action);
        abort();
    }

    return 0;
}

void* HELPER(qasan_fake_instr)(CPUArchState *env, void* action, void* arg1,
                               void* arg2, void* arg3) {

  return (void*)qasan_actions_dispatcher(env,
                                         (target_long)action, (target_long)arg1,
                                         (target_long)arg2, (target_long)arg3);

}

#ifndef CONFIG_USER_ONLY
#undef g2h
#define g2h(x) \
  ({ \
    void *_a; \
    if (!qasan_addr_to_host(ENV_GET_CPU(env), (x), &_a)) \
      return; \
    _a; \
  })
// h2g must not be defined
// #define h2g(x) (x)
#endif

// TODO find what "off" really does

void HELPER(qasan_load1)(CPUArchState *env, void * ptr, uint32_t off) {

  uintptr_t addr = g2h((target_long)ptr);
#ifdef ASAN_GIOVESE
  if (asan_giovese_load1(addr)) {
    target_ulong saved_pc, saved_bp, saved_sp;
    qasan_get_pc_bp_sp(env, &saved_pc, &saved_bp, &saved_sp);
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 1, (target_long)ptr,
                                  saved_pc, saved_bp, saved_sp);
  }
#else
  __asan_load1(addr);
#endif

}

void HELPER(qasan_load2)(CPUArchState *env, void * ptr, uint32_t off) {

  uintptr_t addr = g2h((target_long)ptr);
#ifdef ASAN_GIOVESE
  if (asan_giovese_load2(addr)) {
    target_ulong saved_pc, saved_bp, saved_sp;
    qasan_get_pc_bp_sp(env, &saved_pc, &saved_bp, &saved_sp);
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 2, (target_long)ptr,
                                  saved_pc, saved_bp, saved_sp);
  }
#else
  __asan_load2(addr);
#endif

}

void HELPER(qasan_load4)(CPUArchState *env, void * ptr, uint32_t off) {

  uintptr_t addr = g2h((target_long)ptr);
#ifdef ASAN_GIOVESE
  if (asan_giovese_load4(addr)) {
    target_ulong saved_pc, saved_bp, saved_sp;
    qasan_get_pc_bp_sp(env, &saved_pc, &saved_bp, &saved_sp);
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 4, (target_long)ptr,
                                  saved_pc, saved_bp, saved_sp);
  }
#else
  __asan_load4(addr);
#endif

}

void HELPER(qasan_load8)(CPUArchState *env, void * ptr, uint32_t off) {

  uintptr_t addr = g2h((target_long)ptr);
#ifdef ASAN_GIOVESE
  if (asan_giovese_load8(addr)) {
    target_ulong saved_pc, saved_bp, saved_sp;
    qasan_get_pc_bp_sp(env, &saved_pc, &saved_bp, &saved_sp);
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 8, (target_long)ptr,
                                  saved_pc, saved_bp, saved_sp);
  }
#else
  __asan_load8(addr);
#endif

}

void HELPER(qasan_store1)(CPUArchState *env, void * ptr, uint32_t off) {

  uintptr_t addr = g2h((target_long)ptr);
#ifdef ASAN_GIOVESE
  if (asan_giovese_store1(addr)) {
    target_ulong saved_pc, saved_bp, saved_sp;
    qasan_get_pc_bp_sp(env, &saved_pc, &saved_bp, &saved_sp);
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 1, (target_long)ptr,
                                  saved_pc, saved_bp, saved_sp);
  }
#else
  __asan_store1(addr);
#endif

}

void HELPER(qasan_store2)(CPUArchState *env, void * ptr, uint32_t off) {

  uintptr_t addr = g2h((target_long)ptr);
#ifdef ASAN_GIOVESE
  if (asan_giovese_store2(addr)) {
    target_ulong saved_pc, saved_bp, saved_sp;
    qasan_get_pc_bp_sp(env, &saved_pc, &saved_bp, &saved_sp);
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 2, (target_long)ptr,
                                  saved_pc, saved_bp, saved_sp);
  }
#else
  __asan_store2(addr);
#endif

}

void HELPER(qasan_store4)(CPUArchState *env, void * ptr, uint32_t off) {

  uintptr_t addr = g2h((target_long)ptr);
#ifdef ASAN_GIOVESE
  if (asan_giovese_store4(addr)) {
    target_ulong saved_pc, saved_bp, saved_sp;
    qasan_get_pc_bp_sp(env, &saved_pc, &saved_bp, &saved_sp);
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 4, (target_long)ptr,
                                  saved_pc, saved_bp, saved_sp);
  }
#else
  __asan_store4(addr);
#endif

}

void HELPER(qasan_store8)(CPUArchState *env, void * ptr, uint32_t off) {

  uintptr_t addr = g2h((target_long)ptr);
#ifdef ASAN_GIOVESE
  if (asan_giovese_store8(addr)) {
    target_ulong saved_pc, saved_bp, saved_sp;
    qasan_get_pc_bp_sp(env, &saved_pc, &saved_bp, &saved_sp);
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 8, (target_long)ptr,
                                  saved_pc, saved_bp, saved_sp);
  }
#else
  __asan_store8(addr);
#endif

}

#ifdef ASAN_GIOVESE
#include "../../asan-giovese/interval-tree/rbtree.c"
#include "../../asan-giovese/alloc.c"
#include "../../asan-giovese/init.c"
#include "../../asan-giovese/poison.c"
#include "../../asan-giovese/report.c"
#endif
