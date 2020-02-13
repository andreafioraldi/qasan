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

__thread CPUState* qasan_cpu;
#define g2h(x) \
  ({ \
    void *_a; \
    if (!qasan_addr_to_host(qasan_cpu, (x), &_a)) {\
      /* fprintf(stderr, "QASan error: virtual address translation for %p failed!\n", (x)); */ \
      return 0;\
    } \
    _a; \
  })

// h2g must not be defined
// #define h2g(x) (x)

#endif

int qasan_addr_to_host(CPUState* cpu, target_ulong addr, void** host_addr);

int __qasan_debug;
int qasan_disabled;

#define MAX_ASAN_CALL_STACK 16

__thread struct shadow_stack qasan_shadow_stack;

#ifdef ASAN_GIOVESE

#include "../../asan-giovese/interval-tree/rbtree.c"
#include "../../asan-giovese/asan-giovese-inl.h"

void asan_giovese_populate_context(struct call_context* ctx, TARGET_ULONG pc) {

  ctx->size = MIN(qasan_shadow_stack.size, MAX_ASAN_CALL_STACK -1) +1;
  ctx->addresses = calloc(sizeof(void*), ctx->size);
  ctx->tid = 0; // TODO
  ctx->addresses[0] = pc;
  
  if (qasan_shadow_stack.size == 0) return;
  
  int i, j = 1;
  for (i = qasan_shadow_stack.first->index -1; i >= 0 && j < MAX_ASAN_CALL_STACK; --i)
    ctx->addresses[j++] = qasan_shadow_stack.first->buf[i];

  struct shadow_stack_block* b = qasan_shadow_stack.first->next;
  while (b && j < MAX_ASAN_CALL_STACK) {
  
    for (i = SHADOW_BK_SIZE-1; i >= 0; --i)
      ctx->addresses[j++] = b->buf[i];
  
  }

}

#ifdef CONFIG_USER_ONLY
#include "../../asan-giovese/pmparser.h"

static void addr2line_cmd(char* lib, uintptr_t off, char** function, char** line) {
  
  if (getenv("QASAN_DONT_SYMBOLIZE")) goto addr2line_cmd_skip;
  
  FILE *fp;

  size_t cmd_siz = 128 + strlen(lib);
  char* cmd = malloc(cmd_siz);
  snprintf(cmd, cmd_siz, "addr2line -f -e '%s' 0x%lx", lib, off);

  fp = popen(cmd, "r");
  free(cmd);
  
  if (fp == NULL) goto addr2line_cmd_skip;

  *function = malloc(PATH_MAX + 32);
  
  if (!fgets(*function, PATH_MAX + 32, fp) || !strncmp(*function, "??", 2)) {

    free(*function);
    *function = NULL;

  } else {

    size_t l = strlen(*function);
    if (l && (*function)[l-1] == '\n')
      (*function)[l-1] = 0;
      
  }
  
  *line = malloc(PATH_MAX + 32);
  
  if (!fgets(*line, PATH_MAX + 32, fp) || !strncmp(*line, "??:", 3)) {

    free(*line);
    *line = NULL;

  } else {

    size_t l = strlen(*line);
    if (l && (*line)[l-1] == '\n')
      (*line)[l-1] = 0;
      
  }

  pclose(fp);
  
  return;

addr2line_cmd_skip:
  *line = NULL;
  *function = NULL;
  
}

char* asan_giovese_printaddr(target_ulong guest_addr) {

  procmaps_iterator* maps = pmparser_parse(-1);
  procmaps_struct*   maps_tmp = NULL;

  uintptr_t a = (uintptr_t)g2h(guest_addr);

  while ((maps_tmp = pmparser_next(maps)) != NULL) {

    if (a >= (uintptr_t)maps_tmp->addr_start &&
        a < (uintptr_t)maps_tmp->addr_end) {

      char* s;
      char * function;
      char * line;
      addr2line_cmd(maps_tmp->pathname, a - (uintptr_t)maps_tmp->addr_start,
                    &function, &line);

      if (function) {
      
        if (line) {
        
          size_t l = strlen(function) + strlen(line) + 32;
          s = malloc(l);
          snprintf(s, l, " in %s %s", function, line);
          free(line);
          
        } else {

          size_t l = strlen(function) + strlen(maps_tmp->pathname) + 32;
          s = malloc(l);
          snprintf(s, l, " in %s (%s+0x%lx)", function, maps_tmp->pathname,
                   a - (uintptr_t)maps_tmp->addr_start);
          
        }
        
        free(function);
      
      } else {

        size_t l = strlen(maps_tmp->pathname) + 32;
        s = malloc(l);
        snprintf(s, l, " (%s+0x%lx)", maps_tmp->pathname,
                 a - (uintptr_t)maps_tmp->addr_start);

      }

      pmparser_free(maps);
      return s;

    }

  }

  pmparser_free(maps);
  return NULL;

}
#else
char* asan_giovese_printaddr(TARGET_ULONG guest_addr) {

  return NULL;

}
#endif

#endif

void HELPER(qasan_shadow_stack_push)(target_ulong ptr) {

  if (unlikely(!qasan_shadow_stack.first)) {
    
    qasan_shadow_stack.first = malloc(sizeof(struct shadow_stack_block));
    qasan_shadow_stack.first->index = 0;
    qasan_shadow_stack.size = 0; // may be negative due to last pop
    qasan_shadow_stack.first->next = NULL;

  }
    
  qasan_shadow_stack.first->buf[qasan_shadow_stack.first->index++] = ptr;
  qasan_shadow_stack.size++;

  if (qasan_shadow_stack.first->index >= SHADOW_BK_SIZE) {

      struct shadow_stack_block* ns = malloc(sizeof(struct shadow_stack_block));
      ns->next = qasan_shadow_stack.first;
      ns->index = 0;
      qasan_shadow_stack.first = ns;
  }

}

void HELPER(qasan_shadow_stack_pop)(target_ulong ptr) {

  struct shadow_stack_block* cur_bk = qasan_shadow_stack.first;
  if (unlikely(cur_bk == NULL)) return;

  do {
      
      cur_bk->index--;
      qasan_shadow_stack.size--;
      
      if (cur_bk->index < 0) {
          
          struct shadow_stack_block* ns = cur_bk->next;
          free(cur_bk);
          cur_bk = ns;
          if (!cur_bk) break;
          cur_bk->index--;
      }
      
  } while(cur_bk->buf[cur_bk->index] != ptr);
  
  qasan_shadow_stack.first = cur_bk;

}

target_long qasan_actions_dispatcher(void *cpu_env,
                                     target_long action, target_long arg1,
                                     target_long arg2, target_long arg3) {

    CPUArchState *env = cpu_env;
#ifndef CONFIG_USER_ONLY
    qasan_cpu = ENV_GET_CPU(env);
#endif

    switch(action) {
#ifdef ASAN_GIOVESE
        case QASAN_ACTION_CHECK_LOAD:
        if (asan_giovese_loadN(arg1, arg2)) {
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, arg1, arg2, GET_PC(env), GET_BP(env), GET_SP(env));
        }
        break;
        
        case QASAN_ACTION_CHECK_STORE:
        if (asan_giovese_storeN(arg1, arg2)) {
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, arg1, arg2, GET_PC(env), GET_BP(env), GET_SP(env));
        }
        break;
        
        case QASAN_ACTION_POISON:
        // fprintf(stderr, "POISON: %p %ld %x\n", arg1, arg2, arg3);
        asan_giovese_poison_region(arg1, arg2, arg3);
        break;
        
        case QASAN_ACTION_USER_POISON:
        // fprintf(stderr, "USER POISON: %p %ld\n", arg1, arg2);
        asan_giovese_user_poison_region(arg1, arg2);
        break;
        
        case QASAN_ACTION_UNPOISON:
        // fprintf(stderr, "UNPOISON: %p %ld\n", arg1, arg2);
        asan_giovese_unpoison_region(arg1, arg2);
        break;
        
        case QASAN_ACTION_ALLOC: {
          // fprintf(stderr, "ALLOC: %p - %p\n", arg1, arg2);
          struct call_context* ctx = calloc(sizeof(struct call_context), 1);
          asan_giovese_populate_context(ctx, GET_PC(env));
          asan_giovese_alloc_insert(arg1, arg2, ctx);
          break;
        }
        
        case QASAN_ACTION_DEALLOC: {
          // fprintf(stderr, "DEALLOC: %p\n", arg1);
          struct chunk_info* ckinfo = asan_giovese_alloc_search(arg1);
          if (ckinfo) {
            ckinfo->free_ctx = calloc(sizeof(struct call_context), 1);
            asan_giovese_populate_context(ckinfo->free_ctx, GET_PC(env));
          }
          break;
        }
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
        
        case QASAN_ACTION_USER_POISON:
        __asan_poison_memory_region(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_UNPOISON:
        __asan_unpoison_memory_region(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_ALLOC:
          break;
        
        case QASAN_ACTION_DEALLOC:
          break;
#endif

        case QASAN_ACTION_ENABLE:
        qasan_disabled = 0;
        break;
        
        case QASAN_ACTION_DISABLE:
        qasan_disabled = 1;
        break;

        case QASAN_ACTION_SWAP_STATE: {
          int r = qasan_disabled;
          qasan_disabled = arg1;
          return r;
        }

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

#ifndef ASAN_GIOVESE
#ifndef CONFIG_USER_ONLY

#undef g2h
#define g2h(x) \
  ({ \
    void *_a; \
    if (!qasan_addr_to_host(qasan_cpu, (x), &_a)) {\
      /* fprintf(stderr, "QASan error: virtual address translation for %p failed!\n", (x)); */ \
      return;\
    } \
    _a; \
  })

#endif
#endif

// TODO find what "off" really does

void HELPER(qasan_load1)(CPUArchState *env, target_ulong ptr, uint32_t off) {

  if (qasan_disabled) return;

#ifndef CONFIG_USER_ONLY
  qasan_cpu = ENV_GET_CPU(env);
#endif
#ifdef ASAN_GIOVESE
  if (asan_giovese_load1((target_long)ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, (target_long)ptr, 1, GET_PC(env), GET_BP(env), GET_SP(env));
  }
#else
  uintptr_t addr = g2h((target_long)ptr);
  __asan_load1(addr);
#endif

}

void HELPER(qasan_load2)(CPUArchState *env, target_ulong ptr, uint32_t off) {

  if (qasan_disabled) return;

#ifndef CONFIG_USER_ONLY
  qasan_cpu = ENV_GET_CPU(env);
#endif
#ifdef ASAN_GIOVESE
  if (asan_giovese_load2((target_long)ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, (target_long)ptr, 2, GET_PC(env), GET_BP(env), GET_SP(env));
  }
#else
  uintptr_t addr = g2h((target_long)ptr);
  __asan_load2(addr);
#endif

}

void HELPER(qasan_load4)(CPUArchState *env, target_ulong ptr, uint32_t off) {

  if (qasan_disabled) return;

#ifndef CONFIG_USER_ONLY
  qasan_cpu = ENV_GET_CPU(env);
#endif
#ifdef ASAN_GIOVESE
  if (asan_giovese_load4((target_long)ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, (target_long)ptr, 4, GET_PC(env), GET_BP(env), GET_SP(env));
  }
#else
  uintptr_t addr = g2h((target_long)ptr);
  __asan_load4(addr);
#endif

}

void HELPER(qasan_load8)(CPUArchState *env, target_ulong ptr, uint32_t off) {

  if (qasan_disabled) return;

#ifndef CONFIG_USER_ONLY
  qasan_cpu = ENV_GET_CPU(env);
#endif
#ifdef ASAN_GIOVESE
  if (asan_giovese_load8((target_long)ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, (target_long)ptr, 8, GET_PC(env), GET_BP(env), GET_SP(env));
  }
#else
  uintptr_t addr = g2h((target_long)ptr);
  __asan_load8(addr);
#endif

}

void HELPER(qasan_store1)(CPUArchState *env, target_ulong ptr, uint32_t off) {

  if (qasan_disabled) return;

#ifndef CONFIG_USER_ONLY
  qasan_cpu = ENV_GET_CPU(env);
#endif
#ifdef ASAN_GIOVESE
  if (asan_giovese_store1((target_long)ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, (target_long)ptr, 1, GET_PC(env), GET_BP(env), GET_SP(env));
  }
#else
  uintptr_t addr = g2h((target_long)ptr);
  __asan_store1(addr);
#endif

}

void HELPER(qasan_store2)(CPUArchState *env, target_ulong ptr, uint32_t off) {

  if (qasan_disabled) return;

#ifndef CONFIG_USER_ONLY
  qasan_cpu = ENV_GET_CPU(env);
#endif
#ifdef ASAN_GIOVESE
  if (asan_giovese_store2((target_long)ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, (target_long)ptr, 2, GET_PC(env), GET_BP(env), GET_SP(env));
  }
#else
  uintptr_t addr = g2h((target_long)ptr);
  __asan_store2(addr);
#endif

}

void HELPER(qasan_store4)(CPUArchState *env, target_ulong ptr, uint32_t off) {

  if (qasan_disabled) return;

#ifndef CONFIG_USER_ONLY
  qasan_cpu = ENV_GET_CPU(env);
#endif
#ifdef ASAN_GIOVESE
  if (asan_giovese_store4((target_long)ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, (target_long)ptr, 4, GET_PC(env), GET_BP(env), GET_SP(env));
  }
#else
  uintptr_t addr = g2h((target_long)ptr);
  __asan_store4(addr);
#endif

}

void HELPER(qasan_store8)(CPUArchState *env, target_ulong ptr, uint32_t off) {

  if (qasan_disabled) return;

#ifndef CONFIG_USER_ONLY
  qasan_cpu = ENV_GET_CPU(env);
#endif
#ifdef ASAN_GIOVESE
  if (asan_giovese_store8((target_long)ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, (target_long)ptr, 8, GET_PC(env), GET_BP(env), GET_SP(env));
  }
#else
  uintptr_t addr = g2h((target_long)ptr);
  __asan_store8(addr);
#endif

}
