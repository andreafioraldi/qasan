#ifndef __QASAN_QEMU_H__
#define __QASAN_QEMU_H__

#define _GNU_SOURCE
#include <malloc.h>
#include "../../include/qasan.h"
#include "tcg.h"

#define WIDE_PAD 16

void *__asan_memcpy(void *dest, const void *src, size_t n);
void *__asan_memset(void *s, int c, size_t n);

static abi_long qasan_fake_syscall(abi_long action, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6, abi_long arg7)
{
    switch(action) {
        case QASAN_HYPER_MALLOC_USABLE_SIZE:
        return malloc_usable_size(g2h(arg1));
        
        case QASAN_HYPER_MALLOC: {
            abi_long r = h2g(malloc(arg1));
            if (r) page_set_flags(r - WIDE_PAD, r + arg1 + WIDE_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_HYPER_CALLOC: {
            abi_long r = h2g(calloc(arg1, arg2));
            if (r) page_set_flags(r - WIDE_PAD, r + (arg1 * arg2) + WIDE_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_HYPER_REALLOC: {
            free(g2h(arg1));
            abi_long r = h2g(malloc(arg2));
            if (r) page_set_flags(r - WIDE_PAD, r + arg2 + WIDE_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_HYPER_FREE:
        free(g2h(arg1));
        break;
        
        case QASAN_HYPER_MEMALIGN: {
            abi_long r = h2g(memalign(arg1, arg2));
            if (r) page_set_flags(r - WIDE_PAD, r + arg2 + WIDE_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_HYPER_MEMCPY:
        return __asan_memcpy(g2h(arg1), g2h(arg2), arg3);
        
        case QASAN_HYPER_MEMSET:
        return __asan_memset(g2h(arg1), arg2, arg3);
        
        default:
        QASAN_LOG("Invalid QASAN hyper action %d\n", action);
        abort();
    }

    return 0;
}

void __asan_load1(void*);
void __asan_load2(void*);
void __asan_load4(void*);
void __asan_load8(void*);
void __asan_store1(void*);
void __asan_store2(void*);
void __asan_store4(void*);
void __asan_store8(void*);

extern __thread int cur_block_is_good;

// TODO collapse into a macro

static void qasan_gen_load1(TCGv_ptr ptr, int off) {
  
  if (cur_block_is_good) gen_helper_qasan_load1(ptr, tcg_const_i32(off));

}

static void qasan_gen_load2(TCGv_ptr ptr, int off) {
  
  if (cur_block_is_good) gen_helper_qasan_load2(ptr, tcg_const_i32(off));

}

static void qasan_gen_load4(TCGv_ptr ptr, int off) {
  
  if (cur_block_is_good) gen_helper_qasan_load4(ptr, tcg_const_i32(off));

}

static void qasan_gen_load8(TCGv_ptr ptr, int off) {
  
  if (cur_block_is_good) gen_helper_qasan_load8(ptr, tcg_const_i32(off));

}

static void qasan_gen_store1(TCGv_ptr ptr, int off) {
  
  if (cur_block_is_good) gen_helper_qasan_store1(ptr, tcg_const_i32(off));

}

static void qasan_gen_store2(TCGv_ptr ptr, int off) {
  
  if (cur_block_is_good) gen_helper_qasan_store2(ptr, tcg_const_i32(off));

}

static void qasan_gen_store4(TCGv_ptr ptr, int off) {
  
  if (cur_block_is_good) gen_helper_qasan_store4(ptr, tcg_const_i32(off));

}

static void qasan_gen_store8(TCGv_ptr ptr, int off) {
  
  if (cur_block_is_good) gen_helper_qasan_store8(ptr, tcg_const_i32(off));

}

#endif
