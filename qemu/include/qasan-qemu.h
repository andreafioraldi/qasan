#ifndef __QASAN_QEMU_H__
#define __QASAN_QEMU_H__

#define _GNU_SOURCE
#include <malloc.h>
#include "../../include/qasan.h"
#include "tcg.h"

static abi_long qasan_hypercall(abi_long action, abi_long arg1, abi_long arg2)
{
    switch(action) {
        case QASAN_HYPER_MALLOC_USABLE_SIZE:
        return malloc_usable_size(g2h(arg1));
        
        case QASAN_HYPER_MALLOC: {
            abi_long r = h2g(malloc(arg1));
            page_set_flags(r, r + arg1, PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_HYPER_CALLOC: {
            abi_long r = h2g(calloc(arg1, arg2));
            page_set_flags(r, r + (arg1 * arg2), PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_HYPER_REALLOC: {
            free(g2h(arg1));
            abi_long r = h2g(malloc(arg2));
            page_set_flags(r, r + arg2, PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_HYPER_FREE:
        free(g2h(arg1));
        break;
        
        case QASAN_HYPER_MEMALIGN: {
            abi_long r = h2g(memalign(arg1, arg2));
            page_set_flags(r, r + arg2, PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
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

extern abi_ulong afl_start_code, afl_end_code;

// TODO collapse into a macro

static void qasan_gen_load1(TCGv_ptr ptr, int off) {
  
  gen_helper_qasan_load1(ptr, tcg_const_i32(off));

}

static void qasan_gen_load2(TCGv_ptr ptr, int off) {
  
  gen_helper_qasan_load2(ptr, tcg_const_i32(off));

}

static void qasan_gen_load4(TCGv_ptr ptr, int off) {
  
  gen_helper_qasan_load4(ptr, tcg_const_i32(off));

}

static void qasan_gen_load8(TCGv_ptr ptr, int off) {
  
  gen_helper_qasan_load8(ptr, tcg_const_i32(off));

}

static void qasan_gen_store1(TCGv_ptr ptr, int off) {
  
  gen_helper_qasan_store1(ptr, tcg_const_i32(off));

}

static void qasan_gen_store2(TCGv_ptr ptr, int off) {
  
  gen_helper_qasan_store2(ptr, tcg_const_i32(off));

}

static void qasan_gen_store4(TCGv_ptr ptr, int off) {
  
  gen_helper_qasan_store4(ptr, tcg_const_i32(off));

}

static void qasan_gen_store8(TCGv_ptr ptr, int off) {
  
  gen_helper_qasan_store8(ptr, tcg_const_i32(off));

}

#endif
