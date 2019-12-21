#ifndef __QASAN_SYSCALL_H__
#define __QASAN_SYSCALL_H__

#include "qasan-qemu.h"

static abi_long qasan_fake_syscall(abi_long action, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6, abi_long arg7) {

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

    switch(action) {
        case QASAN_ACTION_CHECK_LOAD:
        __asan_loadN(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_CHECK_STORE:
        __asan_storeN(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_MALLOC_USABLE_SIZE:
        return __interceptor_malloc_usable_size(g2h(arg1));
        
        case QASAN_ACTION_MALLOC: {
            abi_long r = h2g(__interceptor_malloc(arg1));
            if (r) page_set_flags(r - HEAP_PAD, r + arg1 + HEAP_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_CALLOC: {
            abi_long r = h2g(__interceptor_calloc(arg1, arg2));
            if (r) page_set_flags(r - HEAP_PAD, r + (arg1 * arg2) + HEAP_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_REALLOC: {
            abi_long r = h2g(__interceptor_malloc(arg2));
            if (r) {
              page_set_flags(r - HEAP_PAD, r + arg2 + HEAP_PAD,
                             PROT_READ | PROT_WRITE | PAGE_VALID);
              size_t l = __interceptor_malloc_usable_size(g2h(arg1));
              if (arg2 < l) l = arg2;
              __asan_memcpy(g2h(r), g2h(arg1), l);
            }
            __interceptor_free(g2h(arg1));
            /*abi_long r = h2g(__interceptor_realloc(g2h(arg1), arg2));
            if (r) page_set_flags(r - HEAP_PAD, r + arg1 + HEAP_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);*/
            return r;
        }
        
        case QASAN_ACTION_POSIX_MEMALIGN: {
            void ** memptr = (void **)g2h(arg1);
            abi_long r = __interceptor_posix_memalign(memptr, arg2, arg3);
            if (*memptr) {
              *memptr = h2g(*memptr);
              page_set_flags(*memptr - HEAP_PAD, *memptr + arg2 + HEAP_PAD,
                             PROT_READ | PROT_WRITE | PAGE_VALID);
            }
            return r;
        }
        
        case QASAN_ACTION_MEMALIGN: {
            abi_long r = h2g(__interceptor_memalign(arg1, arg2));
            if (r) page_set_flags(r - HEAP_PAD, r + arg2 + HEAP_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_ALIGNED_ALLOC: {
            abi_long r = h2g(__interceptor_aligned_alloc(arg1, arg2));
            if (r) page_set_flags(r - HEAP_PAD, r + arg2 + HEAP_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_VALLOC: {
            abi_long r = h2g(__interceptor_valloc(arg1));
            if (r) page_set_flags(r - HEAP_PAD, r + arg1 + HEAP_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_PVALLOC: {
            abi_long r = h2g(__interceptor_pvalloc(arg1));
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
        
        case QASAN_ACTION_STRCAT:
        return __interceptor_strcat(g2h(arg1), g2h(arg2));
        
        case QASAN_ACTION_STRCMP:
        return __interceptor_strcmp(g2h(arg1), g2h(arg2));
        
        case QASAN_ACTION_STRCPY:
        return h2g(__interceptor_strcpy(g2h(arg1), g2h(arg2)));
        
        case QASAN_ACTION_STRDUP: {
            size_t l = __interceptor_strlen(g2h(arg1));
            abi_long r = h2g(__interceptor_strdup(g2h(arg1)));
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
        
        case QASAN_ACTION_STRNCPY:
        return h2g(__interceptor_strncpy(g2h(arg1), g2h(arg2), arg3));
        
        case QASAN_ACTION_STRNLEN:
        return __interceptor_strnlen(g2h(arg1), arg2);
        
        default:
        QASAN_LOG("Invalid QASAN action %d\n", action);
        abort();
    }

    return 0;
}

#endif
