#ifndef __interceptor_QEMU_H__
#define __interceptor_QEMU_H__

#define _GNU_SOURCE
#include <malloc.h>
#include "../../include/qasan.h"
#include "tcg.h"

#define WIDE_PAD 16

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

void *__asan_memcpy(void *, void *, size_t);
void *__asan_memmove(void *, void *, size_t);
void *__asan_memset(void *, int, size_t);

size_t __interceptor_malloc_usable_size (void * ptr);
void * __interceptor_malloc(size_t size);
void * __interceptor_calloc(size_t nmemb, size_t size);
void * __interceptor_realloc(void *ptr, size_t size);
int __interceptor_posix_memalign(void **memptr, size_t alignment, size_t size);
void * __interceptor_memalign(size_t alignment, size_t size);
void * __interceptor_aligned_alloc(size_t alignment, size_t size);
void * __interceptor_valloc(size_t size);
void * __interceptor_pvalloc(size_t size);
void __interceptor_free(void * ptr);
int __interceptor_memcmp(const void *s1, const void *s2, size_t n);
char * __interceptor_strchr(const char *s, int c);
int __interceptor_strcasecmp(const char *s1, const char *s2);
char * __interceptor_strcat(char *dest, const char *src);
int __interceptor_strcmp(const char *s1, const char *s2);
char * __interceptor_strcpy(char *dest, const char *src);
char * __interceptor_strdup(const char *s);
size_t __interceptor_strlen(const char *s);
int __interceptor_strncasecmp(const char *s1, const char *s2, size_t n);
int __interceptor_strncmp(const char *s1, const char *s2, size_t n);
char * __interceptor_strncpy(char *dest, const char *src, size_t n);
size_t __interceptor_strnlen(const char *s, size_t n);


static abi_long qasan_fake_syscall(abi_long action, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6, abi_long arg7) {

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
            if (r) page_set_flags(r - WIDE_PAD, r + arg1 + WIDE_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_CALLOC: {
            abi_long r = h2g(__interceptor_calloc(arg1, arg2));
            if (r) page_set_flags(r - WIDE_PAD, r + (arg1 * arg2) + WIDE_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_REALLOC: {
            abi_long r = h2g(__interceptor_malloc(arg2));
            if (r) {
              page_set_flags(r - WIDE_PAD, r + arg2 + WIDE_PAD,
                             PROT_READ | PROT_WRITE | PAGE_VALID);
              size_t l = __interceptor_malloc_usable_size(g2h(arg1));
              if (arg2 < l) l = arg2;
              __asan_memcpy(g2h(r), g2h(arg1), l);
            }
            __interceptor_free(g2h(arg1));
            /*abi_long r = h2g(__interceptor_realloc(g2h(arg1), arg2));
            if (r) page_set_flags(r - WIDE_PAD, r + arg1 + WIDE_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);*/
            return r;
        }
        
        case QASAN_ACTION_POSIX_MEMALIGN: {
            void ** memptr = (void **)g2h(arg1);
            abi_long r = __interceptor_posix_memalign(memptr, arg2, arg3);
            if (*memptr) {
              *memptr = h2g(*memptr);
              page_set_flags(*memptr - WIDE_PAD, *memptr + arg2 + WIDE_PAD,
                             PROT_READ | PROT_WRITE | PAGE_VALID);
            }
            return r;
        }
        
        case QASAN_ACTION_MEMALIGN: {
            abi_long r = h2g(__interceptor_memalign(arg1, arg2));
            if (r) page_set_flags(r - WIDE_PAD, r + arg2 + WIDE_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_ALIGNED_ALLOC: {
            abi_long r = h2g(__interceptor_aligned_alloc(arg1, arg2));
            if (r) page_set_flags(r - WIDE_PAD, r + arg2 + WIDE_PAD,
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_VALLOC: {
            abi_long r = h2g(__interceptor_valloc(arg1));
            if (r) page_set_flags(r - WIDE_PAD, r + arg1 + WIDE_PAD, 
                                  PROT_READ | PROT_WRITE | PAGE_VALID);
            return r;
        }
        
        case QASAN_ACTION_PVALLOC: {
            abi_long r = h2g(__interceptor_pvalloc(arg1));
            if (r) page_set_flags(r - WIDE_PAD, r + arg1 + WIDE_PAD, 
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
        return h2g(__asan_memmove(g2h(arg1), g2h(arg2), arg3));
        
        case QASAN_ACTION_MEMSET:
        return h2g(__asan_memset(g2h(arg1), arg2, arg3));
        
        case QASAN_ACTION_STRCHR:
        return h2g(__interceptor_strchr(g2h(arg1), arg2));
        
        case QASAN_ACTION_STRCASECMP:
        return __interceptor_strcasecmp(g2h(arg1), g2h(arg2));
        
        case QASAN_ACTION_STRCAT:
        return __interceptor_strcasecmp(g2h(arg1), g2h(arg2));
        
        case QASAN_ACTION_STRCMP:
        return __interceptor_strcmp(g2h(arg1), g2h(arg2));
        
        case QASAN_ACTION_STRCPY:
        return h2g(__interceptor_strcpy(g2h(arg1), g2h(arg2)));
        
        case QASAN_ACTION_STRDUP: {
            size_t l = __interceptor_strlen(g2h(arg1));
            abi_long r = h2g(__interceptor_strdup(g2h(arg1)));
            if (r) page_set_flags(r - WIDE_PAD, r + l + WIDE_PAD, 
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
