/*
 * ngx_shim.h — prototypes for the two nginx pool allocators the sd_ceph driver
 * names, for the standalone tools and live test. Force-included (`-include`)
 * into BOTH the driver TU and the test TU so the driver sees a correct
 * (pointer-returning) declaration — without it gcc assumes int and TRUNCATES
 * the 64-bit pointer.
 *
 * Exactly ONE TU per binary defines BRIX_NGX_SHIM_IMPL and (re)includes this
 * header to also get the definitions (calloc/malloc, pool ignored); that block
 * sits outside the main guard so it still fires after a plain `-include`.
 */
#ifndef BRIX_TEST_NGX_SHIM_H
#define BRIX_TEST_NGX_SHIM_H

#include <stddef.h>
#include <string.h>
#include "sd.h"   /* ngx_pool_t typedef (XRDPROTO_NO_NGX branch) */

void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);

#ifndef ngx_memcpy
#define ngx_memcpy(dst, src, n)  memcpy(dst, src, (n))
#endif

#endif /* BRIX_TEST_NGX_SHIM_H */

#if defined(BRIX_NGX_SHIM_IMPL) && !defined(BRIX_NGX_SHIM_IMPL_DONE)
#define BRIX_NGX_SHIM_IMPL_DONE 1

#include <stdlib.h>

void *ngx_pcalloc(ngx_pool_t *pool, size_t size) { (void) pool; return calloc(1, size); }
void *ngx_pnalloc(ngx_pool_t *pool, size_t size) { (void) pool; return malloc(size); }

#endif /* BRIX_NGX_SHIM_IMPL */
