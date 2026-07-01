/*
 * ngx_shim.h — prototypes for the two nginx pool allocators the sd_ceph driver
 * names, for the standalone live test. Force-included (`-include`) into BOTH the
 * driver TU and the test TU so the driver sees a correct (pointer-returning)
 * declaration — without it gcc assumes int and TRUNCATES the 64-bit pointer.
 * The definitions live in sd_ceph_live_test.c (calloc/malloc, pool ignored).
 */
#ifndef XROOTD_TEST_NGX_SHIM_H
#define XROOTD_TEST_NGX_SHIM_H

#include <stddef.h>
#include <string.h>
#include "sd.h"   /* ngx_pool_t typedef (XRDPROTO_NO_NGX branch) */

void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);

#ifndef ngx_memcpy
#define ngx_memcpy(dst, src, n)  memcpy(dst, src, (n))
#endif

#endif /* XROOTD_TEST_NGX_SHIM_H */
