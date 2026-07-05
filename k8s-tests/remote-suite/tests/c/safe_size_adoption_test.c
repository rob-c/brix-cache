/* tests/c/safe_size_adoption_test.c
 * Standalone (no nginx) checks that the overflow-checked size helpers reject
 * wraparound. Compile: see tests/fuzz/README. */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

/* Minimal nginx shims — the pool/alloc helpers in safe_size.h reference these
 * opaque types even in standalone mode; forward-declare them so the signatures
 * compile without nginx headers.  Modelled on tests/fuzz/fuzz_safe_size.c. */
typedef struct ngx_pool_s ngx_pool_t;
typedef struct ngx_log_s  ngx_log_t;
static void *ngx_palloc(ngx_pool_t *p, size_t n)  { (void) p; return malloc(n); }
static void *ngx_pcalloc(ngx_pool_t *p, size_t n) { (void) p; return calloc(1, n); }
static void *ngx_alloc(size_t n, ngx_log_t *l)    { (void) l; return malloc(n); }

#define BRIX_SAFE_SIZE_STANDALONE 1
typedef long ngx_int_t;
#define NGX_OK 0
#define NGX_ERROR -1
#define ngx_inline inline
/* pool/alloc helpers are not exercised here; only the arithmetic. */
#include "../../src/core/compat/safe_size.h"

int main(void) {
    size_t out = 0;
    /* SIZE_MAX * 2 must be rejected, not wrap to SIZE_MAX-1 */
    assert(brix_size_mul((size_t)-1, 2, &out) == NGX_ERROR);
    /* header offset + huge comp_size must be rejected */
    assert(brix_size_add((size_t)-1, 4096, &out) == NGX_ERROR);
    /* a legitimate small computation still succeeds */
    assert(brix_size_mul(16, 256, &out) == NGX_OK && out == 4096);
    assert(brix_size_add(4096, 1, &out) == NGX_OK && out == 4097);
    printf("safe_size_adoption_test: OK\n");
    return 0;
}
