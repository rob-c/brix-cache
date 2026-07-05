/*
 * fuzz_safe_size.c — Phase 27 W7: libFuzzer target for the W1 overflow-checked
 * size arithmetic and array-allocation helpers.
 *
 * This is the runnable reference target (and template for the wire-parser
 * targets described in README.md).  It interprets the fuzz input as two
 * size_t operands and asserts the safety contract of safe_size.h:
 *
 *   - brix_size_mul / brix_size_add report overflow instead of wrapping;
 *     when they report success the product/sum is the true mathematical value.
 *   - the *_array allocators return NULL on overflow rather than a truncated
 *     buffer (which a caller would then overrun).
 *
 * Build (clang + libFuzzer + ASAN):
 *   clang -O1 -g -fsanitize=fuzzer,address,undefined \
 *       -I ../../src -I ../../src/core/compat fuzz_safe_size.c -o fuzz_safe_size
 *
 * The helpers depend only on <ngx_config.h>/<ngx_core.h> for ngx_int_t/size_t
 * and the alloc wrappers; to keep this target standalone we provide the minimal
 * shims below instead of linking nginx.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>

/* ---- minimal nginx shims so safe_size.h compiles standalone ---- */
typedef intptr_t  ngx_int_t;
typedef struct ngx_pool_s ngx_pool_t;
typedef struct ngx_log_s  ngx_log_t;
#define NGX_OK     0
#define NGX_ERROR -1
#define ngx_inline inline
static void *ngx_palloc(ngx_pool_t *p, size_t n) { (void) p; return malloc(n); }
static void *ngx_pcalloc(ngx_pool_t *p, size_t n) { (void) p; return calloc(1, n); }
static void *ngx_alloc(size_t n, ngx_log_t *l) { (void) l; return malloc(n); }

/* Pull in the unit under test, standalone (no real ngx headers). */
#define BRIX_SAFE_SIZE_STANDALONE 1
#include "safe_size.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t a = 0, b = 0, out = 0;

    if (size >= sizeof(size_t))     { __builtin_memcpy(&a, data, sizeof(a)); }
    if (size >= 2 * sizeof(size_t)) { __builtin_memcpy(&b, data + sizeof(a),
                                                       sizeof(b)); }

    if (brix_size_mul(a, b, &out) == NGX_OK) {
        /* On reported success the product must not have wrapped. */
        assert(b == 0 || out / b == a);
    }
    if (brix_size_add(a, b, &out) == NGX_OK) {
        assert(out >= a && out >= b);
    }

    /*
     * The array allocator must refuse an OVERFLOWING request without
     * allocating.  We assert that contract directly.  We deliberately do not
     * malloc a huge non-overflowing size here (that would just exhaust memory /
     * trip ASAN's max-allocation guard — a test-harness artefact, not a bug in
     * the helper).
     */
    {
        size_t chk;
        if (brix_size_mul(a, b, &chk) != NGX_OK) {
            assert(brix_palloc_array(NULL, a, b) == NULL);   /* no wrap-alloc */
        } else {
            /* Non-overflow: only exercise a bounded allocation. */
            size_t aa = a % 4096, bb = b % 4096;
            void *p = brix_palloc_array(NULL, aa, bb);
            if (aa != 0 && bb != 0) { assert(p != NULL); }
            free(p);
        }
    }
    return 0;
}
