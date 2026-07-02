/*
 * safe_size.h — Phase 27 W1: overflow-checked size arithmetic and array
 * allocation.
 *
 * WHAT: Header-only helpers that compute `a*b` / `a+b` with overflow detection
 * and allocate `n*sz`-byte arrays that return NULL (rather than a truncated,
 * heap-overflowing buffer) when the size computation would wrap.
 *
 * WHY: Anything whose size or count comes off the wire is attacker-controlled.
 * A `malloc(n * sizeof(*p))` where `n` derives from a client-supplied length or
 * segment count can silently wrap on 32-bit `size_t` math (or even 64-bit with
 * a large enough `n`), producing a tiny allocation that the caller then writes
 * `n` elements into — a classic heap overflow.  These helpers make the overflow
 * a clean NULL/error instead.
 *
 * HOW: Built on the compiler's `__builtin_*_overflow` intrinsics (GCC/Clang;
 * the module is already built with one of these).  All functions are
 * `static ngx_inline` so there is no new translation unit and no ./configure
 * change — include the header and call them.
 *
 * Adoption: convert every wire-driven `n * sizeof(...)` and `len + 1` size
 * computation to these helpers (start with the readv segment array and the
 * eviction-candidate realloc growth).
 */
#ifndef XROOTD_SHARED_SAFE_SIZE_H
#define XROOTD_SHARED_SAFE_SIZE_H

/* The fuzz harness (tests/fuzz/) compiles this header standalone and supplies
 * its own ngx_int_t/size_t/alloc shims; define XROOTD_SAFE_SIZE_STANDALONE to
 * skip the nginx includes in that mode. */
#ifndef XROOTD_SAFE_SIZE_STANDALONE
#include <ngx_config.h>
#include <ngx_core.h>
#endif

/* Multiply: *out = a*b.  Returns NGX_OK on success, NGX_ERROR on overflow
 * (in which case *out is left unspecified — callers must not use it). */
static ngx_inline ngx_int_t
xrootd_size_mul(size_t a, size_t b, size_t *out)
    __attribute__((warn_unused_result));

static ngx_inline ngx_int_t
xrootd_size_mul(size_t a, size_t b, size_t *out)
{
#if defined(__GNUC__) || defined(__clang__)
    if (__builtin_mul_overflow(a, b, out)) {
        return NGX_ERROR;
    }
    return NGX_OK;
#else
    if (a != 0 && b > (size_t) -1 / a) {
        return NGX_ERROR;
    }
    *out = a * b;
    return NGX_OK;
#endif
}

/* Add: *out = a+b.  Returns NGX_OK / NGX_ERROR (on wrap). */
static ngx_inline ngx_int_t
xrootd_size_add(size_t a, size_t b, size_t *out)
    __attribute__((warn_unused_result));

static ngx_inline ngx_int_t
xrootd_size_add(size_t a, size_t b, size_t *out)
{
#if defined(__GNUC__) || defined(__clang__)
    if (__builtin_add_overflow(a, b, out)) {
        return NGX_ERROR;
    }
    return NGX_OK;
#else
    if (b > (size_t) -1 - a) {
        return NGX_ERROR;
    }
    *out = a + b;
    return NGX_OK;
#endif
}

/*
 * Allocate an n-element array of sz-byte elements from a pool.
 * Returns NULL on overflow OR allocation failure — a single check at the
 * callsite covers both.
 */
static ngx_inline void *
xrootd_palloc_array(ngx_pool_t *pool, size_t n, size_t sz)
    __attribute__((warn_unused_result, malloc, alloc_size(2, 3)));

static ngx_inline void *
xrootd_palloc_array(ngx_pool_t *pool, size_t n, size_t sz)
{
    size_t total;

    if (xrootd_size_mul(n, sz, &total) != NGX_OK || total == 0) {
        return NULL;
    }
    return ngx_palloc(pool, total);
}

/* Same, zero-initialised. */
static ngx_inline void *
xrootd_pcalloc_array(ngx_pool_t *pool, size_t n, size_t sz)
    __attribute__((warn_unused_result, alloc_size(2, 3)));

static ngx_inline void *
xrootd_pcalloc_array(ngx_pool_t *pool, size_t n, size_t sz)
{
    size_t total;

    if (xrootd_size_mul(n, sz, &total) != NGX_OK || total == 0) {
        return NULL;
    }
    return ngx_pcalloc(pool, total);
}

/*
 * Heap (non-pool) array allocation for the long-lived stream path, where a
 * connection/persistent buffer outlives any request pool.  Returns NULL on
 * overflow or OOM; free with ngx_free().
 */
static ngx_inline void *
xrootd_alloc_array(ngx_log_t *log, size_t n, size_t sz)
    __attribute__((warn_unused_result, malloc, alloc_size(2, 3)));

static ngx_inline void *
xrootd_alloc_array(ngx_log_t *log, size_t n, size_t sz)
{
    size_t total;

    if (xrootd_size_mul(n, sz, &total) != NGX_OK || total == 0) {
        return NULL;
    }
    return ngx_alloc(total, log);
}

#endif /* XROOTD_SHARED_SAFE_SIZE_H */
