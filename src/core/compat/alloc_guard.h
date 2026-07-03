/*
 * alloc_guard.h — pool-allocation-with-OOM-guard helpers.
 *
 * WHAT: collapse the ubiquitous three-line idiom
 *
 *     dst = ngx_pcalloc(pool, n);
 *     if (dst == NULL) {
 *         return err;
 *     }
 *
 * into a single statement.  `err` is whatever the enclosing function returns on
 * out-of-memory — an ngx_int_t status (NGX_ERROR, NGX_HTTP_INTERNAL_SERVER_ERROR,
 * NGX_CONF_ERROR), a NULL pointer, or even a send-error call whose result is
 * returned.  The macros are a pure syntactic transform: each expands to exactly
 * the code it replaces, so behaviour is identical (the failure block must be a
 * bare `return`; sites that also log or free are intentionally left untouched).
 *
 * WHY: this idiom appears at ~100 sites across src/.  Centralising it removes the
 * boilerplate and makes the OOM-return uniform, without hiding the allocation
 * arguments (pool and size stay visible at the call site).
 */
#ifndef BRIX_COMPAT_ALLOC_GUARD_H
#define BRIX_COMPAT_ALLOC_GUARD_H

#include <ngx_core.h>

#define BRIX_PCALLOC_OR_RETURN(dst, pool, n, err)                            \
    do {                                                                       \
        (dst) = ngx_pcalloc((pool), (n));                                      \
        if ((dst) == NULL) {                                                   \
            return (err);                                                      \
        }                                                                      \
    } while (0)

#define BRIX_PALLOC_OR_RETURN(dst, pool, n, err)                             \
    do {                                                                       \
        (dst) = ngx_palloc((pool), (n));                                       \
        if ((dst) == NULL) {                                                   \
            return (err);                                                      \
        }                                                                      \
    } while (0)

#define BRIX_PNALLOC_OR_RETURN(dst, pool, n, err)                            \
    do {                                                                       \
        (dst) = ngx_pnalloc((pool), (n));                                      \
        if ((dst) == NULL) {                                                   \
            return (err);                                                      \
        }                                                                      \
    } while (0)

#endif /* BRIX_COMPAT_ALLOC_GUARD_H */
