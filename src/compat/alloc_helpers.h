/*
 * src/compat/alloc_helpers.h - Safe memory allocation helper macros.
 *
 * WHAT: Provides safe memory allocation macros that check for NULL and return
 *       error codes. Reduces boilerplate in configuration parsing and
 *       initialization code.
 *
 * WHY: Memory allocation patterns (alloc + NULL check + return error) repeat
 *      50+ times throughout the codebase. Centralizing into macros eliminates
 *      code duplication and ensures consistent error handling.
 *
 * HOW: Macros take care of allocation, NULL checking, and returning the
 *      appropriate error code (NGX_CONF_ERROR, NGX_ERROR, etc.) based on context.
 *      Do not use with variable-length arrays or complex expressions.
 */

#ifndef XROOTD_ALLOC_HELPERS_H
#define XROOTD_ALLOC_HELPERS_H

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* ---- NGX_ALLOC_OR_CONF_ERROR(ptr, pool, size) ----
 *
 * Allocate memory from pool; if allocation fails, return NGX_CONF_ERROR.
 * Used during configuration parsing.
 *
 * USAGE:
 *   char *buf;
 *   NGX_ALLOC_OR_CONF_ERROR(buf, cf->pool, 256);
 *   // buf is now allocated or function has returned NGX_CONF_ERROR
 */
#define NGX_ALLOC_OR_CONF_ERROR(ptr, pool, size)                     \
    do {                                                             \
        (ptr) = ngx_pnalloc((pool), (size));                         \
        if ((ptr) == NULL) {                                         \
            return NGX_CONF_ERROR;                                   \
        }                                                            \
    } while (0)

/* ---- NGX_ALLOC_OR_STREAM_ERROR(ptr, pool, size) ----
 *
 * Allocate memory from pool; if allocation fails, return NGX_ERROR
 * for stream module context.
 *
 * USAGE:
 *   char *buf;
 *   if (NGX_ALLOC_OR_STREAM_ERROR(buf, pool, 256) == NGX_ERROR) {
 *       return NGX_ERROR;
 *   }
 */
#define NGX_ALLOC_OR_STREAM_ERROR(ptr, pool, size)                   \
    do {                                                             \
        (ptr) = ngx_pnalloc((pool), (size));                         \
        if ((ptr) == NULL) {                                         \
            return NGX_ERROR;                                        \
        }                                                            \
    } while (0)

/* ---- NGX_ALLOC_OR_HTTP_ERROR(ptr, pool, size) ----
 *
 * Allocate memory from pool; if allocation fails, return NGX_ERROR
 * for HTTP module context.
 *
 * USAGE:
 *   char *buf;
 *   NGX_ALLOC_OR_HTTP_ERROR(buf, pool, 256);
 */
#define NGX_ALLOC_OR_HTTP_ERROR(ptr, pool, size)                     \
    do {                                                             \
        (ptr) = ngx_pnalloc((pool), (size));                         \
        if ((ptr) == NULL) {                                         \
            return NGX_ERROR;                                        \
        }                                                            \
    } while (0)

/* ---- NGX_ALLOC_PTR_OR_NULL(ptr, pool, size) ----
 *
 * Allocate memory from pool and assign to ptr. Returns NULL on failure.
 * Caller is responsible for checking ptr != NULL.
 *
 * USAGE:
 *   char *buf;
 *   NGX_ALLOC_PTR_OR_NULL(buf, pool, 256);
 *   if (buf == NULL) { handle_error(); }
 */
#define NGX_ALLOC_PTR_OR_NULL(ptr, pool, size)                       \
    ((ptr) = ngx_pnalloc((pool), (size)))

/* ---- NGX_CALLOC_OR_CONF_ERROR(ptr, pool, size) ----
 *
 * Allocate and zero-initialize memory from pool; if allocation fails,
 * return NGX_CONF_ERROR. Used during configuration parsing when memory
 * must be initialized to zero.
 *
 * USAGE:
 *   char *buf;
 *   NGX_CALLOC_OR_CONF_ERROR(buf, cf->pool, sizeof(*buf));
 */
#define NGX_CALLOC_OR_CONF_ERROR(ptr, pool, size)                    \
    do {                                                             \
        (ptr) = ngx_pcalloc((pool), (size));                         \
        if ((ptr) == NULL) {                                         \
            return NGX_CONF_ERROR;                                   \
        }                                                            \
    } while (0)

/* ---- NGX_CALLOC_OR_ERROR(ptr, pool, size) ----
 *
 * Allocate and zero-initialize memory from pool; if allocation fails,
 * return NGX_ERROR. Used in request/stream processing context.
 *
 * USAGE:
 *   MyStruct *s;
 *   NGX_CALLOC_OR_ERROR(s, pool, sizeof(*s));
 */
#define NGX_CALLOC_OR_ERROR(ptr, pool, size)                         \
    do {                                                             \
        (ptr) = ngx_pcalloc((pool), (size));                         \
        if ((ptr) == NULL) {                                         \
            return NGX_ERROR;                                        \
        }                                                            \
    } while (0)

#endif /* XROOTD_ALLOC_HELPERS_H */
