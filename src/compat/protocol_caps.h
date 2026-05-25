#ifndef XROOTD_PROTOCOL_CAPS_H
#define XROOTD_PROTOCOL_CAPS_H

#include <ngx_http.h>

/*
 * protocol_caps.h — shared HTTP operation capability registry.
 *
 * Each protocol module (WebDAV, S3) keeps its own static operation table.
 * This header defines the shared descriptor shape and the two helper functions
 * that query and format those tables.
 *
 * Protocol-specific concerns (metric slots, auth decisions, dispatch routing)
 * stay in the protocol modules.  These helpers only answer:
 *   - which operation does this request map to?
 *   - what is the correct Allow / Access-Control-Allow-Methods string for the
 *     enabled set of operations?
 */

/* Capability flags — bitfield stored in xrootd_http_operation_t.flags. */
typedef enum {
    XROOTD_PROTO_OP_READ       = 0x0001,  /* safe, idempotent reads */
    XROOTD_PROTO_OP_WRITE      = 0x0002,  /* mutating operations */
    XROOTD_PROTO_OP_LIST       = 0x0004,  /* directory/bucket listing */
    XROOTD_PROTO_OP_TPC        = 0x0008,  /* third-party copy */
    XROOTD_PROTO_OP_LOCK       = 0x0010,  /* locking (LOCK/UNLOCK) */
    XROOTD_PROTO_OP_ASYNC_BODY = 0x0020   /* reads body asynchronously */
} xrootd_proto_op_flags_t;

/*
 * xrootd_http_operation_t — descriptor for one HTTP operation.
 *
 *   name         NUL-terminated uppercase method name (e.g. "GET", "PUT")
 *   http_method  nginx r->method constant (NGX_HTTP_GET etc.)
 *   metric_slot  protocol-local metric slot constant (e.g. XROOTD_WEBDAV_METHOD_GET)
 *   access_op    access-op enum value for auth/scope decisions (0 if not used)
 *   flags        bitmask of xrootd_proto_op_flags_t
 */
typedef struct {
    const char *name;
    ngx_uint_t  http_method;
    ngx_uint_t  metric_slot;
    ngx_uint_t  access_op;
    ngx_uint_t  flags;
} xrootd_http_operation_t;

/*
 * xrootd_http_operation_find — look up the operation descriptor for a request.
 *
 * Searches ops[0..nops) for the entry whose http_method matches r->method.
 * Returns a pointer to the matching entry, or NULL if none matches.
 */
const xrootd_http_operation_t *xrootd_http_operation_find(
    ngx_http_request_t *r,
    const xrootd_http_operation_t *ops, ngx_uint_t nops);

/*
 * xrootd_http_operation_allow_header — build an Allow header value string.
 *
 * Collects the names of all operations in ops[0..nops) whose flags field has
 * at least one bit in common with enabled_flags, then writes a
 * comma-separated list into *out using pool allocation.
 *
 * Pass enabled_flags = ~0u to include every operation in the table.
 * Pass enabled_flags = XROOTD_PROTO_OP_READ|XROOTD_PROTO_OP_LIST for a
 * read-only subset.
 *
 * Returns NGX_OK on success, NGX_ERROR on pool allocation failure.
 */
ngx_int_t xrootd_http_operation_allow_header(ngx_pool_t *pool,
    const xrootd_http_operation_t *ops, ngx_uint_t nops,
    ngx_uint_t enabled_flags, ngx_str_t *out);

#endif /* XROOTD_PROTOCOL_CAPS_H */
