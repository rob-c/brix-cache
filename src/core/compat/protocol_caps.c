/*
 * protocol_caps.c — shared HTTP operation capability registry helpers.
 *
 * These two thin functions are reused by WebDAV and S3 to query and format
 * their per-protocol operation tables.  All protocol-specific knowledge
 * (which operations exist, what their metric slots are) stays in the caller's
 * table; the helpers just search and format.
 */

#include "protocol_caps.h"
#include "alloc_guard.h"

const brix_http_operation_t *
brix_http_operation_find(ngx_http_request_t *r,
    const brix_http_operation_t *ops, ngx_uint_t nops)
{
    ngx_uint_t i;

    for (i = 0; i < nops; i++) {
        if (ops[i].http_method != 0 && ops[i].http_method == r->method) {
            return &ops[i];
        }

        if (r->method_name.len == ngx_strlen(ops[i].name)
            && ngx_strncmp(r->method_name.data, ops[i].name,
                           r->method_name.len) == 0)
        {
            return &ops[i];
        }
    }
    return NULL;
}

ngx_int_t
brix_http_operation_allow_header(ngx_pool_t *pool,
    const brix_http_operation_t *ops, ngx_uint_t nops,
    ngx_uint_t enabled_flags, ngx_str_t *out)
{
    size_t      total = 0;
    ngx_uint_t  i;
    u_char     *p;
    int         first;

    /* First pass: compute total length of the comma-separated list. */
    for (i = 0; i < nops; i++) {
        if (ops[i].flags & enabled_flags) {
            total += ngx_strlen(ops[i].name) + 2;  /* ", " separator */
        }
    }

    if (total == 0) {
        out->len  = 0;
        out->data = (u_char *) "";
        return NGX_OK;
    }

    /* Second pass: write the string. */
    BRIX_PALLOC_OR_RETURN(p, pool, total + 1, NGX_ERROR);

    out->data = p;
    first = 1;

    for (i = 0; i < nops; i++) {
        if (ops[i].flags & enabled_flags) {
            size_t nlen = ngx_strlen(ops[i].name);
            if (!first) {
                *p++ = ',';
                *p++ = ' ';
            }
            ngx_memcpy(p, ops[i].name, nlen);
            p    += nlen;
            first = 0;
        }
    }
    *p = '\0';

    out->len = (size_t)(p - out->data);
    return NGX_OK;
}
