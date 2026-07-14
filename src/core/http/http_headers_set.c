/*
 * http_headers_set.c - shared HTTP header construction/mutation helpers.
 *
 * WHAT: Builds and inserts headers rather than inspecting them — maps an nginx
 *       handler return code to the HTTP status to record, pushes response
 *       headers onto r->headers_out (from an ngx_str_t, a NUL-terminated string,
 *       or a decimal number), emits the AGPL-3.0 X-Source offer header, and
 *       injects a header onto the REQUEST list (r->headers_in) for proxy/TPC
 *       forwarding.
 *
 * WHY: Split from http_headers.c at the phase-79 500-line cap. That file mixes
 *      two distinct concerns — reading/parsing request data (header lookup,
 *      value comparison, bearer extraction, query args) and WRITING/constructing
 *      headers. This file owns the write side so each half stays under the cap
 *      and focused; both share the one public header http_headers.h and there is
 *      no cross-file static call, so nothing here is exported beyond that header.
 *
 * HOW: effective_status applies the response-metric status policy; set_header_str
 *      pushes an ngx_table_elt_t via ngx_list_push and optionally ngx_pstrdup's
 *      the value; set_header/set_header_num/source_offer are thin wrappers over
 *      it; request_header_add pushes onto headers_in with a lowercase hash.
 */

#include "http_headers.h"

#include <stdio.h>

/*
 * brix_http_effective_status - convert an nginx handler rc to an HTTP status.
 *
 * WHAT: Applies the project-wide response-metric status policy: NGX_ERROR is
 *       recorded as 500, explicit NGX_HTTP_* returns win, headers_out.status is
 *       used when a handler set it before returning NGX_OK, and the default is
 *       200 OK.
 *
 * WHY: WebDAV and S3 response metrics both need the same handler-return-code
 *      interpretation.  Keeping it here prevents 2xx/4xx/5xx bucket drift.
 */
ngx_uint_t
brix_http_effective_status(ngx_http_request_t *r, ngx_int_t rc)
{
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return (ngx_uint_t) rc;
    }

    if (r != NULL && r->headers_out.status != 0) {
        return r->headers_out.status;
    }

    return NGX_HTTP_OK;
}

/*
 * brix_http_set_header_str - insert header into headers_out with optional value copy and pointer return.
 *
 * WHAT: Pushes a new ngx_table_elt_t onto r->headers_out.headers list. Sets
 *       key from const char (hash=1), value either copied via ngx_pstrdup or
 *      set directly from value struct. Optionally returns h pointer via out.
 *
 * WHY: WebDAV and S3 both need to construct response headers dynamically (ETag,
 *      Content-Range, CORS). This function handles pool allocation, key/value
 *      setup, and optional caller-pointer return in one call.
 *
 * HOW: ngx_list_push(&r->headers_out.headers) → set hash=1, key from strlen(key),
 *      value: if copy_value → ngx_pstrdup(r->pool, value); else h->value=*value.
 *      If out != NULL → *out = h. Return NGX_OK or NGX_HTTP_INTERNAL_SERVER_ERROR.
 */

ngx_int_t
brix_http_set_header_str(ngx_http_request_t *r, const char *key,
    const ngx_str_t *value, ngx_flag_t copy_value, ngx_table_elt_t **out)
{
    ngx_table_elt_t *h;

    if (out != NULL) {
        *out = NULL;
    }

    if (r == NULL || key == NULL || value == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    h->key.len = ngx_strlen(key);
    h->key.data = (u_char *) key;

    if (copy_value) {
        h->value.data = ngx_pstrdup(r->pool, (ngx_str_t *) value);
        if (h->value.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        h->value.len = value->len;

    } else {
        h->value = *value;
    }

    if (out != NULL) {
        *out = h;
    }

    return NGX_OK;
}

/*
 * brix_http_set_header - convenience wrapper: set header from const char value with copy.
 *
 * WHAT: Converts value to ngx_str_t (strlen + cast), then calls
 *       brix_http_set_header_str(r, key, &v, 1, out) — always copies value,
 *      optionally returns pointer via out.
 *
 * WHY: Most callers have a const char* ETag string or similar and want it set
 *      as a header with pool copy. This wrapper avoids constructing the ngx_str_t
 *      manually before calling set_header_str.
 *
 * HOW: v.len = strlen(value); v.data = (u_char*)value → set_header_str(r, key, &v, 1, out).
 */

ngx_int_t
brix_http_set_header(ngx_http_request_t *r, const char *key,
    const char *value, ngx_table_elt_t **out)
{
    ngx_str_t v;

    if (value == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    v.len = ngx_strlen(value);
    v.data = (u_char *) value;

    return brix_http_set_header_str(r, key, &v, 1, out);
}

ngx_int_t
brix_http_set_header_num(ngx_http_request_t *r, const char *key, long value)
{
    char      buf[32];
    int       n;
    ngx_str_t v;

    n = snprintf(buf, sizeof(buf), "%ld", value);
    if (n < 0 || (size_t) n >= sizeof(buf)) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    v.len = (size_t) n;
    v.data = (u_char *) buf;

    return brix_http_set_header_str(r, key, &v, 1, NULL);
}

void
brix_http_source_offer(ngx_http_request_t *r)
{
    /* AGPL-3.0 sec.13: prominently offer remote users the Corresponding Source.
     * Best-effort — a header allocation failure must never fail the request. */
    static const ngx_str_t  src =
        ngx_string(BRIX_SOURCE_URL " (nginx-xrootd, AGPL-3.0)");

    (void) brix_http_set_header_str(r, "X-Source", &src, 0, NULL);
}

ngx_int_t
brix_http_request_header_add(ngx_http_request_t *r, const char *key,
    const char *value, ngx_table_elt_t **out)
{
    ngx_table_elt_t *h;
    ngx_str_t        v;

    if (out != NULL) {
        *out = NULL;
    }

    if (r == NULL || key == NULL || value == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = ngx_hash_key_lc((u_char *) key, ngx_strlen(key));
    h->key.len = ngx_strlen(key);
    h->key.data = (u_char *) key;

    v.len = ngx_strlen(value);
    v.data = (u_char *) value;
    h->value.data = ngx_pstrdup(r->pool, &v);
    if (h->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->value.len = v.len;

    if (out != NULL) {
        *out = h;
    }

    return NGX_OK;
}
