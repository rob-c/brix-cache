#ifndef BRIX_COMPAT_HTTP_HEADERS_H
#define BRIX_COMPAT_HTTP_HEADERS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * Shared HTTP header helpers for request lookup, value comparison, bearer
 * extraction, and safe response-header insertion.
 */
/*
 * Case-insensitive lookup of a request header (headers_in) by name (name_len
 * bytes, no NUL needed). Returns a borrowed pointer into the request's header
 * list (do not free); NULL if absent or if r/name is NULL.
 */
ngx_table_elt_t *brix_http_find_header(ngx_http_request_t *r,
    const char *name, size_t name_len);
/*
 * Convenience over find_header: returns the matching request header's value as
 * a borrowed ngx_str_t (points into the request, valid for the request's life;
 * do not free/modify). Missing header yields the empty string (len 0, NULL data).
 */
ngx_str_t brix_http_get_header(ngx_http_request_t *r, const char *name);
/*
 * Parse an "Authorization: Bearer <token>" value. On success token_out is a
 * no-copy slice into auth_header (trimmed of surrounding whitespace); do not
 * free. token_out is always cleared first. Returns NGX_OK on a valid bearer
 * token, NGX_DECLINED if the scheme is absent/not Bearer, NGX_ERROR if
 * token_out is NULL or the token is empty after the scheme.
 */
ngx_int_t brix_http_extract_bearer(const ngx_str_t *auth_header,
    ngx_str_t *token_out);
/*
 * Decode %XX and '+' in a NUL-terminated string in place; returns the new length.
 * Invalid %XX sequences are passed through verbatim. Shared by query-arg decoding
 * and URL-encoded form parsing.
 */
size_t brix_urldecode_inplace(char *str);
/*
 * Look up query-string argument `name` (name_len bytes) in r->args and copy its
 * raw (still %XX-encoded) value into a freshly pool-allocated, NUL-terminated
 * buffer at *out. Returns NGX_OK with *out set, NGX_DECLINED if absent, or
 * NGX_ERROR on allocation failure. The caller may decode in place with
 * brix_urldecode_inplace().
 */
ngx_int_t brix_http_arg(ngx_http_request_t *r, const char *name,
    size_t name_len, ngx_str_t *out);
/*
 * Redact the value of every "authz="/"access_token=" query key, in place and
 * LENGTH-PRESERVING (each value byte → 'x', no shrink/memmove), so a bearer token
 * presented via the URL never reaches a log line. Safe to apply to the overlapping
 * log sources r->args, r->unparsed_uri and r->request_line (their independent ->len
 * fields stay valid). Idempotent; other args preserved.
 */
void brix_http_redact_query_token(ngx_str_t *query);
/*
 * Returns 1 (treat as unsafe) if data[0..len) contains any byte < 0x20 or 0x7F
 * (DEL), else 0. NULL data returns 1. Note: HTAB (0x09) is reported as a ctl.
 */
ngx_int_t brix_http_str_has_ctl(const u_char *data, size_t len);
/*
 * Whitespace-trimmed, case-insensitive equality of a header value against a
 * NUL-terminated literal; requires exact length match after trimming SP/HTAB.
 * Returns 1 if equal, 0 otherwise (0 also if value/literal/value->data is NULL).
 */
ngx_int_t brix_http_header_value_equals(const ngx_str_t *value,
    const char *literal);
/*
 * Map an nginx handler return code to the HTTP status to record/report:
 * NGX_ERROR -> 500; an explicit status rc (>= NGX_HTTP_SPECIAL_RESPONSE) wins;
 * else r->headers_out.status if a handler set it; else 200. r may be NULL.
 */
ngx_uint_t brix_http_effective_status(ngx_http_request_t *r,
    ngx_int_t rc);
/*
 * Append a response header (headers_out). key is aliased, not copied, so it
 * must remain valid for the response (use a string literal/long-lived buffer).
 * If copy_value, the value bytes are ngx_pstrdup'd into r->pool; otherwise the
 * value struct is aliased and its bytes must outlive the response. *out (if
 * non-NULL) receives the pushed element, and is cleared on any failure path.
 * Returns NGX_OK or NGX_HTTP_INTERNAL_SERVER_ERROR (alloc failure or NULL arg).
 */
ngx_int_t brix_http_set_header_str(ngx_http_request_t *r, const char *key,
    const ngx_str_t *value, ngx_flag_t copy_value, ngx_table_elt_t **out);
/*
 * Append a response header from NUL-terminated strings; the value is always
 * copied into r->pool. key is aliased (must be long-lived). See set_header_str
 * for *out semantics. Returns NGX_OK or NGX_HTTP_INTERNAL_SERVER_ERROR.
 */
ngx_int_t brix_http_set_header(ngx_http_request_t *r, const char *key,
    const char *value, ngx_table_elt_t **out);
/*
 * Append a response header whose value is the decimal rendering of value (long).
 * The rendered value is copied into r->pool; key is aliased (must be long-lived).
 * Does not expose the pushed element. Returns NGX_OK or NGX_HTTP_INTERNAL_SERVER_ERROR.
 */
ngx_int_t brix_http_set_header_num(ngx_http_request_t *r,
    const char *key, long value);

/* Canonical source-code location for this software (AGPL-3.0). */
#ifndef BRIX_SOURCE_URL
#define BRIX_SOURCE_URL  "https://github.com/rob-c/nginx-xrootd"
#endif

/*
 * AGPL-3.0 section 13: prominently offer remote users the Corresponding Source.
 * Adds an "X-Source" response header pointing at BRIX_SOURCE_URL.  Best-effort
 * (a header allocation failure is ignored) — call once per HTTP request, early,
 * from each HTTP-facing handler (WebDAV, S3, dashboard, metrics, SRR).
 */
void brix_http_source_offer(ngx_http_request_t *r);
/*
 * Append a header to the REQUEST list (headers_in), used to inject/forward
 * headers (e.g. for proxying/TPC) rather than to respond. The value is copied
 * into r->pool and the lowercase hash is computed; key is aliased (must be
 * long-lived). *out (if non-NULL) receives the element, cleared on failure.
 * Returns NGX_OK or NGX_HTTP_INTERNAL_SERVER_ERROR.
 */
ngx_int_t brix_http_request_header_add(ngx_http_request_t *r,
    const char *key, const char *value, ngx_table_elt_t **out);

#endif /* BRIX_COMPAT_HTTP_HEADERS_H */
