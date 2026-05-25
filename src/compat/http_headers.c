/*
 * http_headers.c - shared HTTP request/response header helpers.
 *
 * WHAT: Finds, reads, sets, and compares HTTP headers in nginx requests (headers_in)
 *       and responses (headers_out). Supports case-insensitive name lookup,
 *       control-character validation, whitespace-trimmed value comparison,
 *      and safe header insertion with pool allocation.
 *
 * WHY: WebDAV and S3 modules both read request headers (If-None-Match, Range,
 *      Overwrite) and write response headers (ETag, Content-Range). Shared
 *      implementation prevents duplicated list traversal, alloc patterns,
 *      and comparison logic across the two HTTP protocols.
 *
 * HOW: find_header walks r->headers_in.headers.part chain with ngx_strncasecmp;
 *      set_header pushes to r->headers_out.headers via ngx_list_push; value_equals
 *      trims whitespace then case-insensitive compares. ctl check rejects bytes <0x20/0x7F.
*/

#include "http_headers.h"

#include <stdio.h>
#include <string.h>

/*
 * xrootd_http_find_header - search headers_in list by name (case-insensitive).
 *
 * WHAT: Iterates r->headers_in.headers.part → next parts, comparing each header
 *       key against name using ngx_strncasecmp. Returns pointer to matching
 *      ngx_table_elt_t or NULL if not found.
 *
 * WHY: HTTP headers are stored in nginx's linked-list structure (ngx_list_part_t).
 *      Both WebDAV and S3 need to look up specific headers (If-None-Match,
 *      Range, Overwrite) without knowing which part of the list they reside in.
 *
 * HOW: Walk r->headers_in.headers.part → next until end. Compare key.len == name_len
 *      && ngx_strncasecmp(key.data, name, name_len). Return match or NULL.
 */

ngx_table_elt_t *
xrootd_http_find_header(ngx_http_request_t *r, const char *name,
    size_t name_len)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *hdr;
    ngx_uint_t       i;

    if (r == NULL || name == NULL) {
        return NULL;
    }

    part = &r->headers_in.headers.part;
    hdr = part->elts;

    for (;;) {
        for (i = 0; i < part->nelts; i++) {
            if (hdr[i].key.len == name_len
                && ngx_strncasecmp(hdr[i].key.data,
                                   (u_char *) name, name_len) == 0)
            {
                return &hdr[i];
            }
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        hdr = part->elts;
    }

    return NULL;
}

/*
 * xrootd_http_get_header - convenience wrapper: find header and return value as ngx_str_t.
 *
 * WHAT: Calls xrootd_http_find_header() with the given name, returns h->value as
 *       ngx_str_t if found, or ngx_null_string (empty) if not found.
 *
 * WHY: Callers frequently need just the header value bytes without the full
 *      ngx_table_elt_t struct. This wrapper avoids repeated find_header calls
 *      and provides a safe null return for missing headers.
 *
 * HOW: find_header(name, strlen(name)) → if NULL return ngx_null_string,
 *      else return h->value.
 */

ngx_str_t
xrootd_http_get_header(ngx_http_request_t *r, const char *name)
{
    ngx_table_elt_t *h;

    h = xrootd_http_find_header(r, name, ngx_strlen(name));
    if (h == NULL) {
        return (ngx_str_t) ngx_null_string;
    }

    return h->value;
}

/*
 * xrootd_http_extract_bearer - parse "Authorization: Bearer <token>".
 *
 * WHAT: Returns a no-copy token slice when the auth scheme is Bearer,
 *       matching the scheme case-insensitively and trimming optional
 *       whitespace around the token value.
 *
 * WHY: WebDAV token auth and HTTP-TPC credential delegation both need this
 *      parsing.  Keeping it here prevents auth-scheme case bugs from
 *      reappearing in individual protocol handlers.
 */
ngx_int_t
xrootd_http_extract_bearer(const ngx_str_t *auth_header, ngx_str_t *token_out)
{
    static const u_char bearer[] = "Bearer";
    u_char             *p;
    u_char             *end;
    size_t              bearer_len = sizeof(bearer) - 1;

    if (token_out == NULL) {
        return NGX_ERROR;
    }

    token_out->data = NULL;
    token_out->len = 0;

    if (auth_header == NULL || auth_header->data == NULL) {
        return NGX_DECLINED;
    }

    p = auth_header->data;
    end = auth_header->data + auth_header->len;

    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }

    if ((size_t) (end - p) < bearer_len
        || ngx_strncasecmp(p, (u_char *) bearer, bearer_len) != 0)
    {
        return NGX_DECLINED;
    }

    p += bearer_len;
    if (p >= end || (*p != ' ' && *p != '\t')) {
        return NGX_DECLINED;
    }

    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }
    while (end > p && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }

    if (p >= end) {
        return NGX_ERROR;
    }

    token_out->data = p;
    token_out->len = (size_t) (end - p);
    return NGX_OK;
}

/*
 * xrootd_http_str_has_ctl - check for HTTP control characters in string data.
 *
 * WHAT: Scans data[0..len] for bytes < 0x20 (space) or == 0x7F (DEL). Returns
 *       1 if any found, 0 if clean. NULL data returns 1 (unsafe).
 *
 * WHY: RFC 7230 §3 restricts header values to visible characters (0x21-0x7E)
 *      plus HTAB (0x09). Control bytes in path strings or header values can
 *      cause log corruption, injection, or parsing ambiguity. This check
 *      validates user-supplied strings before use.
 *
 * HOW: for(i=0..len): if data[i]<0x20 || data[i]==0x7F → return 1. Else return 0.
 */

ngx_int_t
xrootd_http_str_has_ctl(const u_char *data, size_t len)
{
    size_t i;

    if (data == NULL) {
        return 1;
    }

    for (i = 0; i < len; i++) {
        if (data[i] < 0x20 || data[i] == 0x7f) {
            return 1;
        }
    }

    return 0;
}

/*
 * xrootd_http_header_value_equals - case-insensitive literal comparison with whitespace trim.
 *
 * WHAT: Strips leading/trailing space and tab from value->data, then compares
 *       the trimmed length and bytes against literal using ngx_strncasecmp.
 *      Returns 1 (true) or 0 (false).
 *
 * WHY: HTTP header values may contain optional whitespace per RFC 7230 §3.2.
 *      Comparisons for "F" (Overwrite), "T", etc. must ignore leading/trailing
 *      whitespace while still enforcing exact length match after trimming.
 *
 * HOW: trim start past ' '/'\t'; trim end back past ' '/'\t'. Compare len==strlen(literal)
 *      && ngx_strncasecmp(trimmed, literal, literal_len). Return result.
 */

ngx_int_t
xrootd_http_header_value_equals(const ngx_str_t *value, const char *literal)
{
    u_char *start;
    u_char *end;
    size_t  len;
    size_t  literal_len;

    if (value == NULL || literal == NULL || value->data == NULL) {
        return 0;
    }

    start = value->data;
    end = value->data + value->len;

    while (start < end && (*start == ' ' || *start == '\t')) {
        start++;
    }
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }

    len = (size_t) (end - start);
    literal_len = strlen(literal);

    return len == literal_len
           && ngx_strncasecmp(start, (u_char *) literal, literal_len) == 0;
}

/*
 * xrootd_http_effective_status - convert an nginx handler rc to an HTTP status.
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
xrootd_http_effective_status(ngx_http_request_t *r, ngx_int_t rc)
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
 * xrootd_http_set_header_str - insert header into headers_out with optional value copy and pointer return.
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
xrootd_http_set_header_str(ngx_http_request_t *r, const char *key,
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
 * xrootd_http_set_header - convenience wrapper: set header from const char value with copy.
 *
 * WHAT: Converts value to ngx_str_t (strlen + cast), then calls
 *       xrootd_http_set_header_str(r, key, &v, 1, out) — always copies value,
 *      optionally returns pointer via out.
 *
 * WHY: Most callers have a const char* ETag string or similar and want it set
 *      as a header with pool copy. This wrapper avoids constructing the ngx_str_t
 *      manually before calling set_header_str.
 *
 * HOW: v.len = strlen(value); v.data = (u_char*)value → set_header_str(r, key, &v, 1, out).
 */

ngx_int_t
xrootd_http_set_header(ngx_http_request_t *r, const char *key,
    const char *value, ngx_table_elt_t **out)
{
    ngx_str_t v;

    if (value == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    v.len = ngx_strlen(value);
    v.data = (u_char *) value;

    return xrootd_http_set_header_str(r, key, &v, 1, out);
}

ngx_int_t
xrootd_http_set_header_num(ngx_http_request_t *r, const char *key, long value)
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

    return xrootd_http_set_header_str(r, key, &v, 1, NULL);
}

ngx_int_t
xrootd_http_request_header_add(ngx_http_request_t *r, const char *key,
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
