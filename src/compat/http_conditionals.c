/*
 * http_conditionals.c - shared HTTP conditional request checks (RFC 7232).
 *
 * WHAT: Evaluates If-None-Match, If-Match, If-Modified-Since, and Overwrite headers
 *       against resource metadata. Returns 304 Not Modified, 412 Precondition Failed,
 *       or NGX_OK (conditions pass) for each conditional type.
 *
 * WHY: RFC 7232 §3 requires servers to validate conditional requests before returning
 *      content. WebDAV PUT/MOVE/COPY and S3 GET/PUT all use these checks. Shared
 *      implementation ensures consistent behaviour across both modules.
 *
 * HOW: ETag path generates resource ETag from mtime/size, then compares against header
 *      list entries (case-insensitive, weak-equivalence support). Time path parses
 *      HTTP date via ngx_parse_http_time(), compares against st_mtime. Overwrite
 *      checks header value equals "F".
*/

#include "http_conditionals.h"
#include "etag.h"
#include "http_headers.h"

#include <string.h>

/*
 * xrootd_http_strip_weak - strip W/ prefix from ETag string.
 *
 * WHAT: If the data starts with "W/", advances data pointer by 2 and reduces len
 *       by 2. Otherwise leaves data and len unchanged.
 *
 * WHY: RFC 7232 §2.3 defines weak equivalence: W/"etag1" ≡ "etag1" for If-None-Match
 *      comparison. This helper normalises both resource ETag and header entries before
 *      string comparison when flags include XROOTD_HTTP_COND_WEAK_EQUIV.
 *
 * HOW: len >= 2 && data[0]=='W' && data[1]=='/' → data+=2, len-=2.
 */

static void
xrootd_http_strip_weak(const char **data, size_t *len)
{
    if (*len >= 2 && (*data)[0] == 'W' && (*data)[1] == '/') {
        *data += 2;
        *len -= 2;
    }
}

ngx_int_t
xrootd_http_etag_list_contains(const ngx_str_t *header, const char *etag,
    unsigned flags)
{
    const char *p;
    const char *end;
    const char *etag_data;
    size_t      etag_len;

    if (header == NULL || header->data == NULL || etag == NULL) {
        return NGX_DECLINED;
    }

    p = (const char *) header->data;
    end = p + header->len;
    etag_data = etag;
    etag_len = strlen(etag);

    if (flags & XROOTD_HTTP_COND_WEAK_EQUIV) {
        xrootd_http_strip_weak(&etag_data, &etag_len);
    }

    while (p < end) {
        const char *tok_start;
        const char *tok_end;
        size_t      tok_len;

        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        tok_start = p;
        while (p < end && *p != ',') {
            p++;
        }
        tok_end = p;

        while (tok_end > tok_start
               && (tok_end[-1] == ' ' || tok_end[-1] == '\t'))
        {
            tok_end--;
        }

        tok_len = (size_t) (tok_end - tok_start);
        if (flags & XROOTD_HTTP_COND_WEAK_EQUIV) {
            xrootd_http_strip_weak(&tok_start, &tok_len);
        }

        if (tok_len == etag_len
            && ngx_strncmp(tok_start, etag_data, tok_len) == 0)
        {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

ngx_int_t
xrootd_http_check_etag_preconditions(ngx_http_request_t *r,
    ngx_flag_t resource_exists, const struct stat *st, unsigned etag_flags,
    unsigned condition_flags)
{
    ngx_table_elt_t *if_match;
    ngx_table_elt_t *if_none_match;
    char             etag_buf[64];
    const char      *etag;

    if_match = r->headers_in.if_match;
    if_none_match = r->headers_in.if_none_match;

    if (if_match == NULL && if_none_match == NULL) {
        return NGX_OK;
    }

    etag = NULL;
    if (resource_exists && st != NULL) {
        xrootd_http_etag_str(etag_buf, sizeof(etag_buf),
                             st->st_mtime, st->st_size, etag_flags);
        etag = etag_buf;
    }

    if (if_match != NULL) {
        if (!resource_exists) {
            return NGX_HTTP_PRECONDITION_FAILED;
        }

        if (if_match->value.len == 1 && if_match->value.data[0] == '*') {
            /* wildcard match passed; If-None-Match below may still fail */
        } else if (xrootd_http_etag_list_contains(&if_match->value, etag,
                                                  condition_flags) != NGX_OK)
        {
            return NGX_HTTP_PRECONDITION_FAILED;
        }
    }

    if (if_none_match != NULL) {
        if (if_none_match->value.len == 1
            && if_none_match->value.data[0] == '*')
        {
            return resource_exists ? NGX_HTTP_PRECONDITION_FAILED : NGX_OK;
        }

        if (resource_exists
            && xrootd_http_etag_list_contains(&if_none_match->value, etag,
                                              condition_flags) == NGX_OK)
        {
            return NGX_HTTP_PRECONDITION_FAILED;
        }
    }

    return NGX_OK;
}

ngx_int_t
xrootd_http_check_if_modified_since(ngx_http_request_t *r, time_t mtime)
{
    ngx_str_t ims;
    time_t    ims_time;

    if (r->headers_in.if_modified_since == NULL) {
        return NGX_OK;
    }

    ims = r->headers_in.if_modified_since->value;
    ims_time = ngx_parse_http_time(ims.data, ims.len);
    if (ims_time != NGX_ERROR && mtime <= ims_time) {
        return NGX_HTTP_NOT_MODIFIED;
    }

    return NGX_OK;
}

ngx_flag_t
xrootd_http_overwrite_forbidden(ngx_http_request_t *r)
{
    ngx_table_elt_t *h;

    h = xrootd_http_find_header(r, "Overwrite", sizeof("Overwrite") - 1);
    return h != NULL && xrootd_http_header_value_equals(&h->value, "F");
}
