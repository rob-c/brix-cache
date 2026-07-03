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
 * brix_http_strip_weak - strip W/ prefix from ETag string.
 *
 * WHAT: If the data starts with "W/", advances data pointer by 2 and reduces len
 *       by 2. Otherwise leaves data and len unchanged.
 *
 * WHY: RFC 7232 §2.3 defines weak equivalence: W/"etag1" ≡ "etag1" for If-None-Match
 *      comparison. This helper normalises both resource ETag and header entries before
 *      string comparison when flags include BRIX_HTTP_COND_WEAK_EQUIV.
 *
 * HOW: len >= 2 && data[0]=='W' && data[1]=='/' → data+=2, len-=2.
 */

static void
brix_http_strip_weak(const char **data, size_t *len)
{
    if (*len >= 2 && (*data)[0] == 'W' && (*data)[1] == '/') {
        *data += 2;
        *len -= 2;
    }
}

ngx_int_t
brix_http_etag_list_contains(const ngx_str_t *header, const char *etag,
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

    if (flags & BRIX_HTTP_COND_WEAK_EQUIV) {
        brix_http_strip_weak(&etag_data, &etag_len);
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
        if (flags & BRIX_HTTP_COND_WEAK_EQUIV) {
            brix_http_strip_weak(&tok_start, &tok_len);
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
brix_http_check_etag_preconditions(ngx_http_request_t *r,
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
        brix_http_etag_str(etag_buf, sizeof(etag_buf),
                             st->st_mtime, st->st_size, etag_flags);
        etag = etag_buf;
    }

    if (if_match != NULL) {
        if (!resource_exists) {
            return NGX_HTTP_PRECONDITION_FAILED;
        }

        if (if_match->value.len == 1 && if_match->value.data[0] == '*') {
            /* wildcard match passed; If-None-Match below may still fail */
        } else if (brix_http_etag_list_contains(&if_match->value, etag,
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
            && brix_http_etag_list_contains(&if_none_match->value, etag,
                                              condition_flags) == NGX_OK)
        {
            return NGX_HTTP_PRECONDITION_FAILED;
        }
    }

    return NGX_OK;
}

/*
 * cond_header_present - is a conditional header usable?
 *
 * WHAT: True when the header exists with a non-empty value.
 * WHY: An empty conditional header is invalid per RFC 9110; treating it as
 *      absent (rather than as a never-matching list) keeps a malformed client
 *      from turning every request into a 412.
 * HOW: NULL / len check.
 */
static ngx_flag_t
cond_header_present(const ngx_table_elt_t *h)
{
    return h != NULL && h->value.len > 0;
}

/*
 * cond_is_wildcard - is the header value the `*` any-representation token?
 *
 * WHAT: True for a value that is exactly "*".
 * WHY: RFC 9110 §13.1.1/§13.1.2: `*` selects any existing representation and
 *      must be recognised before list matching.
 * HOW: Length-1 compare (nginx has already trimmed surrounding whitespace).
 */
static ngx_flag_t
cond_is_wildcard(const ngx_str_t *v)
{
    return v->len == 1 && v->data[0] == '*';
}

ngx_int_t
brix_http_eval_preconditions(ngx_http_request_t *r,
    ngx_flag_t resource_exists, time_t mtime, off_t size,
    unsigned etag_flags, unsigned condition_flags)
{
    ngx_table_elt_t *if_match = r->headers_in.if_match;
    ngx_table_elt_t *if_none  = r->headers_in.if_none_match;
    ngx_table_elt_t *if_unmod = r->headers_in.if_unmodified_since;
    ngx_table_elt_t *if_mod   = r->headers_in.if_modified_since;
    unsigned         read_mode = condition_flags & BRIX_HTTP_COND_READ;
    unsigned         time_mode = condition_flags & BRIX_HTTP_COND_TIME;
    char             etag_buf[64];
    const char      *etag = NULL;

    if (resource_exists) {
        brix_http_etag_str(etag_buf, sizeof(etag_buf), mtime, size,
                             etag_flags);
        etag = etag_buf;
    }

    /* 1. If-Match — fails (412) unless the representation exists and the
     *    validator selects it. */
    if (cond_header_present(if_match)) {
        if (!resource_exists) {
            return NGX_HTTP_PRECONDITION_FAILED;
        }
        if (!cond_is_wildcard(&if_match->value)
            && brix_http_etag_list_contains(&if_match->value, etag,
                                              condition_flags) != NGX_OK)
        {
            return NGX_HTTP_PRECONDITION_FAILED;
        }
    } else if (time_mode && cond_header_present(if_unmod)) {
        /* 2. If-Unmodified-Since — only when If-Match is absent. */
        time_t t = ngx_parse_http_time(if_unmod->value.data,
                                       if_unmod->value.len);
        if (t != (time_t) NGX_ERROR && mtime > t) {
            return NGX_HTTP_PRECONDITION_FAILED;
        }
    }

    /* 3. If-None-Match — a match means the client already holds (or must not
     *    overwrite) this representation: 304 on reads, 412 on writes. */
    if (cond_header_present(if_none)) {
        ngx_flag_t selected;

        if (cond_is_wildcard(&if_none->value)) {
            selected = resource_exists;
        } else {
            selected = resource_exists
                       && brix_http_etag_list_contains(&if_none->value, etag,
                                                         condition_flags)
                          == NGX_OK;
        }
        if (selected) {
            return read_mode ? NGX_HTTP_NOT_MODIFIED
                             : NGX_HTTP_PRECONDITION_FAILED;
        }
    } else if (read_mode && time_mode && cond_header_present(if_mod)) {
        /* 4. If-Modified-Since — reads only, when If-None-Match is absent.
         *    `before` semantics: not modified since the given date ⇒ 304. */
        time_t t = ngx_parse_http_time(if_mod->value.data, if_mod->value.len);
        if (t != (time_t) NGX_ERROR && mtime <= t) {
            return NGX_HTTP_NOT_MODIFIED;
        }
    }

    return NGX_OK;
}

ngx_int_t
brix_http_check_if_modified_since(ngx_http_request_t *r, time_t mtime)
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
brix_http_overwrite_forbidden(ngx_http_request_t *r)
{
    ngx_table_elt_t *h;

    h = brix_http_find_header(r, "Overwrite", sizeof("Overwrite") - 1);
    return h != NULL && brix_http_header_value_equals(&h->value, "F");
}
