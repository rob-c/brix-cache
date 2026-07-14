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

/*
 * brix_http_next_etag_token - pull the next comma-separated entry from an ETag list.
 *
 * WHAT: Advances *cursor past leading separators, then captures one entry up to the
 *       next comma (trailing spaces/tabs trimmed). Returns 1 with tok_start/tok_len set
 *       when an entry was found, 0 (cursor at end) when the list is exhausted.
 *
 * WHY: If-Match / If-None-Match carry a comma-separated list of entity-tags
 *      (RFC 7232 §2.3, §3.1). Isolating the tokeniser keeps the comparison loop in
 *      brix_http_etag_list_contains flat and independently testable.
 *
 * HOW: 1. Skip leading ' ', '\t', ','. 2. If at end, publish cursor and return 0.
 *      3. Mark start; scan to next ',' or end. 4. Trim trailing OWS. 5. Publish
 *      cursor, token start and length; return 1.
 */

static ngx_flag_t
brix_http_next_etag_token(const char **cursor, const char *end,
    const char **tok_start, size_t *tok_len)
{
    const char *p = *cursor;
    const char *start;
    const char *stop;

    while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
        p++;
    }
    if (p >= end) {
        *cursor = p;
        return 0;
    }

    start = p;
    while (p < end && *p != ',') {
        p++;
    }
    stop = p;

    while (stop > start && (stop[-1] == ' ' || stop[-1] == '\t')) {
        stop--;
    }

    *cursor = p;
    *tok_start = start;
    *tok_len = (size_t) (stop - start);
    return 1;
}

ngx_int_t
brix_http_etag_list_contains(const ngx_str_t *header, const char *etag,
    unsigned flags)
{
    const char *cursor;
    const char *end;
    const char *etag_data;
    size_t      etag_len;
    const char *tok_start;
    size_t      tok_len;

    if (header == NULL || header->data == NULL || etag == NULL) {
        return NGX_DECLINED;
    }

    cursor = (const char *) header->data;
    end = cursor + header->len;
    etag_data = etag;
    etag_len = strlen(etag);

    if (flags & BRIX_HTTP_COND_WEAK_EQUIV) {
        brix_http_strip_weak(&etag_data, &etag_len);
    }

    while (brix_http_next_etag_token(&cursor, end, &tok_start, &tok_len)) {
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

/*
 * brix_http_validator_selects - does an entity-tag validator select this resource?
 *
 * WHAT: Returns true when the header value (a `*` wildcard or a comma-separated
 *       entity-tag list) selects the current representation. A missing resource is
 *       never selected.
 *
 * WHY: RFC 7232 §3.1/§3.2 define the same "does this validator match the selected
 *      representation" test for both If-Match and If-None-Match — the two differ only
 *      in what they do with the answer. Sharing the predicate keeps that answer
 *      byte-identical across every conditional callsite.
 *
 * HOW: 1. No representation ⇒ not selected. 2. `*` ⇒ selected (a representation
 *      exists). 3. Otherwise the list must contain the resource's entity-tag.
 */

static ngx_flag_t
brix_http_validator_selects(const ngx_str_t *value, ngx_flag_t resource_exists,
    const char *etag, unsigned condition_flags)
{
    if (!resource_exists) {
        return 0;
    }
    if (cond_is_wildcard(value)) {
        return 1;
    }
    return brix_http_etag_list_contains(value, etag, condition_flags) == NGX_OK;
}

/*
 * brix_http_eval_if_unmodified_since - apply an If-Unmodified-Since precondition.
 *
 * WHAT: Returns NGX_HTTP_PRECONDITION_FAILED (412) when the resource was modified
 *       after the header date, otherwise NGX_DECLINED (precondition passes / proceed).
 *
 * WHY: RFC 7232 §3.4: a write must not proceed if the representation changed since the
 *      client last saw it. An unparseable date is ignored (treated as passing) per the
 *      same section.
 *
 * HOW: Parse the HTTP date; if valid and mtime is strictly newer, fail with 412.
 */

static ngx_int_t
brix_http_eval_if_unmodified_since(const ngx_table_elt_t *if_unmod, time_t mtime)
{
    time_t t = ngx_parse_http_time(if_unmod->value.data, if_unmod->value.len);

    if (t != (time_t) NGX_ERROR && mtime > t) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }
    return NGX_DECLINED;
}

/*
 * brix_http_eval_if_modified_since - apply an If-Modified-Since precondition.
 *
 * WHAT: Returns NGX_HTTP_NOT_MODIFIED (304) when the resource has not been modified
 *       since the header date, otherwise NGX_DECLINED (precondition passes / proceed).
 *
 * WHY: RFC 7232 §3.3: a GET may be short-circuited to 304 when the client's cached
 *      copy is still current. An unparseable date is ignored (treated as modified).
 *
 * HOW: Parse the HTTP date; if valid and mtime is at or before it, return 304.
 */

static ngx_int_t
brix_http_eval_if_modified_since(const ngx_table_elt_t *if_mod, time_t mtime)
{
    time_t t = ngx_parse_http_time(if_mod->value.data, if_mod->value.len);

    if (t != (time_t) NGX_ERROR && mtime <= t) {
        return NGX_HTTP_NOT_MODIFIED;
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

    /* If-Match: fail unless the validator selects the existing representation. */
    if (if_match != NULL
        && !brix_http_validator_selects(&if_match->value, resource_exists, etag,
                                         condition_flags))
    {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    /* If-None-Match: fail when the validator DOES select it (write semantics). */
    if (if_none_match != NULL
        && brix_http_validator_selects(&if_none_match->value, resource_exists,
                                       etag, condition_flags))
    {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    return NGX_OK;
}

/*
 * brix_http_eval_match_group - first RFC-7232 precedence step (If-Match, else
 *                              If-Unmodified-Since).
 *
 * WHAT: Returns NGX_HTTP_PRECONDITION_FAILED (412) when the step's precondition fails,
 *       otherwise NGX_DECLINED (proceed to the If-None-Match step).
 *
 * WHY: RFC 7232 §6 fixes the order: If-Match takes precedence and, when it is absent,
 *      If-Unmodified-Since is evaluated in its place (the two are mutually exclusive at
 *      this step). Encapsulating the pair preserves that "else" relationship exactly.
 *
 * HOW: 1. If-Match present ⇒ 412 unless the validator selects the representation;
 *      otherwise proceed. 2. Else, in time mode, an If-Unmodified-Since header is
 *      applied. 3. Neither present ⇒ proceed.
 */

static ngx_int_t
brix_http_eval_match_group(ngx_table_elt_t *if_match, ngx_table_elt_t *if_unmod,
    ngx_flag_t resource_exists, const char *etag, unsigned condition_flags,
    unsigned time_mode, time_t mtime)
{
    if (cond_header_present(if_match)) {
        if (!brix_http_validator_selects(&if_match->value, resource_exists, etag,
                                         condition_flags))
        {
            return NGX_HTTP_PRECONDITION_FAILED;
        }
        return NGX_DECLINED;
    }

    if (time_mode && cond_header_present(if_unmod)) {
        return brix_http_eval_if_unmodified_since(if_unmod, mtime);
    }

    return NGX_DECLINED;
}

/*
 * brix_http_eval_none_match_group - second RFC-7232 precedence step (If-None-Match,
 *                                   else If-Modified-Since).
 *
 * WHAT: Returns NGX_HTTP_NOT_MODIFIED (304) or NGX_HTTP_PRECONDITION_FAILED (412) when
 *       the step's precondition triggers, otherwise NGX_DECLINED (conditions pass).
 *
 * WHY: RFC 7232 §6 evaluates If-None-Match after the If-Match step and, when it is
 *      absent, evaluates If-Modified-Since in its place (reads only). A selecting
 *      If-None-Match means the client already holds the representation: 304 on reads,
 *      412 on writes.
 *
 * HOW: 1. If-None-Match present ⇒ if the validator selects it, 304 for reads / 412 for
 *      writes; otherwise proceed. 2. Else, for reads in time mode, apply
 *      If-Modified-Since. 3. Neither present ⇒ proceed.
 */

static ngx_int_t
brix_http_eval_none_match_group(ngx_table_elt_t *if_none,
    ngx_table_elt_t *if_mod, ngx_flag_t resource_exists, const char *etag,
    unsigned condition_flags, unsigned read_mode, unsigned time_mode,
    time_t mtime)
{
    if (cond_header_present(if_none)) {
        if (brix_http_validator_selects(&if_none->value, resource_exists, etag,
                                        condition_flags))
        {
            return read_mode ? NGX_HTTP_NOT_MODIFIED
                             : NGX_HTTP_PRECONDITION_FAILED;
        }
        return NGX_DECLINED;
    }

    if (read_mode && time_mode && cond_header_present(if_mod)) {
        return brix_http_eval_if_modified_since(if_mod, mtime);
    }

    return NGX_DECLINED;
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
    ngx_int_t        decision;

    if (resource_exists) {
        brix_http_etag_str(etag_buf, sizeof(etag_buf), mtime, size,
                             etag_flags);
        etag = etag_buf;
    }

    /* Step 1: If-Match, or (absent) If-Unmodified-Since — may 412. */
    decision = brix_http_eval_match_group(if_match, if_unmod, resource_exists,
                                          etag, condition_flags, time_mode,
                                          mtime);
    if (decision != NGX_DECLINED) {
        return decision;
    }

    /* Step 2: If-None-Match, or (absent) If-Modified-Since — may 304/412. */
    decision = brix_http_eval_none_match_group(if_none, if_mod, resource_exists,
                                               etag, condition_flags, read_mode,
                                               time_mode, mtime);
    if (decision != NGX_DECLINED) {
        return decision;
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
