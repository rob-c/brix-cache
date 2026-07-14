/*
 * http_headers.c - shared HTTP request-header read/parse helpers.
 *
 * WHAT: Finds and reads HTTP request headers (headers_in), validates and
 *       compares their values (case-insensitive name lookup, control-character
 *       rejection, whitespace-trimmed value comparison, Bearer extraction), and
 *       reads/redacts query-string arguments. The write side — response/request
 *       header construction and handler-rc→status mapping — lives in the sibling
 *       http_headers_set.c.
 *
 * WHY: WebDAV and S3 modules both inspect request headers (If-None-Match, Range,
 *      Overwrite, Authorization) and query args (?authz=). A shared
 *      implementation prevents duplicated list traversal, whitespace-trim, and
 *      comparison logic across the two HTTP protocols.
 *
 * HOW: find_header walks r->headers_in.headers.part chain with ngx_strncasecmp;
 *      value_equals trims whitespace then case-insensitive compares; the ctl
 *      check rejects bytes <0x20/0x7F; the query helpers scan/decode/redact
 *      r->args in place.
*/

#include "http_headers.h"
#include "core/compat/cstr.h"

#include <string.h>

/*
 * brix_http_find_header - search headers_in list by name (case-insensitive).
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
brix_http_find_header(ngx_http_request_t *r, const char *name,
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
 * brix_http_get_header - convenience wrapper: find header and return value as ngx_str_t.
 *
 * WHAT: Calls brix_http_find_header() with the given name, returns h->value as
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
brix_http_get_header(ngx_http_request_t *r, const char *name)
{
    ngx_table_elt_t *h;

    h = brix_http_find_header(r, name, ngx_strlen(name));
    if (h == NULL) {
        return (ngx_str_t) ngx_null_string;
    }

    return h->value;
}

/*
 * brix_http_skip_ws - advance a cursor past leading HTTP whitespace.
 *
 * WHAT: Returns the first pointer at or after p that is neither space (0x20) nor
 *       HTAB (0x09), never advancing beyond end.
 *
 * WHY: RFC 7230 section 3.2 permits optional whitespace around header tokens, so
 *      several parsers (Bearer scheme, token value, value comparison) must strip
 *      leading OWS. Factoring the forward scan into one pure helper keeps those
 *      callers flat and low in cyclomatic complexity.
 *
 * HOW: 1. Walk forward while p is below end and points at a space or tab byte.
 *      2. Return the resulting cursor.
 */
static u_char *
brix_http_skip_ws(u_char *p, const u_char *end)
{
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }

    return p;
}

/*
 * brix_http_trim_trailing_ws - retract an end pointer past trailing whitespace.
 *
 * WHAT: Returns the largest pointer no greater than end and no less than start
 *       whose immediately preceding byte is neither space (0x20) nor HTAB (0x09).
 *
 * WHY: The same RFC 7230 section 3.2 optional-whitespace rule applies to the tail
 *      of a header value; a shared reverse-scan helper avoids repeating the loop
 *      and keeps the trimming semantics identical across callers.
 *
 * HOW: 1. Walk end backward while it is above start and the preceding byte is a
 *         space or tab.
 *      2. Return the resulting end.
 */
static u_char *
brix_http_trim_trailing_ws(const u_char *start, u_char *end)
{
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }

    return end;
}

/*
 * brix_http_extract_bearer - parse "Authorization: Bearer <token>".
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
brix_http_extract_bearer(const ngx_str_t *auth_header, ngx_str_t *token_out)
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

    p = brix_http_skip_ws(p, end);

    if ((size_t) (end - p) < bearer_len
        || ngx_strncasecmp(p, (u_char *) bearer, bearer_len) != 0)
    {
        return NGX_DECLINED;
    }

    p += bearer_len;
    if (p >= end || (*p != ' ' && *p != '\t')) {
        return NGX_DECLINED;
    }

    p = brix_http_skip_ws(p, end);
    end = brix_http_trim_trailing_ws(p, end);

    if (p >= end) {
        return NGX_ERROR;
    }

    token_out->data = p;
    token_out->len = (size_t) (end - p);
    return NGX_OK;
}

/*
 * brix_http_str_has_ctl - check for HTTP control characters in string data.
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
brix_http_str_has_ctl(const u_char *data, size_t len)
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
 * brix_http_header_value_equals - case-insensitive literal comparison with whitespace trim.
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
brix_http_header_value_equals(const ngx_str_t *value, const char *literal)
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

    start = brix_http_skip_ws(start, end);
    end = brix_http_trim_trailing_ws(start, end);

    len = (size_t) (end - start);
    literal_len = strlen(literal);

    return len == literal_len
           && ngx_strncasecmp(start, (u_char *) literal, literal_len) == 0;
}

/* query-string token helpers (shared by §1 ?authz= and form decoding) */
static int
brix_hex_nibble(u_char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

size_t
brix_urldecode_inplace(char *str)
{
    char *rp = str;
    char *wp = str;
    int   hi, lo;

    while (*rp) {
        if (*rp == '%' && rp[1] && rp[2]
            && (hi = brix_hex_nibble((u_char) rp[1])) >= 0
            && (lo = brix_hex_nibble((u_char) rp[2])) >= 0)
        {
            *wp++ = (char) ((hi << 4) | lo);
            rp   += 3;
        } else if (*rp == '+') {
            *wp++ = ' ';
            rp++;
        } else {
            *wp++ = *rp++;
        }
    }
    *wp = '\0';
    return (size_t) (wp - str);
}

ngx_int_t
brix_http_arg(ngx_http_request_t *r, const char *name, size_t name_len,
    ngx_str_t *out)
{
    ngx_str_t v;

    if (r == NULL || out == NULL || r->args.len == 0) {
        return NGX_DECLINED;
    }
    if (ngx_http_arg(r, (u_char *) name, name_len, &v) != NGX_OK) {
        return NGX_DECLINED;
    }
    out->data = (u_char *) brix_pstrdup_z(r->pool, &v);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    out->len = v.len;
    return NGX_OK;
}

void
brix_http_redact_query_token(ngx_str_t *query)
{
    static const char *const keys[] = { "authz=", "access_token=" };
    size_t                    k;

    if (query == NULL || query->data == NULL || query->len == 0) {
        return;
    }

    /* Length-preserving: overwrite each token value with 'x' in place. The log
     * sources (r->args / r->unparsed_uri / r->request_line) alias overlapping
     * regions of the same request buffer, so we must NOT memmove/shrink — that
     * would desync their independent ->len fields. Overwriting same-length is
     * idempotent and safe to apply to all three. */
    for (k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
        u_char *p    = query->data;
        u_char *end  = query->data + query->len;
        size_t  klen = ngx_strlen(keys[k]);

        while (p < end
               && (p = ngx_strlcasestrn(p, end, (u_char *) keys[k], klen - 1))
                  != NULL)
        {
            u_char *v = p + klen;
            /* A query arg value ends at '&'; in r->request_line it also ends at the
             * SP before the HTTP version (and CR/LF/HTAB) — stop there so we never
             * clobber " HTTP/1.1". */
            while (v < end && *v != '&' && *v != ' ' && *v != '\t'
                   && *v != '\r' && *v != '\n') {
                *v++ = 'x';
            }
            p = v;
        }
    }
}
