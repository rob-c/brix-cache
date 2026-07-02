#include "s3.h"
#include "s3_auth_internal.h"
#include "compat/http_headers.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>

/* WHY: SigV4 Authorization header parsing is the first step in S3 auth verification —
 * extracts Credential (AKID/DATE/REGION), SignedHeaders, and Signature from the
 * header value; presigned variant additionally parses X-Amz-Expires query parameter.
 * The credential scope parsing validates 4-slash structure required by AWS SigV4.
 * All helpers are static — only parse_authorization() and
 * parse_presigned_authorization() are public entry points. */
/*
 * Get a request header value (lowercased name)
 * */

ngx_str_t
get_header(ngx_http_request_t *r, const char *name)
{
    return xrootd_http_get_header(r, name);
}

/*
 * Parse Authorization header
 *
 * Format:
 *   AWS4-HMAC-SHA256 Credential=AKID/DATE/REGION/s3/aws4_request,
 *   SignedHeaders=host;x-amz-content-sha256;x-amz-date,
 *   Signature=<hex64>
 * */

/*
 * WHAT: Locate "<name>=" inside the Authorization header value [start,end).
 * WHY:  The header is a comma/space-separated list of Key=Value pairs
 *       (Credential=, SignedHeaders=, Signature=). We must match a *field
 *       boundary*, not an arbitrary substring — otherwise "Signature" could be
 *       falsely found inside another value. HOW: only accept a match when the
 *       byte before it is the start of the string, a space, or a comma (i.e.
 *       the start of a new pair), and the byte after the name is '='.
 * Returns a pointer to the start of the name, or NULL if not present.
 */
static const char *
sigv4_find_auth_pair(const char *start, const char *end, const char *name)
{
    const char *p;
    size_t      name_len;

    name_len = strlen(name);

    for (p = start; p < end; p++) {
        /* Need room for "name" + at least the trailing '=' to follow. */
        if ((size_t) (end - p) <= name_len) {
            return NULL;
        }

        /* Enforce pair boundary: must be at list start or just after a
         * separator, else this is a substring match inside another value. */
        if (p != start && p[-1] != ' ' && p[-1] != ',') {
            continue;
        }

        if (p[name_len] == '='
            && ngx_strncmp((u_char *) p, (u_char *) name, name_len) == 0)
        {
            return p;
        }
    }

    return NULL;
}

/*
 * WHAT: NUL-terminated copy of [value_start,value_end) into dst.
 * WHY:  Components come straight off the wire; reject empty and over-long
 *       values up front so callers can treat dst as a trusted C string.
 * Returns 1 on success, 0 if empty or it would not fit (with room for NUL).
 */
static int
sigv4_copy_component(const char *value_start, const char *value_end,
    char *dst, size_t dst_size)
{
    size_t value_len;

    value_len = (size_t) (value_end - value_start);
    if (value_len == 0 || value_len >= dst_size) {
        return 0;
    }

    memcpy(dst, value_start, value_len);
    dst[value_len] = '\0';
    return 1;
}

/*
 * WHAT: Find "<name>=" and copy its value (up to the next separator) into dst.
 * HOW:  value_start skips past the name and the '=' (hence name_len + 1); the
 *       value runs until the next ',', ' ', NUL, or end of the header.
 * Returns 1 on success, 0 if the field is absent or the value does not fit.
 */
static int
sigv4_extract_auth_value(const char *start, const char *end,
    const char *name, char *dst, size_t dst_size)
{
    const char *field;
    const char *value_start;
    const char *value_end;
    size_t      name_len;

    field = sigv4_find_auth_pair(start, end, name);
    if (field == NULL) {
        return 0;
    }

    name_len = strlen(name);
    value_start = field + name_len + 1;     /* +1 steps over the '=' */
    value_end = value_start;

    /* Value ends at the first pair separator (',' or ' '), NUL, or buffer end. */
    while (value_end < end
           && *value_end != ','
           && *value_end != ' '
           && *value_end != '\0')
    {
        value_end++;
    }

    return sigv4_copy_component(value_start, value_end, dst, dst_size);
}

/*
 * WHAT: Split a Credential into its scope parts and store them in `out`.
 * WHY:  AWS SigV4 credential scope is exactly "AKID/DATE/REGION/s3/aws4_request".
 *       We only need the first three components; the trailing "s3/aws4_request"
 *       is implied and not validated here. HOW: find the first three '/' to
 *       bound AKID (before slash1), DATE (slash1..slash2), REGION (slash2..slash3).
 *       Anything past slash3 is the service/terminator and is ignored.
 * Returns 1 if at least three slashes exist and every component copies; else 0.
 */
static int
sigv4_parse_credential_scope(const char *credential,
    sigv4_components_t *out)
{
    const char *credential_end;
    const char *slash1;
    const char *slash2;
    const char *slash3;

    credential_end = credential + strlen(credential);

    /* Locate the first three '/' delimiters; each search starts just past the
     * previous slash so the bounded lengths cannot read off the end. */
    slash1 = memchr(credential, '/', (size_t) (credential_end - credential));
    if (slash1 == NULL) {
        return 0;
    }

    slash2 = memchr(slash1 + 1,
                    '/',
                    (size_t) (credential_end - slash1 - 1));
    if (slash2 == NULL) {
        return 0;
    }

    slash3 = memchr(slash2 + 1,
                    '/',
                    (size_t) (credential_end - slash2 - 1));
    if (slash3 == NULL) {
        return 0;
    }

    /* AKID = [start,slash1), DATE = (slash1,slash2), REGION = (slash2,slash3). */
    if (!sigv4_copy_component(credential, slash1, out->akid,
                              sizeof(out->akid))
        || !sigv4_copy_component(slash1 + 1, slash2, out->date,
                                 sizeof(out->date))
        || !sigv4_copy_component(slash2 + 1, slash3, out->region,
                                 sizeof(out->region)))
    {
        return 0;
    }

    return 1;
}

/*
 * WHAT: Fetch a query-string arg by name and URL-decode it into dst.
 * WHY:  Presigned-URL fields (X-Amz-Credential, X-Amz-Date, ...) arrive percent-
 *       encoded in the query string. We decode '+' as space and reject embedded
 *       NUL so callers receive a clean, trusted C string. HOW: ngx_http_arg
 *       gets the raw value; xrootd_http_urldecode does the bounded decode.
 * Returns 1 on success, 0 if the arg is missing/empty or decode fails/overflows.
 */
static int
sigv4_copy_arg_decoded(ngx_http_request_t *r, const char *name,
    char *dst, size_t dst_size)
{
    ngx_str_t raw;

    if (ngx_http_arg(r, (u_char *) name, ngx_strlen(name), &raw) != NGX_OK
        || raw.len == 0)
    {
        return 0;
    }

    return xrootd_http_urldecode(raw.data, raw.len, dst, dst_size,
        XROOTD_URLDECODE_PLUS_TO_SPACE |
        XROOTD_URLDECODE_REJECT_NUL) == XROOTD_URLDECODE_OK;
}

/*
 * WHAT: Parse X-Amz-Expires (presigned URL validity, in seconds).
 * WHY:  AWS caps presigned-URL lifetime at 7 days; a zero or out-of-range value
 *       is rejected so we never honour an unbounded/garbage expiry window. HOW:
 *       strtoul with strict validation — require the whole string to be consumed
 *       (*end == '\0'), no errno, and 1 <= value <= 604800 (7*24*3600).
 * Returns 1 and sets *out on success, 0 on any malformed/out-of-range input.
 */
static int
sigv4_parse_expires(const char *value, ngx_uint_t *out)
{
    char          *end;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0'
        || parsed == 0 || parsed > 604800)
    {
        return 0;
    }

    *out = (ngx_uint_t) parsed;
    return 1;
}

int
parse_authorization(const ngx_str_t *auth, sigv4_components_t *out)
{
    char        credential[256];
    const char *start;
    const char *end;

    /* Require the exact scheme prefix "AWS4-HMAC-SHA256 " (17 bytes incl. the
     * trailing space). Reject anything shorter or differently named before we
     * attempt to scan key=value pairs. */
    if (auth->len < 17
        || ngx_strncasecmp(auth->data,
                           (u_char *) "AWS4-HMAC-SHA256 ", 17) != 0)
    {
        return 0;
    }

    /* Scan only the pair list that follows the scheme prefix. */
    start = (char *) auth->data + 17;
    end = (char *) auth->data + auth->len;

    if (!sigv4_extract_auth_value(start, end, "SignedHeaders",
                                  out->signed_hdrs,
                                  sizeof(out->signed_hdrs))
        || !sigv4_extract_auth_value(start, end, "Signature",
                                     out->signature,
                                     sizeof(out->signature))
        || !sigv4_extract_auth_value(start, end, "Credential",
                                     credential, sizeof(credential)))
    {
        return 0;
    }

    /* Parse Credential=AKID/DATE/REGION/s3/aws4_request */
    if (!sigv4_parse_credential_scope(credential, out)) {
        return 0;
    }

    return 1;
}

/*
 * WHAT: Parse SigV4 components from a presigned-URL query string (no Auth header).
 * WHY:  Presigned requests carry the same Credential/SignedHeaders/Signature plus
 *       X-Amz-Date/X-Amz-Expires in the query instead of an Authorization header.
 *       Presence of X-Amz-Signature is what distinguishes a presigned request, so
 *       its absence is NGX_DECLINED ("not a presigned request"), while a present-
 *       but-malformed set of params is NGX_ERROR.
 * HOW:  Mark out->presigned, copy the (already-decoded by ngx) signature verbatim,
 *       then URL-decode the remaining fields; every required field must be present
 *       and the algorithm must be AWS4-HMAC-SHA256 — any failure is all-or-nothing.
 * Returns NGX_OK on a complete valid set, NGX_DECLINED if not presigned at all,
 * NGX_ERROR if presigned but malformed.
 */
int
parse_presigned_authorization(ngx_http_request_t *r, sigv4_components_t *out)
{
    ngx_str_t sig_qs;
    char      algorithm[64];
    char      credential[256];
    char      expires[32];

    /* X-Amz-Signature is the presence test: absent => this is not presigned. */
    if (ngx_http_arg(r, (u_char *) "X-Amz-Signature", 15, &sig_qs)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    ngx_memzero(out, sizeof(*out));
    out->presigned = 1;

    if (sig_qs.len == 0 || sig_qs.len >= sizeof(out->signature)) {
        return NGX_ERROR;
    }

    ngx_memcpy(out->signature, sig_qs.data, sig_qs.len);
    out->signature[sig_qs.len] = '\0';

    /* All of these fields are mandatory; the short-circuit && treats any
     * missing/over-long/badly-encoded field (or wrong algorithm) as a single
     * malformed-request failure. */
    if (!sigv4_copy_arg_decoded(r, "X-Amz-Algorithm",
                                algorithm, sizeof(algorithm))
        || ngx_strcmp((u_char *) algorithm,
                      (u_char *) "AWS4-HMAC-SHA256") != 0
        || !sigv4_copy_arg_decoded(r, "X-Amz-Credential",
                                   credential, sizeof(credential))
        || !sigv4_copy_arg_decoded(r, "X-Amz-Date",
                                   out->amz_date, sizeof(out->amz_date))
        || !sigv4_copy_arg_decoded(r, "X-Amz-Expires",
                                   expires, sizeof(expires))
        || !sigv4_copy_arg_decoded(r, "X-Amz-SignedHeaders",
                                   out->signed_hdrs,
                                   sizeof(out->signed_hdrs)))
    {
        return NGX_ERROR;
    }

    if (!sigv4_parse_credential_scope(credential, out)
        || !sigv4_parse_expires(expires, &out->amz_expires))
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
