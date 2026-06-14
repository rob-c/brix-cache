/*
 * post_object.c — S3 browser POST Object handler.
 *
 * Implements the multipart/form-data upload path used by browser forms:
 * POST /<bucket>/ with form fields such as key, policy, x-amz-credential,
 * x-amz-signature, success_action_status, and a file part.  Object bytes are
 * committed through the same confined staged-file pattern as PUT.
 */

#include "s3.h"
#include "s3_auth_internal.h"
#include "../compat/crypto.h"
#include "../compat/hex.h"
#include "../compat/http_body.h"
#include "../compat/http_headers.h"
#include "../compat/staged_file.h"
#include "../path/path.h"

#include <jansson.h>
#include <openssl/crypto.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define S3_POST_MAX_BODY    (128 * 1024 * 1024)
#define S3_POST_MAX_FIELD   4096
#define S3_POST_MAX_FIELDS  64
#define S3_POST_MAX_POLICY  65536

typedef struct {
    char name[128];
    char value[S3_POST_MAX_FIELD];
} s3_post_field_t;

typedef struct {
    s3_post_field_t fields[S3_POST_MAX_FIELDS];
    ngx_uint_t      nfields;

    char            key[S3_MAX_KEY];
    char            filename[256];
    char            content_type[256];
    char            policy[S3_POST_MAX_POLICY];
    char            algorithm[64];
    char            credential[256];
    char            amz_date[32];
    char            signature[129];
    char            success_status[8];
    char            success_redirect[2048];

    u_char         *file_data;
    size_t          file_len;
    ngx_flag_t      have_file;
} s3_post_form_t;

static ngx_int_t
s3_post_error(ngx_http_request_t *r, ngx_uint_t status, const char *code,
    const char *message)
{
    return s3_send_xml_error(r, status, code, message);
}

/*
 * WHAT: Copy `len` raw form bytes into a fixed C-string buffer `dst`.
 * WHY:  Form values are attacker-controlled; we reject embedded NUL bytes so a
 *       value cannot be truncated when later treated as a C string (smuggling a
 *       different key/policy past length-based checks). HOW: bounds-check, scan
 *       for NUL, then copy and terminate.
 * Returns NGX_OK, or NGX_ERROR if it would overflow or contains a NUL.
 */
static ngx_int_t
s3_post_copy_text(const u_char *data, size_t len, char *dst, size_t dstsz)
{
    size_t i;

    if (len >= dstsz) {
        return NGX_ERROR;
    }

    /* Reject embedded NUL so dst is an unambiguous C string downstream. */
    for (i = 0; i < len; i++) {
        if (data[i] == '\0') {
            return NGX_ERROR;
        }
    }

    ngx_memcpy(dst, data, len);
    dst[len] = '\0';
    return NGX_OK;
}

/*
 * WHAT: Resolve a policy-condition field name to its submitted form value.
 * WHY:  POST-policy conditions reference fields the same way the form submits
 *       them; AWS writes some condition keys with a leading '$' (e.g. "$key"),
 *       which we strip so "$key" and "key" map to the same value. The special
 *       "key" and "Content-Type" fields live in dedicated struct members rather
 *       than the generic fields[] table, so they are checked explicitly.
 * Returns the value string, or NULL if no such field was submitted.
 */
static const char *
s3_post_field_value(const s3_post_form_t *form, const char *name)
{
    ngx_uint_t i;

    /* AWS policy syntax writes condition keys as "$name"; normalise to "name". */
    if (name[0] == '$') {
        name++;
    }

    if (strcmp(name, "key") == 0) {
        return form->key;
    }

    for (i = 0; i < form->nfields; i++) {
        if (strcmp(form->fields[i].name, name) == 0) {
            return form->fields[i].value;
        }
    }

    if (strcmp(name, "Content-Type") == 0) {
        return form->content_type;
    }

    return NULL;
}

/*
 * WHAT: Record one submitted form field (non-file part) into `form`.
 * WHY:  Every field is appended to the generic fields[] table (so policy
 *       conditions can later look it up by name), AND the auth-relevant fields
 *       (key, policy, x-amz-*) are mirrored into dedicated struct members for
 *       direct, fast access during signature verification. HOW: validate+copy
 *       once into the table (subject to the 64-field cap), then dispatch on the
 *       known field names to also populate the typed members.
 * Returns NGX_OK, or NGX_ERROR on a missing name or a copy that overflows.
 */
static ngx_int_t
s3_post_store_field(s3_post_form_t *form, const char *name,
    const u_char *data, size_t len)
{
    char value[S3_POST_MAX_FIELD];

    if (name == NULL || name[0] == '\0') {
        return NGX_ERROR;
    }

    if (s3_post_copy_text(data, len, value, sizeof(value)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (form->nfields < S3_POST_MAX_FIELDS
        && strlen(name) < sizeof(form->fields[form->nfields].name))
    {
        ngx_cpystrn((u_char *) form->fields[form->nfields].name,
                    (u_char *) name,
                    sizeof(form->fields[form->nfields].name));
        ngx_cpystrn((u_char *) form->fields[form->nfields].value,
                    (u_char *) value,
                    sizeof(form->fields[form->nfields].value));
        form->nfields++;
    }

    if (strcmp(name, "key") == 0) {
        return s3_post_copy_text(data, len, form->key, sizeof(form->key));
    }
    if (strcmp(name, "policy") == 0) {
        return s3_post_copy_text(data, len, form->policy,
                                 sizeof(form->policy));
    }
    if (strcmp(name, "x-amz-algorithm") == 0) {
        return s3_post_copy_text(data, len, form->algorithm,
                                 sizeof(form->algorithm));
    }
    if (strcmp(name, "x-amz-credential") == 0) {
        return s3_post_copy_text(data, len, form->credential,
                                 sizeof(form->credential));
    }
    if (strcmp(name, "x-amz-date") == 0) {
        return s3_post_copy_text(data, len, form->amz_date,
                                 sizeof(form->amz_date));
    }
    if (strcmp(name, "x-amz-signature") == 0) {
        return s3_post_copy_text(data, len, form->signature,
                                 sizeof(form->signature));
    }
    if (strcmp(name, "success_action_status") == 0) {
        return s3_post_copy_text(data, len, form->success_status,
                                 sizeof(form->success_status));
    }
    if (strcmp(name, "success_action_redirect") == 0) {
        return s3_post_copy_text(data, len, form->success_redirect,
                                 sizeof(form->success_redirect));
    }

    return NGX_OK;
}

/*
 * WHAT: Extract the multipart boundary from the request Content-Type header.
 * WHY:  POST Object only accepts "multipart/form-data; boundary=...". The
 *       boundary may be quoted ("...") or a bare token; both forms must be
 *       handled, and length is capped (RFC 2046 limits boundaries to 70 chars,
 *       we allow up to 200) to bound the stack buffer.
 * HOW:  Verify the media type, then walk the ';'-separated parameter list to
 *       find "boundary="; copy the quoted-string or token value out.
 * Returns NGX_OK with `boundary` filled; NGX_DECLINED if not multipart / no
 * boundary param; NGX_ERROR if the boundary is malformed or too long.
 */
static ngx_int_t
s3_post_boundary(ngx_http_request_t *r, char *boundary, size_t boundary_sz)
{
    ngx_table_elt_t *ct;
    u_char          *p, *end;
    size_t           len;

    ct = xrootd_http_find_header(r, "Content-Type",
                                 sizeof("Content-Type") - 1);
    if (ct == NULL || ct->value.len == 0) {
        return NGX_DECLINED;
    }

    if (ngx_strncasecmp(ct->value.data, (u_char *) "multipart/form-data",
                        sizeof("multipart/form-data") - 1) != 0)
    {
        return NGX_DECLINED;
    }

    p = ct->value.data;
    end = ct->value.data + ct->value.len;

    /* Walk the ';'-separated parameters looking for "boundary=". */
    while (p < end) {
        /* Skip leading separators/whitespace before a parameter token. */
        while (p < end && (*p == ';' || *p == ' ' || *p == '\t')) {
            p++;
        }
        if ((size_t) (end - p) >= sizeof("boundary=") - 1
            && ngx_strncasecmp(p, (u_char *) "boundary=",
                               sizeof("boundary=") - 1) == 0)
        {
            p += sizeof("boundary=") - 1;
            if (p < end && *p == '"') {
                /* Quoted form: value is everything up to the closing '"'. */
                u_char *q;
                p++;
                q = p;
                while (q < end && *q != '"') {
                    q++;
                }
                if (q == end) {
                    return NGX_ERROR;       /* unterminated quoted boundary */
                }
                len = (size_t) (q - p);
            } else {
                /* Token form: value ends at the next separator/whitespace. */
                u_char *q = p;
                while (q < end && *q != ';' && *q != ' '
                       && *q != '\t')
                {
                    q++;
                }
                len = (size_t) (q - p);
            }

            if (len == 0 || len >= boundary_sz || len > 200) {
                return NGX_ERROR;
            }

            ngx_memcpy(boundary, p, len);
            boundary[len] = '\0';
            return NGX_OK;
        }

        /* Not this parameter — advance to the next ';' and retry. */
        while (p < end && *p != ';') {
            p++;
        }
    }

    return NGX_DECLINED;
}

/*
 * WHAT: Find the first occurrence of `needle` within the binary buffer `hay`.
 * WHY:  The multipart body is binary (file bytes may contain NUL), so libc
 *       strstr() cannot be used to locate boundary/CRLF markers. HOW: naive
 *       O(n*m) byte scan, which is adequate for the small needles used here.
 * Returns a pointer into `hay`, or NULL if not found.
 */
static u_char *
s3_memmem(u_char *hay, size_t hay_len, const u_char *needle,
    size_t needle_len)
{
    size_t i;

    if (needle_len == 0 || hay_len < needle_len) {
        return NULL;
    }

    for (i = 0; i <= hay_len - needle_len; i++) {
        if (hay[i] == needle[0]
            && ngx_memcmp(hay + i, needle, needle_len) == 0)
        {
            return hay + i;
        }
    }

    return NULL;
}

/*
 * WHAT: Extract a ';'-delimited parameter (e.g. name= / filename=) from a
 *       Content-Disposition header line into `out`.
 * WHY:  Each multipart part header carries its field name and optional filename
 *       as Content-Disposition parameters; we need them to route the part. Value
 *       may be quoted or a bare token. HOW: scan ';'-separated params for one
 *       whose token equals `name` followed by '='; copy the quoted/token value.
 * Returns NGX_OK if found (out filled), NGX_DECLINED if absent, NGX_ERROR if
 * the value does not fit (out is pre-emptied so callers can ignore DECLINED).
 */
static ngx_int_t
s3_post_extract_param(const char *line, const char *name,
    char *out, size_t outsz)
{
    const char *p;
    size_t      nlen;

    out[0] = '\0';
    nlen = strlen(name);
    p = line;

    /* Each iteration positions p at a ';' beginning the next parameter. */
    while ((p = strchr(p, ';')) != NULL) {
        p++;
        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (ngx_strncasecmp((u_char *) p, (u_char *) name, nlen) == 0
            && p[nlen] == '=')
        {
            const char *v = p + nlen + 1;       /* +1 steps over the '=' */
            const char *e;
            size_t      len;

            if (*v == '"') {
                /* Quoted value: spans to the closing '"'. */
                v++;
                e = v;
                while (*e != '\0' && *e != '"') {
                    e++;
                }
            } else {
                e = v;
                while (*e != '\0' && *e != ';' && *e != ' '
                       && *e != '\t')
                {
                    e++;
                }
            }

            len = (size_t) (e - v);
            if (len >= outsz) {
                return NGX_ERROR;
            }
            ngx_memcpy(out, v, len);
            out[len] = '\0';
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

/*
 * WHAT: Reduce a client-supplied filename to its basename, in place.
 * WHY:  Browsers may send a full path (e.g. "C:\\Users\\x\\f.txt" or
 *       "/home/x/f.txt") in the multipart filename; only the final component is
 *       meaningful and stripping leading path segments removes a directory-
 *       traversal vector before the name is used in ${filename} expansion. HOW:
 *       take whichever of the last '/' or last '\\' appears later, then shift
 *       the tail (incl. its NUL) down to the front of the buffer.
 */
static void
s3_post_basename(char *s)
{
    char *slash;
    char *bslash;
    char *base;

    slash = strrchr(s, '/');
    bslash = strrchr(s, '\\');
    base = slash > bslash ? slash : bslash;     /* later separator wins */

    if (base != NULL) {
        ngx_memmove(s, base + 1, strlen(base + 1) + 1);
    }
}

/*
 * WHAT: Substitute every "${filename}" token in form->key with the uploaded
 *       part's (already basename-reduced) filename, writing back into form->key.
 * WHY:  The S3 POST API lets the key template reference the upload's filename.
 *       Expansion must be bounded (S3_MAX_KEY) and the result must not contain
 *       control characters, since the key becomes a filesystem path.
 * HOW:  Walk the template; copy literal spans, and at each token emit the
 *       filename instead. Every append is length-checked against `left` so a
 *       too-long result fails cleanly rather than overflowing `expanded`.
 * Returns NGX_OK (form->key updated), or NGX_ERROR on overflow / control chars.
 */
static ngx_int_t
s3_post_expand_filename(ngx_http_request_t *r, s3_post_form_t *form)
{
    static const char needle[] = "${filename}";
    char              expanded[S3_MAX_KEY];
    const char       *src;
    char             *dst;
    size_t            left;

    if (strstr(form->key, needle) == NULL) {
        return NGX_OK;
    }

    src = form->key;
    dst = expanded;
    left = sizeof(expanded);

    while (*src != '\0') {
        const char *m = strstr(src, needle);
        size_t      n;

        if (m == NULL) {
            /* No further token: copy the remaining literal tail (incl. NUL). */
            n = strlen(src);
            if (n >= left) {
                return NGX_ERROR;
            }
            ngx_memcpy(dst, src, n + 1);
            break;
        }

        /* Copy the literal span before the token, then the filename in its place. */
        n = (size_t) (m - src);
        if (n + strlen(form->filename) >= left) {
            return NGX_ERROR;
        }
        ngx_memcpy(dst, src, n);
        dst += n;
        left -= n;
        n = strlen(form->filename);
        ngx_memcpy(dst, form->filename, n);
        dst += n;
        left -= n;
        src = m + sizeof(needle) - 1;
    }

    if (xrootd_http_str_has_ctl((u_char *) expanded, strlen(expanded))) {
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) form->key, (u_char *) expanded,
                sizeof(form->key));
    (void) r;
    return NGX_OK;
}

/*
 * WHAT: Parse a multipart/form-data body into `form` — both the named form
 *       fields and the single "file" part (whose bytes are referenced in place).
 * WHY:  This is the wire parser for browser POST uploads; it must handle binary
 *       file content and is hostile-input facing, so every span is bounds-checked.
 * HOW (RFC 2046 framing):
 *   - "--BOUNDARY" CRLF opens the body (marker).
 *   - Each part is a CRLF-terminated header block, a blank line, then the body,
 *     followed by "\r\n--BOUNDARY" (delim) introducing the next part.
 *   - A trailing "--" after a delimiter ("\r\n--BOUNDARY--") closes the body.
 *   The file part's data is NOT copied: form->file_data points into `body`, so
 *   `body` must outlive `form` (it does — both live for the request).
 * Returns NGX_OK when the closing delimiter is reached, NGX_ERROR on any
 * framing violation or oversized header.
 */
static ngx_int_t
s3_post_parse_form(ngx_http_request_t *r, u_char *body, size_t body_len,
    const char *boundary, s3_post_form_t *form)
{
    char     marker[256];
    char     delim[258];
    size_t   marker_len, delim_len;
    u_char  *pos, *end;

    /* marker = opening "--BOUNDARY"; delim = inter-part "\r\n--BOUNDARY". */
    marker_len = (size_t) snprintf(marker, sizeof(marker), "--%s", boundary);
    delim_len = (size_t) snprintf(delim, sizeof(delim), "\r\n--%s", boundary);
    if (marker_len >= sizeof(marker) || delim_len >= sizeof(delim)) {
        return NGX_ERROR;
    }

    pos = body;
    end = body + body_len;

    /* Body must begin with the opening marker followed by CRLF. */
    if ((size_t) (end - pos) < marker_len
        || ngx_memcmp(pos, marker, marker_len) != 0)
    {
        return NGX_ERROR;
    }
    pos += marker_len;
    if ((size_t) (end - pos) < 2 || pos[0] != '\r' || pos[1] != '\n') {
        return NGX_ERROR;
    }
    pos += 2;

    /* Outer loop: one iteration consumes one complete part. */
    while (pos < end) {
        char    name[128] = "";
        char    filename[256] = "";
        char    content_type[256] = "";
        u_char *content;
        u_char *next;
        size_t  content_len;

        /* Inner loop: read this part's header lines until the blank line that
         * separates headers from the part body. */
        for (;;) {
            u_char *line_end;
            size_t  line_len;
            char    line[1024];

            line_end = s3_memmem(pos, (size_t) (end - pos),
                                 (u_char *) "\r\n", 2);
            if (line_end == NULL) {
                return NGX_ERROR;
            }

            line_len = (size_t) (line_end - pos);
            if (line_len == 0) {
                /* Blank line: headers end here; part body starts after CRLF. */
                pos = line_end + 2;
                break;
            }
            if (line_len >= sizeof(line)) {
                return NGX_ERROR;
            }

            ngx_memcpy(line, pos, line_len);
            line[line_len] = '\0';
            pos = line_end + 2;

            if (ngx_strncasecmp((u_char *) line,
                                (u_char *) "Content-Disposition:",
                                sizeof("Content-Disposition:") - 1) == 0)
            {
                if (s3_post_extract_param(line, "name", name, sizeof(name))
                    == NGX_ERROR
                    || s3_post_extract_param(line, "filename", filename,
                                             sizeof(filename)) == NGX_ERROR)
                {
                    return NGX_ERROR;
                }
                if (filename[0] != '\0') {
                    s3_post_basename(filename);
                }
            } else if (ngx_strncasecmp((u_char *) line,
                                       (u_char *) "Content-Type:",
                                       sizeof("Content-Type:") - 1) == 0)
            {
                const char *v = line + sizeof("Content-Type:") - 1;
                while (*v == ' ' || *v == '\t') {
                    v++;
                }
                if (ngx_strlen(v) >= sizeof(content_type)) {
                    return NGX_ERROR;
                }
                ngx_cpystrn((u_char *) content_type, (u_char *) v,
                            sizeof(content_type));
            }
        }

        /* Every part must have declared a field name in its headers. */
        if (name[0] == '\0') {
            return NGX_ERROR;
        }

        /* Part body runs from `pos` up to the next "\r\n--BOUNDARY" delimiter. */
        content = pos;
        next = s3_memmem(content, (size_t) (end - content),
                         (u_char *) delim, delim_len);
        if (next == NULL) {
            return NGX_ERROR;
        }

        content_len = (size_t) (next - content);
        if (strcmp(name, "file") == 0) {
            /* File part: reference bytes in place (zero-copy) rather than store. */
            form->file_data = content;
            form->file_len = content_len;
            form->have_file = 1;
            ngx_cpystrn((u_char *) form->filename, (u_char *) filename,
                        sizeof(form->filename));
            ngx_cpystrn((u_char *) form->content_type,
                        (u_char *) content_type,
                        sizeof(form->content_type));
        } else if (s3_post_store_field(form, name, content, content_len)
                   != NGX_OK)
        {
            return NGX_ERROR;
        }

        /* Advance past the delimiter and decide what follows it. */
        pos = next + delim_len;
        if ((size_t) (end - pos) >= 2 && pos[0] == '-' && pos[1] == '-') {
            return NGX_OK;          /* "--BOUNDARY--": end of the multipart body */
        }
        if ((size_t) (end - pos) < 2 || pos[0] != '\r' || pos[1] != '\n') {
            return NGX_ERROR;       /* delimiter must be followed by "--" or CRLF */
        }
        pos += 2;                   /* CRLF: another part follows */
    }

    /* Ran off the end without seeing the closing "--BOUNDARY--": malformed. */
    (void) r;
    return NGX_ERROR;
}

/*
 * WHAT: Convert a proleptic-Gregorian civil date (y, m, d) to a day count
 *       relative to the Unix epoch (1970-01-01 == 0).
 * WHY:  Policy expiry must be compared against ngx_time() without depending on
 *       the host timezone, so we compute a UTC epoch directly rather than via
 *       mktime() (which is local-time and not async-signal-safe).
 * HOW:  Howard Hinnant's well-known days_from_civil algorithm. It shifts the
 *       year so March is month 1 (Feb's leap day lands at year-end), groups
 *       years into 400-year "eras" (each exactly 146097 days), then offsets by
 *       719468 to re-anchor era day 0 onto the Unix epoch. Constants are exact,
 *       not approximations. Reference: howardhinnant.github.io/date_algorithms.html
 * Returns signed days since 1970-01-01 (negative for pre-epoch dates).
 */
static int64_t
s3_post_days_from_civil(int y, unsigned m, unsigned d)
{
    int64_t   era;
    unsigned  yoe, doy, doe;
    int       mp;

    y -= m <= 2;                                /* Jan/Feb count to prior year */
    era = (y >= 0 ? y : y - 399) / 400;         /* 400-year era index */
    yoe = (unsigned) (y - era * 400);           /* year-of-era [0, 399] */
    mp = (int) m + (m > 2 ? -3 : 9);            /* month, March=0 .. Feb=11 */
    doy = (153 * (unsigned) mp + 2) / 5 + d - 1;/* day-of-year, March 1 == 0 */
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;/* day-of-era [0, 146096] */

    return era * 146097 + (int64_t) doe - 719468;
}

/*
 * WHAT: Parse an ISO 8601 UTC timestamp "YYYY-MM-DDTHH:MM:SSZ" to a time_t.
 * WHY:  POST policy "expiration" is given in this exact UTC form; we need it as
 *       an epoch seconds value to compare against ngx_time(). HOW: strict
 *       sscanf with field widths, range-check each component (se <= 60 allows a
 *       leap second), then combine the civil-day count with the time-of-day.
 * Returns NGX_OK with *out set, or NGX_ERROR on a malformed/out-of-range value.
 */
static ngx_int_t
s3_post_parse_iso8601(const char *s, time_t *out)
{
    int y, mo, d, h, mi, se;

    if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2dZ",
               &y, &mo, &d, &h, &mi, &se) != 6)
    {
        return NGX_ERROR;
    }

    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31
        || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 60)
    {
        return NGX_ERROR;
    }

    /* epoch = (whole days since 1970) * 86400 + seconds within the day. */
    *out = (time_t) (s3_post_days_from_civil(y, (unsigned) mo, (unsigned) d)
                     * 86400 + h * 3600 + mi * 60 + se);
    return NGX_OK;
}

/*
 * WHAT: Exact-match a submitted field value against a policy-required value.
 * Returns NGX_OK on match, NGX_DECLINED on mismatch or a missing value.
 */
static ngx_int_t
s3_post_check_field_eq(const char *actual, const char *expected)
{
    if (actual == NULL || expected == NULL || strcmp(actual, expected) != 0) {
        return NGX_DECLINED;
    }
    return NGX_OK;
}

/*
 * WHAT: Evaluate a single POST-policy condition against the submitted form.
 * WHY:  This is the access-control core: a signed policy lists conditions the
 *       upload must satisfy; if any fails the upload is rejected even though the
 *       signature is valid. Two JSON shapes occur (AWS spec):
 *         - Object  {"field":"value", ...}  : every field must equal exactly
 *           (the special "bucket" key is matched against the configured bucket).
 *         - Array   ["op", "field|$field", "value"] : op is "eq", "starts-with",
 *           or "content-length-range" (which bounds the file size).
 * HOW:  Dispatch on JSON type, then on operator; compare against the form
 *       value resolved via s3_post_field_value().
 * Returns NGX_OK if the condition is satisfied, NGX_DECLINED if it is violated,
 * NGX_ERROR if the condition itself is malformed (unknown shape/op/types).
 */
static ngx_int_t
s3_post_policy_condition(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, json_t *cond)
{
    const char *key;
    json_t     *value;

    /* Object form: implicit "equals" for every key/value pair. */
    if (json_is_object(cond)) {
        json_object_foreach(cond, key, value) {
            const char *expected;
            const char *actual;

            if (!json_is_string(value)) {
                return NGX_ERROR;
            }

            expected = json_string_value(value);
            /* "bucket" is not a form field — match the configured bucket name. */
            if (strcmp(key, "bucket") == 0) {
                if (cf->bucket.len != strlen(expected)
                    || ngx_strncmp(cf->bucket.data, (u_char *) expected,
                                   cf->bucket.len) != 0)
                {
                    return NGX_DECLINED;
                }
                continue;
            }

            actual = s3_post_field_value(form, key);
            if (s3_post_check_field_eq(actual, expected) != NGX_OK) {
                return NGX_DECLINED;
            }
        }
        return NGX_OK;
    }

    /* Array form: ["op", arg1, arg2] — element 0 selects the comparison. */
    if (json_is_array(cond) && json_array_size(cond) >= 3) {
        const char *op;

        if (!json_is_string(json_array_get(cond, 0))) {
            return NGX_ERROR;
        }

        op = json_string_value(json_array_get(cond, 0));

        /* content-length-range: [op, min, max] bounds the uploaded file size. */
        if (strcmp(op, "content-length-range") == 0) {
            json_int_t minv, maxv;

            if (json_array_size(cond) != 3
                || !json_is_integer(json_array_get(cond, 1))
                || !json_is_integer(json_array_get(cond, 2)))
            {
                return NGX_ERROR;
            }

            minv = json_integer_value(json_array_get(cond, 1));
            maxv = json_integer_value(json_array_get(cond, 2));
            if ((json_int_t) form->file_len < minv
                || (json_int_t) form->file_len > maxv)
            {
                return NGX_DECLINED;
            }
            return NGX_OK;
        }

        /* eq: exact match; starts-with: prefix match (empty value => any). */
        if ((strcmp(op, "eq") == 0 || strcmp(op, "starts-with") == 0)
            && json_array_size(cond) == 3
            && json_is_string(json_array_get(cond, 1))
            && json_is_string(json_array_get(cond, 2)))
        {
            const char *field = json_string_value(json_array_get(cond, 1));
            const char *expected = json_string_value(json_array_get(cond, 2));
            const char *actual = s3_post_field_value(form, field);

            if (actual == NULL) {
                return NGX_DECLINED;
            }

            if (strcmp(op, "eq") == 0) {
                return strcmp(actual, expected) == 0 ? NGX_OK : NGX_DECLINED;
            }

            return strncmp(actual, expected, strlen(expected)) == 0
                   ? NGX_OK : NGX_DECLINED;
        }
    }

    (void) r;
    return NGX_ERROR;
}

/*
 * WHAT: Parse the base64-decoded POST policy JSON and enforce all of it.
 * WHY:  The policy document is what the signature actually covers; once the
 *       signature is verified we must (a) confirm the policy has not expired and
 *       (b) confirm every listed condition holds for this upload. The upload is
 *       only authorised if BOTH hold.
 * HOW:  Load JSON, check "expiration" against ngx_time(), then evaluate each
 *       entry of "conditions" via s3_post_policy_condition().
 * Ownership: `root` is jansson-refcounted; every early-return path json_decref()s
 *       it exactly once to avoid leaking the parse tree.
 * Returns NGX_OK (allow), NGX_DECLINED (expired or a condition failed -> 403),
 * NGX_ERROR (document malformed -> treated as invalid policy).
 */
static ngx_int_t
s3_post_validate_policy_json(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form,
    u_char *policy_json, size_t policy_len)
{
    json_error_t  jerr;
    json_t       *root;
    json_t       *expiration;
    json_t       *conditions;
    size_t        i;
    time_t        exp;

    root = json_loadb((const char *) policy_json, policy_len, 0, &jerr);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);          /* decref only if a tree was built */
        }
        return NGX_ERROR;
    }

    /* "expiration" must be present, parseable, and not in the past. */
    expiration = json_object_get(root, "expiration");
    if (!json_is_string(expiration)
        || s3_post_parse_iso8601(json_string_value(expiration), &exp)
           != NGX_OK
        || ngx_time() > exp)
    {
        json_decref(root);
        return NGX_DECLINED;
    }

    conditions = json_object_get(root, "conditions");
    if (!json_is_array(conditions)) {
        json_decref(root);
        return NGX_ERROR;
    }

    /* Every condition must pass; the first non-OK result short-circuits and is
     * propagated (DECLINED = violated, ERROR = malformed condition). */
    for (i = 0; i < json_array_size(conditions); i++) {
        ngx_int_t rc;

        rc = s3_post_policy_condition(r, cf, form,
                                      json_array_get(conditions, i));
        if (rc != NGX_OK) {
            json_decref(root);
            return rc;
        }
    }

    json_decref(root);
    return NGX_OK;
}

/*
 * WHAT: Validate the x-amz-credential scope and extract its date and region.
 * WHY:  The credential must be exactly "AKID/YYYYMMDD/REGION/s3/aws4_request"
 *       (full 5-part scope, unlike the parser in auth_sigv4_parse.c which only
 *       needs the first three). We enforce an 8-char date and the literal
 *       "s3/aws4_request" suffix so a forged/short scope is rejected before any
 *       crypto. HOW: locate the four '/' boundaries; *akid is set to point at
 *       the start (the caller measures its length up to p1).
 * Returns NGX_OK (date/region filled, *akid set), or NGX_ERROR if the scope is
 * malformed, the date is not 8 chars, or the suffix is wrong.
 */
static ngx_int_t
s3_post_parse_credential(const char *credential, char *date, size_t date_sz,
    char *region, size_t region_sz, const char **akid)
{
    const char *p1, *p2, *p3, *p4;
    size_t      len;

    p1 = strchr(credential, '/');
    if (p1 == NULL) {
        return NGX_ERROR;
    }
    *akid = credential;                 /* AKID = [credential, p1) */

    /* Locate the remaining three slashes; require exactly the 5-part scope and
     * the fixed "s3/aws4_request" trailer (text after the third slash). */
    p2 = strchr(p1 + 1, '/');
    p3 = p2 ? strchr(p2 + 1, '/') : NULL;
    p4 = p3 ? strchr(p3 + 1, '/') : NULL;
    if (p2 == NULL || p3 == NULL || p4 == NULL
        || strcmp(p3 + 1, "s3/aws4_request") != 0)
    {
        return NGX_ERROR;
    }

    /* DATE = (p1, p2) — must be exactly 8 chars (YYYYMMDD). */
    len = (size_t) (p2 - (p1 + 1));
    if (len != 8 || len >= date_sz) {
        return NGX_ERROR;
    }
    ngx_memcpy(date, p1 + 1, len);
    date[len] = '\0';

    /* REGION = (p2, p3). */
    len = (size_t) (p3 - (p2 + 1));
    if (len == 0 || len >= region_sz) {
        return NGX_ERROR;
    }
    ngx_memcpy(region, p2 + 1, len);
    region[len] = '\0';

    return NGX_OK;
}

/*
 * WHAT: Verify the SigV4 signature over the POST policy, then enforce the policy.
 * WHY:  This is the authentication+authorization gate for a browser upload. The
 *       signature in the form proves the policy was issued by the holder of the
 *       secret key; the policy then constrains what may be uploaded. Note the
 *       signed message is the base64 policy string *as submitted* — we HMAC the
 *       raw form->policy bytes, NOT the decoded JSON.
 * HOW (in order, fail-closed at each step):
 *   1. If no access key is configured, S3 auth is disabled -> allow.
 *   2. Require all signature fields to be present.
 *   3. Validate algorithm, signature length (hex64), and credential scope shape.
 *   4. Match the credential's AKID, region, and date against this endpoint.
 *   5. Derive the SigV4 signing key and HMAC-SHA256 the policy string; compare
 *      against the provided signature with CRYPTO_memcmp (constant-time, so a
 *      mismatch position cannot be timing-probed).
 *   6. Only after the signature matches, base64-decode the policy and enforce
 *      its expiration + conditions.
 * Returns NGX_OK if authorised; otherwise an already-sent S3 error status (the
 * return value is the HTTP status, suitable for the metrics finalize call).
 */
static ngx_int_t
s3_post_verify_policy(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form)
{
    char        date[16];
    char        region[64];
    const char *akid;
    u_char      k4[32], computed[32];
    char        computed_hex[65];
    ngx_str_t   src, decoded;
    ngx_int_t   rc;

    /* Step 1: no configured key => S3 authentication disabled for this location. */
    if (cf->access_key.len == 0) {
        return NGX_OK;
    }

    /* Step 2: every signature-bearing field must be present. */
    if (form->policy[0] == '\0' || form->algorithm[0] == '\0'
        || form->credential[0] == '\0' || form->amz_date[0] == '\0'
        || form->signature[0] == '\0')
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                             "Missing POST policy signature fields.");
    }

    /* Step 3: algorithm fixed, signature is 64 hex chars, credential well-formed. */
    if (strcmp(form->algorithm, "AWS4-HMAC-SHA256") != 0
        || strlen(form->signature) != 64
        || s3_post_parse_credential(form->credential, date, sizeof(date),
                                    region, sizeof(region), &akid) != NGX_OK)
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidRequest",
                             "Malformed POST policy signature fields.");
    }

    /* Step 4a: AKID = bytes from `akid` up to the first '/'; its length must
     * equal the configured key length AND the bytes must match exactly. */
    if ((size_t) (strchr(form->credential, '/') - akid) != cf->access_key.len
        || ngx_strncmp(cf->access_key.data, (u_char *) akid,
                       cf->access_key.len) != 0)
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidAccessKeyId",
                             "The access key ID does not exist.");
    }

    /* Step 4b: region must match the endpoint, and the credential-scope date
     * must agree with the first 8 chars (YYYYMMDD) of x-amz-date. */
    if (cf->region.len != strlen(region)
        || ngx_strncmp(cf->region.data, (u_char *) region, cf->region.len) != 0
        || ngx_strncmp((u_char *) form->amz_date, (u_char *) date, 8) != 0)
    {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                             "Credential scope does not match this endpoint.");
    }

    /* Step 5: derive the date/region-scoped signing key, HMAC the policy string
     * (the base64 text, not the JSON), hex-encode, and compare. */
    if (!s3_sigv4_derive_signing_key_cached(&cf->secret_key,
                                             date, region, k4)
        || !xrootd_hmac_sha256(k4, 32, (u_char *) form->policy,
                               strlen(form->policy), computed))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    xrootd_hex_encode(computed, 32, computed_hex);
    /* Constant-time compare to avoid leaking how many bytes matched. */
    if (CRYPTO_memcmp(computed_hex, form->signature, 64) != 0) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "SignatureDoesNotMatch",
                             "The request signature we calculated does not "
                             "match the signature you provided.");
    }

    /* Step 6: signature is valid -> decode the policy and enforce its contents.
     * base64 expands ~4:3, so allocate len/4*3 plus slack and a NUL terminator. */
    src.data = (u_char *) form->policy;
    src.len = ngx_strlen(form->policy);
    decoded.len = src.len / 4 * 3 + 4;
    decoded.data = ngx_pnalloc(r->pool, decoded.len + 1);
    if (decoded.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_decode_base64(&decoded, &src) != NGX_OK) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidPolicyDocument",
                             "The POST policy document is invalid.");
    }
    decoded.data[decoded.len] = '\0';

    rc = s3_post_validate_policy_json(r, cf, form, decoded.data, decoded.len);
    /* DECLINED = a condition/expiry failed (403); other non-OK = bad document. */
    if (rc == NGX_DECLINED) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                             "POST policy conditions were not satisfied.");
    }
    if (rc != NGX_OK) {
        return s3_post_error(r, NGX_HTTP_FORBIDDEN, "InvalidPolicyDocument",
                             "The POST policy document is invalid.");
    }

    return NGX_OK;
}

/*
 * WHAT: Commit the uploaded file bytes to `fs_path` and compute its ETag.
 * WHY:  Uses the confined staged-file pattern (write to a temp, atomically
 *       rename on success) so a partial/failed upload never leaves a corrupt
 *       object visible — the same durability contract as PUT. All filesystem
 *       access is confined to root_canon to prevent escaping the bucket root.
 * HOW:  ensure the parent directory exists, open a staged fd, pwrite the whole
 *       buffer, commit (atomic rename), then stat the result for the ETag.
 * Cleanup: any write error calls xrootd_staged_abort (discard temp) before
 *       returning NGX_ERROR, so no orphan temp file is left behind.
 * Returns NGX_OK (object committed, etag set) or NGX_ERROR.
 */
static ngx_int_t
s3_post_write_object(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, const char *fs_path, char *etag,
    size_t etag_sz)
{
    xrootd_staged_file_t staged;
    off_t                off = 0;
    size_t               remaining;
    u_char              *p;
    struct stat          sb;

    /* Create the key's parent directories (S3 keys may embed '/'). EEXIST is
     * benign; any other mkdir failure aborts the write. */
    {
        char   parent[PATH_MAX];
        char  *last_slash;
        size_t flen = strlen(fs_path);

        if (flen < sizeof(parent)) {
            ngx_memcpy(parent, fs_path, flen + 1);
            last_slash = strrchr(parent, '/');
            /* Skip if the slash is the root itself (last_slash == parent). */
            if (last_slash && last_slash != parent) {
                *last_slash = '\0';
                if (xrootd_mkdir_recursive_confined_canon(
                        r->connection->log, cf->common.root_canon,
                        parent, 0755, NULL) != 0
                    && errno != EEXIST)
                {
                    return NGX_ERROR;
                }
            }
        }
    }

    if (xrootd_staged_open(r->connection->log, cf->common.root_canon,
                           fs_path, O_WRONLY, 0600, 16, &staged) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Write the full in-memory file part; pwrite may short-write, so loop until
     * `remaining` is drained, advancing both the buffer pointer and offset. */
    remaining = form->file_len;
    p = form->file_data;
    while (remaining > 0) {
        ssize_t n = pwrite(staged.fd, p, remaining, off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;               /* interrupted syscall: retry */
            }
            xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                &staged, 1);
            return NGX_ERROR;
        }
        if (n == 0) {
            /* Zero progress with bytes left is unexpected: treat as I/O error. */
            errno = EIO;
            xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                &staged, 1);
            return NGX_ERROR;
        }

        p += n;
        off += n;
        remaining -= (size_t) n;
    }

    /* Atomically publish the staged temp as the final object. */
    if (xrootd_staged_commit(r->connection->log, cf->common.root_canon,
                             &staged, fs_path) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Best-effort ETag: a stat failure here is non-fatal (empty ETag). */
    if (stat(fs_path, &sb) == 0) {
        s3_etag(&sb, etag, etag_sz);
        (void) s3_set_header(r, "ETag", etag);
    } else {
        etag[0] = '\0';
    }

    return NGX_OK;
}

/* Send a header-only response with the given status and no body. */
static ngx_int_t
s3_post_send_empty(ngx_http_request_t *r, ngx_uint_t status)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/*
 * WHAT: Send the 201 Created <PostResponse> XML document (Location/Bucket/Key/
 *       ETag) used when the form requested success_action_status=201.
 * HOW:  Build the Location URL (absolute if a Host header is present, else a
 *       path), then assemble the XML via the XML_APPEND* helper macros.
 */
static ngx_int_t
s3_post_send_created(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, const char *etag)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;
    u_char       *xml;
    size_t        xml_capacity = 8192;
    size_t        xml_len = 0;
    ngx_int_t     rc;
    ngx_str_t     host;
    char          location[S3_MAX_KEY + 512];

    xml = ngx_pnalloc(r->pool, xml_capacity);
    if (xml == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Absolute URL when a Host header is available; otherwise a bare path. */
    host = r->headers_in.host ? r->headers_in.host->value
                              : (ngx_str_t) ngx_null_string;
    if (host.len > 0) {
        snprintf(location, sizeof(location), "http://%.*s/%.*s/%s",
                 (int) host.len, host.data,
                 (int) cf->bucket.len, cf->bucket.data, form->key);
    } else {
        snprintf(location, sizeof(location), "/%.*s/%s",
                 (int) cf->bucket.len, cf->bucket.data, form->key);
    }

    /* Assemble the <PostResponse> body (mechanical field-by-field build). */
    XML_APPEND("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
               "<PostResponse>");
    XML_APPEND_ELEM("Location", location, strlen(location));
    XML_APPEND_ELEM("Bucket", cf->bucket.data, cf->bucket.len);
    XML_APPEND_ELEM("Key", form->key, strlen(form->key));
    XML_APPEND_ELEM("ETag", etag, strlen(etag));
    XML_APPEND("</PostResponse>");

    b = ngx_create_temp_buf(r->pool, xml_len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, xml, xml_len);
    b->last = b->pos + xml_len;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_CREATED;
    r->headers_out.content_length_n = (off_t) xml_len;
    r->headers_out.content_type.len = sizeof("application/xml") - 1;
    r->headers_out.content_type.data = (u_char *) "application/xml";
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

/*
 * WHAT: Produce the client-requested success response after a stored object.
 * WHY:  The S3 POST form controls the success shape via two optional fields,
 *       checked in precedence order:
 *         - success_action_redirect: 303 redirect to the client-supplied URL
 *           (validated for control chars first, since it becomes a Location).
 *         - success_action_status: 200 / 201 / 204 (default 204 if unset).
 *       Anything else is a client error.
 */
static ngx_int_t
s3_post_send_success(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, const char *etag)
{
    /* Redirect takes precedence over success_action_status when both are set. */
    if (form->success_redirect[0] != '\0') {
        /* Reject control chars: this value is reflected into a Location header. */
        if (xrootd_http_str_has_ctl((u_char *) form->success_redirect,
                                    strlen(form->success_redirect)))
        {
            return s3_post_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                                 "success_action_redirect is invalid.");
        }
        if (s3_set_header(r, "Location", form->success_redirect) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return s3_post_send_empty(r, NGX_HTTP_SEE_OTHER);
    }

    /* Default success status is 204 No Content when unspecified. */
    if (form->success_status[0] == '\0'
        || strcmp(form->success_status, "204") == 0)
    {
        return s3_post_send_empty(r, NGX_HTTP_NO_CONTENT);
    }

    if (strcmp(form->success_status, "200") == 0) {
        return s3_post_send_empty(r, NGX_HTTP_OK);
    }

    if (strcmp(form->success_status, "201") == 0) {
        return s3_post_send_created(r, cf, form, etag);
    }

    return s3_post_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                         "success_action_status must be 200, 201, or 204.");
}

/*
 * WHAT: Request-body callback for S3 browser POST Object uploads.
 * WHY:  nginx invokes this once the full request body is buffered (registered as
 *       the body handler), so the multipart payload is available in memory here.
 *       This drives the whole pipeline; on any failure it sends the appropriate
 *       S3 error and finalizes per-method metrics — there is no return value
 *       because nginx owns the request lifecycle from a body handler.
 * HOW (ordered pipeline, each step finalizes metrics on failure):
 *   parse boundary -> read body -> parse multipart -> require key+file ->
 *   expand ${filename} and resolve the confined fs path -> verify the signed
 *   policy -> write the object -> send the success response.
 * NOTE: verifying the SIGNATURE before resolving/writing is intentional — but
 *       path resolution happens before the (potentially expensive) crypto since
 *       a bad key is a cheap reject; the object is only written post-verify.
 */
void
s3_post_object_body_handler(ngx_http_request_t *r)
{
    ngx_http_s3_loc_conf_t *cf;
    u_char                 *body;
    size_t                  body_len;
    char                    boundary[256];
    s3_post_form_t          form;
    char                    fs_path[PATH_MAX];
    char                    etag[48];
    ngx_int_t               rc;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    ngx_memzero(&form, sizeof(form));

    if (s3_post_boundary(r, boundary, sizeof(boundary)) != NGX_OK) {
        s3_metrics_finalize_request_method(
            r, XROOTD_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_BAD_REQUEST, "MalformedPOSTRequest",
                          "POST Object requires multipart/form-data."));
        return;
    }

    rc = xrootd_http_body_read_all(r, S3_POST_MAX_BODY, &body, &body_len);
    if (rc == NGX_DECLINED) {
        s3_metrics_finalize_request_method(
            r, XROOTD_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE,
                          "EntityTooLarge", "POST body is too large."));
        return;
    }
    if (rc != NGX_OK) {
        s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_POST,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s3_post_parse_form(r, body, body_len, boundary, &form) != NGX_OK) {
        s3_metrics_finalize_request_method(
            r, XROOTD_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_BAD_REQUEST, "MalformedPOSTRequest",
                          "The multipart form-data body is invalid."));
        return;
    }

    if (!form.have_file || form.key[0] == '\0') {
        s3_metrics_finalize_request_method(
            r, XROOTD_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                          "POST Object requires key and file fields."));
        return;
    }

    if (s3_post_expand_filename(r, &form) != NGX_OK
        || !s3_resolve_key(cf->common.root_canon, form.key,
                           fs_path, sizeof(fs_path)))
    {
        s3_metrics_finalize_request_method(
            r, XROOTD_S3_METHOD_POST,
            s3_post_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                          "Access Denied."));
        return;
    }

    rc = s3_post_verify_policy(r, cf, &form);
    if (rc != NGX_OK) {
        s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_POST, rc);
        return;
    }

    if (s3_post_write_object(r, cf, &form, fs_path, etag, sizeof(etag))
        != NGX_OK)
    {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
        s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_POST,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    XROOTD_S3_METRIC_ADD(bytes_rx_total, form.file_len);

    s3_metrics_finalize_request_method(
        r, XROOTD_S3_METHOD_POST,
        s3_post_send_success(r, cf, &form, etag));
}
