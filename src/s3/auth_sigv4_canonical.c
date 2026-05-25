/*
 * auth.c — AWS Signature Version 4 (HMAC-SHA256) verification.
 *
 * Verifies the Authorization header sent by XrdClS3 and any other S3 client
 * that uses SigV4.  The implementation follows the AWS SigV4 specification.
 *
 * XrdClS3 always uses UNSIGNED-PAYLOAD so we do not verify the request body
 * hash.  The signed headers are typically: host;x-amz-content-sha256;x-amz-date
 *
 * Reference algorithm:
 *   https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 */

#include "s3.h"
#include "../compat/uri.h"

#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Canonical query string: sort params, percent-encode name and value
 * ---------------------------------------------------------------------- */

typedef struct {
    u_char name[256];
    size_t name_len;
    u_char value[1024];
    size_t value_len;
} qparam_t;

static int
qparam_cmp(const void *a, const void *b)
{
    const qparam_t *pa = (const qparam_t *) a;
    const qparam_t *pb = (const qparam_t *) b;
    size_t ml = pa->name_len < pb->name_len ? pa->name_len : pb->name_len;
    int r = memcmp(pa->name, pb->name, ml);
    if (r != 0) return r;
    if (pa->name_len != pb->name_len) {
        return (pa->name_len < pb->name_len) ? -1 : 1;
    }

    ml = pa->value_len < pb->value_len ? pa->value_len : pb->value_len;
    r = memcmp(pa->value, pb->value, ml);
    if (r != 0) return r;
    return (pa->value_len < pb->value_len) ? -1
         : (pa->value_len > pb->value_len) ? 1 : 0;
}

/* Thin wrapper: percent-encode a query-param name or value (unreserved chars only). */
static size_t
uriencode_param(const u_char *src, size_t slen, u_char *out, size_t outsz)
{
    ssize_t n = xrootd_http_urlencode(src, slen, (char *) out, outsz, "");
    return n < 0 ? 0 : (size_t) n;
}

size_t
build_canonical_qs(const u_char *qs, size_t qslen, ngx_flag_t skip_signature,
                    u_char *out, size_t outsz)
{
/* WHY: SigV4 canonical query string requires parameters sorted alphabetically
 * by name then value, with names and values percent-encoded — this is the
 * exact string that clients compute and sign. Skipping X-Amz-Signature from
 * the canonical qs ensures the signature field itself is not part of what
 * it signs (self-referential). Parameter count capped at 64 to bound stack
 * allocation of params[] array. */
    /* Parse query string into at most 64 parameters */
    qparam_t     params[64];
    int          param_count = 0;
    const u_char *cursor = qs;
    const u_char *end = qs + qslen;

    while (cursor < end && param_count < 64) {
        const u_char *segment_start = cursor;
        const u_char *segment_end = cursor;
        const u_char *equals = NULL;

        while (segment_end < end && *segment_end != '&') {
            if (*segment_end == '=' && equals == NULL) {
                equals = segment_end;
            }
            segment_end++;
        }

        if (segment_start < segment_end) {
            size_t      raw_name_len;
            size_t      raw_value_len;
            const u_char *raw_value;

            raw_name_len = (size_t) ((equals ? equals : segment_end)
                                     - segment_start);
            raw_value = equals ? equals + 1 : (u_char *) "";
            raw_value_len = equals ? (size_t) (segment_end - equals - 1) : 0;

            if (xrootd_http_urldecode(segment_start, raw_name_len,
                    (char *) params[param_count].name,
                    sizeof(params[param_count].name),
                    XROOTD_URLDECODE_PLUS_TO_SPACE |
                    XROOTD_URLDECODE_REJECT_NUL) != XROOTD_URLDECODE_OK)
            {
                goto next_param;
            }
            params[param_count].name_len =
                strlen((char *) params[param_count].name);

            if (skip_signature
                && params[param_count].name_len == 15
                && ngx_strcmp(params[param_count].name,
                              (u_char *) "X-Amz-Signature") == 0)
            {
                goto next_param;
            }

            if (xrootd_http_urldecode(raw_value, raw_value_len,
                    (char *) params[param_count].value,
                    sizeof(params[param_count].value),
                    XROOTD_URLDECODE_PLUS_TO_SPACE |
                    XROOTD_URLDECODE_REJECT_NUL) != XROOTD_URLDECODE_OK)
            {
                goto next_param;
            }
            params[param_count].value_len =
                strlen((char *) params[param_count].value);
            param_count++;
        }

next_param:
        cursor = (segment_end < end) ? segment_end + 1 : segment_end;
    }

    qsort(params, (size_t) param_count, sizeof(params[0]), qparam_cmp);

    size_t oi = 0;
    u_char enc[1024];

    for (int i = 0; i < param_count; i++) {
        if (i > 0 && oi + 1 < outsz) {
            out[oi++] = '&';
        }
        size_t n;
        n = uriencode_param(params[i].name, params[i].name_len,
                            enc, sizeof(enc));
        if (oi + n < outsz) {
            ngx_memcpy(out + oi, enc, n);
            oi += n;
        }
        if (oi + 1 < outsz) out[oi++] = '=';
        n = uriencode_param(params[i].value, params[i].value_len,
                            enc, sizeof(enc));
        if (oi + n < outsz) {
            ngx_memcpy(out + oi, enc, n);
            oi += n;
        }
    }
    out[oi] = '\0';
    return oi;
}
