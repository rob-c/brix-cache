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

/*
 * Canonical query string: sort params, percent-encode name and value
 * */

typedef struct {
    u_char name[256];
    size_t name_len;
    u_char value[1024];
    size_t value_len;
} qparam_t;

/*
 * qsort comparator implementing SigV4's "sort by name, then by value" ordering.
 *
 * SigV4 sorts on the byte values of the *encoded* params, but because percent-
 * encoding is order-preserving for the unreserved-only alphabet used here, a raw
 * byte compare of the decoded bytes yields the same ordering — so we compare the
 * decoded buffers directly and avoid encoding twice.
 *
 * Names are not NUL-terminated to a common length, so a plain strcmp/memcmp over
 * the longer length would read past one buffer. We instead memcmp() the common
 * prefix (the shorter of the two lengths); only if that prefix is equal does the
 * shorter string sort first (the length tiebreak below). This reproduces standard
 * lexicographic ordering where "a" < "ab". Value comparison repeats the same
 * prefix-then-length scheme as the secondary key.
 */
static int
qparam_cmp(const void *a, const void *b)
{
    const qparam_t *pa = (const qparam_t *) a;
    const qparam_t *pb = (const qparam_t *) b;
    size_t ml = pa->name_len < pb->name_len ? pa->name_len : pb->name_len;
    int r = memcmp(pa->name, pb->name, ml);
    if (r != 0) return r;
    /* common prefix equal -> shorter name is the lesser ("a" < "ab") */
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

/*
 * Parse one "name=value" (or bare-flag "name") query segment spanning
 * [segment_start, segment_end), with `equals` pointing at the first '=' in the
 * segment or NULL when there is none, url-decoding the name and value into *p.
 * Returns 1 if the parameter was stored, 0 if it should be skipped — a decode
 * failure on either half, or the X-Amz-Signature parameter when skip_signature
 * is set (it must not appear in the string it signs).
 */
static int
sigv4_store_param(qparam_t *p, const u_char *segment_start,
    const u_char *segment_end, const u_char *equals, ngx_flag_t skip_signature)
{
    size_t        raw_name_len;
    size_t        raw_value_len;
    const u_char *raw_value;

    /* No '=' in the segment -> a bare flag parameter: the whole segment is the
     * name and the value is empty (""), which SigV4 still canonicalises as
     * "name=". When '=' is present, name is everything before it and value is
     * everything after (excluding the '=' itself). */
    raw_name_len  = (size_t) ((equals ? equals : segment_end) - segment_start);
    raw_value     = equals ? equals + 1 : (u_char *) "";
    raw_value_len = equals ? (size_t) (segment_end - equals - 1) : 0;

    if (xrootd_http_urldecode(segment_start, raw_name_len,
            (char *) p->name, sizeof(p->name),
            XROOTD_URLDECODE_PLUS_TO_SPACE |
            XROOTD_URLDECODE_REJECT_NUL) != XROOTD_URLDECODE_OK)
    {
        return 0;
    }
    p->name_len = strlen((char *) p->name);

    if (skip_signature
        && p->name_len == 15
        && ngx_strcmp(p->name, (u_char *) "X-Amz-Signature") == 0)
    {
        return 0;
    }

    if (xrootd_http_urldecode(raw_value, raw_value_len,
            (char *) p->value, sizeof(p->value),
            XROOTD_URLDECODE_PLUS_TO_SPACE |
            XROOTD_URLDECODE_REJECT_NUL) != XROOTD_URLDECODE_OK)
    {
        return 0;
    }
    p->value_len = strlen((char *) p->value);
    return 1;
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

        /* Scan one "name=value" segment up to the next '&' (or end). Record the
         * FIRST '=' only: a value may legitimately contain '=' bytes, so any
         * '=' after the first belongs to the value, not the name/value split. */
        while (segment_end < end && *segment_end != '&') {
            if (*segment_end == '=' && equals == NULL) {
                equals = segment_end;
            }
            segment_end++;
        }

        if (segment_start < segment_end
            && sigv4_store_param(&params[param_count], segment_start,
                                 segment_end, equals, skip_signature))
        {
            param_count++;
        }

        /* Step past the '&' delimiter; if segment_end already hit `end` there is
         * no delimiter to skip, so leave cursor at end to terminate the loop. */
        cursor = (segment_end < end) ? segment_end + 1 : segment_end;
    }

    qsort(params, (size_t) param_count, sizeof(params[0]), qparam_cmp);

    /* Emit the sorted params as "enc(name)=enc(value)&..." into out[]. Every
     * append is guarded against outsz so a short buffer truncates cleanly rather
     * than overflowing; one trailing byte is always reserved for the final NUL
     * written after the loop (hence the strict "< outsz", not "<="). */
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
