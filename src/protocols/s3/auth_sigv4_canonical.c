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
#include "core/compat/uri.h"

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
    ssize_t n = brix_http_urlencode(src, slen, (char *) out, outsz, "");
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

    if (brix_http_urldecode(segment_start, raw_name_len,
            (char *) p->name, sizeof(p->name),
            BRIX_URLDECODE_PLUS_TO_SPACE |
            BRIX_URLDECODE_REJECT_NUL) != BRIX_URLDECODE_OK)
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

    if (brix_http_urldecode(raw_value, raw_value_len,
            (char *) p->value, sizeof(p->value),
            BRIX_URLDECODE_PLUS_TO_SPACE |
            BRIX_URLDECODE_REJECT_NUL) != BRIX_URLDECODE_OK)
    {
        return 0;
    }
    p->value_len = strlen((char *) p->value);
    return 1;
}

/* ---- Scan one query-string segment, locating its end and first '=' ----
 *
 * WHAT: Given the start of a segment and the end of the query string, returns a
 * pointer to the segment end (the next '&' or the query-string end, whichever
 * comes first) and writes the position of the FIRST '=' within the segment to
 * *equals_out, or NULL when the segment contains no '='.
 *
 * WHY: The name/value split in a SigV4 query parameter is defined by the first
 * '=' only — a value may legitimately contain further '=' bytes, so those later
 * '=' bytes belong to the value, not the split. Isolating the scan keeps the
 * parse loop flat and the "first-equals-wins" rule stated in exactly one place,
 * which is load-bearing for byte-identical canonicalisation.
 *
 * HOW:
 *   1. Walk from segment_start until end or a '&' delimiter is reached.
 *   2. Record the position of the first '=' seen (leave NULL if none).
 *   3. Publish the first-'=' position via *equals_out and return the end pointer.
 */
static const u_char *
sigv4_scan_segment(const u_char *segment_start, const u_char *end,
    const u_char **equals_out)
{
    const u_char *segment_end = segment_start;
    const u_char *equals = NULL;

    while (segment_end < end && *segment_end != '&') {
        if (*segment_end == '=' && equals == NULL) {
            equals = segment_end;
        }
        segment_end++;
    }

    *equals_out = equals;
    return segment_end;
}

/* ---- Parse a raw query string into decoded, storable parameters ----
 *
 * WHAT: Splits [qs, qs+qslen) on '&' into at most max_params segments, decodes
 * each into params[], and returns the number of parameters stored. Segments
 * that are empty or rejected by sigv4_store_param (decode failure, or the
 * X-Amz-Signature parameter when skip_signature is set) are dropped.
 *
 * WHY: The canonical query string is the exact byte sequence a client signs, so
 * the parse must reproduce SigV4's segmentation precisely. Capping at max_params
 * bounds the caller's fixed-size params[] stack array. Skipping X-Amz-Signature
 * keeps the signature field out of the string it signs (self-referential).
 *
 * HOW:
 *   1. Walk the query string one '&'-delimited segment at a time.
 *   2. For each segment, locate its end and first '=' via sigv4_scan_segment.
 *   3. Store non-empty segments accepted by sigv4_store_param, counting them.
 *   4. Step past the '&' delimiter, or stop when the query-string end is hit.
 */
static int
sigv4_parse_qs(const u_char *qs, size_t qslen, ngx_flag_t skip_signature,
    qparam_t *params, int max_params)
{
    int           param_count = 0;
    const u_char *cursor = qs;
    const u_char *end = qs + qslen;

    while (cursor < end && param_count < max_params) {
        const u_char *segment_start = cursor;
        const u_char *equals = NULL;
        const u_char *segment_end =
            sigv4_scan_segment(segment_start, end, &equals);

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

    return param_count;
}

/* ---- Percent-encode one component and append it to the output buffer ----
 *
 * WHAT: Percent-encodes [src, src+slen) and appends the result at out[oi],
 * returning the new write offset. If the encoded bytes would not fit within
 * outsz (keeping the strict "< outsz" reservation for the caller's trailing
 * NUL), nothing is written and oi is returned unchanged.
 *
 * WHY: Every append into the canonical buffer must be bounds-guarded so a short
 * buffer truncates cleanly rather than overflowing; centralising the encode-and-
 * guard step keeps that safety rule identical for both the name and the value.
 *
 * HOW:
 *   1. Percent-encode the source component into a local scratch buffer.
 *   2. Append it only if oi + encoded_len stays strictly below outsz.
 *   3. Return the advanced offset (or the original offset when it did not fit).
 */
static size_t
sigv4_append_encoded(u_char *out, size_t oi, size_t outsz,
    const u_char *src, size_t slen)
{
    u_char enc[1024];
    size_t n = uriencode_param(src, slen, enc, sizeof(enc));

    if (oi + n < outsz) {
        ngx_memcpy(out + oi, enc, n);
        oi += n;
    }
    return oi;
}

/* ---- Emit sorted parameters as the canonical "name=value&..." string ----
 *
 * WHAT: Writes the already-sorted params[] as "enc(name)=enc(value)" joined by
 * '&' into out[], NUL-terminates it, and returns the byte length written
 * (excluding the NUL).
 *
 * WHY: This is the final canonical query string that both client and server feed
 * into the signature. The '&' separator, the '=' between name and value, and the
 * per-append bounds guard must be byte-identical to what clients compute, so the
 * emission is expressed once here with reserved space for the trailing NUL.
 *
 * HOW:
 *   1. For each parameter, prepend '&' before all but the first (bounds-guarded).
 *   2. Append the encoded name, then a '=', then the encoded value.
 *   3. NUL-terminate the buffer and return the written length.
 */
static size_t
sigv4_emit_canonical_qs(const qparam_t *params, int param_count,
    u_char *out, size_t outsz)
{
    size_t oi = 0;

    for (int i = 0; i < param_count; i++) {
        if (i > 0 && oi + 1 < outsz) {
            out[oi++] = '&';
        }
        oi = sigv4_append_encoded(out, oi, outsz, params[i].name,
                                  params[i].name_len);
        if (oi + 1 < outsz) {
            out[oi++] = '=';
        }
        oi = sigv4_append_encoded(out, oi, outsz, params[i].value,
                                  params[i].value_len);
    }

    out[oi] = '\0';
    return oi;
}

/* ---- Build the SigV4 canonical query string ----
 *
 * WHAT: Parses the raw query string [qs, qs+qslen), sorts its parameters, and
 * writes the canonical "enc(name)=enc(value)&..." form into out[] (NUL-
 * terminated), returning the byte length written (excluding the NUL).
 *
 * WHY: SigV4 requires parameters sorted alphabetically by name then value with
 * names and values percent-encoded — this is the exact string clients compute
 * and sign, so it must be reproduced byte-for-byte. Parameter count is capped at
 * 64 to bound the stack allocation of the params[] array.
 *
 * HOW:
 *   1. Parse the query string into at most 64 decoded parameters.
 *   2. Sort them by name then value using qparam_cmp (SigV4 ordering).
 *   3. Emit the sorted parameters as the canonical query string.
 */
size_t
build_canonical_qs(const u_char *qs, size_t qslen, ngx_flag_t skip_signature,
                    u_char *out, size_t outsz)
{
    qparam_t params[64];
    int      param_count;

    param_count = sigv4_parse_qs(qs, qslen, skip_signature, params, 64);
    qsort(params, (size_t) param_count, sizeof(params[0]), qparam_cmp);
    return sigv4_emit_canonical_qs(params, param_count, out, outsz);
}
