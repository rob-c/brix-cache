/*
 *
 * WHAT: Decodes base64url-encoded input (RFC 4648 URL-safe variant) into raw binary.
 *
 *   - Uses '-' instead of '+' and '_' instead of '/' (URL-safe alphabet)
 *   - Validates padded length <= BRIX_B64_DECODE_MAX bytes (overflow prevention)
 *   - Converts '-' -> '+' and '_' -> '/' via char-by-char replacement in stack buffer
 *   - Pads remainder with '=' for OpenSSL decoder alignment
 *   - Calculates decoded_max = padded_len/4*3 - pad_count; rejects if > out_max
 *   - Decodes via OpenSSL EVP_ENCODE_CTX API into private buffer (not caller's)
 *     - EVP_DecodeInit() initializes context
 *     - EVP_DecodeUpdate() processes main block (returns out_len)
 *     - EVP_DecodeFinal() handles padding (returns tmp_len)
 *   - Total = out_len + tmp_len, re-checked against out_max, memcpy'd out
 *   - Returns -1 on any validation or decoding failure
 *   - Stack-only: BRIX_B64_DECODE_MAX input buffer + BRIX_B64_DECODE_MAX*3/4 decode buffer
 *
 * WHY: Required for JWT token payloads and opaque continuation tokens in URLs.
 *
 *   - '-'/'_' substitution avoids percent-encoding in URLs/HTTP headers
 *   - OpenSSL EVP API provides verified crypto decoding (no reimplementation)
 *   - BRIX_B64_DECODE_MAX cap prevents DoS via oversized inputs
 *   - Thread-safe: pure function, no shared state, stack-only allocation
 */

#include "b64url.h"
#include "core/types/tunables.h"  /* BRIX_B64_DECODE_MAX */

#include <openssl/evp.h>
#include <string.h>

/*
 * WHAT: locate the two '.' separators of "header.payload.signature" and return
 *       each segment as a (pointer,len) slice into the input — no copy/decode.
 * WHY:  both the module's token validate path and the client's token-introspection
 *       reimplemented this two-dot scan; one shared splitter keeps them in step.
 * HOW:  memchr for the first dot, then the second after it; signature is the rest
 *       (a JWS signature is base64url and carries no dot, so we don't reject more). */
int
xrdjwt_split(const char *tok, size_t len, xrdjwt_seg seg[3])
{
    const char *dot1, *dot2, *end;

    if (tok == NULL || seg == NULL) {
        return -1;
    }
    end  = tok + len;
    dot1 = (const char *) memchr(tok, '.', len);
    if (dot1 == NULL) {
        return -1;
    }
    dot2 = (const char *) memchr(dot1 + 1, '.', (size_t) (end - (dot1 + 1)));
    if (dot2 == NULL) {
        return -1;
    }
    seg[0].p = tok;       seg[0].n = (size_t) (dot1 - tok);
    seg[1].p = dot1 + 1;  seg[1].n = (size_t) (dot2 - (dot1 + 1));
    seg[2].p = dot2 + 1;  seg[2].n = (size_t) (end - (dot2 + 1));
    return 0;
}

ssize_t b64url_decode(const char *in, size_t in_len, uint8_t *out, size_t out_max) {
    size_t padded_len = in_len + (4 - in_len % 4) % 4;
    if (padded_len > BRIX_B64_DECODE_MAX) return -1;
    char tmp[BRIX_B64_DECODE_MAX];  /* Max base64 decode buffer */
    /* OpenSSL writes three bytes for every four base64 characters and subtracts
     * the padding from the *reported* count only (EVP_DecodeBlock semantics), so
     * a padded token has up to two bytes written past the length it decodes to.
     * The capacity check below deliberately admits an out_max sized to that
     * decoded length, so decoding straight into `out` overruns a caller who
     * sized exactly — pre-auth, on every bearer token. Decode into our own
     * buffer instead and hand back only the bytes that are really there; the
     * client's ftp_gsi_cred.c meets the same hazard by allocating the full 3/4
     * width. Do NOT collapse this back on the grounds that it does not
     * reproduce: OpenSSL 3.5 no longer writes those bytes, 3.0.x does, and the
     * contract cannot depend on which one is linked. */
    uint8_t raw[BRIX_B64_DECODE_MAX / 4 * 3];  /* Decoded output (3/4 of input) */
    size_t i;
    for (i = 0; i < in_len; i++) {
        if (in[i] == '-')      tmp[i] = '+';
        else if (in[i] == '_') tmp[i] = '/';
        else                   tmp[i] = in[i];
    }
    for (; i < padded_len; i++) tmp[i] = '=';
    size_t pad = 0;
    while (pad < padded_len && tmp[padded_len - pad - 1] == '=') pad++;
    size_t decoded_max = padded_len / 4 * 3 - pad;
    if (decoded_max > out_max) return -1;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (!ctx) return -1;
    EVP_DecodeInit(ctx);
    int out_len = 0, tmp_len = 0;
    if (EVP_DecodeUpdate(ctx, raw, &out_len, (unsigned char*)tmp, (int)padded_len) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecodeFinal(ctx, raw + out_len, &tmp_len) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    EVP_ENCODE_CTX_free(ctx);
    /* Widen each operand BEFORE the add so the sum is computed in ssize_t,
     * not int (bugprone-misplaced-widening-cast). */
    ssize_t decoded = (ssize_t) out_len + (ssize_t) tmp_len;
    if (decoded < 0 || (size_t) decoded > out_max) return -1;
    memcpy(out, raw, (size_t) decoded);
    return decoded;
}
/* HOW: Padded length calculation and validation.
 *
 *   - padded_len = in_len + (4 - in_len % 4) % 4; rejects if > BRIX_B64_DECODE_MAX
 *   - Stack tmp[BRIX_B64_DECODE_MAX] for converted input
 *   - Loop i=0→in_len: '-'→'+', '_'→'/', else copy unchanged
 *   - Pad i→padded_len with '=' characters
 *   - Count pad by scanning backwards from padded_len-1 for '='
 *   - decoded_max = padded_len/4*3 - pad; rejects if > out_max
 *   - EVP_ENCODE_CTX_new(); returns -1 on NULL
 *   - EVP_DecodeInit(ctx)
 *   - EVP_DecodeUpdate(ctx,raw,&out_len,tmp,(int)padded_len); -1 on error
 *   - EVP_DecodeFinal(ctx,raw+out_len,&tmp_len); -1 on error
 *   - EVP_ENCODE_CTX_free(ctx)
 *   - Sum out_len + tmp_len in ssize_t; rejects if > out_max
 *   - memcpy(decoded bytes) from raw to out; returns decoded length
 */

/*
 *
 * WHAT: Encodes source bytes into base64url string (RFC 4648 URL-safe variant).
 *
 *   - Uses '-' instead of '+' and '_' instead of '/' (URL-safe alphabet)
 *   - Custom 64-char lookup table: A-Z, a-z, 0-9, '-', '_'
 *   - Processes 3-byte chunks -> 4 output chars per iteration
 *   - Loop: i+2 < slen && di+4 < dsz-1 (checks source + dest capacity)
 *   - Partial final group: i < slen but i+2 >= slen
 *     - 1 remaining byte -> 2 output chars
 *     - 2 remaining bytes -> 3 output chars
 *   - Null-terminates: dst[di] = '\0'
 *   - Returns length implicitly via di counter (caller checks dsz capacity)
 *
 * WHY: URL-safe strings for JWT tokens, continuation tokens, HTTP transport.
 *
 *   - No percent-encoding needed for '+' and '/' in URLs/headers
 *   - Minimal impl avoids OpenSSL for non-crypto encoding
 *   - Stack-only (static lookup table) - no heap pressure
 *   - Thread-safe: pure function, static table, no shared state
 */

/*
 * Minimal base64url encode — key string → opaque continuation token.
 * */
void
b64url_encode(const char *src, size_t slen, char *dst, size_t dsz)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t di = 0;
    size_t i;

    for (i = 0; i + 2 < slen && di + 4 < dsz - 1; i += 3) {
        uint32_t v = ((uint32_t)(unsigned char)src[i]     << 16)
                   | ((uint32_t)(unsigned char)src[i + 1] << 8)
                   | ((uint32_t)(unsigned char)src[i + 2]);
        dst[di++] = tbl[(v >> 18) & 0x3f];
        dst[di++] = tbl[(v >> 12) & 0x3f];
        dst[di++] = tbl[(v >>  6) & 0x3f];
        dst[di++] = tbl[ v        & 0x3f];
    }
    if (i < slen && di + 2 < dsz - 1) {
        uint32_t v = (uint32_t)(unsigned char)src[i] << 16;
        if (i + 1 < slen) {
            v |= (uint32_t)(unsigned char)src[i + 1] << 8;
        }
        dst[di++] = tbl[(v >> 18) & 0x3f];
        dst[di++] = tbl[(v >> 12) & 0x3f];
        if (i + 1 < slen) {
            dst[di++] = tbl[(v >> 6) & 0x3f];
        }
    }
    dst[di] = '\0';
}
/* HOW: Encoding algorithm.
 *
 *   - Static 64-char lookup table: A-Z,a-z,0-9,-,_ (base64url alphabet)
 *   - Initializes di=0, i=0
 *   - Main loop (i+2<slen && di+4<dsz-1):
 *     - Reads 3 source bytes into uint32_t v via left-shifts
 *     - Extracts 6-bit groups: (v>>18)&0x3f, (v>>12)&0x3f, (v>>6)&0x3f, v&0x3f
 *     - Maps each to tbl[] char at dst[di++]
 *   - Partial final group (i<slen && di+2<dsz-1):
 *     - Reads 1-2 remaining bytes into v via shift
 *     - Extracts 6-bit groups -> 2-3 output chars based on available source
 *   - Null-terminates: dst[di] = '\0'
 *   - Returns implicitly via di counter (caller checks dsz before calling)
 */
