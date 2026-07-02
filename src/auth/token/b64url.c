/*
 *
 * WHAT: Decodes base64url-encoded input (RFC 4648 URL-safe variant using '-' instead of '+' and '_' instead of '/') into raw binary output. Validates padded length ≤ 8192 bytes to prevent buffer overflow on oversized inputs. Converts '-' → '+' and '_' → '/' characters into standard base64 equivalents using character-by-character replacement into temporary stack buffer, then pads remainder with '=' characters for OpenSSL decoder alignment. Calculates decoded maximum size (padded_len/4*3 - pad_count) — rejects if exceeds caller-provided out_max capacity. Performs actual decoding via OpenSSL EVP_ENCODE_CTX API: EVP_DecodeInit() initializes context, EVP_DecodeUpdate() processes main data block returning out_len bytes, EVP_DecodeFinal() handles remaining padding returning tmp_len bytes. Total decoded length = out_len + tmp_len returned as ssize_t; returns -1 on any validation or decoding failure. All memory allocated from stack (8192-byte tmp buffer) — no heap allocation during decode operation.
 *
 * WHY: Base64url encoding is required for JWT token payloads and opaque continuation tokens that must survive URL transmission without special character escaping. The '-'/'_' substitution ensures encoded strings can be safely transmitted in URLs, HTTP headers, or query parameters without requiring percent-encoding of '+' and '/' characters. OpenSSL EVP API provides verified cryptographic decoding rather than reimplementing base64 logic — reduces attack surface by relying on well-tested library functions. 8192-byte padded length cap prevents denial-of-service via oversized inputs that would overflow stack buffer. Thread safety: pure function with no shared state — operates only on provided input/output buffers and local stack variables. */

#include "b64url.h"

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
    if (padded_len > 8192) return -1;
    char tmp[8192];
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
    if (EVP_DecodeUpdate(ctx, (unsigned char*)out, &out_len, (unsigned char*)tmp, (int)padded_len) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecodeFinal(ctx, (unsigned char*)out + out_len, &tmp_len) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    EVP_ENCODE_CTX_free(ctx);
    return (ssize_t)(out_len + tmp_len);
}
/* HOW: Computes padded_len = in_len + (4 - in_len % 4) % 4 — rejects if > 8192. Declares stack tmp[8192]. Iterates i=0→in_len: replaces '-' with '+' and '_' with '/' in tmp[i], copies others unchanged. Pads remainder from i→padded_len with '=' characters. Counts pad by scanning backwards from padded_len-1 for trailing '=' chars. Computes decoded_max = padded_len/4*3 - pad — rejects if > out_max. Allocates EVP_ENCODE_CTX via new() — returns -1 on NULL. Calls EVP_DecodeInit(ctx), then EVP_DecodeUpdate(ctx,out,&out_len,tmp,(int)padded_len) — returns -1 on error (frees ctx). Calls EVP_DecodeFinal(ctx,out+out_len,&tmp_len) — returns -1 on error (frees ctx). Frees ctx via EVP_ENCODE_CTX_free(). Returns out_len + tmp_len as ssize_t. */

/*
 *
 * WHAT: Encodes source bytes into base64url string (RFC 4648 URL-safe variant using '-' instead of '+' and '_' instead of '/') for safe transmission in URLs, HTTP headers, or query parameters. Uses custom 64-character lookup table containing A-Z, a-z, 0-9, '-', '_' characters. Processes source in 3-byte chunks producing 4 output characters per iteration — loop condition checks both source remaining bytes (i+2 < slen) and destination capacity (di+4 < dsz-1). Handles partial final group: when i < slen but i+2 ≥ slen, encodes 1 or 2 remaining bytes producing 2 or 3 output characters respectively based on available source length. Always null-terminates output string at dst[di]='\0'. Returns encoded string length implicitly via di counter; caller determines capacity by checking dsz before calling.
 *
 * WHY: Base64url encoding produces URL-safe strings that can be transmitted without percent-encoding of '+' and '/' characters — essential for JWT tokens, opaque continuation tokens, and other binary payloads that must survive HTTP transport. Minimal implementation avoids OpenSSL dependency for simple encoding operations where cryptographic verification is not required (unlike decode which uses EVP API). Stack-only allocation (static lookup table) ensures no heap pressure during encoding operations on high-throughput requests. Thread safety: pure function with static lookup table — operates only on provided source/destination buffers and local stack variables, no shared state accessed. */

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
/* HOW: Declares static 64-char lookup table tbl[] containing A-Z,a-z,0-9,-,_ (base64url alphabet). Initializes di=0,i=0. Main loop: i+2<slen && di+4<dsz-1 — reads 3 source bytes into uint32_t v via left-shifts, extracts 6-bit groups via (v>>18)&0x3f,(v>>12)&0x3f,(v>>6)&0x3f,v&0x3f, maps each to tbl[] character at dst[di++]. Handles partial final group: if i<slen && di+2<dsz-1 — reads 1 or 2 remaining bytes into v via shift; extracts 6-bit groups producing 2 or 3 output chars based on available source length. Null-terminates dst[di]='\0'. Returns implicitly via di counter (caller checks dsz capacity before calling). */
