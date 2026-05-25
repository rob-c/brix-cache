/*
 * uri.c - shared HTTP percent-decode used by WebDAV and S3.
 *
 * Pure C; no nginx dependencies.  Protocol-specific wrappers in
 * src/webdav/util/uri.c and src/s3/util.c map return codes to their
 * respective error conventions and apply protocol-appropriate flags.
 */

#include "uri.h"
#include "hex.h"
#include <string.h>

int
xrootd_http_urldecode(const unsigned char *src, size_t src_len,
    char *dst, size_t dst_sz, unsigned flags)
{
    size_t si = 0, di = 0;
    int    hi, lo;

    if (dst == NULL || dst_sz < 2) {
        return XROOTD_URLDECODE_BADARG;
    }

    while (si < src_len) {
        if (di + 1 >= dst_sz) {
            return XROOTD_URLDECODE_OVERFLOW;
        }

        if (src[si] == '%' && si + 2 < src_len
            && (hi = xrootd_hex_from_char(src[si + 1])) >= 0
            && (lo = xrootd_hex_from_char(src[si + 2])) >= 0)
        {
            unsigned char decoded = (unsigned char) ((hi << 4) | lo);

            if (decoded == '\0' && (flags & XROOTD_URLDECODE_REJECT_NUL)) {
                return XROOTD_URLDECODE_NUL_BYTE;
            }

            dst[di++] = (char)decoded;
            si += 3;
            continue;
        }

        if (src[si] == '+' && (flags & XROOTD_URLDECODE_PLUS_TO_SPACE)) {
            dst[di++] = ' ';
            si++;
            continue;
        }

        dst[di++] = (char)src[si++];
    }

    dst[di] = '\0';
    return XROOTD_URLDECODE_OK;
}
/*
 * WHAT: Encode a plain text string into HTTP percent-encoded form (RFC 3986).
 *
 * WHY: S3 and WebDAV need to encode paths, query params, or metadata values for inclusion in
 *      URLs or headers. Unreserved characters (letters, digits, -._~) pass through; all others
 *      are percent-encoded as %XX with uppercase hex.
 *
 * HOW: Iterate src bytes. Check against unreserved set + safe_extra chars — if matched, copy
 *      directly. Otherwise emit '%' followed by two uppercase hex nibbles via h[]. Track
 *      overflow (di+1/di+3 >= dstsz) at each write. Null-terminate on success.
 *
 * Parameters:
 *   src/srclen — input string to encode
 *   dst/dstsz — output buffer for encoded result
 *   safe_extra — additional characters treated as unreserved (e.g. "/" for path segments)
 *
 * Returns: number of bytes written (excluding null terminator), or -1 on overflow/badarg.
 */
ssize_t
xrootd_http_urlencode(const unsigned char *src, size_t srclen,
                      char *dst, size_t dstsz,
                      const char *safe_extra)
{
    static const char unreserved[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    static const char h[] = "0123456789ABCDEF";
    size_t si, di = 0;

    if (dst == NULL || dstsz < 1) {
        return -1;
    }

    for (si = 0; si < srclen; si++) {
        unsigned char c = src[si];

        if (strchr(unreserved, c)
            || (safe_extra != NULL && strchr(safe_extra, c)))
        {
            if (di + 1 >= dstsz) {
                return -1;
            }
            dst[di++] = (char) c;
        } else {
            if (di + 3 >= dstsz) {
                return -1;
            }
            dst[di++] = '%';
            dst[di++] = h[c >> 4];
            dst[di++] = h[c & 0x0f];
        }
    }

    dst[di] = '\0';
    return (ssize_t) di;
}
