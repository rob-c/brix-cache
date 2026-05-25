#ifndef XROOTD_COMPAT_URI_H
#define XROOTD_COMPAT_URI_H

#include <stddef.h>
#include <sys/types.h>

/*
 * uri.h — HTTP percent-encode / decode shared by WebDAV and S3.
 *
 * WHAT: Declares xrootd_http_urldecode() (RFC 3986-aware decoder) and
 *       xrootd_http_urlencode() (RFC 3986 encoder). Pure C, no nginx deps.
 *
 * WHY: WebDAV query parameters, S3 canonical requests, and XrdHttp path parsing
 *      all need percent-decode. S3 signing needs percent-encode for canonical URLs.
 *
 * HOW: Protocol-specific wrappers in src/webdav/util/uri.c and src/s3/util.c map
 *      return codes to their respective error conventions and apply protocol-appropriate
 *      flags. The core functions are here so they can be reused across modules.
 */

/*
 * Flags for xrootd_http_urldecode.
 *
 * Combine with bitwise OR; each flag controls one decoding behaviour.
 */
#define XROOTD_URLDECODE_REJECT_NUL     0x01u  /* return NUL_BYTE on %00 */
#define XROOTD_URLDECODE_PLUS_TO_SPACE  0x02u  /* convert '+' to ' ' */

/*
 * Return codes from xrootd_http_urldecode.
 *
 * Zero (OK) means success. Non-zero values indicate a specific failure mode;
 * the caller should inspect the exact code rather than treating all non-zero
 * as a generic error.
 */
#define XROOTD_URLDECODE_OK         0
#define XROOTD_URLDECODE_OVERFLOW   1   /* output buffer exhausted */
#define XROOTD_URLDECODE_NUL_BYTE   2   /* %00 decoded (REJECT_NUL set) */
#define XROOTD_URLDECODE_BADARG     3   /* NULL dst or dst_sz < 2 */

/*
 * xrootd_http_urldecode — decode percent-encoded HTTP input into a C string.
 *
 * WHAT: Scans src[0..src_len] for '%' escape sequences and decodes them to the
 *       corresponding byte value. Well-formed escapes (%HH with valid hex digits)
 *       are decoded; malformed '%' sequences (missing digits, invalid hex) are
 *       preserved verbatim — nginx-lenient strategy.
 *
 * WHY: WebDAV query parameters, S3 canonical request strings, and XrdHttp paths
 *      arrive percent-encoded from HTTP clients. This function decodes them to
 *      raw bytes suitable for path resolution, auth signing, or storage ops.
 *
 * HOW: Iterate src byte-by-byte. When '%' is found, read the next two bytes as
 *      hex nibbles via xrootd_hex_from_char(). If both are valid hex, combine
 *      them into a decoded byte and write to dst. If either nibble is invalid,
 *      copy the '%' verbatim. Check for NUL_BYTE when REJECT_NUL flag is set.
 *      Track overflow at each write (di+1 >= dst_sz). Always null-terminate on OK.
 *
 * Parameters:
 *   src     — input bytes to decode (may contain '%', '+', raw chars)
 *   src_len — length of the input buffer
 *   dst     — output buffer for decoded result (must have at least 2 bytes)
 *   dst_sz  — total size of the output buffer
 *   flags   — combination of XROOTD_URLDECODE_* flags (0 = default behaviour)
 *
 * Returns:
 *   XROOTD_URLDECODE_OK         — success; NUL terminator written at dst[di]
 *   XROOTD_URLDECODE_OVERFLOW   — output buffer too small for decoded result
 *   XROOTD_URLDECODE_NUL_BYTE   — %00 encountered with REJECT_NUL flag set
 *   XROOTD_URLDECODE_BADARG     — dst is NULL or dst_sz < 2
 */
int xrootd_http_urldecode(const unsigned char *src, size_t src_len,
    char *dst, size_t dst_sz, unsigned flags);

/*
 * xrootd_http_urlencode — RFC 3986 percent-encoder.
 *
 * WHAT: Encodes src[0..srclen] into HTTP percent-encoded form. Unreserved
 *       characters per RFC 3986 ([A-Za-z0-9._~-]) plus any character in
 *       safe_extra pass through unchanged. All others are encoded as %XX
 *       with uppercase hex digits.
 *
 * WHY: S3 canonical request construction, WebDAV URL generation, and XrdHttp
 *      path encoding all need RFC 3986-compliant percent-encoding. The encoder
 *      produces deterministic output suitable for HMAC-SHA256 signing (S3).
 *
 * HOW: Iterate src bytes. Check against the unreserved set + safe_extra chars;
 *      if matched, copy directly to dst. Otherwise emit '%' followed by two
 *      uppercase hex nibbles via h[]. Track overflow at each write position.
 *      Null-terminate on success.
 *
 * Parameters:
 *   src        — input bytes to encode
 *   srclen     — length of the input buffer
 *   dst        — output buffer for encoded result (must have at least 1 byte)
 *   dstsz      — total size of the output buffer
 *   safe_extra — additional characters treated as unreserved (e.g. "/" for path segments);
 *                NULL means only RFC 3986 unreserved chars pass through
 *
 * Returns:
 *   >= 0 — number of bytes written (excluding NUL terminator) on success
 *   -1   — output buffer too small, or dst is NULL / dstsz < 1
 */
ssize_t xrootd_http_urlencode(const unsigned char *src, size_t srclen,
    char *dst, size_t dstsz, const char *safe_extra);
#endif /* XROOTD_COMPAT_URI_H */
