#ifndef TOKEN_B64URL_H
#define TOKEN_B64URL_H
#include <stddef.h>
#include <stdint.h>
#if !defined(_SSIZE_T_DEFINED) && !defined(__ssize_t_defined) && !defined(__ssize_t)
# if defined(_WIN32) || defined(_WIN64)
typedef long ssize_t;
# else
#  include <sys/types.h>
# endif
#endif
ssize_t b64url_decode(const char *in, size_t in_len, uint8_t *out, size_t out_max);
/* Decodes base64url-encoded input (RFC 4648 URL-safe variant) into raw binary.
 * in:       base64url string to decode
 * in_len:   length of the input string
 * out:      destination buffer for decoded bytes
 * out_max:  maximum capacity of out buffer
 * Returns:  number of decoded bytes written to out, or -1 on failure. */
/* A JWS segment: a slice into the original token (NOT NUL-terminated). */
typedef struct { const char *p; size_t n; } xrdjwt_seg;
/* Split a compact JWS "header.payload.signature" into its three dot-separated
 * segments (pointers into `tok`; signature is everything after the 2nd dot).
 * Returns 0 on a well-formed 2-dot token, -1 otherwise. Does not decode/validate. */
int xrdjwt_split(const char *tok, size_t len, xrdjwt_seg seg[3]);

void      b64url_encode(const char *src, size_t slen, char *dst, size_t dsz);
/* Encodes source bytes into base64url string (RFC 4648 URL-safe variant).
 * src:      source bytes to encode
 * slen:     length of the source data
 * dst:      destination buffer for encoded string (must be null-terminated)
 * dsz:      capacity of dst buffer including space for null terminator
 * Returns:  void — caller determines success by checking dsz before calling. */
#endif // TOKEN_B64URL_H
