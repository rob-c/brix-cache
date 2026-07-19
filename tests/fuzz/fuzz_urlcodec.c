/* tests/fuzz/fuzz_urlcodec.c — libFuzzer target for the shared HTTP percent-codec.
 *
 * WHAT: Feeds arbitrary bytes through brix_http_urldecode() (with both an exact
 *       and a deliberately-undersized destination, and both decode-flag
 *       combinations) and brix_http_urlencode(), under ASan + UBSan.
 *
 * WHY:  brix_http_urldecode / brix_http_urlencode (src/core/compat/uri.c) are the
 *       one percent-codec under S3 SigV4 canonicalisation, WebDAV query-parameter
 *       parsing, and XrdHttp path handling — all of which decode attacker-supplied
 *       percent-encoded bytes BEFORE (or as part of) the auth check. A decode-side
 *       overflow or an off-by-one in the "%HH" scan is pre-auth remote-reachable
 *       (hyper-hardening C-1: the byte-handling core beneath target 5's SigV4
 *       canonicaliser, shared with the WebDAV/XrdHttp paths). The decoder's
 *       contract — malformed '%' preserved verbatim, overflow reported not
 *       written past, always NUL-terminated on OK — is exactly the kind of
 *       invariant a fuzzer with ASan bounds-checking nails down.
 *
 * Build: see tests/fuzz/README.md (clang -fsanitize=fuzzer,address,undefined,
 *        links uri.c + hex.c). Driven in CI by cmdscripts.fuzz_all.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include "core/compat/uri.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t   dst_sz;
    char    *dst;
    unsigned flags;

    if (size < 2) {
        return 0;
    }

    /* First byte selects the decode flag combination (REJECT_NUL / PLUS_TO_SPACE
     * in every mix); second byte derives a destination size that is frequently
     * SMALLER than the input, so the overflow guard (di+1 >= dst_sz) is the code
     * path most exercised — a decode that must truncate cleanly, never overrun. */
    flags  = (unsigned) (data[0] & (BRIX_URLDECODE_REJECT_NUL |
                                    BRIX_URLDECODE_PLUS_TO_SPACE));
    dst_sz = (size_t) data[1] + 2;            /* >= 2 (decoder rejects dst_sz < 2) */

    const uint8_t *body     = data + 2;
    size_t         body_len = size - 2;

    dst = (char *) malloc(dst_sz);
    if (dst != NULL) {
        (void) brix_http_urldecode(body, body_len, dst, dst_sz, flags);
        free(dst);
    }

    /* Encode leg: worst-case expansion is 3x (every byte -> %XX) plus the NUL, so
     * a full-size buffer must never overflow. */
    size_t enc_sz = body_len * 3 + 1;
    char  *enc    = (char *) malloc(enc_sz);
    if (enc != NULL) {
        (void) brix_http_urlencode(body, body_len, enc, enc_sz, "/");
        free(enc);
    }

    /* A deliberately-undersized encode destination (its own exact-size alloc, so
     * the size passed always matches the buffer — a short buffer must return -1,
     * never write past). */
    char *shortenc = (char *) malloc(dst_sz);
    if (shortenc != NULL) {
        (void) brix_http_urlencode(body, body_len, shortenc, dst_sz, "/");
        free(shortenc);
    }

    return 0;
}
