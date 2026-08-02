/* tests/fuzz/fuzz_sigv4_canonical.c — libFuzzer target for the S3 SigV4
 * canonical query-string builder.
 *
 * WHAT: Feeds an arbitrary raw query string through build_canonical_qs() — the
 *       AWS SigV4 canonicaliser that splits `k=v&...`, percent-encodes each name
 *       and value, sorts, and emits the canonical form into a caller buffer —
 *       under ASan + UBSan, with both skip-signature modes and a deliberately
 *       undersized output buffer.
 *
 * WHY:  build_canonical_qs (src/protocols/s3/auth_sigv4_canonical.c) runs over
 *       the attacker-supplied query string as PART OF computing the signature the
 *       request is then checked against — pre-auth, remote-reachable (hyper-
 *       hardening C-1 target 5: SigV4 canonicaliser). Its fixed qparam_t buffers
 *       (name[256]/value[1024]) and the output-length accounting are exactly the
 *       kind of bounds a fuzzer with ASan nails: an over-long param name, a value
 *       that fills the buffer, or an output that must truncate cleanly.
 *
 * HOW:  Unity build — auth_sigv4_canonical.c is #included with
 *       BRIX_SIGV4_STANDALONE defined, so it substitutes libc for its three
 *       ngx_* aliases (see auth_sigv4_canonical_standalone.h) instead of pulling
 *       nginx via s3.h. uri.c + hex.c (the pure percent-codec it calls) are
 *       #included too. No production change: with the macro undefined the file
 *       compiles byte-identically against s3.h. Recipe in fuzz_all.py.
 */
#define BRIX_SIGV4_STANDALONE 1

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

/* Unity: the TU under test plus the pure percent-codec it depends on. */
#include "protocols/s3/auth_sigv4_canonical.c"
#include "core/compat/uri.c"
#include "core/compat/hex.c"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_flag_t skip_signature;
    size_t     out_sz;
    u_char    *out;

    if (size < 2) {
        return 0;
    }

    /* First byte: skip-signature mode (drop the X-Amz-Signature param, as the
     * verifier does when canonicalising the presented request). Second byte:
     * an output buffer that is frequently SMALLER than the input, so the
     * truncation/length-guard path is the one most exercised. */
    skip_signature = (ngx_flag_t) (data[0] & 1);
    out_sz         = (size_t) data[1] + 1;

    out = (u_char *) malloc(out_sz);
    if (out != NULL) {
        (void) build_canonical_qs(data + 2, size - 2, skip_signature,
                                  out, out_sz);
        free(out);
    }
    return 0;
}
