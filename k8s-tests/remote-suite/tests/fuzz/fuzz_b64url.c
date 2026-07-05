/* tests/fuzz/fuzz_b64url.c — libFuzzer target for the token base64url decoder.
 * WHAT: feeds arbitrary bytes as a base64url string and a range of output caps.
 * WHY:  b64url_decode runs on every bearer token before any auth check — a
 *       decode-side overflow is pre-auth attacker-reachable.
 * Build: see tests/fuzz/README.md. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "../../src/auth/token/b64url.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    /* out_max derived from the first byte: exercises both the exact-fit and the
     * deliberately-too-small output buffer (truncation must not overflow). */
    size_t out_max = (size_t) data[0] + 1;
    uint8_t *out = (uint8_t *) malloc(out_max);
    if (!out) return 0;
    (void) b64url_decode((const char *) data + 1, size - 1, out, out_max);
    free(out);
    return 0;
}
