/* tests/fuzz/fuzz_gsi_bucket.c — libFuzzer target for the GSI XrdSecBuffer walk.
 *
 * WHAT: Feeds arbitrary bytes through brix_gsi_find_bucket() — the XrdSecgsi
 *       bucket locator that scans an attacker-supplied credential blob for a
 *       typed bucket (kXRS_* tag) and hands back its {ptr,len} — under ASan +
 *       UBSan. The first 4 bytes select the searched bucket type so every branch
 *       of the tag/length walk is reachable.
 *
 * WHY:  brix_gsi_find_bucket (src/auth/gsi/gsi_buf.c) runs over the raw
 *       XrdSecBuffer BEFORE any signature or certificate check — it is the first
 *       structural decode of the GSI handshake, the "ASN.1/bucket framing" surface
 *       named in hyper-hardening C-1 (remaining fuzz target: GSI). Each bucket
 *       carries a 4-byte big-endian length the walker must bound against the
 *       remaining blob; an unchecked length is a classic pre-auth over-read. The
 *       carve is byte-identical to what the handshake calls, so a clean fuzz run
 *       is a real proof, not an approximation.
 *
 * HOW:  Links the pure gsi_buf.c TU (nginx-free: strnlen/memcpy/ntohl only) with
 *       -lcrypto (its sibling header pulls openssl). No production change — the
 *       function was already extern and pure. Build recipe in fuzz_all.py.
 */
#include <stddef.h>
#include <stdint.h>

#include "auth/gsi/gsi_core.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint32_t       type;
    const uint8_t *out    = NULL;
    size_t         outlen = 0;

    if (size < 4) {
        return 0;
    }

    /* First 4 bytes (big-endian) pick the bucket type to search for, so the
     * fuzzer drives both the "tag matches" and "tag skipped" walk branches over
     * the remaining hostile bytes. */
    type = ((uint32_t) data[0] << 24) | ((uint32_t) data[1] << 16)
         | ((uint32_t) data[2] << 8) | (uint32_t) data[3];

    (void) brix_gsi_find_bucket(data + 4, size - 4, type, &out, &outlen);
    return 0;
}
