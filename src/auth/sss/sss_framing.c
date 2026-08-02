/*
 * sss_framing.c — pure SSS outer-header framing predicate (see sss_framing.h).
 *
 * Carved out of auth_request.c (hyper-hardening C-1 target 3) so the untrusted
 * pre-auth framing bounds can be fuzzed standalone. Behaviour is byte-identical
 * to the former static sss_header_framing_ok(); auth_request.c now calls this.
 *
 * Depends only on the SSS wire constants (single source of truth in
 * protocols/root/protocol/sss.h) and BRIX_SSS_NAME_MAX (core/types/tunables.h);
 * both headers are nginx-free, so this TU builds against libc alone.
 */
#include "sss_framing.h"

#include "protocols/root/protocol/sss.h"   /* BRIX_SSS_HDR_LEN / _DATA_HDR_LEN / _ENC_BF32 */
#include "core/types/tunables.h"           /* BRIX_SSS_NAME_MAX */

/*
 * WHAT: validate the fixed magic ("sss\0" + BF32 encoding marker), the
 *       key-name-size field, and the header-length/NUL-termination against the
 *       received datagram length.
 * WHY:  bundling the several untrusted-framing bounds checks into one pure test
 *       keeps the SSS parse helper flat and the deny condition auditable, and
 *       makes the bound machine-checkable under ASan+UBSan via a fuzz harness.
 * HOW:  pure — reads the payload and the datagram length, writes the computed
 *       header length via *hdr_len; returns 1 when every check passes, else 0.
 */
int
brix_sss_header_framing_ok(const unsigned char *payload, size_t dlen,
                           size_t *hdr_len)
{
    unsigned char kn_size;

    if (payload == NULL
        || dlen < BRIX_SSS_HDR_LEN + BRIX_SSS_DATA_HDR_LEN + 4)
    {
        return 0;
    }

    if (payload[0] != 's' || payload[1] != 's' || payload[2] != 's'
        || payload[3] != '\0' || payload[7] != BRIX_SSS_ENC_BF32)
    {
        return 0;
    }

    kn_size = payload[6];
    if (kn_size != 0 && (kn_size > BRIX_SSS_NAME_MAX || (kn_size & 0x07))) {
        return 0;
    }

    *hdr_len = BRIX_SSS_HDR_LEN + kn_size;
    if (*hdr_len >= dlen || (kn_size && payload[*hdr_len - 1] != '\0')) {
        return 0;
    }

    return 1;
}
