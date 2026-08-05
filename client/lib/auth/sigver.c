/*
 * sigver.c — client request signing (kXR_sigver), the mirror of the server's
 * src/protocols/root/handshake/sigver.c verifier.
 *
 * WHAT: When the session has a negotiated GSI session cipher and the server's
 *       advertised security level requires a signature for an opcode, prepend a
 *       kXR_sigver frame carrying the stock XrdSecProtect secver-0 signature:
 *       the session-cipher encryption of SHA-256(seqno_be(8) || request_hdr(24)
 *       || payload), IV-prepended on the signed-DH path. The server stays
 *       silent on success and verifies the following request against the
 *       recorded blob.
 * WHY:  XRootD high-security configs (security_level >= 2) reject unsigned
 *       mutating/open requests; this lets the native client interoperate with
 *       them — including stock xrootd servers, which verify this exact scheme.
 * HOW:  Gated on c->signing_active (armed by sec_gsi once the DH session cipher
 *       exists AND c->sec_level >= 2) so it is a no-op on the common level-0
 *       servers. seqno is monotonic per connection. Opcode policy is the shared
 *       brix_gsi_sigver_required() table. Write payloads are excluded from the
 *       hash unless the server advertised kXR_secOData (kXR_nodata_sig set),
 *       matching stock's secVerData behaviour. The sigver frame reuses the
 *       covered request's streamid —
 *       stock XrdSecProtect::Verify rejects a mismatch.
 */
#include "brix.h"
#include "auth/gsi/gsi_core.h"    /* sigver kernels + policy (libxrdproto) */
#include "protocols/root/protocol/frame_hdr.h" /* unaligned-safe BE field accessors (libxrdproto) */

#include <arpa/inet.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>

int
brix_sigver_maybe(brix_conn *c, const uint8_t *hdr24, const void *payload,
                  uint32_t plen, brix_status *st)
{
    uint16_t            reqid;
    uint64_t            seq;
    int                 nodata;
    brix_gsi_cipher_t   cipher;
    uint8_t            *sig;
    size_t              siglen = 0;
    ClientSigverRequest sv;

    reqid = xrd_get_u16_be(hdr24 + 2);   /* unaligned-safe */

    if (!c->signing_active || c->sec_level < 2
        || !brix_gsi_sigver_required(reqid, c->sec_level)) {
        return 0;   /* signing not required for this op */
    }

    if (!c->gsi_deleg_ready
        || !brix_gsi_cipher_lookup(c->gsi_deleg_cipher, &cipher)
        || c->gsi_deleg_keylen < (size_t) cipher.key_len) {
        brix_status_set(st, XRDC_EAUTH, 0, "sigver: no session cipher");
        return -1;
    }

    seq = ++c->sig_seqno;

    /* Stock parity: write payloads are hashed only when the server advertised
     * kXR_secOData (secVerData); everything else always covers its payload. */
    nodata = (reqid == kXR_write || reqid == kXR_pgwrite) && !c->sec_odata;

    /* Shared kernel (libxrdproto gsi_core): SHA-256 over seqno_be || request
     * header || payload-unless-nodata, encrypted with the DH session cipher —
     * byte-identical to what stock XrdSecProtect and the server verify. */
    sig = brix_gsi_sigver_sign(&cipher, c->gsi_deleg_key, c->gsi_deleg_use_iv,
                                 seq, hdr24, payload, plen, nodata, &siglen);
    if (sig == NULL || siglen == 0 || siglen > INT32_MAX) {
        free(sig);
        brix_status_set(st, XRDC_EAUTH, 0, "sigver: signing failed");
        return -1;
    }

    /* Build + send the kXR_sigver frame on the COVERED request's streamid —
     * the hash covers the header as sent, and stock servers require the two
     * frames to share a stream. */
    memset(&sv, 0, sizeof(sv));
    sv.streamid[0] = hdr24[0];
    sv.streamid[1] = hdr24[1];
    sv.requestid = htons(kXR_sigver);
    {
        xrdw_sigver_req_t b = { .expectrid = reqid, .version = 0,
                                .flags = nodata ? kXR_nodata_sig : 0,
                                .seqno = seq, .crypto = kXR_SHA256_sig };
        xrdw_sigver_req_pack(&b, ((ClientRequestHdr *) &sv)->body);
    }
    sv.dlen = (kXR_int32) htonl((uint32_t) siglen);

    if (brix_write_full(&c->io, &sv, sizeof(sv), st) != 0
        || brix_write_full(&c->io, sig, siglen, st) != 0) {
        free(sig);
        return -1;
    }
    free(sig);
    /*
     * kXR_sigver is a request PREFIX: a spec-conformant server (stock XRootD,
     * and now this module) sends NO response on success — only kXR_SigVerErr on
     * failure, which surfaces as the covered request's reply. So do NOT read an
     * ack here; the next recv is the covered request's response. Reading a
     * non-existent ack would consume that reply (or block).
     */
    return 0;
}
