/*
 * sigver.c — client request signing (kXR_sigver), the mirror of the server's
 * src/handshake/sigver.c verifier.
 *
 * WHAT: When the session has a GSI signing key and the server's advertised
 *       security level requires a signature for an opcode, prepend a kXR_sigver
 *       frame carrying HMAC-SHA256(signing_key, seqno_be(8) || request_hdr(24) ||
 *       payload). The server replies kXR_ok, then verifies the following request
 *       against the recorded HMAC.
 * WHY:  XRootD high-security configs (security_level >= 2) reject unsigned
 *       mutating/open requests; this lets the native client interoperate with them.
 * HOW:  Gated on c->sec_level (parsed from the protocol reply's SecurityInfo) so it
 *       is a no-op on the common level-0 servers. seqno is monotonic per
 *       connection. Opcode policy is copied verbatim from the server.
 *
 * NOTE: not exercised by the test harness (its GSI servers run at level 0); the
 *       implementation follows the server verifier byte-for-byte. See the
 *       clean-room log for the validation gap.
 */
#include "xrdc.h"
#include "compat/crypto.h"   /* xrootd_hmac_sha256 (libxrdproto) */
#include "gsi/gsi_core.h"    /* xrootd_gsi_sigver_required (shared policy) */
#include "protocol/frame_hdr.h" /* unaligned-safe BE field accessors (libxrdproto) */

#include <arpa/inet.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>

int
xrdc_sigver_maybe(xrdc_conn *c, const uint8_t *hdr24, const void *payload,
                  uint32_t plen, xrdc_status *st)
{
    uint16_t            reqid;
    uint64_t            seq, seq_be;
    uint8_t             mac[32];
    ClientSigverRequest sv;
    uint16_t            sid, status;
    uint8_t            *body = NULL;
    uint32_t            blen = 0;

    reqid = xrd_get_u16_be(hdr24 + 2);   /* unaligned-safe */

    if (!c->signing_active || c->sec_level < 2
        || !xrootd_gsi_sigver_required(reqid, c->sec_level)) {
        return 0;   /* signing not required for this op */
    }

    seq = ++c->sig_seqno;

    /* Shared HMAC (libxrdproto gsi_core) over seqno_be || request header ||
     * payload — byte-identical to what the server verifies. The client always
     * covers the payload (nodata = 0). */
    if (!xrootd_gsi_sigver_hmac(c->signing_key, seq, hdr24, payload, plen, 0,
                                mac)) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "sigver: HMAC failed");
        return -1;
    }

    /* Build + send the kXR_sigver frame (its own streamid). */
    memset(&sv, 0, sizeof(sv));
    sid = c->next_sid++;
    sv.streamid[0] = (uint8_t) (sid >> 8);
    sv.streamid[1] = (uint8_t) (sid & 0xff);
    sv.requestid = htons(kXR_sigver);
    sv.expectrid = htons(reqid);
    sv.version = 0;
    sv.flags = 0;                       /* payload is included in the HMAC */
    seq_be = htobe64(seq);
    memcpy(&sv.seqno, &seq_be, 8);
    sv.crypto = (kXR_char) kXR_SHA256_sig;
    sv.dlen = (kXR_int32) htonl(32);

    if (xrdc_write_full(&c->io, &sv, sizeof(sv), st) != 0
        || xrdc_write_full(&c->io, mac, 32, st) != 0) {
        return -1;
    }

    /* The server acks the sigver with kXR_ok before the covered request. */
    if (xrdc_recv(c, sid, &status, &body, &blen, st) != 0) {
        return -1;
    }
    free(body);
    if (status != kXR_ok) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "sigver rejected (status %u)", status);
        return -1;
    }
    return 0;
}
