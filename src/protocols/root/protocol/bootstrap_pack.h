/*
 * bootstrap_pack.h — XRootD outbound session-bootstrap request packers
 *                    (single source of truth for the handshake/login wire layout).
 *
 * WHAT: header-only static inlines that fill the three fixed-layout request
 *       structs every outbound XRootD session sends, in order, before any file op:
 *         - xrd_pack_handshake:        ClientInitHandShake  (20B init hello)
 *         - xrd_pack_protocol_request: ClientProtocolRequest(24B kXR_protocol)
 *         - xrd_pack_login_request:    ClientLoginRequest   (24B kXR_login)
 * WHY:  this exact byte layout was hand-assembled in FOUR places — the native
 *       client (client/lib/conn.c), the proxy upstream (src/upstream/bootstrap.c,
 *       twice: bootstrap + TLS-resend), and native TPC pull (src/tpc/outbound/bootstrap.c).
 *       It is security-relevant (protocol version, TLS-capability flags, login
 *       capver) and was therefore audited 4× and could drift between roles. One
 *       header keeps the wire facts in a single place; the per-role policy that
 *       genuinely differs (streamid ownership, TLS flags, username, pid, async
 *       capability) stays at the call site as explicit parameters.
 * HOW:  header-only static inlines over the packed wire structs — no ngx, no
 *       allocation, no OpenSSL — so the same code compiles into both the nginx
 *       module and the ngx-free libxrdproto archive the native client links.
 *       Each packer pre-zeroes its struct (so reserved/padding bytes and dlen
 *       are 0) then writes only the fields it owns. Callers that manage their own
 *       streamid (the client's xrdc_send stamps it post-pack) pass {0,0}.
 *
 * Clean-room: layouts from src/protocol/wire_core_requests.h (vs XProtocol.hh).
 */
#ifndef BRIX_PROTOCOL_BOOTSTRAP_PACK_H
#define BRIX_PROTOCOL_BOOTSTRAP_PACK_H

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "wire_core_requests.h"   /* ClientInitHandShake / Protocol / Login + types/opcodes */
#include "flags.h"                /* kXR_ver005, kXR_secreqs/ableTLS/wantTLS, kXR_asyncap */
#include "protocols/root/protocol/codec/wire_codec.h"     /* shared per-opcode wire-body codec */

/*
 * ClientInitHandShake = {0,0,0, htonl(4), htonl(ROOTD_PQ)} (20 bytes). The first
 * three words are zero; the server validates fourth==htonl(4) and
 * fifth==htonl(2012=ROOTD_PQ) to accept the client as protocol-compatible.
 * Identical for every role — no parameters.
 */
static inline void
xrd_pack_handshake(ClientInitHandShake *hs)
{
    memset(hs, 0, sizeof(*hs));
    hs->fourth = htonl(4);
    hs->fifth  = htonl(ROOTD_PQ);
}

/*
 * ClientProtocolRequest (kXR_protocol, 24 bytes). `flags` is the per-role
 * capability byte (0 for a server-internal connector; kXR_secreqs|kXR_ableTLS
 * [|kXR_wantTLS] for the user-facing client requesting the security trailer and
 * advertising/forcing TLS). `streamid` is the 2-byte id the caller owns (a
 * server connector uses a fixed {0,1}; the client passes its protocol streamid).
 * clientpv, requestid and expect (kXR_ExpLogin=0x03) are fixed wire facts.
 */
static inline void
xrd_pack_protocol_request(ClientProtocolRequest *pr,
                          const uint8_t streamid[2], uint8_t flags)
{
    xrdw_protocol_req_t b = { .clientpv = kXR_PROTOCOLVERSION,
                              .flags = flags, .expect = kXR_ExpLogin };
    memset(pr, 0, sizeof(*pr));
    pr->streamid[0] = streamid[0];
    pr->streamid[1] = streamid[1];
    pr->requestid   = htons(kXR_protocol);
    xrdw_protocol_req_pack(&b, ((ClientRequestHdr *) pr)->body);  /* clientpv/flags/expect */
    pr->dlen        = 0;
}

/*
 * ClientLoginRequest (kXR_login, 24 bytes). The auth-relevant policy is the
 * caller's: `username` (a NUL-terminated string, copied NUL-padded into the
 * 8-byte wire field and truncated at 8 — matching XRootD's strnlen contract),
 * `pid` (informational), and `capver` (kXR_ver005, optionally |kXR_asyncap).
 * `streamid` is {0,1} for a server connector; the client passes {0,0} because
 * its xrdc_send stamps the real streamid (and dlen) after packing. ability and
 * ability2 stay 0 (pre-zeroed); dlen=0 means anonymous (no credential payload).
 */
static inline void
xrd_pack_login_request(ClientLoginRequest *lr, const uint8_t streamid[2],
                       int32_t pid, const char *username, uint8_t capver)
{
    size_t          n = (username != NULL) ? strlen(username) : 0;
    xrdw_login_req_t b = { .pid = pid, .capver = capver };

    if (n > sizeof(b.username)) {
        n = sizeof(b.username);
    }
    if (n > 0) {
        memcpy(b.username, username, n);   /* NUL-padded; b pre-zeroed by init */
    }

    memset(lr, 0, sizeof(*lr));
    lr->streamid[0] = streamid[0];
    lr->streamid[1] = streamid[1];
    lr->requestid   = htons(kXR_login);
    xrdw_login_req_pack(&b, ((ClientRequestHdr *) lr)->body);  /* pid/username/capver */
    lr->dlen        = 0;
}

#endif /* BRIX_PROTOCOL_BOOTSTRAP_PACK_H */
