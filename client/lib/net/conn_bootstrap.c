/*
 * conn_bootstrap.c — the bootstrap wire exchange of a new session: the 20-byte
 * ClientInitHandShake + kXR_protocol segment and the anonymous kXR_login (with
 * auth hand-off). Split from conn.c (600-line ratchet); the connection
 * lifecycle (connect / TLS decision / bind / reconnect / close) stays there.
 *
 * wire: XProtocol.hh ClientInitHandShake — {0,0,0,htonl(4),htonl(2012=ROOTD_PQ)}.
 * wire: XProtocol.hh ServerProtocolBody — pval[4] flags[4]; flags carry server caps.
 * wire: XProtocol.hh ServerLoginBody — sessid[16] [+ "&P=..." security list].
 */
#include "brix.h"
#include "conn_internal.h"
#include "protocols/root/protocol/frame_hdr.h"      /* shared resp-hdr codec (libxrdproto) */
#include "protocols/root/protocol/bootstrap_pack.h" /* shared handshake/protocol/login packers */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>

static void
fill_username(char out[9])
{
    /* The login username is the OS identity advertised for monitoring/default
     * mapping (real authz comes from the chosen sec protocol). Prefer $LOGNAME/
     * $USER — set in every interactive/login shell — so the common path skips the
     * getpwuid() NSS lookup entirely (it lazy-loads libnss_* on first call, a
     * measurable per-process cost the async manager would otherwise pay once per
     * parallel stream). Fall back to getpwuid() when the environment is unset. */
    const char    *name = getenv("LOGNAME");
    struct passwd *pw;
    size_t         n;

    if (name == NULL || name[0] == '\0') { name = getenv("USER"); }
    if (name == NULL || name[0] == '\0') {
        pw = getpwuid(geteuid());
        name = (pw != NULL && pw->pw_name != NULL) ? pw->pw_name : "nobody";
    }
    n = strlen(name);

    if (n > 8) { n = 8; }       /* the wire field is 8 bytes; truncate */
    memcpy(out, name, n);
    out[n] = '\0';              /* NUL-terminated for xrd_pack_login_request */
}

/* Read one response frame raw (header + body), bypassing streamid checks; used
 * for the handshake exchange where the first reply carries streamid {0,0}. */
static int
recv_raw(brix_conn *c, uint16_t *sid, uint16_t *status,
         uint8_t *body, uint32_t bodycap, uint32_t *blen, brix_status *st)
{
    uint8_t  hdr[XRD_RESPONSE_HDR_LEN];
    uint32_t dlen;

    if (brix_read_full(&c->io, hdr, sizeof(hdr), st) != 0) {
        return -1;
    }
    xrd_resp_hdr_unpack(hdr, sid, status, &dlen);   /* unaligned-safe */

    if (dlen > bodycap) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "handshake body too large (%u > %u)", dlen, bodycap);
        return -1;
    }
    if (dlen > 0 && brix_read_full(&c->io, body, dlen, st) != 0) {
        return -1;
    }
    *blen = dlen;
    if (c->diag.wire_trace) {   /* §15: trace handshake/protocol replies too */
        brix_trace_frame(c, '<', *sid, *status, 0, dlen, body, dlen);
    }
    return 0;
}

int
brix_conn_handshake(brix_conn *c, uint16_t proto_sid, int want_tls,
                    brix_status *st)
{
    uint8_t              seg[XRD_HANDSHAKE_LEN + XRD_REQUEST_HDR_LEN];
    ClientInitHandShake  hs;
    ClientProtocolRequest pr;
    uint16_t             sid, status;
    uint8_t              body[256];
    uint32_t             blen;
    int                  saw_proto = 0;
    int                  rounds;

    xrd_pack_handshake(&hs);

    /* The client owns its protocol streamid; ask for the security-requirements
     * trailer (to learn the signing level) and advertise TLS capability,
     * requiring TLS for roots:// / --tls. */
    {
        const uint8_t sid[2] = { (uint8_t) (proto_sid >> 8),
                                 (uint8_t) (proto_sid & 0xff) };
        uint8_t flags = (uint8_t) (kXR_secreqs | kXR_ableTLS |
                                   (want_tls ? kXR_wantTLS : 0));
        xrd_pack_protocol_request(&pr, sid, flags);
    }

    memcpy(seg, &hs, XRD_HANDSHAKE_LEN);
    memcpy(seg + XRD_HANDSHAKE_LEN, &pr, XRD_REQUEST_HDR_LEN);

    if (brix_write_full(&c->io, seg, sizeof(seg), st) != 0) {
        return -1;
    }
    if (c->diag.wire_trace) {   /* §15: the 20B init has no streamid/requestid */
        fprintf(stderr, "> handshake-init (20B) + kXR_protocol sid=%u\n", proto_sid);
    }

    /* Expect up to two frames: a handshake reply (streamid {0,0}) and the
     * protocol reply (streamid == proto_sid). Some servers may send only the
     * protocol reply; key on the streamid rather than assume an ordering. */
    for (rounds = 0; rounds < 2 && !saw_proto; rounds++) {
        if (recv_raw(c, &sid, &status, body, sizeof(body), &blen, st) != 0) {
            return -1;
        }
        if (status != kXR_ok) {
            /* The server completed the framing and EXPLICITLY rejected the
             * handshake (e.g. kXR_error because we asked for TLS on a non-TLS
             * port).  That is a permanent decision: classify it by the server's
             * own status code (not the retryable XRDC_EPROTO framing-desync
             * code) so the resilient loop fails fast instead of re-handshaking
             * the same rejection until its stall window expires. */
            brix_status_set(st, (int) status, 0,
                            "handshake: server status %u", status);
            return -1;
        }
        if (sid == proto_sid) {
            if (blen < sizeof(ServerProtocolBody)) {
                brix_status_set(st, XRDC_EPROTO, 0,
                                "protocol reply too short (%u bytes)", blen);
                return -1;
            }
            /* ServerProtocolBody = pval[4] flags[4]; capabilities in flags. */
            c->server_flags = xrd_get_u32_be(body + 4);   /* unaligned-safe */
            /* Optional signing trailer (present because we set kXR_secreqs):
             * ServerResponseReqs_Protocol immediately after the 8-byte body —
             * theTag 'S', rsvd, secver, secopt, seclvl, secvsz (then secvsz*2
             * secvec bytes we do not consume; BriX and default stock servers
             * send secvsz=0 and express the level in seclvl).  Defensive:
             * default 0 (no signing). */
            c->sec_level = 0;
            c->sec_odata = 0;
            if (blen >= 14 && body[8] == 'S') {
                c->sec_odata = (body[11] & kXR_secOData) ? 1 : 0;
                c->sec_level = body[12];
            }
            saw_proto = 1;
        }
        /* else: handshake reply (streamid {0,0}); keep reading for the protocol. */
    }

    if (!saw_proto) {
        brix_status_set(st, XRDC_EPROTO, 0, "no protocol reply from server");
        return -1;
    }
    return 0;
}

int
brix_conn_login(brix_conn *c, const brix_opts *o, brix_status *st)
{
    ClientLoginRequest req;
    uint16_t           sid, status;
    uint8_t           *body = NULL;
    uint32_t           blen = 0;

    /* streamid {0,0}: brix_send stamps the real streamid (and dlen) after
     * packing. The username is the OS identity; advertise async-response
     * capability. dlen=0 → anonymous (no credential/CGI payload). */
    {
        static const uint8_t sid0[2] = { 0, 0 };
        char uname[9];
        fill_username(uname);
        xrd_pack_login_request(&req, sid0, (int32_t) getpid(), uname,
                               (uint8_t) (kXR_ver005 | kXR_asyncap));
    }

    {
        brix_resp_out out = { &status, &body, &blen };
        if (brix_send(c, &req, NULL, &sid, st) != 0) {
            return -1;
        }
        if (brix_recv(c, sid, &out, st) != 0) {
            return -1;
        }
    }
    if (status != kXR_ok) {
        brix_status_set(st, XRDC_EPROTO, 0, "login: server status %u", status);
        free(body);
        return -1;
    }
    if (blen < BRIX_SESSION_ID_LEN) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "login reply too short (%u bytes)", blen);
        free(body);
        return -1;
    }
    memcpy(c->sessid, body, BRIX_SESSION_ID_LEN);

    /* Anything past the 16-byte sessid is a "&P=<proto>,..." security list:
     * the server demands authentication. Hand off to the auth driver. */
    if (blen > BRIX_SESSION_ID_LEN) {
        char     sec[256];
        uint32_t n = blen - BRIX_SESSION_ID_LEN;
        if (n >= sizeof(sec)) { n = sizeof(sec) - 1; }
        memcpy(sec, body + BRIX_SESSION_ID_LEN, n);
        sec[n] = '\0';
        free(body);
        snprintf(c->sec_list, sizeof(c->sec_list), "%s", sec);  /* §15 explain */
        return brix_authenticate(c, sec, o, st);
    }

    free(body);
    return 0;
}

