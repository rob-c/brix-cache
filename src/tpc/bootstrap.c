/* File: bootstrap.c — Anonymous XRootD source session setup for TPC pull
 * WHAT: Establishes an anonymous XRootD session on the remote origin by executing the three-step handshake pipeline: ClientInitHandShake → kXR_protocol version negotiation → kXR_login with username "xrd" and capver kXR_ver005. Supports OAuth2/OIDC token delegation — when t->token_mode is set, fetches a delegated token before login so authenticated source fetch replaces anonymous login.
 *
 * WHY: Native TPC pull requires nginx to connect to the remote root:// source as an XRootD client before it can read the file and write it locally. This bootstrap establishes the session layer (handshake + protocol version check + login) that every subsequent kXR_open/read/close operation depends on. Token delegation enables authenticated source fetches when the source site requires auth but nginx has a delegated token from the destination's OIDC provider.
 *
 * HOW: ClientInitHandShake with fourth=4 and fifth=ROOTD_PQ → send/recv response → kXR_protocol request with streamid[1]=1, requestid=kXR_protocol, clientpv=kXR_PROTOCOLVERSION, expect=0x03 → send/recv response → OAuth2 token fetch if t->token_mode is non-empty/non-"none" → kXR_login with pid=ngx_pid, username="xrd", capver=kXR_ver005 → send/recv response → handle status: kXR_ok returns immediately (anonymous login complete), kXR_authmore delegates to tpc_outbound_finish_login() for multi-step auth, other status rejects.
 * */

#include "tpc_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared handshake/protocol/login packers */


#include <string.h>
#include <stdlib.h>

/* Server-internal TPC source connector: fixed streamid {0,1}, anonymous "xrd". */
static const uint8_t tpc_bootstrap_streamid[2] = { 0, 1 };

/* Helper functions declared in gsi_outbound_common.c — extern to link them. */
extern void tpc_put_u32(u_char *p, uint32_t v);
extern int tpc_send_kxr_auth(xrootd_tpc_pull_t *t, int fd, u_char seq, const u_char *cred, uint32_t len);

/* Anonymous XRootD session setup: handshake → kXR_protocol → kXR_login */
/* WHAT: Bootstrap anonymous XRootD session on remote TPC origin — execute handshake → protocol version negotiation → login pipeline. */

int
tpc_bootstrap(xrootd_tpc_pull_t *t, int fd)
{
    ClientInitHandShake   hs;
    ClientProtocolRequest pr;
    ClientLoginRequest    lr;
    uint16_t              status;
    uint32_t              dlen;
    u_char               *body;

    /* Initial handshake */
    xrd_pack_handshake(&hs);

    if (tpc_send_all(t, fd, &hs, sizeof(hs)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC handshake send failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC handshake recv failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    free(body);
    if (status != kXR_ok) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC handshake rejected (status=%u)", (unsigned) status);
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    /* kXR_protocol — advertise kXR_ableTLS when outbound TLS is enabled so a
     * TLS-requiring source answers with kXR_gotoTLS (phase-57 §F5). With the
     * directive off we send no TLS flag, so the source never offers gotoTLS and
     * behaviour is identical to before. */
    xrd_pack_protocol_request(&pr, tpc_bootstrap_streamid,
                              t->conf->tpc_outbound_tls ? kXR_ableTLS : 0);

    if (tpc_send_all(t, fd, &pr, sizeof(pr)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_protocol send failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_protocol recv failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (status != kXR_ok) {
        free(body);
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC kXR_protocol rejected (status=%u)", (unsigned) status);
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    /*
     * TLS upgrade (phase-57 §F5): the kXR_protocol reply body is the 8-byte
     * ServerProtocolBody { pval[4], flags[4] }. If the source set kXR_gotoTLS we
     * must complete an in-protocol TLS handshake before login; every subsequent
     * frame (login + GSI/ztn auth + open/read/close) then rides the TLS socket
     * via the I/O helpers (t->tls). Mirrors src/upstream/bootstrap.c.
     */
    {
        uint32_t flags = 0;

        if (body != NULL && dlen >= 8) {
            uint32_t flags_be;

            ngx_memcpy(&flags_be, body + 4, sizeof(flags_be));
            flags = ntohl(flags_be);
        }
        free(body);
        body = NULL;

        if (flags & kXR_gotoTLS) {
            if (!t->conf->tpc_outbound_tls) {
                snprintf(t->err_msg, sizeof(t->err_msg),
                    "TPC source requires TLS; set xrootd_tpc_outbound_tls on");
                t->xrd_error = kXR_NotAuthorized;
                return -1;
            }
            if (tpc_start_tls(t, fd) != 0) {
                return -1;   /* tpc_start_tls sets t->err_msg / t->xrd_error */
            }
        }
    }

    /*
     * OAuth2/OIDC token delegation: fetch a delegated token before the
     * initial kXR_login when the client requested a delegation mode.
     * The fetched token replaces the anonymous login when the source
     * advertises token auth.
     */
    if (t->token_mode[0] != '\0'
        && ngx_strcmp(t->token_mode, "none") != 0) {
        if (tpc_fetch_delegated_token(t) != 0) {
            return -1;
        }
    }

    /* kXR_login — anonymous or delegated-token-aware */
    xrd_pack_login_request(&lr, tpc_bootstrap_streamid, (int32_t) ngx_pid,
                           "xrd", kXR_ver005);

    if (tpc_send_all(t, fd, &lr, sizeof(lr)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_login send failed");
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_login recv failed");
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    /*
     * Authenticate whenever the login reply carries a security token, whether the
     * status is kXR_authmore OR kXR_ok.  In XRootD a kXR_ok login can still
     * REQUIRE auth: the reply body is the session id (XROOTD_SESSION_ID_LEN) plus
     * the "&P=<proto>,..." security-protocol list, and the client must send
     * kXR_auth before any operation (exactly what stock XrdCl does — its own login
     * returns ok with a non-empty body, then it sends kXR_auth).  Treating kXR_ok
     * as "anonymous, done" here made the destination open the source without
     * authenticating, so a GSI source rejected the pull with "user not
     * authenticated".  A reply body no larger than the bare session id (or an
     * empty body) means no security token → genuinely anonymous.
     */
    if (status == kXR_ok || status == kXR_authmore) {
        int frc = 0;

        if (dlen > XROOTD_SESSION_ID_LEN) {
            frc = tpc_outbound_finish_login(t, fd, body, dlen);
        }
        free(body);
        return (frc == 0) ? 0 : -1;
    }

    free(body);
    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC kXR_login rejected (status=%u)", (unsigned) status);
    t->xrd_error = kXR_AuthFailed;
    return -1;
}

