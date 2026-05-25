/* ---- File: bootstrap.c — Anonymous XRootD source session setup for TPC pull ----
 *
 * WHAT: Establishes an anonymous XRootD session on the remote origin by executing the three-step handshake pipeline: ClientInitHandShake → kXR_protocol version negotiation → kXR_login with username "xrd" and capver kXR_ver005. Supports OAuth2/OIDC token delegation — when t->token_mode is set, fetches a delegated token before login so authenticated source fetch replaces anonymous login.
 *
 * WHY: Native TPC pull requires nginx to connect to the remote root:// source as an XRootD client before it can read the file and write it locally. This bootstrap establishes the session layer (handshake + protocol version check + login) that every subsequent kXR_open/read/close operation depends on. Token delegation enables authenticated source fetches when the source site requires auth but nginx has a delegated token from the destination's OIDC provider.
 *
 * HOW: ClientInitHandShake with fourth=4 and fifth=ROOTD_PQ → send/recv response → kXR_protocol request with streamid[1]=1, requestid=kXR_protocol, clientpv=kXR_PROTOCOLVERSION, expect=0x03 → send/recv response → OAuth2 token fetch if t->token_mode is non-empty/non-"none" → kXR_login with pid=ngx_pid, username="xrd", capver=kXR_ver005 → send/recv response → handle status: kXR_ok returns immediately (anonymous login complete), kXR_authmore delegates to tpc_outbound_finish_login() for multi-step auth, other status rejects.
 * ------------------------------------------------------------------ */

#include "tpc_internal.h"


#include <string.h>
#include <stdlib.h>

/* Helper functions declared in gsi_outbound_common.c — extern to link them. */
extern void tpc_put_u32(u_char *p, uint32_t v);
extern int tpc_send_kxr_auth(xrootd_tpc_pull_t *t, int fd, u_char seq, const u_char *cred, uint32_t len);

/* ------------------------------------------------------------------ */
/* Anonymous XRootD session setup: handshake → kXR_protocol → kXR_login */
/* ------------------------------------------------------------------ */
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
    ngx_memzero(&hs, sizeof(hs));
    hs.fourth = htonl(4);
    hs.fifth  = htonl(ROOTD_PQ);

    if (tpc_send_all(fd, &hs, sizeof(hs)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC handshake send failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
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

    /* kXR_protocol */
    ngx_memzero(&pr, sizeof(pr));
    pr.streamid[1] = 1;
    pr.requestid   = htons(kXR_protocol);
    pr.clientpv    = htonl(kXR_PROTOCOLVERSION);
    pr.expect      = 0x03;

    if (tpc_send_all(fd, &pr, sizeof(pr)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_protocol send failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_protocol recv failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    free(body);
    body = NULL;
    if (status != kXR_ok) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC kXR_protocol rejected (status=%u)", (unsigned) status);
        t->xrd_error = kXR_ServerError;
        return -1;
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
    ngx_memzero(&lr, sizeof(lr));
    lr.streamid[1] = 1;
    lr.requestid   = htons(kXR_login);
    lr.pid         = htonl((kXR_int32) ngx_pid);
    lr.username[0] = 'x';
    lr.username[1] = 'r';
    lr.username[2] = 'd';
    lr.capver      = kXR_ver005;

    if (tpc_send_all(fd, &lr, sizeof(lr)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_login send failed");
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }
    if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_login recv failed");
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    if (status == kXR_ok) {
        /* Anonymous login (or auth=none): one round-trip, session is ready. */
        free(body);
        return 0;
    }

    if (status == kXR_authmore) {
        if (tpc_outbound_finish_login(t, fd, body, dlen) != 0) {
            free(body);
            return -1;
        }
        free(body);
        return 0;
    }

    free(body);
    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC kXR_login rejected (status=%u)", (unsigned) status);
    t->xrd_error = kXR_AuthFailed;
    return -1;
}

