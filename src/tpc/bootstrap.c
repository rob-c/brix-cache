#include "tpc_internal.h"

#if (NGX_THREADS)

#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Anonymous XRootD session setup: handshake → kXR_protocol → kXR_login */
/* ------------------------------------------------------------------ */

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

    if (status == kXR_authmore) {
        if (tpc_outbound_finish_login(t, fd, body, dlen) != 0) {
            free(body);
            return -1;
        }
        free(body);
        return 0;
    }
    if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_login recv failed");
        t->xrd_error = kXR_ServerError;
        return -1;
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
    if (status != kXR_ok) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC kXR_login rejected (status=%u)", (unsigned) status);
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    return 0;
}

#endif /* NGX_THREADS */
