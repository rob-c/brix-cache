/* ---- File: gsi_outbound_common.c — Credentialed XRootD login for native TPC pulls ----
 *
 * WHAT: After kXR_login returns kXR_authmore, completes the authentication handshake using either WLCG JWT (ztn) from xrootd_tpc_outbound_bearer_file or GSI cert chain when the server advertises &P=ztn / &P=gsi in the login parameter block. Provides wire helpers (tpc_put_u32 for big-endian encoding, tpc_send_kxr_auth for ClientRequestHdr construction + send_all) and public auth path functions (tpc_outbound_ztn for JWT bearer, tpc_read_bearer_token for file read delegation).
 *
 * WHY: Native TPC pull connects directly to a remote xrootd server; after anonymous handshake (bootstrap.c), authenticated fetch requires sending credentials on the outbound socket. The server's kXR_login response parameter block advertises which auth method it accepts (&P=ztn for JWT, &P=gsi for GSI). This file provides both wire-level helpers and the credential assembly + send logic for each path — ztn reads token from config file or delegated_token buffer, builds "ztn\x00" + token payload, sends kXR_auth ClientRequestHdr. GSI path (certreq chain) lives in gsi_outbound_certreq.c and gsi_outbound_exchange.c.
 *
 * HOW: tpc_put_u32 — htonl(v) → ngx_memcpy to output buffer for big-endian wire encoding; tpc_send_kxr_auth — zero ClientRequestHdr, set streamid[1] = seq + requestid = kXR_auth, memcpy ctype from cred_payload into hdr body offset 12, set dlen via htonl, send_all(hdr) then send_all(cred_payload); tpc_read_bearer_token — read path from t->conf->tpc_outbound_bearer_file, delegate to xrootd_token_read_file with "TPC outbound" label; tpc_outbound_ztn — check delegated_token[0] != '\0' (OAuth2/OIDC exchange result) → strlen → malloc(4+token_len) → memcpy("ztn\x00") + token → tpc_send_kxr_auth → recv_response checking status == kXR_ok → free(cred/body). Caller: tpc/thread.c (auth path dispatch based on login parameter block).
 * ------------------------------------------------------------------ */

#include "tpc_internal.h"
#include "../session/session.h"
#include "../protocol/gsi.h"
#include "../token/file.h"

#include <stdio.h>
#include <errno.h>

#if defined(__linux__)
#include <endian.h>
#endif


#define TPC_BEARER_MAX     65536
#define TPC_GSI_MAX_BODY   (256 * 1024)

/* WHAT: Big-endian uint32 wire encoding helper — htonl(v) → ngx_memcpy to output buffer. */

void
tpc_put_u32(u_char *p, uint32_t v)
{
    uint32_t be;

    be = htonl(v);
    ngx_memcpy(p, &be, sizeof(be));
}

/* WHAT: Construct kXR_auth ClientRequestHdr (streamid + requestid + ctype from cred_payload + dlen via htonl), send_all(hdr) then send_all(cred_payload). Returns 0 or -1 with error code. */

int
tpc_send_kxr_auth(xrootd_tpc_pull_t *t, int fd, u_char stream_seq,
    const u_char *cred_payload, uint32_t cred_len)
{
    ClientRequestHdr  hdr;
    u_char            ctype[4];

    ngx_memzero(&hdr, sizeof(hdr));
    hdr.streamid[1]    = stream_seq;
    hdr.requestid      = htons(kXR_auth);
    ngx_memcpy(ctype, cred_payload, sizeof(ctype));
    ngx_memcpy(hdr.body + 12, ctype, 4);
    hdr.dlen           = htonl((kXR_int32) cred_len);

    if (tpc_send_all(fd, &hdr, sizeof(hdr)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_auth send hdr failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (tpc_send_all(fd, cred_payload, cred_len) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_auth send body failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    return 0;
}

/* WHAT: Read JWT bearer token from xrootd_tpc_outbound_bearer_file config path — delegate to xrootd_token_read_file with 'TPC outbound' label, store result in buf. Returns 0 or -1 with error code (kXR_ArgInvalid for invalid/missing/empty file, kXR_IOError for read failure). Caller: tpc_outbound_ztn. */

static int
tpc_read_bearer_token(xrootd_tpc_pull_t *t, u_char *buf, size_t buf_sz,
    size_t *out_len)
{
    ngx_str_t     *path;

    path = &t->conf->tpc_outbound_bearer_file;

    if (xrootd_token_read_file(path, buf, buf_sz, out_len, NULL,
                               "TPC outbound") != NGX_OK)
    {
        if (errno == EINVAL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC outbound bearer file path invalid, missing, or empty");
            t->xrd_error = kXR_ArgInvalid;
        } else {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC cannot read xrootd_tpc_outbound_bearer_file: %s",
                     strerror(errno));
            t->xrd_error = kXR_IOError;
        }
        return -1;
    }

    return 0;
}

/* WHAT: JWT bearer auth path — check delegated_token[0] != '\0' (OAuth2/OIDC exchange result) → strlen → malloc(4+token_len) → memcpy("ztn\x00") + token → tpc_send_kxr_auth(kXR_auth, seq=3) → recv_response checking status == kXR_ok → free(cred/body). Returns 0 or -1 with error code. Caller: tpc/thread.c (auth path dispatch based on login parameter block &P=ztn). */

int
tpc_outbound_ztn(xrootd_tpc_pull_t *t, int fd)
{
    u_char         *cred;
    uint32_t        cred_len;
    uint16_t        status;
    uint32_t        dlen;
    u_char         *body;
    size_t          token_len;

    /*
     * Use the delegated token from OAuth2/OIDC token exchange when available;
     * otherwise fall back to reading from the bearer file.
     */
    if (t->delegated_token[0] != '\0') {
        token_len = strlen(t->delegated_token);
    } else {
        u_char token_buf[TPC_BEARER_MAX];
        if (tpc_read_bearer_token(t, token_buf, sizeof(token_buf), &token_len)
            != 0)
        {
            return -1;
        }
        ngx_memcpy(t->delegated_token, token_buf, token_len + 1);
        token_len = strlen(t->delegated_token);
    }

    cred_len = (uint32_t) (4 + token_len);
    cred = malloc((size_t) cred_len);
    if (cred == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC ztn cred OOM");
        t->xrd_error = kXR_NoMemory;
        return -1;
    }

    ngx_memcpy(cred, "ztn\x00", 4);
    ngx_memcpy(cred + 4, t->delegated_token, token_len);

    if (tpc_send_kxr_auth(t, fd, 3, cred, cred_len) != 0) {
        free(cred);
        return -1;
    }
    free(cred);

    body = NULL;
    if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC ztn auth recv failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    free(body);

    if (status != kXR_ok) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC ztn auth rejected (status=%u)", (unsigned) status);
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    return 0;
}

