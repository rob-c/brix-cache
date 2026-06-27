/* File: gsi_outbound_common.c — Credentialed XRootD login for native TPC pulls
 * WHAT: After kXR_login returns kXR_authmore, completes the authentication handshake using either WLCG JWT (ztn) from xrootd_tpc_outbound_bearer_file or GSI cert chain when the server advertises &P=ztn / &P=gsi in the login parameter block. Provides wire helpers (tpc_put_u32 for big-endian encoding, tpc_send_kxr_auth for ClientRequestHdr construction + send_all) and public auth path functions (tpc_outbound_ztn for JWT bearer, tpc_read_bearer_token for file read delegation).
 *
 * WHY: Native TPC pull connects directly to a remote xrootd server; after anonymous handshake (bootstrap.c), authenticated fetch requires sending credentials on the outbound socket. The server's kXR_login response parameter block advertises which auth method it accepts (&P=ztn for JWT, &P=gsi for GSI). This file provides both wire-level helpers and the credential assembly + send logic for each path — ztn reads token from config file or delegated_token buffer, builds "ztn\x00" + token payload, sends kXR_auth ClientRequestHdr. GSI path (certreq chain) lives in gsi_outbound_certreq.c and gsi_outbound_exchange.c.
 *
 * HOW: tpc_put_u32 — htonl(v) → ngx_memcpy to output buffer for big-endian wire encoding; tpc_send_kxr_auth — zero ClientRequestHdr, set streamid[1] = seq + requestid = kXR_auth, memcpy ctype from cred_payload into hdr body offset 12, set dlen via htonl, send_all(hdr) then send_all(cred_payload); tpc_read_bearer_token — read path from t->conf->tpc_outbound_bearer_file, delegate to xrootd_token_read_file with "TPC outbound" label; tpc_outbound_ztn — check delegated_token[0] != '\0' (OAuth2/OIDC exchange result) → strlen → malloc(4+token_len) → memcpy("ztn\x00") + token → tpc_send_kxr_auth → recv_response checking status == kXR_ok → free(cred/body). Caller: tpc/thread.c (auth path dispatch based on login parameter block).
 * */

#include "tpc_internal.h"
#include "../session/session.h"
#include "../protocol/gsi.h"
#include "../token/file.h"

#include <stdio.h>
#include <errno.h>

#if defined(__linux__)
#include <endian.h>
#endif


/*
 * TPC_BEARER_MAX  — stack cap for a single JWT read from the bearer file; 64 KiB
 *                   is far above any real WLCG token, so it doubles as an upper
 *                   sanity bound on file size.
 * TPC_GSI_MAX_BODY — shared upper bound (256 KiB) on a decoded GSI auth body,
 *                   referenced by the certreq/exchange siblings.
 */
#define TPC_BEARER_MAX     65536
#define TPC_GSI_MAX_BODY   (256 * 1024)

/* WHAT: Big-endian uint32 wire encoding helper — htonl(v) → ngx_memcpy to output buffer. */

void
tpc_put_u32(u_char *p, uint32_t v)
{
    uint32_t be;

    /*
     * XRootD security buckets carry length/tag fields as network-order
     * (big-endian) uint32. htonl() normalises from host order, then we copy the
     * raw 4 bytes — ngx_memcpy (not a *(uint32_t *)p store) so callers can write
     * to unaligned cursor positions inside a packed wire buffer.
     */
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

    /*
     * Build the fixed 24-byte kXR_auth request header. ClientRequestHdr is the
     * generic overlay: streamid[2] | requestid (u16) | body[16] | dlen (u32).
     * For kXR_auth that body region maps to ClientAuthRequest as
     * reserved[12] | credtype[4], so the credtype lands at body offset 12
     * (= absolute byte offset 16 in the header).
     */
    ngx_memzero(&hdr, sizeof(hdr));
    /* streamid[1] is the low byte; we use it as the handshake sequence number
     * (streamid[0] stays 0). Matches the seq the server echoes in replies. */
    hdr.streamid[1]    = stream_seq;
    hdr.requestid      = htons(kXR_auth);          /* network order on the wire */
    /*
     * The credtype field advertises the auth protocol name as the first 4 bytes
     * of the payload, NUL-padded — "gsi\0", "ztn\0", etc. Mirror those bytes
     * verbatim into the header's credtype slot; the full name (and its trailing
     * data) is also sent in the payload below. cred_payload must be >= 4 bytes.
     */
    ngx_memcpy(ctype, cred_payload, sizeof(ctype));
    ngx_memcpy(hdr.body + 12, ctype, 4);           /* credtype field (offset 16) */
    hdr.dlen           = htonl((kXR_int32) cred_len); /* payload length, net order */

    /*
     * Wire order: header first, then the cred_len-byte payload. Both go through
     * tpc_send_all which loops over partial writes; a short/failed send here
     * leaves the socket mid-message, so the caller must treat -1 as fatal for
     * this connection (it does — every caller aborts the pull).
     */
    if (tpc_send_all(t, fd, &hdr, sizeof(hdr)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_auth send hdr failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (tpc_send_all(t, fd, cred_payload, cred_len) != 0) {
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
        /* Already populated by an earlier OAuth2/OIDC exchange for this pull. */
        token_len = strlen(t->delegated_token);
    } else {
        u_char token_buf[TPC_BEARER_MAX];
        if (tpc_read_bearer_token(t, token_buf, sizeof(token_buf), &token_len)
            != 0)
        {
            return -1;
        }
        /*
         * Cache the file-sourced token in t->delegated_token so any later auth
         * round reuses it. token_len + 1 copies the trailing NUL that
         * tpc_read_bearer_token guarantees; re-derive token_len from the cached
         * copy so a NUL embedded in the file truncates here, not on the wire.
         */
        ngx_memcpy(t->delegated_token, token_buf, token_len + 1);
        token_len = strlen(t->delegated_token);
    }

    /*
     * ztn credential layout: 4-byte protocol tag "ztn\0" followed by the raw
     * token bytes (no NUL, no length prefix — dlen in the header bounds it).
     */
    cred_len = (uint32_t) (4 + token_len);
    cred = malloc((size_t) cred_len);
    if (cred == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC ztn cred OOM");
        t->xrd_error = kXR_NoMemory;
        return -1;
    }

    ngx_memcpy(cred, "ztn\x00", 4);                /* protocol tag, slots 0..3 */
    ngx_memcpy(cred + 4, t->delegated_token, token_len);

    /*
     * seq=3 is the handshake sequence following bootstrap (protocol=1, login=2),
     * so this is the first authenticated request on the outbound socket. cred is
     * a malloc()'d temporary owned here — free it on every exit path (the send
     * helper copies what it needs into the header and writes the body inline).
     */
    if (tpc_send_kxr_auth(t, fd, 3, cred, cred_len) != 0) {
        free(cred);
        return -1;
    }
    free(cred);

    /*
     * tpc_recv_response allocates *body for the server reply; we own it from
     * here. The reply payload is unused for ztn (success is signalled by status
     * alone), so free it unconditionally before inspecting status.
     */
    body = NULL;
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
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

