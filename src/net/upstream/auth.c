/* File: auth.c — outbound kXR_auth framing for the transparent upstream connector
 * WHAT: brix_upstream_send_auth_frame() serialises one ClientAuthRequest (24-byte
 *   header echoing the client's stream ID, `credtype` in the 4-byte slot, dlen =
 *   payload length) followed by the caller's payload into a pool buffer, sets
 *   bs_phase = XRD_UP_BS_AUTH, resets the response accumulator and flushes.
 *   brix_upstream_send_token_auth() is the ztn (WLCG JWT) producer on top of it:
 *   it reads brix_upstream_token_file synchronously via brix_token_read_file()
 *   (small local file < 64 KiB, refreshed externally) and sends "ztn\0" + JWT.
 *   The gsi producers live in auth_gsi.c and use the same framer.
 *
 * WHY: an upstream redirector may require its own authentication separate from
 *   the client's.  ztn is one round; GSI is two (kXGC_certreq, kXGC_cert) and both
 *   must frame identically — one framer keeps the stream-ID echo, the credtype
 *   slot and the accumulator reset in a single place.  Echoing the client's
 *   stream ID keeps request correlation end-to-end; XRD_UP_BS_AUTH tells the
 *   bootstrap dispatcher which reply phase to expect.
 *
 * HOW: BRIX_PALLOC_OR_RETURN(frame) → header fill (xrdw_auth_req_pack for the
 *   credtype slot) → payload copy → wbuf/bs_phase/accumulator → brix_upstream_flush;
 *   a partial write arms the write event (the write handler arms the read when
 *   drained), a full write arms the read event directly.
 */

#include "upstream_internal.h"
#include "auth/token/file.h"
#include "core/compat/alloc_guard.h"

#define UPSTREAM_BEARER_MAX  65536   /* max token file size (bytes) */

/*
 * brix_upstream_send_auth_frame — frame `payload` as a kXR_auth request and flush.
 *
 * Wire layout:
 *   [ClientAuthRequest header (24 B)]
 *     streamid[2]   — echo client's stream ID
 *     requestid[2]  — kXR_auth
 *     reserved[12]  — zeroes
 *     credtype[4]   — e.g. "ztn\0" / "gsi\0"
 *     dlen[4]       — plen (big-endian)
 *   [Payload (plen bytes)]  — protocol-specific (ztn: "ztn\0" + JWT; gsi: bucket
 *                             stream from the XrdSecgsi kernel)
 *
 * Returns NGX_OK (sent, or partial with events armed) or NGX_ERROR (caller aborts).
 */
ngx_int_t
brix_upstream_send_auth_frame(brix_upstream_t *up, const char credtype[4],
    const u_char *payload, size_t plen)
{
    size_t              frame_len;
    u_char             *frame;
    ClientAuthRequest  *hdr;
    xrdw_auth_req_t     b;

    frame_len = sizeof(ClientAuthRequest) + plen;
    BRIX_PALLOC_OR_RETURN(frame, up->conn->pool, frame_len, NGX_ERROR);

    hdr = (ClientAuthRequest *)(void *) frame;
    ngx_memzero(hdr, sizeof(*hdr));
    hdr->streamid[0] = up->req_streamid[0];
    hdr->streamid[1] = up->req_streamid[1];
    hdr->requestid   = htons(kXR_auth);
    ngx_memcpy(b.credtype, credtype, 4);
    xrdw_auth_req_pack(&b, ((ClientRequestHdr *) (void *) frame)->body);
    hdr->dlen = htonl((kXR_int32) plen);

    if (plen > 0) {
        ngx_memcpy(frame + sizeof(ClientAuthRequest), payload, plen);
    }

    up->wbuf      = frame;
    up->wbuf_len  = frame_len;
    up->wbuf_pos  = 0;
    up->bs_phase  = XRD_UP_BS_AUTH;

    /* Reset the response accumulator for the kXR_auth reply. */
    up->rhdr_pos      = 0;
    up->resp_dlen     = 0;
    up->resp_body     = NULL;
    up->resp_body_pos = 0;

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, up->conn->log, 0,
                   "brix: upstream sending kXR_auth %*s (%uz payload bytes)",
                   (size_t) 3, credtype, plen);

    if (brix_upstream_flush(up) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (up->wbuf_pos < up->wbuf_len) {
        /* Partial write — arm write event; write handler arms read when done. */
        if (ngx_handle_write_event(up->conn->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    /* All bytes written; arm read event to wait for the kXR_auth response. */
    return ngx_handle_read_event(up->conn->read, 0);
}

/*
 * brix_upstream_send_token_auth — read the configured token file and send it
 * as a kXR_auth "ztn" frame ("ztn\0" repeated at the payload start per the
 * XRootD convention, then the raw JWT bytes).
 *
 * Returns NGX_ERROR on token-read failure (already logged) or the framer's result.
 */
ngx_int_t
brix_upstream_send_token_auth(brix_upstream_t *up,
    ngx_stream_brix_srv_conf_t *conf)
{
    u_char  cred[4 + UPSTREAM_BEARER_MAX];
    size_t  token_len;

    if (brix_token_read_file(&conf->upstream_token_file, cred + 4,
                               UPSTREAM_BEARER_MAX, &token_len, up->conn->log,
                               "brix: upstream") != NGX_OK)
    {
        return NGX_ERROR;
    }
    ngx_memcpy(cred, "ztn\x00", 4);

    return brix_upstream_send_auth_frame(up, "ztn", cred, 4 + token_len);
}
