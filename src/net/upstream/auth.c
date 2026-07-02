/* File: auth.c — Outbound bearer-token (ztn) authentication for upstream redirector
 * WHAT: Sends a kXR_auth request frame containing the configured WLCG JWT token to an upstream XRootD redirector server when it advertises "ztn" credential type. Token file read synchronously from disk via xrootd_token_read_file() (small local file < 64 KiB, refreshed externally by SciTokens daemon or Kubernetes projected-volume refresher — microseconds latency, no event loop stall). Wire frame assembly: ClientAuthRequest header (24 B) with streamid echoing client's ID + kXR_auth requestid + zeroes reserved + "ztn\0" credtype + dlen = 4+token_len big-endian; payload "ztn\0" repeated per XRootD convention + raw JWT bytes. Frame allocated from c->pool via ngx_palloc, flushed to upstream via xrootd_upstream_flush(). State set to bs_phase=XRD_UP_BS_AUTH with read event armed after flush completes (partial write arms write event then read; full write arms read immediately). Response accumulator reset for kXR_auth reply reception (rhdr_pos=0, resp_dlen=0, resp_body=NULL, resp_body_pos=0). Max token size UPSTREAM_BEARER_MAX 65536 bytes.
 *
 * WHY: Upstream redirectors may require their own authentication separate from client auth. When a remote XRootD server responds kXR_login with kXR_authmore + "ztn" credential type, nginx must authenticate itself using the configured upstream token file (different from client-facing tokens). Synchronous read avoids async complexity for small local files. Echoing client streamid maintains request correlation end-to-end. Repeating "ztn\0" in payload follows XRootD wire convention where credtype appears both in header dlen field and payload start. Pool allocation ensures lifecycle tied to connection cleanup. State tracking (XRD_UP_BS_AUTH) enables upstream event handler to know which reply phase is expected. Response accumulator reset prevents stale data from previous phases contaminating the auth reply parsing.
 *
 * HOW: Includes upstream_internal.h + token/file.h → defines UPSTREAM_BEARER_MAX 65536 (line 21) → function xrootd_upstream_send_token_auth(up, conf) (lines 31-113): reads token file via xrootd_token_read_file() returning NGX_OK/NGX_ERROR (lines 43-48) → computes cred_len=4+token_len and frame_len=sizeof(ClientAuthRequest)+cred_len (line 64-65) → allocates frame from pool via ngx_palloc (line 67) → fills header: streamid[0/1] from up->req_streamid, requestid=kXR_auth htons, reserved zeroes, credtype="ztn\0" ngx_memcpy, dlen=cred_len htonl (lines 72-78) → fills payload: "ztn\0" at offset 0 + token_buf at offset 4 (lines 80-82) → sets wbuf/wbuf_len/wbuf_pos/bs_phase=XRD_UP_BS_AUTH for flush (lines 84-87) → resets response accumulator rhdr_pos/resp_dlen/resp_body/resp_body_pos to zero (lines 90-93) → debug log token size (lines 95-97) → flush via xrootd_upstream_flush() returning NGX_ERROR on failure (line 99) → if partial write arms write event with ngx_handle_write_event(up->conn->write,0) then returns NGX_OK; if full write arms read event with ngx_handle_read_event(up->conn->read,0) and returns result (lines 103-112). */

/*
 * auth.c — outbound bearer-token (ztn) authentication for the upstream redirector.
 *
 * When a remote XRootD server responds to kXR_login with kXR_authmore and
 * advertises the "ztn" (WLCG JWT) credential type, this file reads the
 * configured token file and sends a kXR_auth frame containing the token.
 *
 * Token file is read synchronously — it is a small, local file (< 64 KiB)
 * and is refreshed externally (e.g. by a SciTokens credential cache daemon or
 * a Kubernetes projected-volume token refresher).  The read completes in
 * microseconds and does not meaningfully stall the event loop.
 *
 * Credential format on the wire (kXR_auth request):
 *   Header (24 bytes): streamid[2] + requestid[2] + reserved[12] + credtype[4] + dlen[4]
 *   Payload  (dlen bytes): credtype[4]="ztn\0" + raw JWT bytes
 */

#include "upstream_internal.h"
#include "auth/token/file.h"
#include "core/compat/alloc_guard.h"

#define UPSTREAM_BEARER_MAX  65536   /* max token file size (bytes) */

/*
 * xrootd_upstream_send_token_auth — read the configured token file and send
 * a kXR_auth "ztn" frame to the upstream server.
 *
 * Sets bs_phase = XRD_UP_BS_AUTH and arms the read event.
 * Returns NGX_OK on success (may be NGX_AGAIN if write did not complete).
 * Returns NGX_ERROR on any failure; caller must call xrootd_upstream_abort().
 */
ngx_int_t
xrootd_upstream_send_token_auth(xrootd_upstream_t *up,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    u_char              token_buf[UPSTREAM_BEARER_MAX];
    size_t              token_len;
    size_t              cred_len;
    size_t              frame_len;
    u_char             *frame;
    ClientAuthRequest  *hdr;
    u_char             *payload;

    if (xrootd_token_read_file(&conf->upstream_token_file, token_buf,
                               sizeof(token_buf), &token_len, up->conn->log,
                               "xrootd: upstream") != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * Assemble the kXR_auth request:
     *
     *   [ClientAuthRequest header (24 B)]
     *     streamid[2]   — echo client's stream ID
     *     requestid[2]  — kXR_auth
     *     reserved[12]  — zeroes
     *     credtype[4]   — "ztn\0"
     *     dlen[4]       — 4 + token_len (big-endian)
     *
     *   [Payload (cred_len = 4 + token_len bytes)]
     *     credtype[4]   — "ztn\0"  (repeated in payload per XRootD convention)
     *     token bytes   — raw JWT string
     */
    cred_len  = 4 + token_len;
    frame_len = sizeof(ClientAuthRequest) + cred_len;

    XROOTD_PALLOC_OR_RETURN(frame, up->conn->pool, frame_len, NGX_ERROR);

    hdr = (ClientAuthRequest *)(void *) frame;
    ngx_memzero(hdr, sizeof(*hdr));
    hdr->streamid[0] = up->req_streamid[0];
    hdr->streamid[1] = up->req_streamid[1];
    hdr->requestid   = htons(kXR_auth);
    {
        xrdw_auth_req_t b;
        ngx_memcpy(b.credtype, "ztn\x00", 4);
        xrdw_auth_req_pack(&b, ((ClientRequestHdr *) (void *) frame)->body);
    }
    hdr->dlen = htonl((kXR_int32) cred_len);

    payload = frame + sizeof(ClientAuthRequest);
    ngx_memcpy(payload,     "ztn\x00", 4);
    ngx_memcpy(payload + 4, token_buf, token_len);

    up->wbuf      = frame;
    up->wbuf_len  = frame_len;
    up->wbuf_pos  = 0;
    up->bs_phase  = XRD_UP_BS_AUTH;

    /* Reset the response accumulator for the kXR_auth reply. */
    up->rhdr_pos      = 0;
    up->resp_dlen     = 0;
    up->resp_body     = NULL;
    up->resp_body_pos = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, up->conn->log, 0,
                   "xrootd: upstream sending ztn token auth (%uz bytes); "
                   "frame_len=%uz",
                   token_len, frame_len);

    if (xrootd_upstream_flush(up) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (up->wbuf_pos < up->wbuf_len) {
        /* Partial write — arm write event; write handler arms read when done. */
        if (ngx_handle_write_event(up->conn->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    /* All bytes written; arm read event to wait for kXR_auth response. */
    return ngx_handle_read_event(up->conn->read, 0);
}
