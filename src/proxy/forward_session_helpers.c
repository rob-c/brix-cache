/*
 * WHAT: Session helper functions for the transparent XRootD proxy — audit logging,
 *       kXR_wait retry timer callback, local file handle allocation, and lazy open
 *       for bound secondary connections. These helpers bridge client session state
 *       with upstream server operations during opaque relay.
 *
 * WHY:  The proxy must track per-file metadata (path, bytes read/written, duration)
 *       for audit compliance when files are accessed through the backend. kXR_wait
 *       responses from upstream require the proxy to silently re-issue saved requests
 *       without client involvement — a timer callback handles this asynchronously.
 *       Bound secondary connections share file handles with their primary session but
 *       need lazy-open to establish upstream mappings on demand before read/write ops.
 *       Local fh allocation provides the proxy's own handle namespace for each connection.
 *
 * HOW:  proxy_write_audit() writes a JSON line (path, bytes_read, bytes_written, duration_ms)
 *       to conf->proxy_audit_log_fd when configured; skips if audit fd is invalid or
 *       local_fh slot is out of range. xrootd_proxy_wait_handler() fires on timer expiry,
 *       restores fwd_reqid/streamid/fh from saved retry data, resets response state,
 *       flushes the saved request to upstream, and arms read event.
 *       xrootd_proxy_alloc_local_fh() scans fh_map for a free slot (upstream_fh == FREE)
 *       returning the index or -1 if exhausted. xrootd_proxy_lazy_open() looks up the
 *       canonical path from shared session handle registry, builds a synthetic anonymous
 *       kXR_open with streamid[1]=0xfe, marks the slot pending (255), saves read_req for
 *       later dispatch by relay_to_client after open response arrives, and flushes.
 */

#include "proxy_internal.h"
#include "session/registry.h"

/* proxy_write_audit — append a JSON line (path, bytes_read, bytes_written,
 * duration_ms) to the configured audit log for a local file-handle slot; no-op if
 * the audit fd is invalid or the slot is out of range. */
void
proxy_write_audit(xrootd_proxy_ctx_t *proxy, int local_fh)
{
    ngx_stream_xrootd_srv_conf_t *conf = proxy->conf;
    xrootd_proxy_fh_entry_t      *entry;
    u_char                        buf[1024];
    u_char                       *p;
    ngx_msec_int_t                duration_ms;

    if (conf == NULL || conf->proxy_audit_log_fd == NGX_INVALID_FILE) {
        return;
    }
    if (local_fh < 0 || local_fh >= XROOTD_MAX_FILES) {
        return;
    }
    entry = &proxy->fh_map[local_fh];

    duration_ms = (ngx_msec_int_t)(ngx_current_msec - entry->open_msec);

    p = ngx_snprintf(buf, sizeof(buf) - 2,
        "{\"path\":\"%s\","
        "\"bytes_read\":%uL,"
        "\"bytes_written\":%uL,"
        "\"duration_ms\":%M}\n",
        entry->path,
        (uint64_t) entry->bytes_read,
        (uint64_t) entry->bytes_written,
        duration_ms);

    ngx_write_fd(conf->proxy_audit_log_fd, buf, (size_t)(p - buf));
}

/* xrootd_proxy_wait_handler — kXR_wait retry timer: restore the saved request
 * metadata (reqid, streamid, local fh), reset response state, re-flush the saved
 * request to upstream, and arm the read event; cleans up the proxy if the client
 * context was destroyed. */
void
xrootd_proxy_wait_handler(ngx_event_t *ev)
{
    xrootd_proxy_ctx_t *proxy = ev->data;
    xrootd_ctx_t       *ctx;
    u_char             *req;
    size_t              len;
    ngx_int_t           rc;

    if (proxy == NULL) {
        return;
    }
    ctx = proxy->client_ctx;
    if (ctx == NULL || ctx->destroyed) {
        xrootd_proxy_cleanup(proxy);
        return;
    }

    req = proxy->wait_retry_req;
    len = proxy->wait_retry_req_len;
    if (req == NULL || proxy->conn == NULL) {
        return;
    }

    proxy->wait_retry_req     = NULL;
    proxy->wait_retry_req_len = 0;

    /* Re-issue the saved request (any opcode, not only kXR_open) */
    proxy->fwd_reqid       = ntohs(((ClientRequestHdr *)(void *) req)->requestid);
    proxy->fwd_streamid[0] = req[0];
    proxy->fwd_streamid[1] = req[1];
    proxy->fwd_local_fh    = proxy->wait_retry_local_fh;
    proxy->fwd_streaming   = 0;
    proxy->fwd_payload_len = len > XRD_REQUEST_HDR_LEN
                             ? len - XRD_REQUEST_HDR_LEN : 0;

    proxy->wbuf     = req;
    proxy->wbuf_len = len;
    proxy->wbuf_pos = 0;
    proxy->state    = XRD_PX_FORWARDING;

    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body     = NULL;
    proxy->resp_body_pos = 0;

    rc = xrootd_proxy_flush(proxy);
    if (rc == NGX_ERROR) {
        ngx_free(req);
        proxy->wbuf = NULL;
        xrootd_proxy_abort(proxy, "proxy: wait retry send failed");
        return;
    }
    if (proxy->wbuf_pos == proxy->wbuf_len) {
        ngx_free(req);
        proxy->wbuf = NULL;
        if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
            xrootd_proxy_abort(proxy, "proxy: read arm failed after wait retry");
        }
    }
    /* else: write handler will complete the send */
}

/* xrootd_proxy_alloc_local_fh — return the first free slot (upstream_fh == FREE) in
 * the proxy fh_map (its own file-handle namespace), or -1 if all are occupied. */
int
xrootd_proxy_alloc_local_fh(xrootd_proxy_ctx_t *proxy)
{
    int i;

    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        if (proxy->fh_map[i].upstream_fh == XROOTD_PROXY_FH_FREE) {
            return i;
        }
    }
    return -1;
}

/* lazy open for bound secondary connections */

/*
 * xrootd_proxy_lazy_open — issue a synthetic kXR_open on the upstream for a
 * handle that was opened by the primary session.
 *
 * Used when a bound secondary connection (ctx->is_bound) sends kXR_read for a
 * handle that has no upstream mapping yet in this connection's fh_map.  The
 * function looks up the canonical path from the shared session handle registry
 * (where the primary published it), builds an anonymous kXR_open, and queues it.
 * read_req (the original kXR_read) is saved as proxy->saved_req; it will be
 * dispatched by relay_to_client once the open response arrives.
 *
 * Ownership of read_req transfers to this function on NGX_OK; caller must not
 * free it.  On error the function frees read_req itself.
 */
ngx_int_t
xrootd_proxy_lazy_open(xrootd_proxy_ctx_t *proxy,
    xrootd_ctx_t *ctx, ngx_connection_t *c,
    int local_fh, u_char *read_req, size_t read_req_len)
{
    xrootd_shared_handle_entry_t  he;
    size_t                         pathlen, frame_len;
    u_char                        *frame;
    ClientOpenRequest             *oreq;
    ngx_int_t                      rc;

    if (!xrootd_session_handle_lookup(ctx->bound_sessid, local_fh, &he)) {
        ngx_free(read_req);
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "proxy: bound handle not published by primary");
    }

    pathlen   = ngx_strlen(he.path);
    frame_len = sizeof(ClientOpenRequest) + pathlen;

    frame = ngx_alloc(frame_len, c->log);
    if (frame == NULL) {
        ngx_free(read_req);
        return xrootd_send_error(ctx, c, kXR_IOError,
                                 "proxy: OOM for lazy open");
    }

    oreq = (ClientOpenRequest *)(void *) frame;
    ngx_memzero(oreq, sizeof(*oreq));
    oreq->streamid[0] = 0;
    oreq->streamid[1] = 0xfe;          /* synthetic — not echoed to client */
    oreq->requestid   = htons(kXR_open);
    {
        xrdw_open_req_t b = { .options = kXR_open_read };
        xrdw_open_req_pack(&b, ((ClientRequestHdr *) (void *) frame)->body);
    }
    oreq->dlen        = htonl((kXR_int32) pathlen);
    ngx_memcpy(frame + sizeof(*oreq), he.path, pathlen);

    /* Mark the slot pending while we wait for the open response */
    proxy->fh_map[local_fh].upstream_fh = 255;

    /* Save the kXR_read so relay_to_client can dispatch it after open */
    proxy->saved_req        = read_req;
    proxy->saved_req_len    = read_req_len;
    proxy->saved_local_fh   = local_fh;

    proxy->fwd_is_lazy_open = 1;
    proxy->fwd_local_fh     = local_fh;
    proxy->fwd_reqid        = kXR_open;
    proxy->fwd_streaming    = 0;
    proxy->fwd_payload_len  = 0;

    proxy->wbuf     = frame;
    proxy->wbuf_len = frame_len;
    proxy->wbuf_pos = 0;
    proxy->state    = XRD_PX_FORWARDING;

    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body     = NULL;
    proxy->resp_body_pos = 0;

    ctx->state = XRD_ST_PROXY;

    rc = xrootd_proxy_flush(proxy);
    if (rc == NGX_ERROR) {
        ngx_free(frame);
        proxy->wbuf = NULL;
        xrootd_proxy_abort(proxy, "proxy: lazy open send failed");
        return NGX_ERROR;
    }
    if (proxy->wbuf_pos == proxy->wbuf_len) {
        ngx_free(frame);
        proxy->wbuf = NULL;
        if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
            xrootd_proxy_abort(proxy, "proxy: read arm failed after lazy open");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

