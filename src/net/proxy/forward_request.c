#include "proxy_internal.h"
#include "protocols/root/session/registry.h"

/*
 * WHAT: Build and forward a client XRootD request to the upstream server,
 *       translating file handles (local → upstream), applying path rewriting
 *       when configured, capturing paths for audit logging, and saving copies
 *       for transparent kXR_wait retry.
 *
 * WHY:  The transparent proxy must translate every file handle from the
 *       client's namespace to the upstream server's namespace so the backend
 *       can locate files using its own fh numbers. Path rewriting (strip prefix)
 *       allows nginx-xrootd to present a different root path than the backend.
 *       Audit logging captures which paths were mutated for compliance tracking.
 *       kXR_wait retry copies let the proxy silently re-issue requests when
 *       upstream servers return "busy, try later" without client involvement.
 *
 * HOW:  brix_proxy_forward_request() allocates a request buffer, copies the
 *       client's header + payload, then dispatches through a reqid-based switch:
 *       kXR_open → pre-allocate fh slot + path strip + audit capture;
 *       read/write/close/sync/chkpoint → translate single fhandle + bound-secondary lazy-open check;
 *       stat/truncate/fattr → translate fhandle or capture path for audit;
 *       readv/writev → iterate payload segments translating each fhandle,
 *         bound-secondary collects ALL unresolved handles for sequential lazy-open;
 *       clone → translate src and dst handles;
 *       prepare → apply path strip rewrite;
 *       default (rm/rmdir/mkdir/chmod/mv) → path strip + audit capture.
 *       Finally saves a retry copy, queues to upstream write buffer, flushes,
 *       and arms the upstream read event loop.
 */

/*
 * WHAT: Handle kXR_open forwarding — pre-allocate a local fh slot, apply path
 *       rewriting, and capture the path for audit logging.
 * WHY:  The fh slot must be reserved before any error-free path so the open
 *       response can bind to it; path rewrite must precede audit capture.
 * HOW:  Allocates a local fh (255 sentinel = awaiting open response), rewrites
 *       the payload path if configured, then copies the (post-rewrite) path
 *       into the slot's audit buffer. Returns NGX_OK, or NGX_ABORT/NGX_ERROR
 *       via proxy_reject_request() (req freed, error sent to the client).
 *       *req and *total are updated in place.
 */
static ngx_int_t
brix_proxy_forward_open(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
                        ngx_connection_t *c, u_char **req, size_t *total)
{
    /* Pre-allocate a local file handle for when the response arrives */
    int local_fh = brix_proxy_alloc_local_fh(proxy);
    if (local_fh < 0) {
        return proxy_reject_request(ctx, c, *req, kXR_IOError,
                                    "proxy: no free file handles");
    }
    /* Mark slot as pending (non-free but no upstream handle yet) */
    proxy->fh_map[local_fh].upstream_fh = 255; /* sentinel: awaiting open response */
    proxy->fwd_local_fh = local_fh;

    /* Apply path rewriting before capturing path for audit */
    if (proxy->conf != NULL && proxy->conf->proxy.path_strip.len > 0
        && ctx->recv.cur_dlen > 0)
    {
        *req = proxy_rewrite_path(c, proxy->conf, *req, *total,
                                 XRD_REQUEST_HDR_LEN, ctx->recv.cur_dlen,
                                 total);
        /* Recalculate cur_dlen for audit capture below */
    }

    /* Capture path from payload for audit log */
    if (proxy->conf != NULL
        && proxy->conf->proxy.audit_log_fd != NGX_INVALID_FILE)
    {
        const u_char *path_start = *req + XRD_REQUEST_HDR_LEN;
        size_t        path_len   = *total > XRD_REQUEST_HDR_LEN
                                   ? *total - XRD_REQUEST_HDR_LEN : 0;
        size_t        plen       = path_len < BRIX_PROXY_PATH_MAX - 1
                                   ? path_len : BRIX_PROXY_PATH_MAX - 1;
        ngx_memcpy(proxy->fh_map[local_fh].path, path_start, plen);
        proxy->fh_map[local_fh].path[plen] = '\0';
    }
    return NGX_OK;
}

/*
 * WHAT: Capture path/dest audit fields for a default path-based mutation op.
 * WHY:  Split out of brix_proxy_forward_pathop() so the rewrite path and the
 *       per-reqid audit-buffer copies each stay small and single-purpose.
 * HOW:  For rm/rmdir/mkdir/chmod copies the (post-rewrite) payload path; for
 *       kXR_mv splits src[arg1len] + ' ' + dst into fwd_path / fwd_path2.
 */
static void
brix_proxy_pathop_audit(brix_proxy_ctx_t *proxy, uint16_t reqid,
                        u_char *req, size_t total)
{
    switch (reqid) {
    case kXR_rm:
    case kXR_rmdir:
    case kXR_mkdir:
    case kXR_chmod: {
        size_t plen = (total - XRD_REQUEST_HDR_LEN) < BRIX_PROXY_PATH_MAX
                      ? total - XRD_REQUEST_HDR_LEN
                      : BRIX_PROXY_PATH_MAX - 1;
        ngx_memcpy(proxy->fwd_path, req + XRD_REQUEST_HDR_LEN, plen);
        proxy->fwd_path[plen] = '\0';
        proxy->fwd_path2[0]   = '\0';
        proxy->fwd_path_audit = 1;
        break;
    }
    case kXR_mv: {
        /* payload: src[arg1len] + ' ' + dst */
        uint16_t arg1len_be;
        size_t   src_len, dst_off, dst_len;
        ngx_memcpy(&arg1len_be, req + 18, 2);
        src_len = (size_t) ntohs(arg1len_be);
        if (src_len >= BRIX_PROXY_PATH_MAX) {
            src_len = BRIX_PROXY_PATH_MAX - 1;
        }
        ngx_memcpy(proxy->fwd_path, req + XRD_REQUEST_HDR_LEN, src_len);
        proxy->fwd_path[src_len] = '\0';
        dst_off = XRD_REQUEST_HDR_LEN + src_len + 1; /* skip space */
        if (dst_off < total) {
            dst_len = total - dst_off;
            if (dst_len >= BRIX_PROXY_PATH_MAX) {
                dst_len = BRIX_PROXY_PATH_MAX - 1;
            }
            ngx_memcpy(proxy->fwd_path2, req + dst_off, dst_len);
            proxy->fwd_path2[dst_len] = '\0';
        } else {
            proxy->fwd_path2[0] = '\0';
        }
        proxy->fwd_path_audit = 1;
        break;
    }
    default:
        break;
    }
}

/*
 * WHAT: Handle default path-based op forwarding (rm/rmdir/mkdir/chmod/mv) —
 *       rewrite the path payload and capture path/dest for audit.
 * WHY:  Mutation ops carry paths (not fhandles); path rewrite must precede audit
 *       capture so the logged path matches what upstream sees.
 * HOW:  Strips the configured prefix from the payload path, then delegates to
 *       brix_proxy_pathop_audit() for the audit-buffer copies. *req and *total
 *       updated in place.
 */
static void
brix_proxy_forward_pathop(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
                          ngx_connection_t *c, uint16_t reqid,
                          u_char **req, size_t *total)
{
    /* Path-based ops: rewrite the path payload if configured */
    proxy->fwd_local_fh   = -1;
    proxy->fwd_path_audit = 0;
    if (proxy->conf != NULL && proxy->conf->proxy.path_strip.len > 0
        && ctx->recv.cur_dlen > 0)
    {
        *req = proxy_rewrite_path(c, proxy->conf, *req, *total,
                                 XRD_REQUEST_HDR_LEN, ctx->recv.cur_dlen,
                                 total);
    }
    /* Capture path/dest for mutation-op audit log */
    if (proxy->conf != NULL
        && proxy->conf->proxy.audit_log_fd != NGX_INVALID_FILE
        && ctx->recv.cur_dlen > 0)
    {
        brix_proxy_pathop_audit(proxy, reqid, *req, *total);
    }
}

/*
 * WHAT: Save a copy of the fully-assembled request for transparent kXR_wait retry.
 * WHY:  If upstream returns "busy, try later", the proxy silently re-issues the
 *       exact same request without client involvement — but only for reasonably
 *       sized payloads (huge writes are not buffered for retry).
 * HOW:  For total < 128KB, frees any prior retry buffer (avoids leak/double-free),
 *       allocates and copies the request, and records length/fh/count.
 */
static void
brix_proxy_save_wait_retry(brix_proxy_ctx_t *proxy, ngx_connection_t *c,
                           u_char *req, size_t total)
{
    /* Save a copy for transparent kXR_wait retry (if payload is not huge) */
    if (total < 128 * 1024) {
        if (proxy->wait_retry_req != NULL) {
            ngx_free(proxy->wait_retry_req);
        }
        proxy->wait_retry_req = ngx_alloc(total, c->log);
        if (proxy->wait_retry_req != NULL) {
            ngx_memcpy(proxy->wait_retry_req, req, total);
            proxy->wait_retry_req_len  = total;
        } else {
            proxy->wait_retry_req_len  = 0;
        }
        proxy->wait_retry_local_fh = proxy->fwd_local_fh;
        proxy->wait_retry_count    = 0;
    }
}

/*
 * WHAT: Queue the request to the upstream write buffer, flush it, and arm the
 *       upstream read (or a write timeout if the send is parked).
 * WHY:  Completes forwarding — hands ownership of req to the write path and
 *       transitions the proxy/session state machines to await the response.
 * HOW:  Sets wbuf state, resets the response accumulator, suspends the client
 *       read loop, flushes; on full send arms the read event, otherwise arms a
 *       write timeout. Returns NGX_OK or NGX_ERROR (after abort).
 */
static ngx_int_t
brix_proxy_queue_and_flush(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
                           u_char *req, size_t total)
{
    /* Queue the request to the upstream write buffer */
    proxy->wbuf       = req;
    proxy->wbuf_len   = total;
    proxy->wbuf_pos   = 0;
    proxy->wbuf_owned = 1;   /* Phase 39 (PXY-3): raw heap — free on send-complete */
    proxy->state      = XRD_PX_FORWARDING;

    /* Reset response accumulator */
    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body     = NULL;
    proxy->resp_body_pos = 0;

    /* Suspend client read loop while we wait for the upstream response */
    ctx->state = XRD_ST_PROXY;

    ngx_int_t rc = brix_proxy_flush(proxy);
    if (rc == NGX_ERROR) {
        brix_proxy_wbuf_release(proxy);
        brix_proxy_abort(proxy, "proxy: upstream write error");
        return NGX_ERROR;
    }

    if (proxy->wbuf_pos == proxy->wbuf_len) {
        /* Fully sent immediately — free the request buffer and arm upstream read */
        brix_proxy_wbuf_release(proxy);
        if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
            brix_proxy_abort(proxy, "proxy: read arm failed");
            return NGX_ERROR;
        }
    } else if (proxy->conf != NULL && proxy->conf->proxy.write_timeout > 0) {
        /* Phase 39 (PXY-2): the request is parked for the upstream write event —
         * bound how long a slow/backpressured upstream may stall it (the write
         * handler refreshes/clears the timer).  Armed here too in case the write
         * event never fires. */
        ngx_add_timer(proxy->conn->write, proxy->conf->proxy.write_timeout);
    }
    /* else: write handler will complete the send and arm the read */

    return NGX_OK;
}

/*
 * WHAT: Handle kXR_stat/truncate/fattr forwarding — translate the fhandle at
 *       body[0], or (for a path-based truncate) capture the path for audit.
 * WHY:  These ops carry an fhandle only when body[0] is nonzero; a zero fhandle
 *       means the op is path-based and needs audit capture instead.
 * HOW:  Translates the fhandle when nonzero; else, for kXR_truncate, copies the
 *       payload path into the audit buffer. Returns NGX_OK, or NGX_ABORT/NGX_ERROR
 *       via proxy_reject_request() (req freed, error sent).
 */
static ngx_int_t
brix_proxy_forward_stat(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
                        ngx_connection_t *c, uint16_t reqid,
                        u_char *req, size_t total)
{
    (void) total;
    /* fhandle at body[0]; only translate if nonzero (path-based if 0) */
    if (req[4] != 0) {
        if (proxy_translate_fh(proxy, req + 4, 0) != 0) {
            return proxy_reject_request(ctx, c, req, kXR_InvalidRequest,
                                        "proxy: invalid file handle");
        }
    } else if (reqid == kXR_truncate
               && proxy->conf != NULL
               && proxy->conf->proxy.audit_log_fd != NGX_INVALID_FILE
               && ctx->recv.cur_dlen > 0)
    {
        size_t plen = ctx->recv.cur_dlen < BRIX_PROXY_PATH_MAX
                      ? ctx->recv.cur_dlen : BRIX_PROXY_PATH_MAX - 1;
        ngx_memcpy(proxy->fwd_path, req + XRD_REQUEST_HDR_LEN, plen);
        proxy->fwd_path[plen]  = '\0';
        proxy->fwd_path2[0]    = '\0';
        proxy->fwd_path_audit  = 1;
    }
    proxy->fwd_local_fh = -1;
    return NGX_OK;
}

/*
 * WHAT: Handle kXR_clone forwarding — translate the src and dst fhandles.
 * WHY:  Split out of the dispatcher so each op handler stays small.
 * HOW:  Translates both fhandles (body[0], body[4]); on failure rejects the
 *       request (req freed, error sent). Returns NGX_OK or NGX_ABORT/NGX_ERROR.
 */
static ngx_int_t
brix_proxy_forward_clone(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
                         ngx_connection_t *c, u_char *req)
{
    /* src_fhandle at body[0], dst_fhandle at body[4] */
    if (proxy_translate_fh(proxy, req + 4, 0) != 0
        || proxy_translate_fh(proxy, req + 4, 4) != 0)
    {
        return proxy_reject_request(ctx, c, req, kXR_InvalidRequest,
                                    "proxy: invalid fhandle in clone");
    }
    proxy->fwd_local_fh = -1;
    return NGX_OK;
}

/*
 * WHAT: Handle kXR_prepare forwarding — apply path-strip rewrite to the payload.
 * WHY:  Split out of the dispatcher so each op handler stays small.
 * HOW:  Clears fh/audit state and rewrites the prepare payload path if configured.
 *       *req and *total updated in place.
 */
static void
brix_proxy_forward_prepare(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
                           ngx_connection_t *c, u_char **req, size_t *total)
{
    proxy->fwd_local_fh   = -1;
    proxy->fwd_path_audit = 0;
    if (proxy->conf != NULL && proxy->conf->proxy.path_strip.len > 0
        && ctx->recv.cur_dlen > 0)
    {
        *req = proxy_rewrite_prepare_payload(c, proxy->conf, *req, *total, total);
    }
}

/*
 * WHAT: Dispatch fhandle-carrying ops (open/read-group/stat/readv/writev/clone).
 * WHY:  Keeps the fh-translation branches together and under the gate, separate
 *       from the path-op branches.
 * HOW:  Routes each reqid to its handler. Returns NGX_OK / NGX_DONE (req ownership
 *       transferred) / NGX_ERROR (error already sent). Returns NGX_DECLINED for
 *       reqids this dispatcher does not own. *req and *total updated in place.
 */
static ngx_int_t
brix_proxy_translate_fh_op(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
                           ngx_connection_t *c, uint16_t reqid,
                           u_char **req, size_t *total)
{
    switch (reqid) {

    case kXR_open:
        return brix_proxy_forward_open(proxy, ctx, c, req, total);

    case kXR_read:
    case kXR_pgread:
    case kXR_write:
    case kXR_pgwrite:
    case kXR_close:
    case kXR_sync:
    case kXR_chkpoint:
        return brix_proxy_fh_translate_single(proxy, ctx, c, *req, *total,
                                              reqid,
                                              (size_t) ctx->recv.cur_dlen
                                              + ctx->recv.cur_body_extra);

    case kXR_stat:
    case kXR_truncate:
    case kXR_fattr:
        return brix_proxy_forward_stat(proxy, ctx, c, reqid, *req, *total);

    case kXR_readv:
    case kXR_writev:
        return brix_proxy_fh_translate_vector(proxy, ctx, c, *req, *total,
                                              reqid, ctx->recv.cur_dlen);

    case kXR_clone:
        return brix_proxy_forward_clone(proxy, ctx, c, *req);

    default:
        return NGX_DECLINED;
    }
}

/*
 * WHAT: Dispatch a forwarded request through its reqid-specific fh-translation /
 *       path-rewrite / audit-capture handler.
 * WHY:  Isolates the per-opcode switch from the surrounding build/queue logic so
 *       both stay under the readability gate; behavior is byte-identical to the
 *       inline switch it replaces.
 * HOW:  Tries the fh-op dispatcher first; unowned reqids fall through to prepare
 *       or the default path-op handler. Returns NGX_OK to continue, NGX_DONE when
 *       a lazy-open transferred req ownership (caller returns NGX_OK), NGX_ABORT
 *       when a kXR_error was queued to the client (req freed — caller must stop
 *       forwarding and return NGX_OK), or NGX_ERROR on a hard failure (req freed).
 *       *req and *total are updated in place by path-rewriting handlers.
 */
static ngx_int_t
brix_proxy_translate_dispatch(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
                              ngx_connection_t *c, uint16_t reqid,
                              u_char **req, size_t *total)
{
    /* file handle translation */
    ngx_int_t rc = brix_proxy_translate_fh_op(proxy, ctx, c, reqid, req, total);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    if (reqid == kXR_prepare) {
        brix_proxy_forward_prepare(proxy, ctx, c, req, total);
        return NGX_OK;
    }

    brix_proxy_forward_pathop(proxy, ctx, c, reqid, req, total);
    return NGX_OK;
}

/* public API: brix_proxy_forward_request() — build and send forwarded request * WHAT: Forward a client request to the upstream server with file handle translation,
 *       path rewriting, audit capture, and kXR_wait retry support. Returns NGX_OK or NGX_ERROR. */

/* build and send the forwarded request */
ngx_int_t
brix_proxy_forward_request(brix_proxy_ctx_t *proxy,
                              brix_ctx_t       *ctx,
                              ngx_connection_t   *c)
{
    uint16_t  reqid = ctx->recv.cur_reqid;
    /* body_len covers everything after the header: cur_dlen plus any
     * streamed trailing body the recv framing appended (cur_body_extra) —
     * kXR_writev segment data after the dlen-framed descriptor block, or the
     * kXR_ckpXeq sub-request body after the dlen-framed embedded header.
     * The header is forwarded verbatim (its dlen still frames only the
     * dlen-counted part), so the upstream sees the exact stock wire layout. */
    size_t    body_len = (size_t) ctx->recv.cur_dlen + ctx->recv.cur_body_extra;
    size_t    total    = XRD_REQUEST_HDR_LEN + body_len;
    u_char   *req;

    /* Allocate forwarded request buffer — freed by cleanup or after send */
    req = ngx_alloc(total, c->log);
    if (req == NULL) {
        return brix_send_error(ctx, c, kXR_IOError,
                                 "proxy: out of memory building request");
    }

    /* Copy full request header then payload (descriptors + any trailing data) */
    ngx_memcpy(req, ctx->recv.hdr_buf, XRD_REQUEST_HDR_LEN);
    if (body_len > 0 && ctx->recv.payload != NULL) {
        ngx_memcpy(req + XRD_REQUEST_HDR_LEN, ctx->recv.payload, body_len);
    }

    /* Pre-set forwarding metadata */
    proxy->fwd_reqid       = reqid;
    proxy->fwd_streamid[0] = ctx->recv.cur_streamid[0];
    proxy->fwd_streamid[1] = ctx->recv.cur_streamid[1];
    proxy->fwd_streaming   = 0;
    proxy->fwd_payload_len = ctx->recv.cur_dlen;

    /* file handle translation + path rewrite + audit capture, per reqid */
    ngx_int_t drc = brix_proxy_translate_dispatch(proxy, ctx, c, reqid,
                                                  &req, &total);
    if (drc == NGX_DONE) {
        return NGX_OK; /* lazy-open initiated; req ownership transferred */
    }
    if (drc == NGX_ABORT) {
        /* Request rejected: req has been freed and a kXR_error queued to the
         * client — the session continues, but req must NOT be touched again
         * (save_wait_retry/tap/queue below would be a use-after-free). */
        return NGX_OK;
    }
    if (drc != NGX_OK) {
        return drc; /* hard failure; req freed */
    }

    /* fwd_payload_len may have changed if path was rewritten (total updated) */
    proxy->fwd_payload_len = total > XRD_REQUEST_HDR_LEN
                             ? total - XRD_REQUEST_HDR_LEN : 0;

    brix_proxy_save_wait_retry(proxy, c, req, total);

    /* Tap: decode the fully-assembled (post-rewrite) request frame and emit it
     * to the observation tap before it goes upstream. */
    {
        brix_tap_frame_t tf;
        if (brix_tap_decode_request(req, total, &tf) > 0) {
            brix_tap_emit(&proxy->tap, &tf, BRIX_TAP_C2U, NULL, 0);
        }
    }

    return brix_proxy_queue_and_flush(proxy, ctx, req, total);
}

