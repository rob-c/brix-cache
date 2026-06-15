#include "proxy_internal.h"
#include "../session/registry.h"

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
 * HOW:  xrootd_proxy_forward_request() allocates a request buffer, copies the
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

/* ---- public API: xrootd_proxy_forward_request() — build and send forwarded request ----
 * WHAT: Forward a client request to the upstream server with file handle translation,
 *       path rewriting, audit capture, and kXR_wait retry support. Returns NGX_OK or NGX_ERROR. */

/* ---- build and send the forwarded request --------------------------------- */

ngx_int_t
xrootd_proxy_forward_request(xrootd_proxy_ctx_t *proxy,
                              xrootd_ctx_t       *ctx,
                              ngx_connection_t   *c)
{
    uint16_t  reqid = ctx->cur_reqid;
    size_t    total = XRD_REQUEST_HDR_LEN + ctx->cur_dlen;
    u_char   *req;

    /* Allocate forwarded request buffer — freed by cleanup or after send */
    req = ngx_alloc(total, c->log);
    if (req == NULL) {
        return xrootd_send_error(ctx, c, kXR_IOError,
                                 "proxy: out of memory building request");
    }

    /* Copy full request header then payload */
    ngx_memcpy(req, ctx->hdr_buf, XRD_REQUEST_HDR_LEN);
    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        ngx_memcpy(req + XRD_REQUEST_HDR_LEN, ctx->payload, ctx->cur_dlen);
    }

    /* Pre-set forwarding metadata */
    proxy->fwd_reqid       = reqid;
    proxy->fwd_streamid[0] = ctx->cur_streamid[0];
    proxy->fwd_streamid[1] = ctx->cur_streamid[1];
    proxy->fwd_streaming   = 0;
    proxy->fwd_payload_len = ctx->cur_dlen;

    /* ---- file handle translation ---- */

    switch (reqid) {

    case kXR_open: {
        /* Pre-allocate a local file handle for when the response arrives */
        int local_fh = xrootd_proxy_alloc_local_fh(proxy);
        if (local_fh < 0) {
            ngx_free(req);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "proxy: no free file handles");
        }
        /* Mark slot as pending (non-free but no upstream handle yet) */
        proxy->fh_map[local_fh].upstream_fh = 255; /* sentinel: awaiting open response */
        proxy->fwd_local_fh = local_fh;

        /* Apply path rewriting before capturing path for audit */
        if (proxy->conf != NULL && proxy->conf->proxy_path_strip.len > 0
            && ctx->cur_dlen > 0)
        {
            req = proxy_rewrite_path(c, proxy->conf, req, total,
                                     XRD_REQUEST_HDR_LEN, ctx->cur_dlen,
                                     &total);
            /* Recalculate cur_dlen for audit capture below */
        }

        /* Capture path from payload for audit log */
        if (proxy->conf != NULL
            && proxy->conf->proxy_audit_log_fd != NGX_INVALID_FILE)
        {
            const u_char *path_start = req + XRD_REQUEST_HDR_LEN;
            size_t        path_len   = total > XRD_REQUEST_HDR_LEN
                                       ? total - XRD_REQUEST_HDR_LEN : 0;
            size_t        plen       = path_len < XROOTD_PROXY_PATH_MAX - 1
                                       ? path_len : XROOTD_PROXY_PATH_MAX - 1;
            ngx_memcpy(proxy->fh_map[local_fh].path, path_start, plen);
            proxy->fh_map[local_fh].path[plen] = '\0';
        }
        break;
    }

    case kXR_read:
    case kXR_pgread:
    case kXR_write:
    case kXR_pgwrite:
    case kXR_close:
    case kXR_sync:
    case kXR_chkpoint: {
        /* fhandle is at body[0] in the 24-byte request header */
        int local_fh = (int)(unsigned char) req[4]; /* save before translation */

        /* Bound secondary: lazy-open the file on first read for this handle */
        if (ctx->is_bound
            && (reqid == kXR_read || reqid == kXR_pgread)
            && local_fh >= 0 && local_fh < XROOTD_MAX_FILES
            && proxy->fh_map[local_fh].upstream_fh == XROOTD_PROXY_FH_FREE)
        {
            /* req ownership transfers to xrootd_proxy_lazy_open */
            return xrootd_proxy_lazy_open(proxy, ctx, c, local_fh, req, total);
        }

        if (proxy_translate_fh(proxy, req + 4, 0) != 0) {
            ngx_free(req);
            return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                     "proxy: invalid file handle");
        }
        proxy->fwd_local_fh = local_fh;
        break;
    }

    case kXR_stat:
    case kXR_truncate:
    case kXR_fattr:
        /* fhandle at body[0]; only translate if nonzero (path-based if 0) */
        if (req[4] != 0) {
            if (proxy_translate_fh(proxy, req + 4, 0) != 0) {
                ngx_free(req);
                return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                         "proxy: invalid file handle");
            }
        } else if (reqid == kXR_truncate
                   && proxy->conf != NULL
                   && proxy->conf->proxy_audit_log_fd != NGX_INVALID_FILE
                   && ctx->cur_dlen > 0)
        {
            size_t plen = ctx->cur_dlen < XROOTD_PROXY_PATH_MAX
                          ? ctx->cur_dlen : XROOTD_PROXY_PATH_MAX - 1;
            ngx_memcpy(proxy->fwd_path, req + XRD_REQUEST_HDR_LEN, plen);
            proxy->fwd_path[plen]  = '\0';
            proxy->fwd_path2[0]    = '\0';
            proxy->fwd_path_audit  = 1;
        }
        proxy->fwd_local_fh = -1;
        break;

    case kXR_readv: {
        /*
         * Payload is an array of readahead_list: { fhandle[4], rlen[4], offset[8] }
         * Translate fhandle[0] in each entry.
         *
         * Bound secondary: collect ALL unique unresolved fhandles across all
         * segments and open them sequentially before dispatching.  xrdcp parallel
         * streams may reference several handles in a single readv.
         */
        u_char *payload = req + XRD_REQUEST_HDR_LEN;

        if (ctx->is_bound && ctx->cur_dlen >= 4) {
            /* First pass: collect unique unresolved fhs */
            int   pending[XROOTD_MAX_FILES];
            int   n_pending = 0;
            size_t pos;
            int   seen[XROOTD_MAX_FILES];
            int   i;

            for (i = 0; i < XROOTD_MAX_FILES; i++) { seen[i] = 0; }

            pos = 0;
            while (pos + 16 <= ctx->cur_dlen) {
                int fh = (int)(unsigned char) payload[pos];
                if (fh >= 0 && fh < XROOTD_MAX_FILES
                    && proxy->fh_map[fh].upstream_fh == XROOTD_PROXY_FH_FREE
                    && !seen[fh])
                {
                    seen[fh] = 1;
                    pending[n_pending++] = fh;
                }
                pos += 16;
            }

            if (n_pending > 0) {
                /* Store the queue; lazy_open will consume entries one by one */
                int first_fh = pending[0];
                for (i = 1; i < n_pending; i++) {
                    proxy->lazy_open_pending_fhs[i - 1] = pending[i];
                }
                proxy->lazy_open_pending_count = n_pending - 1;
                return xrootd_proxy_lazy_open(proxy, ctx, c, first_fh, req, total);
            }
        }

        {
            size_t pos = 0;
            while (pos + 16 <= ctx->cur_dlen) {
                if (proxy_translate_fh(proxy, payload + pos, 0) != 0) {
                    ngx_free(req);
                    return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                             "proxy: invalid fhandle in readv");
                }
                pos += 16;
            }
        }
        proxy->fwd_local_fh = -1;
        break;
    }

    case kXR_writev: {
        /* Payload: write_list { fhandle[4], wlen[4], offset[8] } */
        u_char *payload = req + XRD_REQUEST_HDR_LEN;
        size_t  pos     = 0;
        while (pos + 16 <= ctx->cur_dlen) {
            if (proxy_translate_fh(proxy, payload + pos, 0) != 0) {
                ngx_free(req);
                return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                         "proxy: invalid fhandle in writev");
            }
            pos += 16;
        }
        proxy->fwd_local_fh = -1;
        break;
    }

    case kXR_clone: {
        /* src_fhandle at body[0], dst_fhandle at body[4] */
        if (proxy_translate_fh(proxy, req + 4, 0) != 0
            || proxy_translate_fh(proxy, req + 4, 4) != 0)
        {
            ngx_free(req);
            return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                     "proxy: invalid fhandle in clone");
        }
        proxy->fwd_local_fh = -1;
        break;
    }

    case kXR_prepare:
        proxy->fwd_local_fh   = -1;
        proxy->fwd_path_audit = 0;
        if (proxy->conf != NULL && proxy->conf->proxy_path_strip.len > 0
            && ctx->cur_dlen > 0)
        {
            req = proxy_rewrite_prepare_payload(c, proxy->conf, req, total, &total);
        }
        break;

    default: {
        /* Path-based ops: rewrite the path payload if configured */
        proxy->fwd_local_fh   = -1;
        proxy->fwd_path_audit = 0;
        if (proxy->conf != NULL && proxy->conf->proxy_path_strip.len > 0
            && ctx->cur_dlen > 0)
        {
            req = proxy_rewrite_path(c, proxy->conf, req, total,
                                     XRD_REQUEST_HDR_LEN, ctx->cur_dlen,
                                     &total);
        }
        /* Capture path/dest for mutation-op audit log */
        if (proxy->conf != NULL
            && proxy->conf->proxy_audit_log_fd != NGX_INVALID_FILE
            && ctx->cur_dlen > 0)
        {
            switch (reqid) {
            case kXR_rm:
            case kXR_rmdir:
            case kXR_mkdir:
            case kXR_chmod: {
                size_t plen = (total - XRD_REQUEST_HDR_LEN) < XROOTD_PROXY_PATH_MAX
                              ? total - XRD_REQUEST_HDR_LEN
                              : XROOTD_PROXY_PATH_MAX - 1;
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
                if (src_len >= XROOTD_PROXY_PATH_MAX) {
                    src_len = XROOTD_PROXY_PATH_MAX - 1;
                }
                ngx_memcpy(proxy->fwd_path, req + XRD_REQUEST_HDR_LEN, src_len);
                proxy->fwd_path[src_len] = '\0';
                dst_off = XRD_REQUEST_HDR_LEN + src_len + 1; /* skip space */
                if (dst_off < total) {
                    dst_len = total - dst_off;
                    if (dst_len >= XROOTD_PROXY_PATH_MAX) {
                        dst_len = XROOTD_PROXY_PATH_MAX - 1;
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
        break;
    }
    }

    /* fwd_payload_len may have changed if path was rewritten (total updated) */
    proxy->fwd_payload_len = total > XRD_REQUEST_HDR_LEN
                             ? total - XRD_REQUEST_HDR_LEN : 0;

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

    ngx_int_t rc = xrootd_proxy_flush(proxy);
    if (rc == NGX_ERROR) {
        xrootd_proxy_wbuf_release(proxy);
        xrootd_proxy_abort(proxy, "proxy: upstream write error");
        return NGX_ERROR;
    }

    if (proxy->wbuf_pos == proxy->wbuf_len) {
        /* Fully sent immediately — free the request buffer and arm upstream read */
        xrootd_proxy_wbuf_release(proxy);
        if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
            xrootd_proxy_abort(proxy, "proxy: read arm failed");
            return NGX_ERROR;
        }
    } else if (proxy->conf != NULL && proxy->conf->proxy_write_timeout > 0) {
        /* Phase 39 (PXY-2): the request is parked for the upstream write event —
         * bound how long a slow/backpressured upstream may stall it (the write
         * handler refreshes/clears the timer).  Armed here too in case the write
         * event never fires. */
        ngx_add_timer(proxy->conn->write, proxy->conf->proxy_write_timeout);
    }
    /* else: write handler will complete the send and arm the read */

    return NGX_OK;
}

