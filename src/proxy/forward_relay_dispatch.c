#include "proxy_internal.h"
#include "../session/registry.h"

/*
 * WHAT: Deferred request dispatch and main proxy entry point — handles lazy upstream connection, request queuing during bootstrap,
 *      and bound-secondary channel lazy-open for file handle translation.
 * WHY: The transparent XRootD proxy must connect to the upstream server lazily (on first non-bootstrap request) rather than eagerly.
 *      Requests arriving before bootstrap completion are saved in proxy->saved_req and dispatched after bootstrap finishes via this function.
 *      Bound-secondary channels (kXR_bind) may carry read/readv requests for handles with no upstream mapping — a synthetic kXR_open is issued first.
 * HOW: Main entry xrootd_proxy_dispatch() creates proxy ctx on first call, connects to upstream lazily; saves pending requests during bootstrap state;
 *      forwards via xrootd_proxy_forward_request when idle. Dispatch pending (after bootstrap) checks bound-secondary lazy-open case then sets forwarding state and flushes request.
 */

/* ---- deferred request dispatch (called after bootstrap completes) --------- */

/* ---- public API: xrootd_proxy_dispatch_pending() — dispatch saved request after bootstrap ----
 * WHAT: Dispatch proxy->saved_req to upstream when bootstrap completion triggers this callback from events.c.
 * WHY: Bound-secondary channel lazy-open case: if a kXR_read/kXR_pgread/kXR_readv arrives for a handle with no upstream mapping,
 *      a synthetic kXR_open must be issued first via xrootd_proxy_lazy_open before the read request can proceed. */

/* ---- public API: xrootd_proxy_dispatch() — main proxy entry point (lazy-connect) ----
 * WHAT: Main dispatch entry point for all post-login opcodes — lazy-initializes upstream connection on first call, queues requests during bootstrap, forwards when ready.
 * WHY: Transparent XRootD proxy must connect lazily to avoid unnecessary overhead; requests arriving before bootstrap are saved and deferred until bootstrap completes via events.c callback. */

ngx_int_t
xrootd_proxy_dispatch_pending(xrootd_proxy_ctx_t *proxy)
{
    xrootd_ctx_t     *ctx = proxy->client_ctx;
    ngx_connection_t *c   = proxy->client_conn;
    u_char           *req = proxy->saved_req;
    size_t            len = proxy->saved_req_len;
    int               saved_lfh = proxy->saved_local_fh;
    uint16_t          reqid;
    ClientRequestHdr *hdr;

    if (req == NULL) {
        return NGX_OK;
    }

    hdr   = (ClientRequestHdr *)(void *) req;
    reqid = ntohs(hdr->requestid);

    /* Bound secondary lazy-open check: kXR_read / kXR_pgread / kXR_readv */
    if (ctx->is_bound) {
        int check_fh = -1;
        if ((reqid == kXR_read || reqid == kXR_pgread) && len >= 5) {
            check_fh = (int)(unsigned char) req[4];
        } else if (reqid == kXR_readv && len > XRD_REQUEST_HDR_LEN + 4) {
            check_fh = (int)(unsigned char) req[XRD_REQUEST_HDR_LEN];
        }
        if (check_fh >= 0 && check_fh < XROOTD_MAX_FILES
            && proxy->fh_map[check_fh].upstream_fh == XROOTD_PROXY_FH_FREE)
        {
            proxy->saved_req = NULL; /* ownership to lazy_open */
            return xrootd_proxy_lazy_open(proxy, ctx, c, check_fh, req, len);
        }
    }

    /* Normal deferred dispatch (e.g. kXR_open queued during bootstrap) */
    proxy->fwd_reqid       = reqid;
    proxy->fwd_streamid[0] = hdr->streamid[0];
    proxy->fwd_streamid[1] = hdr->streamid[1];
    proxy->fwd_local_fh    = saved_lfh;
    proxy->fwd_streaming   = 0;
    proxy->fwd_payload_len = len > XRD_REQUEST_HDR_LEN
                             ? len - XRD_REQUEST_HDR_LEN : 0;
    proxy->saved_req       = NULL;  /* ownership transferred to wbuf */

    proxy->wbuf     = req;
    proxy->wbuf_len = len;
    proxy->wbuf_pos = 0;
    proxy->state    = XRD_PX_FORWARDING;

    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body     = NULL;
    proxy->resp_body_pos = 0;

    if (xrootd_proxy_flush(proxy) == NGX_ERROR) {
        xrootd_proxy_abort(proxy, "proxy: send deferred request failed");
        return NGX_ERROR;
    }
    if (proxy->wbuf_pos < proxy->wbuf_len) {
        return NGX_OK; /* write handler will complete the send */
    }
    if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
        xrootd_proxy_abort(proxy, "proxy: read arm failed after deferred send");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- main dispatch entry point ------------------------------------------- */

ngx_int_t
xrootd_proxy_dispatch(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_xrootd_srv_conf_t *conf)
{
    xrootd_proxy_ctx_t *proxy;
    int                 i;

    /* --- lazy initialisation: connect to upstream on first dispatch --- */
    if (ctx->proxy == NULL) {

        /*
         * Loop guard: a permanently-rejecting upstream (bad credential, all
         * upstreams down) would otherwise make every re-dispatch allocate a
         * fresh proxy ctx on c->pool and reconnect, spinning the worker at
         * event-loop rate and growing the connection pool without bound.  Once
         * this connection has burned through its failure budget, stop retrying
         * and return a hard error instead of spawning another proxy.
         */
        if (ctx->proxy_fail_count >= XROOTD_PROXY_MAX_CONN_FAILS) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "xrootd proxy: %ui consecutive upstream failures on "
                          "this connection — failing request, not retrying",
                          ctx->proxy_fail_count);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "proxy: upstream unavailable");
        }

        proxy = ngx_pcalloc(c->pool, sizeof(xrootd_proxy_ctx_t));
        if (proxy == NULL) {
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "proxy: out of memory");
        }
        for (i = 0; i < XROOTD_MAX_FILES; i++) {
            proxy->fh_map[i].upstream_fh = XROOTD_PROXY_FH_FREE;
        }
        proxy->client_ctx     = ctx;
        proxy->client_conn    = c;
        proxy->conf           = conf;
        proxy->fwd_local_fh   = -1;
        proxy->saved_local_fh = -1;
        proxy->reconnect_left = (int) conf->proxy_reconnect_attempts;
        proxy->splice_pipe[0] = -1;
        proxy->splice_pipe[1] = -1;
        ctx->proxy            = proxy;

        if (xrootd_proxy_connect(proxy, c, conf) != NGX_OK) {
            ctx->proxy = NULL;
            /* Count synchronous connect/selection failures too (e.g. all
             * upstreams down) so they are bounded by the same per-connection
             * budget as async bootstrap aborts. */
            ctx->proxy_fail_count++;
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "proxy: upstream connect failed");
        }
    }

    proxy = ctx->proxy;

    /* --- if bootstrap is still in progress, save this request --- */
    if (proxy->state != XRD_PX_IDLE) {
        size_t total = XRD_REQUEST_HDR_LEN + ctx->cur_dlen;
        u_char *saved;

        saved = ngx_alloc(total, c->log);
        if (saved == NULL) {
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "proxy: out of memory saving request");
        }
        ngx_memcpy(saved, ctx->hdr_buf, XRD_REQUEST_HDR_LEN);
        if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
            ngx_memcpy(saved + XRD_REQUEST_HDR_LEN, ctx->payload, ctx->cur_dlen);
        }

        proxy->saved_req     = saved;
        proxy->saved_req_len = total;

        /* Pre-allocate a local fh for a deferred open */
        if (ctx->cur_reqid == kXR_open) {
            int local_fh = xrootd_proxy_alloc_local_fh(proxy);
            if (local_fh < 0) {
                ngx_free(saved);
                proxy->saved_req = NULL;
                return xrootd_send_error(ctx, c, kXR_IOError,
                                         "proxy: no free file handles");
            }
            proxy->fh_map[local_fh].upstream_fh = 255;  /* pending */
            proxy->saved_local_fh                = local_fh;
        } else {
            proxy->saved_local_fh = -1;
        }

        /* Suspend client read loop until bootstrap + deferred dispatch complete */
        ctx->state = XRD_ST_PROXY;
        return NGX_OK;
    }

    /* --- upstream is ready: forward the request now --- */
    return xrootd_proxy_forward_request(proxy, ctx, c);
}
