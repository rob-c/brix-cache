#include "proxy_internal.h"
#include "protocols/root/session/registry.h"

/*
 * brix_proxy_tap_audit_sink — emit one JSON line per tapped frame to the
 * stable log. brix_proxy_tap_init — lazily set up the tap on first use: a log
 * copy with the per-session handler/data cleared (the connection log's appender
 * dereferences session state that is torn down out from under a late event), and
 * the audit sink registered. Mirrors the Phase-3 relay's stable-log pattern.
 */
void
brix_proxy_tap_audit_sink(void *ctx, const brix_tap_frame_t *f,
    brix_tap_dir_t dir, const u_char *payload, size_t payload_len)
{
    ngx_log_t *log = ctx;
    char       line[1280];

    (void) payload;
    (void) payload_len;

    if (brix_tap_audit_format(f, dir, line, sizeof(line)) > 0) {
        ngx_log_error(NGX_LOG_INFO, log, 0, "xrootd tap: %s", line);
    }
}

void
brix_proxy_tap_init(brix_proxy_ctx_t *proxy, ngx_connection_t *c)
{
    if (proxy->tap_inited) {
        return;
    }
    proxy->tap_log         = *c->log;
    proxy->tap_log.handler = NULL;
    proxy->tap_log.data    = NULL;
    proxy->tap_log.action  = NULL;
    ngx_memzero(&proxy->tap, sizeof(proxy->tap));
    brix_tap_register_sink(&proxy->tap, brix_proxy_tap_audit_sink,
                             &proxy->tap_log);
    proxy->tap_inited = 1;
}

/*
 * WHAT: Deferred request dispatch and main proxy entry point — handles lazy upstream connection, request queuing during bootstrap,
 *      and bound-secondary channel lazy-open for file handle translation.
 * WHY: The transparent XRootD proxy must connect to the upstream server lazily (on first non-bootstrap request) rather than eagerly.
 *      Requests arriving before bootstrap completion are saved in proxy->saved_req and dispatched after bootstrap finishes via this function.
 *      Bound-secondary channels (kXR_bind) may carry read/readv requests for handles with no upstream mapping — a synthetic kXR_open is issued first.
 * HOW: Main entry brix_proxy_dispatch() creates proxy ctx on first call, connects to upstream lazily; saves pending requests during bootstrap state;
 *      forwards via brix_proxy_forward_request when idle. Dispatch pending (after bootstrap) checks bound-secondary lazy-open case then sets forwarding state and flushes request.
 */

/* deferred request dispatch (called after bootstrap completes) */
/* public API: brix_proxy_dispatch_pending() — dispatch saved request after bootstrap * WHAT: Dispatch proxy->saved_req to upstream when bootstrap completion triggers this callback from events.c.
 * WHY: Bound-secondary channel lazy-open case: if a kXR_read/kXR_pgread/kXR_readv arrives for a handle with no upstream mapping,
 *      a synthetic kXR_open must be issued first via brix_proxy_lazy_open before the read request can proceed. */

/* public API: brix_proxy_dispatch() — main proxy entry point (lazy-connect) * WHAT: Main dispatch entry point for all post-login opcodes — lazy-initializes upstream connection on first call, queues requests during bootstrap, forwards when ready.
 * WHY: Transparent XRootD proxy must connect lazily to avoid unnecessary overhead; requests arriving before bootstrap are saved and deferred until bootstrap completes via events.c callback. */

/* ---- Detect a bound-secondary read that needs a synthetic upstream open ----
 *
 * WHAT: Returns the local file handle carried by a queued read-family request
 *      (kXR_read / kXR_pgread / kXR_readv) that currently has no upstream
 *      mapping, or -1 when no lazy open is required. A non-negative result means
 *      the caller must issue brix_proxy_lazy_open before forwarding.
 *
 * WHY: A kXR_bind secondary channel can carry read requests for handles that
 *      were opened on the primary channel and never mapped upstream on this
 *      channel; those must trigger a synthetic kXR_open first. Isolating this
 *      wire-shape probe as a pure query keeps the dispatch decision explicit and
 *      keeps the orchestrator's cyclomatic complexity within cap.
 *
 * HOW: 1. Non-bound channels never lazy-open — return -1 immediately.
 *      2. Extract the file-handle byte by opcode: read/pgread at byte 4,
 *         readv at the first byte past the request header, honoring the same
 *         minimum-length guards as the original inline check.
 *      3. Return the handle only when it is in range and its fh_map slot is
 *         still BRIX_PROXY_FH_FREE (no upstream mapping); otherwise -1.
 */
static int
brix_proxy_pending_lazy_fh(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    const u_char *req, size_t len, uint16_t reqid)
{
    int check_fh = -1;

    if (!ctx->is_bound) {
        return -1;
    }

    if ((reqid == kXR_read || reqid == kXR_pgread) && len >= 5) {
        check_fh = (int)(unsigned char) req[4];
    } else if (reqid == kXR_readv && len > XRD_REQUEST_HDR_LEN + 4) {
        check_fh = (int)(unsigned char) req[XRD_REQUEST_HDR_LEN];
    }

    if (check_fh >= 0 && check_fh < BRIX_MAX_FILES
        && proxy->fh_map[check_fh].upstream_fh == BRIX_PROXY_FH_FREE)
    {
        return check_fh;
    }
    return -1;
}

/* ---- Install the queued request as the write buffer and flush it upstream ----
 *
 * WHAT: Points the proxy write buffer at the saved request, resets the response
 *      accumulator, and flushes to the upstream connection. Returns NGX_OK on a
 *      full or partial send (the write handler completes a partial one) and
 *      NGX_ERROR after aborting the proxy on send or read-arm failure.
 *
 * WHY: The forward tail (buffer install, flush, read arm) is a single-purpose
 *      side-effecting step; extracting it keeps brix_proxy_dispatch_pending a
 *      flat sequence and its complexity within the per-function cap without
 *      altering the send ordering.
 *
 * HOW: 1. Set wbuf to the request bytes and mark the proxy XRD_PX_FORWARDING.
 *      2. Zero the response-parse cursors for the reply that will follow.
 *      3. Flush; on error abort and return NGX_ERROR.
 *      4. If the send is partial, return NGX_OK (write handler resumes it).
 *      5. Otherwise arm the read event; on failure abort and return NGX_ERROR.
 */
static ngx_int_t
brix_proxy_pending_flush(brix_proxy_ctx_t *proxy, u_char *req, size_t len)
{
    proxy->wbuf     = req;
    proxy->wbuf_len = len;
    proxy->wbuf_pos = 0;
    proxy->state    = XRD_PX_FORWARDING;

    proxy->rhdr_pos      = 0;
    proxy->resp_dlen     = 0;
    proxy->resp_body     = NULL;
    proxy->resp_body_pos = 0;

    if (brix_proxy_flush(proxy) == NGX_ERROR) {
        brix_proxy_abort(proxy, "proxy: send deferred request failed");
        return NGX_ERROR;
    }
    if (proxy->wbuf_pos < proxy->wbuf_len) {
        return NGX_OK; /* write handler will complete the send */
    }
    if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
        brix_proxy_abort(proxy, "proxy: read arm failed after deferred send");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_proxy_dispatch_pending(brix_proxy_ctx_t *proxy)
{
    brix_ctx_t     *ctx = proxy->client_ctx;
    ngx_connection_t *c   = proxy->client_conn;
    u_char           *req = proxy->saved_req;
    size_t            len = proxy->saved_req_len;
    int               saved_lfh = proxy->saved_local_fh;
    uint16_t          reqid;
    int               lazy_fh;
    ClientRequestHdr *hdr;

    if (req == NULL) {
        return NGX_OK;
    }

    hdr   = (ClientRequestHdr *)(void *) req;
    reqid = ntohs(hdr->requestid);

    /* Bound secondary lazy-open check: kXR_read / kXR_pgread / kXR_readv */
    lazy_fh = brix_proxy_pending_lazy_fh(proxy, ctx, req, len, reqid);
    if (lazy_fh >= 0) {
        proxy->saved_req = NULL; /* ownership to lazy_open */
        return brix_proxy_lazy_open(proxy, ctx, c, lazy_fh, req, len);
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

    /* Tap: this is the first post-bootstrap request (e.g. the kXR_open), queued
     * directly here rather than through brix_proxy_forward_request — emit it. */
    {
        brix_tap_frame_t tf;
        if (brix_tap_decode_request(req, len, &tf) > 0) {
            brix_tap_emit(&proxy->tap, &tf, BRIX_TAP_C2U, NULL, 0);
        }
    }

    return brix_proxy_pending_flush(proxy, req, len);
}

/* main dispatch entry point */
ngx_int_t
brix_proxy_dispatch(brix_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_brix_srv_conf_t *conf)
{
    brix_proxy_ctx_t *proxy;
    int                 i;

    /* lazy initialisation: connect to upstream on first dispatch */    if (ctx->proxy == NULL) {

        /*
         * Loop guard: a permanently-rejecting upstream (bad credential, all
         * upstreams down) would otherwise make every re-dispatch allocate a
         * fresh proxy ctx on c->pool and reconnect, spinning the worker at
         * event-loop rate and growing the connection pool without bound.  Once
         * this connection has burned through its failure budget, stop retrying
         * and return a hard error instead of spawning another proxy.
         */
        if (ctx->proxy_fail_count >= BRIX_PROXY_MAX_CONN_FAILS) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "xrootd proxy: %ui consecutive upstream failures on "
                          "this connection — failing request, not retrying",
                          ctx->proxy_fail_count);
            return brix_send_error(ctx, c, kXR_IOError,
                                     "proxy: upstream unavailable");
        }

        proxy = ngx_pcalloc(c->pool, sizeof(brix_proxy_ctx_t));
        if (proxy == NULL) {
            return brix_send_error(ctx, c, kXR_IOError,
                                     "proxy: out of memory");
        }
        for (i = 0; i < BRIX_MAX_FILES; i++) {
            proxy->fh_map[i].upstream_fh = BRIX_PROXY_FH_FREE;
        }
        proxy->client_ctx     = ctx;
        proxy->client_conn    = c;
        proxy->conf           = conf;
        brix_proxy_tap_init(proxy, c);
        proxy->fwd_local_fh   = -1;
        proxy->saved_local_fh = -1;
        proxy->reconnect_left = (int) conf->proxy.reconnect_attempts;
        proxy->splice_pipe[0] = -1;
        proxy->splice_pipe[1] = -1;
        ctx->proxy            = proxy;

        if (brix_proxy_connect(proxy, c, conf) != NGX_OK) {
            ctx->proxy = NULL;
            /* Count synchronous connect/selection failures too (e.g. all
             * upstreams down) so they are bounded by the same per-connection
             * budget as async bootstrap aborts. */
            ctx->proxy_fail_count++;
            return brix_send_error(ctx, c, kXR_IOError,
                                     "proxy: upstream connect failed");
        }
    }

    proxy = ctx->proxy;

    /* if bootstrap is still in progress, save this request */    if (proxy->state != XRD_PX_IDLE) {
        size_t total = XRD_REQUEST_HDR_LEN + ctx->recv.cur_dlen;
        u_char *saved;

        saved = ngx_alloc(total, c->log);
        if (saved == NULL) {
            return brix_send_error(ctx, c, kXR_IOError,
                                     "proxy: out of memory saving request");
        }
        ngx_memcpy(saved, ctx->recv.hdr_buf, XRD_REQUEST_HDR_LEN);
        if (ctx->recv.cur_dlen > 0 && ctx->recv.payload != NULL) {
            ngx_memcpy(saved + XRD_REQUEST_HDR_LEN, ctx->recv.payload, ctx->recv.cur_dlen);
        }

        proxy->saved_req     = saved;
        proxy->saved_req_len = total;

        /* Pre-allocate a local fh for a deferred open */
        if (ctx->recv.cur_reqid == kXR_open) {
            int local_fh = brix_proxy_alloc_local_fh(proxy);
            if (local_fh < 0) {
                ngx_free(saved);
                proxy->saved_req = NULL;
                return brix_send_error(ctx, c, kXR_IOError,
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

    /* upstream is ready: forward the request now */    return brix_proxy_forward_request(proxy, ctx, c);
}
