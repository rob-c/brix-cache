#include "proxy_internal.h"
#include "protocols/root/session/registry.h"
#include "protocols/root/protocol/frame_hdr.h"   /* shared kXR_wait seconds parse (libxrdproto) */
#include "core/compat/cstr.h"

/*
 * WHAT: Relay upstream XRootD responses to the client, handling special cases:
 *       bound-secondary lazy-open (synthetic kXR_open), kXR_wait retry,
 *       kXR_redirect follow-through, fhandle translation, path audit,
 *       and streaming kXR_oksofar / mid-stream kXR_wait.
 *
 * WHY:  The transparent proxy must translate upstream file handles to local
 *       handles, absorb transient kXR_wait responses with timed retries,
 *       silently follow redirects (up to 3 hops), emit audit records for
 *       path operations, and support streaming multi-chunk reads — all
 *       while keeping the client unaware of upstream topology changes.
 *
 * HOW:  brix_proxy_relay_to_client() processes proxy->resp_status/body/dlen
 *       from the upstream response. It handles each special case in sequence:
 *       lazy-open → wait-retry → redirect-follow → audit → fhandle-translation
 *       → read/write tracking → close audit → build/send relay buffer.
 */

/* Audit helper declaration — defined in forward_relay_audit.c */
extern void proxy_write_path_audit(brix_proxy_ctx_t *proxy, uint16_t status);

/* public API: brix_proxy_relay_to_client() — relay upstream response to client * WHAT: Relay the upstream server's response frame back to the connected client.
 *       Handles bound-secondary lazy-open (synthetic kXR_open), kXR_wait retry,
 *       kXR_redirect follow-through, fhandle translation, path audit, and streaming. */

static void
brix_proxy_lazy_release_body(brix_proxy_ctx_t *proxy)
{
    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }
}

static void
brix_proxy_lazy_open_failed(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    ngx_connection_t *c, int local_fh)
{
    if (proxy->saved_req != NULL) {
        ngx_free(proxy->saved_req);
        proxy->saved_req = NULL;
    }

    brix_proxy_lazy_release_body(proxy);
    if (local_fh >= 0 && local_fh < BRIX_MAX_FILES) {
        proxy->fh_map[local_fh].upstream_fh = BRIX_PROXY_FH_FREE;
    }

    proxy->state = XRD_PX_IDLE;
    ctx->state = XRD_ST_REQ_HEADER;
    brix_send_error(ctx, c, kXR_IOError,
                    "proxy: lazy open for bound secondary failed");
    brix_schedule_read_resume(c);
}

static void
brix_proxy_lazy_record_open(brix_proxy_ctx_t *proxy, int local_fh)
{
    int upstream_fh;

    upstream_fh = (proxy->resp_body != NULL && proxy->resp_dlen >= 1)
                  ? (int)(unsigned char) proxy->resp_body[0] : 0;
    if (local_fh >= 0 && local_fh < BRIX_MAX_FILES) {
        proxy->fh_map[local_fh].upstream_fh = upstream_fh;
        proxy->fh_map[local_fh].open_msec = ngx_current_msec;
    }
}

static int
brix_proxy_lazy_open_next(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    ngx_connection_t *c)
{
    int next_fh;
    u_char *rreq;
    size_t rlen;

    if (proxy->lazy_open_pending_count <= 0) {
        return 0;
    }

    proxy->lazy_open_pending_count--;
    next_fh = proxy->lazy_open_pending_fhs[proxy->lazy_open_pending_count];

    rreq = proxy->saved_req;
    rlen = proxy->saved_req_len;
    proxy->saved_req = NULL;
    if (brix_proxy_lazy_open(proxy, ctx, c, next_fh, rreq, rlen) != NGX_OK) {
        /* Error already handled / reported. */
    }
    return 1;
}

static int
brix_proxy_translate_saved_readv(brix_proxy_ctx_t *proxy, u_char *rreq,
    size_t rlen)
{
    u_char *pl = rreq + XRD_REQUEST_HDR_LEN;
    size_t pos = 0;
    size_t pdlen = rlen > XRD_REQUEST_HDR_LEN ? rlen - XRD_REQUEST_HDR_LEN : 0;

    while (pos + 16 <= pdlen) {
        int cfh = (int)(unsigned char) pl[pos];
        if (cfh >= 0 && cfh < BRIX_MAX_FILES
            && proxy->fh_map[cfh].upstream_fh >= 0)
        {
            pl[pos] = (u_char)(unsigned int) proxy->fh_map[cfh].upstream_fh;
        }
        pos += 16;
    }
    return -1;
}

static int
brix_proxy_translate_saved_read(brix_proxy_ctx_t *proxy, u_char *rreq,
    size_t rlen, int local_fh)
{
    uint16_t saved_rid;
    int upstream_fh;

    saved_rid = ntohs(((ClientRequestHdr *)(void *) rreq)->requestid);
    if (saved_rid == kXR_read || saved_rid == kXR_pgread) {
        upstream_fh = (local_fh >= 0 && local_fh < BRIX_MAX_FILES)
                      ? proxy->fh_map[local_fh].upstream_fh : -1;
        if (upstream_fh >= 0) {
            rreq[4] = (u_char)(unsigned int) upstream_fh;
        }
        return local_fh;
    }
    if (saved_rid == kXR_readv) {
        return brix_proxy_translate_saved_readv(proxy, rreq, rlen);
    }
    return local_fh;
}

static void
brix_proxy_prepare_saved_forward(brix_proxy_ctx_t *proxy, u_char *rreq,
    size_t rlen, int local_fh)
{
    ClientRequestHdr *hdr = (ClientRequestHdr *)(void *) rreq;

    proxy->fwd_reqid = ntohs(hdr->requestid);
    proxy->fwd_streamid[0] = hdr->streamid[0];
    proxy->fwd_streamid[1] = hdr->streamid[1];
    proxy->fwd_local_fh = local_fh;
    proxy->fwd_streaming = 0;
    proxy->fwd_payload_len = rlen > XRD_REQUEST_HDR_LEN
                             ? rlen - XRD_REQUEST_HDR_LEN : 0;
    proxy->saved_req = NULL;
}

static void
brix_proxy_save_wait_retry(brix_proxy_ctx_t *proxy, ngx_connection_t *c,
    u_char *rreq, size_t rlen)
{
    if (rlen >= 128 * 1024) {
        return;
    }

    if (proxy->wait_retry_req != NULL) {
        ngx_free(proxy->wait_retry_req);
    }
    proxy->wait_retry_req = ngx_alloc(rlen, c->log);
    if (proxy->wait_retry_req != NULL) {
        ngx_memcpy(proxy->wait_retry_req, rreq, rlen);
        proxy->wait_retry_req_len = rlen;
    } else {
        proxy->wait_retry_req_len = 0;
    }
    proxy->wait_retry_local_fh = proxy->fwd_local_fh;
    proxy->wait_retry_count = 0;
}

static int
brix_proxy_dispatch_saved_read(brix_proxy_ctx_t *proxy, ngx_connection_t *c)
{
    u_char *rreq = proxy->saved_req;
    size_t rlen = proxy->saved_req_len;
    int local_fh = proxy->saved_local_fh;

    if (rreq == NULL) {
        return 0;
    }

    local_fh = brix_proxy_translate_saved_read(proxy, rreq, rlen, local_fh);
    brix_proxy_prepare_saved_forward(proxy, rreq, rlen, local_fh);
    brix_proxy_save_wait_retry(proxy, c, rreq, rlen);

    proxy->wbuf = rreq;
    proxy->wbuf_len = rlen;
    proxy->wbuf_pos = 0;
    proxy->state = XRD_PX_FORWARDING;
    proxy->rhdr_pos = 0;
    proxy->resp_dlen = 0;
    proxy->resp_body = NULL;
    proxy->resp_body_pos = 0;

    if (brix_proxy_flush(proxy) == NGX_ERROR) {
        brix_proxy_abort(proxy,
            "proxy: send deferred read after lazy open failed");
        return 1;
    }
    if (proxy->wbuf_pos < proxy->wbuf_len) {
        return 1;
    }
    if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
        brix_proxy_abort(proxy, "proxy: read arm failed after lazy open read");
    }
    return 1;
}

/* relay upstream response to client */
/* Handle the synthetic kXR_open response for a bound-secondary lazy open:
 * translate the upstream fhandle into the reserved local slot (or free it on
 * failure) and resume the client read loop.  Returns 1 when this was a lazy-
 * open response and the caller must return; 0 otherwise. */
static int
brix_proxy_relay_lazy_open(brix_proxy_ctx_t *proxy)
{
    brix_ctx_t *ctx = proxy->client_ctx;
    ngx_connection_t *c = proxy->client_conn;
    int local_fh = proxy->fwd_local_fh;

    if (!proxy->fwd_is_lazy_open) {
        return 0;
    }

    proxy->fwd_is_lazy_open = 0;

    if (proxy->resp_status != kXR_ok) {
        brix_proxy_lazy_open_failed(proxy, ctx, c, local_fh);
        return 1;
    }

    brix_proxy_lazy_record_open(proxy, local_fh);
    brix_proxy_lazy_release_body(proxy);

    if (brix_proxy_lazy_open_next(proxy, ctx, c)) {
        return 1;
    }

    if (brix_proxy_dispatch_saved_read(proxy, c)) {
        return 1;
    }

    proxy->state = XRD_PX_IDLE;
    ctx->state = XRD_ST_REQ_HEADER;
    brix_schedule_read_resume(c);
    return 1;
}

/* kXR_redirect follow-through: when the upstream returns a redirect (and we are
 * under the 3-hop limit), parse the "host:port" target, tear down the current
 * upstream, and reconnect to it re-issuing the saved request.  Returns 1 when
 * the reconnect is in progress and the caller must return; 0 to fall through and
 * relay the redirect to the client (not a redirect, malformed target, or the
 * reconnect attempt failed). */
static int
brix_proxy_relay_try_redirect(brix_proxy_ctx_t *proxy, ngx_connection_t *c,
    uint16_t status, u_char *body, uint32_t dlen)
{
    if (status == kXR_redirect && body != NULL && dlen > 0
        && proxy->redirect_count < 3)
    {
        /* Payload is "host:port\0" */
        char *target = (char *) body;
        char *colon  = ngx_strchr(target, ':');

        if (colon != NULL) {
            *colon = '\0';
            if (proxy->redirect_host.data != NULL) {
                ngx_free(proxy->redirect_host.data);
            }
            proxy->redirect_host.len  = (size_t)(colon - target);
            proxy->redirect_host.data = ngx_alloc(proxy->redirect_host.len + 1,
                                                 c->log);
            if (proxy->redirect_host.data != NULL) {
                (void) brix_cbuf_copy((char *) proxy->redirect_host.data,
                    proxy->redirect_host.len + 1, target, proxy->redirect_host.len);
                {
                    char    *endp;
                    long     pval;
                    errno = 0;
                    pval = strtol(colon + 1, &endp, 10);
                    if (errno != 0 || endp == colon + 1 || pval < 1 || pval > 65535) {
                        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                                      "xrootd proxy: invalid redirect port, dropping");
                    } else {
                        proxy->redirect_port = (uint16_t) pval;

                        proxy->redirect_count++;
                        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                      "xrootd proxy: following redirect %d to %s:%d",
                                      proxy->redirect_count,
                                      proxy->redirect_host.data,
                                      (int) proxy->redirect_port);

                        /* Close current upstream, reconnect to redirected target */
                        if (proxy->conn != NULL) {
                            ngx_close_connection(proxy->conn);
                            proxy->conn = NULL;
                        }
                        if (proxy->resp_body != NULL) {
                            ngx_free(proxy->resp_body);
                            proxy->resp_body = NULL;
                        }
                        /* Reuse the wait-retry copy to re-issue the request */
                        proxy->saved_req      = proxy->wait_retry_req;
                        proxy->saved_req_len  = proxy->wait_retry_req_len;
                        proxy->saved_local_fh = proxy->wait_retry_local_fh;
                        proxy->wait_retry_req     = NULL;
                        proxy->wait_retry_req_len = 0;

                        proxy->state         = XRD_PX_CONNECTING;
                        proxy->bs_phase      = XRD_PX_BS_HANDSHAKE;
                        proxy->rhdr_pos      = 0;
                        proxy->resp_dlen     = 0;
                        proxy->resp_body_pos = 0;

                        if (brix_proxy_connect(proxy, c, proxy->conf) == NGX_OK) {
                            return 1; /* reconnect in progress; dispatches saved_req */
                        }
                        /* reconnect failed — fall through to relay redirect */
                        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                                      "xrootd proxy: redirect follow failed, relaying");
                    }
                }
            }
        }
    }

    return 0;
}

static void
brix_proxy_relay_emit_tap(brix_proxy_ctx_t *proxy, uint16_t status,
    uint32_t dlen)
{
    brix_tap_frame_t tf;

    ngx_memzero(&tf, sizeof(tf));
    tf.is_request = 0;
    tf.streamid = (uint16_t) (((unsigned) proxy->fwd_streamid[0] << 8)
                              | proxy->fwd_streamid[1]);
    tf.status = status;
    tf.dlen = dlen;
    brix_tap_emit(&proxy->tap, &tf, BRIX_TAP_U2C, NULL, 0);
}

static void
brix_proxy_reset_response_state(brix_proxy_ctx_t *proxy)
{
    proxy->rhdr_pos = 0;
    proxy->resp_dlen = 0;
    proxy->resp_body = NULL;
    proxy->resp_body_pos = 0;
}

static int
brix_proxy_relay_absorb_wait(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    ngx_connection_t *c, uint16_t status, u_char *body, uint32_t dlen)
{
    uint32_t wait_secs;

    if (status != kXR_wait || proxy->fwd_streaming
        || proxy->wait_retry_req == NULL
        || proxy->wait_retry_count >= BRIX_PROXY_MAX_WAIT_RETRIES)
    {
        return 0;
    }

    wait_secs = xrd_wait_secs_parse((const uint8_t *) body, dlen, 1,
                                    BRIX_PROXY_MAX_WAIT_SECS);
    proxy->wait_retry_count++;
    BRIX_PROXY_METRIC_INC(ctx, wait_responses_total);
    BRIX_PROXY_UP_INC(proxy, wait_responses_total);

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd proxy: kXR_wait for reqid=%d, retry %d in %us",
                   (int) proxy->fwd_reqid, proxy->wait_retry_count, wait_secs);

    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }
    brix_proxy_reset_response_state(proxy);
    ngx_memzero(&proxy->wait_ev, sizeof(proxy->wait_ev));
    proxy->wait_ev.handler = brix_proxy_wait_handler;
    proxy->wait_ev.data = proxy;
    proxy->wait_ev.log = proxy->conn->log;
    ngx_add_timer(&proxy->wait_ev, wait_secs * 1000);
    return 1;
}

static void
brix_proxy_relay_wait_exhausted(brix_proxy_ctx_t *proxy, uint16_t status)
{
    int local_fh = proxy->fwd_local_fh;

    if (status != kXR_wait) {
        return;
    }
    if (proxy->fwd_reqid == kXR_open && local_fh >= 0
        && local_fh < BRIX_MAX_FILES)
    {
        proxy->fh_map[local_fh].upstream_fh = BRIX_PROXY_FH_FREE;
    }
    if (proxy->wait_retry_req != NULL) {
        ngx_free(proxy->wait_retry_req);
        proxy->wait_retry_req = NULL;
    }
}

static void
brix_proxy_relay_path_audit(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    uint16_t status)
{
    if (!proxy->fwd_path_audit || (status != kXR_ok && status != kXR_error)) {
        return;
    }
    if (status == kXR_ok) {
        BRIX_PROXY_METRIC_INC(ctx, path_ops_total);
        BRIX_PROXY_UP_INC(proxy, path_ops_total);
    } else {
        BRIX_PROXY_METRIC_INC(ctx, path_op_errors_total);
        BRIX_PROXY_UP_INC(proxy, path_op_errors_total);
    }
    proxy_write_path_audit(proxy, status);
    proxy->fwd_path_audit = 0;
}

static void
brix_proxy_free_wait_retry(brix_proxy_ctx_t *proxy)
{
    if (proxy->wait_retry_req != NULL) {
        ngx_free(proxy->wait_retry_req);
        proxy->wait_retry_req = NULL;
    }
}

static void
brix_proxy_relay_open_status(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    uint16_t status, u_char *body, uint32_t dlen)
{
    int local_fh;
    int upstream_fh;

    if (proxy->fwd_reqid != kXR_open) {
        return;
    }

    local_fh = proxy->fwd_local_fh;
    if (status == kXR_ok) {
        upstream_fh = (body != NULL && dlen >= 1) ? (int) (unsigned char) body[0] : 0;
        if (local_fh >= 0 && local_fh < BRIX_MAX_FILES) {
            proxy->fh_map[local_fh].upstream_fh = upstream_fh;
            proxy->fh_map[local_fh].open_msec = ngx_current_msec;
            if (body != NULL) {
                body[0] = (u_char) (unsigned int) local_fh;
                body[1] = 0;
                body[2] = 0;
                body[3] = 0;
            }
        }
        brix_proxy_free_wait_retry(proxy);
        BRIX_PROXY_METRIC_INC(ctx, opens_total);
        BRIX_PROXY_UP_INC(proxy, opens_total);
    } else if (status == kXR_error) {
        if (local_fh >= 0 && local_fh < BRIX_MAX_FILES) {
            proxy->fh_map[local_fh].upstream_fh = BRIX_PROXY_FH_FREE;
        }
        brix_proxy_free_wait_retry(proxy);
        BRIX_PROXY_METRIC_INC(ctx, open_errors);
        BRIX_PROXY_UP_INC(proxy, open_errors);
    }
}

static void
brix_proxy_relay_io_metrics(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    uint16_t status, uint32_t dlen)
{
    int local_fh = proxy->fwd_local_fh;

    if ((status != kXR_ok && status != kXR_oksofar)
        || local_fh < 0 || local_fh >= BRIX_MAX_FILES)
    {
        return;
    }

    switch (proxy->fwd_reqid) {
    case kXR_read:
    case kXR_pgread:
    case kXR_readv:
        proxy->fh_map[local_fh].bytes_read += dlen;
        BRIX_PROXY_METRIC_INC(ctx, reads_total);
        BRIX_PROXY_METRIC_ADD(ctx, read_bytes_total, dlen);
        BRIX_PROXY_UP_INC(proxy, reads_total);
        BRIX_PROXY_UP_ADD(proxy, read_bytes_total, dlen);
        break;
    case kXR_write:
    case kXR_pgwrite:
    case kXR_writev:
        proxy->fh_map[local_fh].bytes_written += proxy->fwd_payload_len;
        BRIX_PROXY_METRIC_INC(ctx, writes_total);
        BRIX_PROXY_METRIC_ADD(ctx, write_bytes_total, proxy->fwd_payload_len);
        BRIX_PROXY_UP_INC(proxy, writes_total);
        BRIX_PROXY_UP_ADD(proxy, write_bytes_total, proxy->fwd_payload_len);
        break;
    default:
        break;
    }
}

static void
brix_proxy_relay_close_status(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    uint16_t status)
{
    int local_fh = proxy->fwd_local_fh;

    if (proxy->fwd_reqid != kXR_close || status != kXR_ok) {
        return;
    }
    if (local_fh >= 0 && local_fh < BRIX_MAX_FILES) {
        proxy_write_audit(proxy, local_fh);
        proxy->fh_map[local_fh].upstream_fh = BRIX_PROXY_FH_FREE;
    }
    BRIX_PROXY_METRIC_INC(ctx, closes_total);
    BRIX_PROXY_UP_INC(proxy, closes_total);
}

static u_char *
brix_proxy_build_relay_buffer(brix_proxy_ctx_t *proxy, ngx_connection_t *c,
    uint16_t status, u_char *body, uint32_t dlen, size_t *total)
{
    u_char *buf;
    uint32_t wire_dlen = (status == kXR_status && dlen > 24) ? 24 : dlen;

    *total = XRD_RESPONSE_HDR_LEN + dlen;
    buf = ngx_palloc(c->pool, *total);
    if (buf == NULL) {
        brix_proxy_abort(proxy, "proxy: pool alloc failed in relay");
        return NULL;
    }
    brix_build_resp_hdr(proxy->fwd_streamid, status, wire_dlen,
                        (ServerResponseHdr *)(void *) buf);
    if (dlen > 0 && body != NULL) {
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, dlen);
    }
    return buf;
}

static int
brix_proxy_relay_streaming_frame(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    ngx_connection_t *c, uint16_t status, u_char resptype, u_char *buf,
    size_t total)
{
    if (status == kXR_oksofar) {
        proxy->fwd_streaming = 1;
        brix_proxy_reset_response_state(proxy);
        brix_queue_response(ctx, c, buf, total);
        return 1;
    }
    if (status == kXR_wait && proxy->fwd_streaming) {
        brix_proxy_reset_response_state(proxy);
        brix_queue_response(ctx, c, buf, total);
        return 1;
    }
    if (status == kXR_waitresp) {
        brix_proxy_reset_response_state(proxy);
        brix_queue_response(ctx, c, buf, total);
        return 1;
    }
    if (status == kXR_status && resptype == 0x01) {
        brix_proxy_reset_response_state(proxy);
        brix_queue_response(ctx, c, buf, total);
        return 1;
    }
    return 0;
}

static void
brix_proxy_relay_finish_final(brix_proxy_ctx_t *proxy, brix_ctx_t *ctx,
    ngx_connection_t *c, u_char *buf, size_t total)
{
    if (proxy->wait_ev.timer_set) {
        ngx_del_timer(&proxy->wait_ev);
    }
    brix_proxy_free_wait_retry(proxy);
    proxy->state = XRD_PX_IDLE;
    ctx->state = XRD_ST_REQ_HEADER;
    brix_queue_response(ctx, c, buf, total);
    brix_schedule_read_resume(c);
}

void
brix_proxy_relay_to_client(brix_proxy_ctx_t *proxy)
{
    brix_ctx_t     *ctx = proxy->client_ctx;
    ngx_connection_t *c   = proxy->client_conn;
    uint16_t          status = proxy->resp_status;
    uint32_t          dlen   = proxy->resp_dlen;
    u_char           *body   = proxy->resp_body;
    size_t            total;
    u_char           *buf;

    /* Tap: emit the upstream response metadata (status/dlen) to the observation
     * tap, keyed to the client's streamid. */
    brix_proxy_relay_emit_tap(proxy, status, dlen);

    /* lazy open (bound secondary): handle synthetic kXR_open response */
    if (brix_proxy_relay_lazy_open(proxy)) {
        return;
    }

    if (brix_proxy_relay_absorb_wait(proxy, ctx, c, status, body, dlen)) {
        return;
    }

    /* kXR_wait exhausted retries — free retry buffer and relay the wait to client */
    brix_proxy_relay_wait_exhausted(proxy, status);

    /* kXR_redirect follow-through (transparently reconnect to the target). */
    if (brix_proxy_relay_try_redirect(proxy, c, status, body, dlen)) {
        return;
    }

    brix_proxy_relay_path_audit(proxy, ctx, status);

    brix_proxy_relay_open_status(proxy, ctx, status, body, dlen);

    brix_proxy_relay_io_metrics(proxy, ctx, status, dlen);

    brix_proxy_relay_close_status(proxy, ctx, status);

    buf = brix_proxy_build_relay_buffer(proxy, c, status, body, dlen, &total);
    if (buf == NULL) {
        return;
    }

    /*
     * Save resptype from kXR_status body[7] before freeing.
     * kXR_PartialResult (0x01) means upstream will send more kXR_status frames;
     * we must stay FORWARDING rather than going IDLE after relaying this chunk.
     */
    u_char resptype = (status == kXR_status && body != NULL && dlen >= 8)
                      ? body[7] : 0;

    /* Free the heap-allocated body now that we've copied it */
    if (proxy->resp_body != NULL) {
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
    }

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "xrootd proxy: relay reqid=%d status=%d dlen=%uz resptype=%d",
                  (int) proxy->fwd_reqid, (int) status, (size_t) dlen,
                  (int) resptype);

    if (brix_proxy_relay_streaming_frame(proxy, ctx, c, status, resptype, buf,
                                         total))
    {
        return;
    }

    /* Final response — transition back to client loop.
     * Cancel any pending kXR_wait retry timer: a final response arrived
     * before the timer fired (spontaneous upstream send).  Free the saved
     * retry buffer too; wait_handler checks req==NULL as a no-op guard. */
    brix_proxy_relay_finish_final(proxy, ctx, c, buf, total);
}
