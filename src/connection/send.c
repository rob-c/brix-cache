/* ------------------------------------------------------------------ */
/* Section: Write Event Handler — Async Response Flush                  */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the nginx write event handler that drives the async response flush cycle when the kernel socket send buffer has room. Called by nginx whenever a previous c->send()/c->send_chain() returned NGX_AGAIN — drains wbuf/wchain into the socket, transitions to XRD_ST_REQ_HEADER on completion, and re-enters recv loop for next request. Also triggers TLS handshake if tls_pending after flushing kXR_haveTLS response. Security invariant: timeout → disconnect immediately. */

/* ------------------------------------------------------------------ */
/* Section: Write Event Handler                                         */
/* ------------------------------------------------------------------ */
/*
 * WHAT: ngx_stream_xrootd_send() is the write event handler called by nginx whenever the kernel socket send buffer has room again after a previous c->send()/c->send_chain() returned NGX_AGAIN — drives the async flush cycle: (1) calls xrootd_flush_pending() to drain wbuf/wchain into the socket; (2) if NGX_AGAIN, returns and waits for next write event; (3) on success with state==XRD_ST_SENDING, transitions to XRD_ST_REQ_HEADER and re-enters recv loop for next request; (4) if tls_pending after flushing kXR_haveTLS response, triggers TLS handshake via xrootd_start_tls(). Security invariant: timeout → disconnect immediately. Thread safety: single-owner per connection on nginx event thread — no locking required. Returns only when flush=NGX_AGAIN or state≠SENDING. */

/* ---- WHY: This handler is the critical counterpart to recv() in the async I/O cycle — without it, response buffers would stall until the next natural epoll write event detection. Flush pending ensures all queued response data (wire protocol headers + payload) are sent efficiently to the client socket rather than accumulating in memory indefinitely. TLS handshake trigger enables in-protocol upgrade for roots:// clients when kXR_haveTLS response has been flushed and the server is ready to negotiate secure transport. ---- */

#include "../ngx_xrootd_module.h"
#include "disconnect.h"
#include "fd_table.h"
#include "tls.h"
#include "write_helpers.h"
#include "deadline.h"

/* ---- ngx_stream_xrootd_send — write event handler for pending response buffers (async flush cycle) ----
 *
 * WHAT: Called by nginx whenever the kernel socket send buffer has room again after a previous c->send()/c->send_chain() returned NGX_AGAIN. Drives the async flush cycle: (1) calls xrootd_flush_pending() to drain wbuf/wchain into the socket; (2) if NGX_AGAIN, returns and waits for next write event; (3) on success with state==XRD_ST_SENDING, transitions to XRD_ST_REQ_HEADER and re-enters recv loop for next request; (4) if tls_pending after flushing kXR_haveTLS response, triggers TLS handshake via xrootd_start_tls(). Security invariant: timeout → disconnect immediately. Thread safety: single-owner per connection on nginx event thread — no locking required. Returns only when flush=NGX_AGAIN or state≠SENDING.
 *
 * WHY: This handler is the critical counterpart to recv() in the async I/O cycle — without it, response buffers would stall until the next natural epoll write event detection. Flush pending ensures all queued response data (wire protocol headers + payload) are sent efficiently to the client socket rather than accumulating in memory indefinitely. TLS handshake trigger enables in-protocol upgrade for roots:// clients when kXR_haveTLS response has been flushed and the server is ready to negotiate secure transport.
 *
 * HOW: Event-driven flow → wev->timedout check (disconnect + close files) → xrootd_flush_pending() call → NGX_AGAIN return (wait for next write event) → on success: state=XRD_ST_REQ_HEADER reset → tls_pending check (trigger TLS handshake) → ngx_stream_xrootd_recv() re-arm read loop. */
void
ngx_stream_xrootd_send(ngx_event_t *wev)
{
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_xrootd_srv_conf_t  *conf;
    xrootd_ctx_t                  *ctx;
    ngx_int_t                      rc;

    c = wev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "xrootd: write timed out");
        /* Phase 39: the response-drain deadline fired — the consumer made no
         * progress for xrootd_send_timeout (slow / half-open reader).  Attribute
         * it and tear down via the single disconnect funnel. */
        ctx->send_deadline_armed = 0;
        XROOTD_SRV_METRIC_INC(ctx, send_drain_timeouts_total);
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    rc = xrootd_flush_pending(ctx, c);
    if (rc == NGX_ERROR) {
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rc == NGX_AGAIN) {
        return;
    }

    if (ctx->state != XRD_ST_SENDING) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                      "xrootd: send_done (state=%d, no recv) avail=%d ready=%d active=%d",
                      (int) ctx->state,
                      c->read->available, (int) c->read->ready,
                      (int) c->read->active);
        return;
    }

    /*
     * Phase 31 W2.1: a windowed read's chunk just finished draining from
     * read_scratch — read and send the next window before accepting any new
     * request.  The pump posts the next window (state XRD_ST_AIO) or finishes
     * and resumes the read side itself.
     */
    if (ctx->rd_win_active) {
        xrootd_read_window_pump(ctx, c, conf);
        return;
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;
    ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                  "xrootd: send_done avail=%d ready=%d active=%d",
                  c->read->available, (int) c->read->ready,
                  (int) c->read->active);

    if (ctx->tls_pending) {
        xrootd_start_tls(ctx, c, conf);
        return;
    }

    ngx_stream_xrootd_recv(c->read);
}
