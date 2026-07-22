#include "proxy_internal.h"
#include "protocols/root/connection/handler.h"
#include "protocols/root/connection/write_helpers.h"   /* brix_queue_response_base */
#include <sys/socket.h>
#include <sys/ioctl.h>   /* FIONREAD — only splice a fully-buffered body */
#include <unistd.h>      /* read() — drain pipe residual on a spurious drain EAGAIN */

/* zero-copy splice fast-path */
#ifdef __linux__

/* Forward declaration — brix_proxy_splice_wev is defined after the pump. */
static void brix_proxy_splice_wev(ngx_event_t *wev);

/* Forward declaration — the under-draining-splice fallback, defined after the
 * pump (the pump calls it when splice stalls with data still queued). */
static void brix_proxy_splice_to_buffered(brix_proxy_ctx_t *proxy);

/* Forward declaration — the drain-side counterpart: when splice(pipe→client)
 * stalls on a writable client (WSL2's under-draining splice), move the pipe
 * residual into userspace and relay the remainder via the buffered path. */
static void brix_proxy_splice_drain_to_buffered(brix_proxy_ctx_t *proxy);

/*
 * brix_proxy_splice_done — called when all splice_total bytes have been
 * moved from the upstream socket to the client socket.  Mirrors the
 * post-relay accounting that relay_to_client() does for reads.
 */
static void
brix_proxy_splice_done(brix_proxy_ctx_t *proxy)
{
    brix_ctx_t     *ctx    = proxy->client_ctx;
    ngx_connection_t *c      = proxy->client_conn;
    uint16_t          status = proxy->resp_status;
    size_t            dlen   = proxy->splice_total;
    int               lfh    = proxy->fwd_local_fh;

    /* Restore the normal client write handler (may have been changed for EAGAIN). */
    c->write->handler = ngx_stream_brix_send;

    /* Per-handle and aggregate byte metrics. */
    if (lfh >= 0 && lfh < BRIX_MAX_FILES) {
        proxy->fh_map[lfh].bytes_read += dlen;
    }
    BRIX_PROXY_METRIC_INC(ctx, reads_total);
    BRIX_PROXY_METRIC_ADD(ctx, read_bytes_total, dlen);
    BRIX_PROXY_UP_INC(proxy, reads_total);
    BRIX_PROXY_UP_ADD(proxy, read_bytes_total, dlen);

    /* Reset accumulator for the next response. */
    proxy->splice_active     = 0;
    proxy->splice_fallback   = 0;
    proxy->splice_total      = 0;
    proxy->splice_upstream   = 0;
    proxy->splice_downstream = 0;
    proxy->rhdr_pos          = 0;
    proxy->resp_dlen         = 0;
    proxy->resp_body         = NULL;
    proxy->resp_body_pos     = 0;

    if (status == kXR_oksofar) {
        proxy->fwd_streaming = 1;
        /*
         * nginx uses edge-triggered epoll.  The upstream socket may already
         * have the trailing kXR_ok(0) frame buffered, but no new edge event
         * will fire for it.  Re-arm even when nginx still marks the event
         * active: after a splice pump the event can be active-but-stale, which
         * otherwise leaves the next oksofar/ok frame buffered forever.
         * Then post the handler so it runs again regardless of whether new data
         * has arrived.
         */
        {
            ngx_event_t *urev = proxy->conn->read;
            if (ngx_handle_read_event(urev, 0) != NGX_OK) {
                brix_proxy_abort(proxy,
                    "proxy: read arm failed after splice oksofar");
                return;
            }
            if (proxy->conf != NULL && proxy->conf->proxy.read_timeout > 0) {
                ngx_add_timer(urev, proxy->conf->proxy.read_timeout);
            }
            if (!urev->posted) {
                ngx_post_event(urev, &ngx_posted_events);
            }
        }
        return;
    }

    /* Final response — hand control back to the client loop. */
    proxy->state = XRD_PX_IDLE;
    ctx->state   = XRD_ST_REQ_HEADER;
    brix_schedule_read_resume(c);
}

/*
 * Pump-stage outcome — steers the pump loop after a fill/drain stage.
 *   BRIX_SPLICE_STEP_CONTINUE — stage made progress; re-run the loop body.
 *   BRIX_SPLICE_STEP_DONE     — all splice_total bytes transferred; finish.
 *   BRIX_SPLICE_STEP_RETURN   — stage armed an event or aborted; pump returns
 *                               immediately without touching `proxy`.
 */
typedef enum {
    BRIX_SPLICE_STEP_CONTINUE = 0,
    BRIX_SPLICE_STEP_DONE,
    BRIX_SPLICE_STEP_RETURN
} brix_splice_step_e;

/*
 * brix_proxy_splice_fill — WHAT: move upstream-socket bytes into pipe[1].
 * WHY: the pipe must hold data before it can be drained to the client; filling
 * only when the pipe is empty keeps splice(upstream→pipe) EAGAIN meaningful
 * (upstream readiness, never pipe-capacity).  HOW: splice at most the residual
 * body; on EAGAIN with body still outstanding hand off to the buffered relay,
 * else arm upstream-read; on 0/error abort.  Returns a pump-step outcome.
 */
static brix_splice_step_e
brix_proxy_splice_fill(brix_proxy_ctx_t *proxy, ngx_connection_t *uconn)
{
    size_t in_pipe_now;
    size_t want;
    ssize_t r;

    if (proxy->splice_upstream >= proxy->splice_total) {
        return BRIX_SPLICE_STEP_CONTINUE;
    }

    in_pipe_now = proxy->splice_upstream - proxy->splice_downstream;
    if (in_pipe_now != 0) {
        /*
         * Pipe still holds data (full) — attempting splice(upstream→pipe) would
         * return EAGAIN for the wrong reason (pipe capacity, not upstream
         * readiness) and arm the upstream-read event prematurely.  Fall through
         * and drain the pipe to the client first.
         */
        return BRIX_SPLICE_STEP_CONTINUE;
    }

    want = proxy->splice_total - proxy->splice_upstream;
    r = splice(uconn->fd, NULL, proxy->splice_pipe[1], NULL, want,
               SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

    if (r > 0) {
        proxy->splice_upstream += (size_t) r;
        return BRIX_SPLICE_STEP_CONTINUE;
    }

    if (r == 0) {
        /* Upstream closed during splice (peer sent FIN). */
        brix_proxy_abort(proxy, "proxy: upstream closed during splice");
        return BRIX_SPLICE_STEP_RETURN;
    }

    if (ngx_errno != NGX_EAGAIN) {
        brix_proxy_abort(proxy, "proxy: splice upstream→pipe failed");
        return BRIX_SPLICE_STEP_RETURN;
    }

    /*
     * The pump always drains everything currently in the upstream socket
     * (looping pipe-fill/pipe-drain) before splice(upstream→pipe) reports
     * EAGAIN.  So reaching EAGAIN with body still outstanding means the
     * remainder has not all arrived yet (or the kernel under-drains socket
     * splice, as WSL2 does — moving a trickle per call and stalling a large
     * read into a 60s client timeout).  Either way the reliable, edge-efficient
     * choice is to relay the remaining body via the buffered recv path, which
     * drains the whole socket buffer per wakeup as data arrives.  (When the
     * entire body was already buffered, the pump finishes via splice_done and
     * never reaches here — so the zero-copy fast path is preserved for the
     * in-buffer case.)
     */
    if (proxy->splice_downstream < proxy->splice_total) {
        brix_proxy_splice_to_buffered(proxy);
        return BRIX_SPLICE_STEP_RETURN;
    }

    /* Body complete — nothing left; arm read and let the loop end. */
    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        brix_proxy_abort(proxy, "proxy: splice read arm failed");
    }
    return BRIX_SPLICE_STEP_RETURN;
}

/*
 * brix_proxy_splice_drain — WHAT: move pipe[0] bytes into the client socket.
 * WHY: this is the client-facing half of the transfer; a full client send
 * buffer must park on the write event, NOT arm upstream-read (that just spins
 * on a full pipe and deadlocks).  HOW: if the pipe is empty, either the body is
 * done or we loop back to refill; on EAGAIN/0 arm the client-write handler; on
 * error abort.  Returns a pump-step outcome.
 */
static brix_splice_step_e
brix_proxy_splice_drain(brix_proxy_ctx_t *proxy, ngx_connection_t *cconn)
{
    size_t in_pipe = proxy->splice_upstream - proxy->splice_downstream;
    ssize_t r;

    if (in_pipe == 0) {
        if (proxy->splice_downstream >= proxy->splice_total) {
            return BRIX_SPLICE_STEP_DONE;
        }
        return BRIX_SPLICE_STEP_CONTINUE;
    }

    r = splice(proxy->splice_pipe[0], NULL, cconn->fd, NULL, in_pipe,
               SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

    if (r > 0) {
        proxy->splice_downstream += (size_t) r;
        if (proxy->splice_downstream >= proxy->splice_total) {
            return BRIX_SPLICE_STEP_DONE;
        }
        return BRIX_SPLICE_STEP_CONTINUE;
    }

    if (r == 0 || ngx_errno == NGX_EAGAIN) {
        /*
         * splice(pipe→client) made no progress.  Two very different causes:
         *
         *  a) The client send buffer is genuinely full — the write event is not
         *     ready.  Arm the client-write handler and wait for the drain edge.
         *     Do NOT arm upstream-read here: any unread upstream data sits in the
         *     kernel TCP receive buffer and is drained by splice_pump (via
         *     splice(upstream→pipe)) once the pipe has room — no epoll wakeup is
         *     needed.  Arming upstream-read while the pipe is full just spins on a
         *     full pipe and deadlocks.
         *
         *  b) The client socket IS writable (write->ready) yet splice still
         *     returned EAGAIN — the kernel's socket-splice under-drains (observed
         *     on WSL2: pipe→socket refuses a tiny residual even though the socket
         *     has room).  No not-writable→writable transition will follow, so an
         *     armed edge-triggered write event would never fire and the pipe
         *     residual would stall into the read timeout.  Drain the residual into
         *     userspace and relay it via the reliable buffered path instead.
         */
        if (cconn->write->ready) {
            brix_proxy_splice_drain_to_buffered(proxy);
            return BRIX_SPLICE_STEP_RETURN;
        }
        cconn->write->handler = brix_proxy_splice_wev;
        if (ngx_handle_write_event(cconn->write, 0) != NGX_OK) {
            brix_proxy_abort(proxy, "proxy: splice client write arm failed");
        }
        return BRIX_SPLICE_STEP_RETURN;
    }

    brix_proxy_abort(proxy, "proxy: splice pipe→client failed");
    return BRIX_SPLICE_STEP_RETURN;
}

/*
 * brix_proxy_splice_pump — drive splice transfers between upstream socket
 * and client socket via the kernel pipe in proxy->splice_pipe[].
 *
 * Called from:
 *   brix_proxy_read_handler  — upstream socket is readable
 *   brix_proxy_splice_wev    — client socket is writable (drain pipe)
 */
void
brix_proxy_splice_pump(brix_proxy_ctx_t *proxy)
{
    ngx_connection_t *uconn = proxy->conn;
    ngx_connection_t *cconn = proxy->client_conn;

    if (uconn == NULL || cconn == NULL) {
        return;
    }

    for (;;) {
        brix_splice_step_e step = brix_proxy_splice_fill(proxy, uconn);
        if (step == BRIX_SPLICE_STEP_RETURN) {
            return;
        }
        /* fill never signals DONE — only drain does. */

        step = brix_proxy_splice_drain(proxy, cconn);
        if (step == BRIX_SPLICE_STEP_RETURN) {
            return;
        }
        if (step == BRIX_SPLICE_STEP_DONE) {
            break;
        }
    }

    brix_proxy_splice_done(proxy);
}

/*
 * brix_proxy_splice_wev — client write event handler during splice.
 * Replaces ngx_stream_brix_send temporarily while draining the pipe.
 */
static void
brix_proxy_splice_wev(ngx_event_t *wev)
{
    ngx_connection_t   *cconn = wev->data;
    brix_ctx_t       *ctx   = cconn->data;
    brix_proxy_ctx_t *proxy;

    if (ctx == NULL || ctx->destroyed) {
        return;
    }
    proxy = ctx->proxy;
    if (proxy == NULL || !proxy->splice_active) {
        /* Splice already finished — restore normal handler and call it. */
        cconn->write->handler = ngx_stream_brix_send;
        ngx_stream_brix_send(wev);
        return;
    }

    brix_proxy_splice_pump(proxy);
}

/*
 * brix_proxy_splice_to_buffered — switch an under-draining splice transfer to
 * the reliable buffered recv relay for the REMAINDER of the current body.
 *
 * Called from the pump when splice(upstream→pipe) reports EAGAIN but a MSG_PEEK
 * shows data is still queued (a kernel whose socket-splice under-drains).  At this
 * point the pipe is empty (splice_upstream == splice_downstream), the 8-byte
 * response header and splice_downstream body bytes are already on the wire, so the
 * remaining splice_total − splice_downstream bytes are accumulated via the normal
 * body loop and relayed RAW (no second header) by brix_proxy_splice_fallback_finish.
 */
static void
brix_proxy_splice_to_buffered(brix_proxy_ctx_t *proxy)
{
    size_t remaining = proxy->splice_total - proxy->splice_downstream;

    /*
     * Bound the buffer: the buffered path holds the remainder in one allocation,
     * so cap it at the same ceiling the normal relay uses.  An oversized remainder
     * keeps splicing (arm + wait) — slow on a broken kernel, but never unbounded
     * memory.  Real reads are far below this; this is belt-and-braces.
     */
    if (remaining == 0 || remaining > BRIX_PROXY_MAX_BODY) {
        if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
            brix_proxy_abort(proxy, "proxy: splice read arm failed");
        }
        return;
    }

    proxy->resp_body = ngx_alloc(remaining + 1, proxy->client_conn->log);
    if (proxy->resp_body == NULL) {
        brix_proxy_abort(proxy, "proxy: splice fallback body alloc failed");
        return;
    }
    proxy->resp_body[remaining] = '\0';
    proxy->resp_dlen     = (uint32_t) remaining;   /* remaining body only */
    proxy->resp_body_pos = 0;
    proxy->splice_active = 0;
    proxy->splice_fallback = 1;

    /* Latch: this upstream's kernel under-drains socket-splice. Re-attempting the
     * splice fast-path on every subsequent read just repeats the wasted trickle-
     * splice + buffered-handoff dance (and its rare lost-wakeup stall into the
     * proxy_read_timeout). Once latched, try_splice declines and every later read
     * goes straight to the reliable buffered relay. Log only on the first latch. */
    ngx_log_error(NGX_LOG_NOTICE, proxy->client_conn->log, 0,
        "xrootd proxy: upstream splice under-draining (%uz/%uz body sent) — "
        "relaying the remaining %uz bytes via the buffered path",
        proxy->splice_downstream, proxy->splice_total, remaining);

    /* Drive the body accumulation in the read handler: arm + post the read
     * event (the queued data produced no fresh edge, so post explicitly). */
    if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
        brix_proxy_abort(proxy, "proxy: splice fallback read arm failed");
        return;
    }
    if (!proxy->conn->read->posted) {
        ngx_post_event(proxy->conn->read, &ngx_posted_events);
    }
}

/*
 * brix_proxy_splice_drain_to_buffered — the drain-side counterpart of
 * brix_proxy_splice_to_buffered.  Called when splice(pipe→client) reports EAGAIN
 * while the client socket is writable — the kernel's pipe→socket splice
 * under-drains (observed on WSL2: it refuses even a tiny residual with room in
 * the socket).  An armed edge-triggered write event would never fire (no
 * not-writable→writable transition follows), stalling the pipe residual into the
 * read timeout.  Instead, read() the pipe residual (already fetched from the
 * upstream socket) into the front of a heap buffer, recv any still-in-socket
 * remainder via the normal body loop, and relay the whole tail RAW through
 * brix_proxy_splice_fallback_finish — the same machinery the fill-side fallback
 * uses.  The 8-byte header and splice_downstream body bytes are already on the
 * wire, so no second header is emitted.
 */
static void
brix_proxy_splice_drain_to_buffered(brix_proxy_ctx_t *proxy)
{
    size_t in_pipe   = proxy->splice_upstream - proxy->splice_downstream;
    size_t remaining = proxy->splice_total - proxy->splice_downstream;
    size_t pos       = 0;

    /* downstream == total is the drain DONE path; guard defensively. */
    if (remaining == 0) {
        brix_proxy_splice_done(proxy);
        return;
    }

    /*
     * An oversized remainder cannot be held in one buffered allocation.  Fall
     * back to the write-event wait (correct for genuine backpressure).  The
     * writable-but-under-draining stall is confined to small trailing residuals
     * far below this ceiling, so this branch is belt-and-braces.
     */
    if (remaining > BRIX_PROXY_MAX_BODY) {
        proxy->client_conn->write->handler = brix_proxy_splice_wev;
        if (ngx_handle_write_event(proxy->client_conn->write, 0) != NGX_OK) {
            brix_proxy_abort(proxy, "proxy: splice client write arm failed");
        }
        return;
    }

    proxy->resp_body = ngx_alloc(remaining + 1, proxy->client_conn->log);
    if (proxy->resp_body == NULL) {
        brix_proxy_abort(proxy, "proxy: splice drain fallback body alloc failed");
        return;
    }

    /*
     * Move the pipe residual — bytes already spliced out of the upstream socket —
     * into the front of the buffer.  The pipe is known to hold exactly in_pipe
     * bytes, so a non-blocking read() returns them; loop only to absorb a short
     * read or EINTR.  Anything else breaks the pipe accounting invariant and
     * would corrupt the frame, so abort rather than relay garbage.
     */
    while (pos < in_pipe) {
        ssize_t got = read(proxy->splice_pipe[0], proxy->resp_body + pos,
                           in_pipe - pos);
        if (got > 0) {
            pos += (size_t) got;
            continue;
        }
        if (got < 0 && ngx_errno == NGX_EINTR) {
            continue;
        }
        ngx_free(proxy->resp_body);
        proxy->resp_body = NULL;
        brix_proxy_abort(proxy, "proxy: splice pipe drain read failed");
        return;
    }

    proxy->resp_body[remaining] = '\0';
    proxy->resp_dlen     = (uint32_t) remaining;
    proxy->resp_body_pos = pos;                 /* pipe residual already buffered */
    proxy->splice_active = 0;
    proxy->splice_fallback = 1;

    /*
     * Restore the normal client write handler: the buffered relay
     * (fallback_finish → brix_queue_response_base) drives the client send through
     * ngx_stream_brix_send, and it must own any genuine-backpressure write event.
     */
    proxy->client_conn->write->handler = ngx_stream_brix_send;

    ngx_log_error(NGX_LOG_NOTICE, proxy->client_conn->log, 0,
        "xrootd proxy: client splice under-draining (%uz/%uz body sent, socket "
        "writable) — relaying the remaining %uz bytes via the buffered path",
        proxy->splice_downstream, proxy->splice_total, remaining);

    /*
     * Recv any still-in-socket remainder in the read handler, then fallback_finish
     * sends the whole tail.  The buffered residual produced no fresh edge, so post
     * the read event explicitly; when the socket remainder is zero the posted
     * handler dispatches straight to fallback_finish.
     */
    if (ngx_handle_read_event(proxy->conn->read, 0) != NGX_OK) {
        brix_proxy_abort(proxy, "proxy: splice drain fallback read arm failed");
        return;
    }
    if (!proxy->conn->read->posted) {
        ngx_post_event(proxy->conn->read, &ngx_posted_events);
    }
}

/*
 * brix_proxy_splice_fallback_finish — complete a splice→buffered fallback once
 * the remaining body has been accumulated into resp_body by the read handler.
 * Sends those bytes RAW to the client (the header is already on the wire), then
 * runs the same post-transfer accounting/finish as a fully-spliced response.
 */
void
brix_proxy_splice_fallback_finish(brix_proxy_ctx_t *proxy)
{
    brix_ctx_t *ctx  = proxy->client_ctx;
    u_char       *body = proxy->resp_body;
    size_t        n    = proxy->resp_dlen;

    /* Hand ownership of the heap body to the send path (freed after it drains). */
    proxy->resp_body     = NULL;
    proxy->splice_fallback = 0;

    if (brix_queue_response_base(ctx, proxy->client_conn, body, n, body)
        != NGX_OK)
    {
        brix_proxy_abort(proxy, "proxy: splice fallback relay failed");
        return;
    }

    /* The whole body (header + spliced prefix + buffered remainder) is now on the
     * wire — account and finish exactly as a fully-spliced response would. */
    proxy->splice_downstream = proxy->splice_total;
    brix_proxy_splice_done(proxy);
}

/*
 * The eligibility gate + one-shot splice setup (brix_proxy_splice_eligible,
 * brix_proxy_splice_pipe_ensure, brix_proxy_splice_send_hdr, and the exported
 * brix_proxy_try_splice) live in events_splice_setup.c.  try_splice kicks off
 * brix_proxy_splice_pump (below); the pump + fallback machinery stay here.
 */

#endif /* __linux__ */
