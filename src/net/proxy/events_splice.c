#include "proxy_internal.h"
#include "protocols/root/connection/handler.h"
#include "protocols/root/connection/write_helpers.h"   /* brix_queue_response_base */
#include <sys/socket.h>
#include <sys/ioctl.h>   /* FIONREAD — only splice a fully-buffered body */

/* zero-copy splice fast-path */
#ifdef __linux__

/* Forward declaration — brix_proxy_splice_wev is defined after the pump. */
static void brix_proxy_splice_wev(ngx_event_t *wev);

/* Forward declaration — the under-draining-splice fallback, defined after the
 * pump (the pump calls it when splice stalls with data still queued). */
static void brix_proxy_splice_to_buffered(brix_proxy_ctx_t *proxy);

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
         * will fire for it.  Ensure the read handler is posted so it runs
         * again regardless of whether new data has arrived.
         */
        {
            ngx_event_t *urev = proxy->conn->read;
            if (!urev->active && !urev->ready) {
                if (ngx_handle_read_event(urev, 0) != NGX_OK) {
                    brix_proxy_abort(proxy,
                        "proxy: read arm failed after splice oksofar");
                    return;
                }
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
         * Client send buffer full.  Arm the client-write event and wait.  Do
         * NOT arm upstream-read here: any unread upstream data sits in the
         * kernel TCP receive buffer and will be drained by splice_pump (via
         * splice(upstream→pipe)) once the pipe has room — no epoll wakeup
         * required for that.  Arming upstream-read while the pipe is full just
         * causes spurious wakeups that retry a full pipe and deadlock.
         */
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
 * brix_proxy_splice_eligible — WHAT: gate the zero-copy splice fast-path for
 * the current response.  WHY: splice bypasses TLS and only makes sense for a
 * fully-buffered read/pgread OK(sofar) body — splicing a still-streaming body
 * causes a fragile mid-transfer EAGAIN handoff with rare lost-wakeup stalls.
 * HOW: reject TLS, wrong state/opcode/status, empty body, and (via FIONREAD) a
 * body not yet fully in the upstream socket buffer.  Returns 1 if eligible.
 */
static int
brix_proxy_splice_eligible(brix_proxy_ctx_t *proxy)
{
    int avail = 0;

#if (NGX_SSL)
    /* Splice bypasses the TLS layer — only valid for plain-text connections. */
    if (proxy->conn->ssl != NULL || proxy->client_conn->ssl != NULL) {
        return 0;
    }
#endif

    if (proxy->state != XRD_PX_FORWARDING) {
        return 0;
    }
    if (proxy->fwd_reqid != kXR_read && proxy->fwd_reqid != kXR_pgread) {
        return 0;
    }
    if (proxy->resp_status != kXR_ok && proxy->resp_status != kXR_oksofar) {
        return 0;
    }
    if (proxy->resp_dlen == 0) {
        return 0;
    }

    /*
     * Only splice a body that has ALREADY fully arrived in the upstream socket
     * buffer (the 8-byte header was just consumed, so FIONREAD now reports body
     * bytes).  Splicing a still-streaming body makes the pump hit a mid-transfer
     * EAGAIN and hand the remainder to the buffered relay — a fragile transition
     * whose epoll-ET re-arm is unreliable after splice() drains the socket
     * (observed as rare multi-second lost-wakeup stalls into proxy_read_timeout
     * over proxy→proxy hops).  When the whole body is buffered, splice completes
     * in one pump with no handoff; otherwise the caller's buffered relay reads the
     * streamed body reliably (it drains the socket per wakeup and is plenty fast).
     * This keeps zero-copy for the fully-buffered common case while removing the
     * stall-prone streaming-splice handoff entirely.
     */
    if (ioctl(proxy->conn->fd, FIONREAD, &avail) != 0
        || (size_t) avail < (size_t) proxy->resp_dlen) {
        return 0;
    }

    return 1;
}

/*
 * brix_proxy_splice_pipe_ensure — WHAT: lazily create the kernel pipe used as
 * the splice conduit.  WHY: the pipe is per-proxy and only needed on the splice
 * path; a larger pipe cuts syscalls on big bodies.  HOW: pipe2(O_NONBLOCK) once,
 * best-effort F_SETPIPE_SZ(1 MiB).  Returns NGX_OK, or NGX_DECLINED if the pipe
 * could not be created (caller falls back to the buffered path).
 */
static ngx_int_t
brix_proxy_splice_pipe_ensure(brix_proxy_ctx_t *proxy)
{
    if (proxy->splice_pipe[0] != -1) {
        return NGX_OK;
    }

    if (pipe2(proxy->splice_pipe, O_NONBLOCK) < 0) {
        ngx_log_error(NGX_LOG_WARN, proxy->client_conn->log, ngx_errno,
                      "xrootd proxy: pipe2 failed, using buffered path");
        return NGX_DECLINED;
    }

    /*
     * Enlarge the pipe to 1 MiB (default is 64 KiB).  splice() pumps at most
     * one pipe-buffer per syscall, so a larger pipe cuts the syscall count on
     * big relayed bodies by ~16x.  Best-effort: F_SETPIPE_SZ can fail if it
     * exceeds /proc/sys/fs/pipe-max-size for an unprivileged process, in which
     * case the kernel keeps the default size and splice still works correctly.
     */
    if (fcntl(proxy->splice_pipe[1], F_SETPIPE_SZ, 1 << 20) < 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log,
                       ngx_errno,
                       "xrootd proxy: F_SETPIPE_SZ(1MiB) failed (errno=%d), "
                       "using default pipe size", ngx_errno);
    }

    return NGX_OK;
}

/*
 * brix_proxy_splice_send_hdr — WHAT: send the full 8-byte response header (with
 * the client's stream ID) before splicing the body.  WHY (Phase 39 / PXY-6):
 * once ANY header byte is on the wire we must not fall back to the buffered
 * relay — it rebuilds and re-sends the WHOLE header, duplicating bytes and
 * corrupting the client frame stream.  HOW: a bounded send loop —
 *   - nothing sent yet (NGX_AGAIN at off==0): decline → buffered path sends it;
 *   - partial: complete the (<=7-byte) remainder here (bounded, off caps at 8);
 *   - NGX_AGAIN mid-remainder or a socket error: abort cleanly (NGX_ERROR).
 * Returns NGX_OK (fully sent), NGX_DECLINED (nothing sent), or NGX_ERROR
 * (aborted — caller must return immediately without touching `proxy`).
 */
static ngx_int_t
brix_proxy_splice_send_hdr(brix_proxy_ctx_t *proxy)
{
    u_char hdr[XRD_RESPONSE_HDR_LEN];
    size_t off = 0;
    ssize_t sent;

    brix_build_resp_hdr(proxy->fwd_streamid,
                        proxy->resp_status,
                        proxy->resp_dlen,
                        (ServerResponseHdr *)(void *) hdr);

    for ( ;; ) {
        sent = proxy->client_conn->send(proxy->client_conn,
                                        hdr + off,
                                        XRD_RESPONSE_HDR_LEN - off);
        if (sent > 0) {
            off += (size_t) sent;
            if (off == XRD_RESPONSE_HDR_LEN) {
                return NGX_OK;             /* fully sent — proceed to splice */
            }
            continue;                      /* partial — send the remainder */
        }
        if (sent == NGX_AGAIN && off == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                           "xrootd proxy: splice header would block, "
                           "using buffered path");
            return NGX_DECLINED;
        }
        /* NGX_AGAIN after a partial header, or a socket error: cannot fall
         * back without duplicating on-wire bytes, and the splice path has no
         * deferred-header state.  Abort rather than corrupt. */
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, proxy->client_conn->log, 0,
                       "xrootd proxy: splice header send incomplete (%z), "
                       "aborting to avoid frame corruption", sent);
        brix_proxy_abort(proxy, "proxy: splice header send incomplete");
        return NGX_ERROR;
    }
}

/*
 * brix_proxy_try_splice — attempt to start a zero-copy splice for the
 * current read response.  Returns NGX_OK if splice was started (the caller
 * must NOT allocate resp_body or loop for body data).  Returns NGX_DECLINED
 * if the conditions are not met and the caller should use the normal path.
 * Returns NGX_ERROR if it had to abort the session (PXY-6 partial-header case);
 * the proxy has been torn down and the caller MUST return immediately without
 * touching `proxy`.
 */
ngx_int_t
brix_proxy_try_splice(brix_proxy_ctx_t *proxy)
{
    ngx_int_t rc;

    if (!brix_proxy_splice_eligible(proxy)) {
        return NGX_DECLINED;
    }

    if (brix_proxy_splice_pipe_ensure(proxy) != NGX_OK) {
        return NGX_DECLINED;
    }

    rc = brix_proxy_splice_send_hdr(proxy);
    if (rc != NGX_OK) {
        return rc;                 /* NGX_DECLINED or NGX_ERROR (aborted) */
    }

    proxy->splice_active     = 1;
    proxy->splice_total      = proxy->resp_dlen;
    proxy->splice_upstream   = 0;
    proxy->splice_downstream = 0;

    brix_proxy_splice_pump(proxy);
    return NGX_OK;
}

#endif /* __linux__ */

