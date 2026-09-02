#include "recv_frame.h"
#include "disconnect.h"
#include "fd_table.h"
#include "tls.h"
#include "budget.h"
#include "deadline.h"
#include "shutdown_hold.h"
#include "net/manager/pending.h"
#include "fs/xfer/stage_waiter.h"
#include "protocols/root/handoff/handoff.h"

/*
 * recv_frame.c — the READ side of the recv framing loop (see recv_frame.h):
 * deferred-request drain, fresh-request housekeeping, non-XRootD handoff, and
 * reading/accumulating the next PDU unit.  The process side (buffer management,
 * body extension, header/payload dispatch) lives in recv_process.c.  Bodies are
 * the original ngx_stream_brix_recv loop-body blocks moved verbatim; only
 * loop-exit statements (break/continue/return) became step codes.
 */

brix_recv_step_t
brix_recv_run_deferred(ngx_stream_session_t *s, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx, ngx_event_t *rev,
    size_t *rx_pending)
{
    ngx_int_t rc;

    /*
     * A non-pipelinable request was fully read (header in cur_*, any payload in
     * payload_buf) while pipelined reads OR writes were still in flight.  Keep
     * it parked until BOTH the ack/response queue (out.count) and the in-flight
     * pwrites (wr_inflight) have drained — a write completion or the send-side
     * drain re-enters recv to re-check.  This is what lets a kXR_close safely
     * follow a burst of pipelined writes: every pwrite lands before the retire.
     * phase-32 WS3: also hold until in-flight cold reads (rd.aio_inflight) drain,
     * so the deferred op never runs while a read worker still holds a handle.
     */
    if (ctx->out.count > 0 || ctx->out.wr_inflight > 0
        || ctx->rd.aio_inflight > 0)
    {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            return BRIX_RECV_STEP_BREAK;
        }
        return BRIX_RECV_STEP_RETURN;
    }

    ctx->out.recv_deferred = 0;

    /*
     * Reinstall the parked request's stream-id: a pipelined pwrite/read ack
     * completing during the park went through brix_aio_restore_stream(), which
     * overwrote recv.cur_streamid with the completed op's sid.  Dispatching the
     * deferred request with that stale sid misdirects its reply onto a sid the
     * client has already retired (and may have recycled for a newer request),
     * while the deferred request itself never gets answered — the client's
     * stream timeout then kills the whole multiplexed connection.
     */
    ctx->recv.cur_streamid[0] = ctx->out.deferred_streamid[0];
    ctx->recv.cur_streamid[1] = ctx->out.deferred_streamid[1];

    BRIX_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, *rx_pending);
    *rx_pending = 0;
    rc = brix_dispatch(ctx, c, conf);
    if (rc == NGX_ERROR) {
        return BRIX_RECV_STEP_BREAK;
    }
    if (ctx->state == XRD_ST_AIO) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            return BRIX_RECV_STEP_BREAK;
        }
        return BRIX_RECV_STEP_RETURN;
    }
    if (ctx->state != XRD_ST_SENDING) {
        if (ctx->tls_pending) {
            brix_start_tls(ctx, c, conf);
            return BRIX_RECV_STEP_RETURN;
        }
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->recv.hdr_pos = 0;
    }
    return BRIX_RECV_STEP_CONTINUE;
}

/*
 * Fresh-request-boundary housekeeping at the top of a REQ_HEADER read (hdr_pos
 * == 0): apply pipelining backpressure, trim grown scratch, reconcile the heap
 * budget, and handle graceful-quit teardown of an idle keepalive.  RETURN when
 * the connection suspended or was torn down; NEXT to proceed reading the header.
 */
static brix_recv_step_t
brix_recv_header_prep(ngx_stream_session_t *s, ngx_connection_t *c,
    brix_ctx_t *ctx, size_t rx_pending)
{
    /*
     * Phase 29 pipelining backpressure: if pipeline_depth responses are already
     * queued/draining (out.count) OR pwrites are still in flight (wr_inflight),
     * stop reading new requests and suspend with state=SENDING.  Bounding
     * out.count + wr_inflight at pipeline_depth caps BOTH in-flight pwrites and
     * queued acks, so the out_ring can never overflow.  (Both counters are 0 for
     * the common serial case, so this is a no-op there.)
     *
     * phase-32 WS3: cold reads in flight (rd.aio_inflight) each hold a rd_pool
     * buffer and will each become a queued response, so count them here too —
     * this is what caps the concurrent-read depth (and guarantees a free pool
     * slot / out_ring slot for the next read the recv loop admits).
     */
    if (ctx->out.count + ctx->out.wr_inflight + ctx->rd.aio_inflight
        >= ctx->out.pipeline_depth)
    {
        ctx->state = XRD_ST_SENDING;
        BRIX_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
        return BRIX_RECV_STEP_RETURN;
    }

    /*
     * Top of a fresh request with the queue empty — the previous response is
     * fully sent, so no chain references the scratch buffers.  Phase 31: trim
     * scratch a prior large read/pgwrite grew back to the streaming window, then
     * reconcile the transfer-heap footprint with the SHM-global budget.  Gated
     * on out.count==0 so a pipelined read still in flight is never disturbed.
     * phase-32 WS3: also gate on rd.aio_inflight==0 — a cold read on a worker
     * thread still owns a pool buffer, and the ngx_exiting idle-close below would
     * otherwise free it (via brix_on_disconnect) mid-pread.
     */
    if (ctx->out.count == 0 && ctx->out.wr_inflight == 0
        && ctx->rd.aio_inflight == 0)
    {
        brix_trim_scratch(ctx, c);
        brix_budget_sync(ctx);

        /*
         * Fast teardown: the worker is draining and this connection is quiescent
         * at a fresh request boundary (no queued response, no in-flight pwrite).
         * Close now rather than parking; the client reconnects to the new worker
         * and resumes.  BUT only when no file is open: a connection holding an
         * open handle is mid-transfer (a streaming read parked between chunks, or
         * a cache slice-fill in progress) — forcing a reconnect there loses the
         * in-flight fill and surfaces as a spurious kXR_NotFound.  Let the active
         * transfer finish on the old worker (bounded by worker_shutdown_timeout).
         */
        ngx_flag_t has_open_file = brix_ctx_has_open_file(ctx);

        brix_shutdown_hold_sync(c, ctx, has_open_file);

        if (ngx_exiting && !has_open_file) {
            brix_on_disconnect(ctx, c);
            brix_close_all_files(ctx);
            ngx_stream_finalize_session(s, NGX_STREAM_OK);
            return BRIX_RECV_STEP_RETURN;
        }

        /*
         * Mark idle so a graceful quit's ngx_close_idle_connections() drops this
         * parked keepalive immediately.  An open handle means an active transfer,
         * not a keepalive idle — leave it un-idle so the reload lets it complete.
         */
        c->idle = has_open_file ? 0 : 1;
    }

    return BRIX_RECV_STEP_NEXT;
}

/*
 * The handshake's first byte is non-zero — not an XRootD client hello (the
 * client hello begins with a zero streamid word); it is an HTTP method letter or
 * a TLS 0x16.  Splice to the local HTTP/WebDAV listener when brix_http_handoff
 * is configured (one port serves both protocols), else close.  RETURN when the
 * relay took the connection; BREAK to close it.
 */
static brix_recv_step_t
brix_recv_handle_nonxrootd(ngx_stream_session_t *s, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx)
{
    if (conf->http_handoff_addr != NULL
        && brix_http_handoff_start(s, c, conf,
               ctx->recv.hdr_buf, ctx->recv.hdr_pos) == NGX_OK)
    {
        return BRIX_RECV_STEP_RETURN;   /* the relay owns the connection now */
    }
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: non-XRootD client (first byte 0x%02xd)"
                   " closing immediately",
                   (unsigned) ctx->recv.hdr_buf[0]);
    return BRIX_RECV_STEP_BREAK;
}

/*
 * Fold `avail` newly-received bytes into the current PDU state and decide the
 * loop action: detect a non-XRootD handshake byte (→ handle_nonxrootd), CONTINUE
 * on a short read (more of this unit still to come), or NEXT when the unit is now
 * complete.
 */
static brix_recv_step_t
brix_recv_advance(ngx_stream_session_t *s, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx, size_t avail,
    size_t need, size_t *rx_pending)
{
    *rx_pending += avail;

    if (ctx->state == XRD_ST_HANDSHAKE) {
        ctx->recv.hdr_pos += avail;

        if (ctx->recv.hdr_pos >= 1 && ctx->recv.hdr_buf[0] != 0) {
            return brix_recv_handle_nonxrootd(s, c, conf, ctx);
        }

    } else if (ctx->state == XRD_ST_REQ_HEADER) {
        ctx->recv.hdr_pos += avail;

    } else {
        ctx->recv.payload_pos += avail;
    }

    if (avail < need) {
        return BRIX_RECV_STEP_CONTINUE;
    }

    return BRIX_RECV_STEP_NEXT;
}

/*
 * Buffered frame read.  Exact-size frame reads cost two extra syscalls each
 * inside ngx_unix_recv (an ioctl(FIONREAD) follows every recv that exactly
 * fills its buffer) plus a separate recv per framing stage.  Once a session
 * can no longer be handed to a raw-socket consumer — auth complete (no
 * handshake sniffing, no post-protocol STARTTLS, and a pre-bind secondary
 * never qualifies, which keeps §1.4 fd migration exact-read), and no
 * upstream/relay configured (those subsystems read the client socket
 * directly and would never see stashed bytes) — pull one big recv into a
 * per-connection stash and feed the framing stages from it: a whole
 * metadata request (often several pipelined ones) costs ONE partial recv
 * that nginx never follows with an ioctl.  Reads of at least the stash size
 * (bulk write payloads) bypass the stash straight into their destination —
 * no bounce copy — but only once the stash is drained, so byte order is
 * preserved.  Returns exactly what c->recv returns (bytes / NGX_AGAIN /
 * NGX_ERROR / 0), so the caller's result handling is unchanged.
 */
static ssize_t
brix_recv_buffered(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, u_char *dest, size_t need)
{
    brix_ctx_recv_t *rv = &ctx->recv;
    size_t            have = (size_t) (rv->stash_len - rv->stash_head);
    ssize_t           n;

    if (have == 0) {
        if (need >= BRIX_RECV_STASH_SIZE
            || !ctx->login.auth_done
            || conf->upstream_host.len > 0
            || conf->relay_addr != NULL)
        {
            return c->recv(c, dest, need);
        }

        if (rv->stash == NULL) {
            rv->stash = ngx_palloc(c->pool, BRIX_RECV_STASH_SIZE);
            if (rv->stash == NULL) {
                return c->recv(c, dest, need);
            }
        }

        n = c->recv(c, rv->stash, BRIX_RECV_STASH_SIZE);
        if (n <= 0) {
            return n;              /* NGX_AGAIN / NGX_ERROR / closed */
        }
        rv->stash_head = 0;
        rv->stash_len  = (uint32_t) n;
        have = (size_t) n;
    }

    if (have > need) {
        have = need;
    }
    ngx_memcpy(dest, rv->stash + rv->stash_head, have);
    rv->stash_head += (uint32_t) have;
    if (rv->stash_head == rv->stash_len) {
        rv->stash_head = 0;
        rv->stash_len  = 0;
    }
    return (ssize_t) have;
}

brix_recv_step_t
brix_recv_read_frame(ngx_stream_session_t *s, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx, ngx_event_t *rev,
    size_t *rx_pending)
{
    u_char *dest;
    size_t  need;
    ssize_t n;

    if (ctx->state == XRD_ST_HANDSHAKE) {
        dest = ctx->recv.hdr_buf + ctx->recv.hdr_pos;
        need = XRD_HANDSHAKE_LEN - ctx->recv.hdr_pos;

    } else if (ctx->state == XRD_ST_REQ_HEADER) {
        if (ctx->recv.hdr_pos == 0) {
            brix_recv_step_t st = brix_recv_header_prep(s, c, ctx, *rx_pending);
            if (st != BRIX_RECV_STEP_NEXT) {
                return st;
            }
        }
        dest = ctx->recv.hdr_buf + ctx->recv.hdr_pos;
        need = XRD_REQUEST_HDR_LEN - ctx->recv.hdr_pos;

    } else {
        /* cur_body_extra is non-zero only for kXR_writev (segment data streams
         * after the dlen-framed descriptor block) and for kXR_chkpoint/ckpXeq
         * (the sub-request body streams after the dlen-framed sub-header). */
        dest = ctx->recv.payload + ctx->recv.payload_pos;
        need = (size_t) ctx->recv.cur_dlen + ctx->recv.cur_body_extra
               - ctx->recv.payload_pos;
    }

    if (need > 0) {
        /* No forced rev->available reset here: -1 made ngx_unix_recv follow
         * every exact-fill read with an ioctl(FIONREAD) this loop never
         * consulted (it reads to EAGAIN regardless of rev->ready). */
        n = brix_recv_buffered(ctx, c, conf, dest, need);

        if (n == NGX_AGAIN) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                          "brix: recv AGAIN st=%d hdr_pos=%uz avail=%d"
                          " ready=%d active=%d",
                          (int) ctx->state, ctx->recv.hdr_pos,
                          rev->available, (int) rev->ready,
                          (int) rev->active);
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                return BRIX_RECV_STEP_BREAK;
            }
            /* Phase 39: genuine incompletion — arm the read deadline once
             * (idempotent, so repeated partial reads of the same PDU do NOT
             * reset it), bounding time-to-complete against a slowloris. */
            brix_arm_read_deadline(c, ctx);
            BRIX_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, *rx_pending);
            return BRIX_RECV_STEP_RETURN;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "brix: client disconnected");
            if (brix_defer_teardown_if_writing(ctx, c, NGX_STREAM_OK)) {
                return BRIX_RECV_STEP_RETURN;
            }
            brix_on_disconnect(ctx, c);
            brix_close_all_files(ctx);
            ngx_stream_finalize_session(s, NGX_STREAM_OK);
            return BRIX_RECV_STEP_RETURN;
        }

        return brix_recv_advance(s, c, conf, ctx, (size_t) n, need, rx_pending);
    }

    return BRIX_RECV_STEP_NEXT;
}
