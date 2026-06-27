#include "../ngx_xrootd_module.h"
#include "disconnect.h"
#include "fd_table.h"
#include "tls.h"
#include "budget.h"
#include "deadline.h"
#include "../manager/pending.h"
#include "../frm/waiter.h"

/* File: recv.c — TCP read-event loop and request framing state machine
 * WHAT: The core async recv loop that drives the XRootD protocol lifecycle on each TCP connection. Frames handshake (20-byte ClientInitHandShake), request headers (24-byte ClientRequestHdr), and payload bytes into a deterministic four-state machine — HANDSHAKE → REQ_HEADER → REQ_PAYLOAD → dispatch, with suspend states for SENDING/AIO/UPSTREAM/TLS. Security invariant: dlen must pass xrootd_max_payload_for_request() BEFORE any allocation. Timeout handling: CMS wait timeout sends retry response; other timeouts disconnect. Thread safety: single-owner per connection on nginx event thread — no locking required.
 *
 * WHY: Every XRootD request flows through recv.c's state machine before dispatch to opcode handlers. The recv loop ensures correct byte-level framing (handshake → header → payload) so dispatch receives a complete, validated request with streamid/reqid/dlen extracted from the wire header. Without this framing layer, dispatch would receive partial or misaligned data causing protocol errors.
 *
 * HOW: On each read-ready event, recv checks ctx->state to determine what bytes are expected (handshake=20, header=24, payload=dlen), calls c->recv(), accumulates into hdr_buf/payload_buf, dispatches when complete, then resets state for the next request. Suspend states (SENDING/AIO/UPSTREAM/TLS) return immediately without reading.
 * */

/* xrootd_max_payload_for_request — return per-opcode payload size limit
 * WHAT: Security guard that defines the maximum allowed wire payload for each request opcode. Called BEFORE any allocation to prevent memory exhaustion attacks — clients sending dlen > this limit are disconnected immediately. Limits vary by opcode type: write/pgwrite/chkpoint -> XROOTD_MAX_WRITE_PAYLOAD; readv -> segments x segsize; auth -> XROOTD_MAX_AUTH_PAYLOAD (16KB); prepare -> XROOTD_MAX_PREPARE_PAYLOAD; all others -> path + 64 bytes. This is the first line of defense against oversized payloads. */
static uint32_t
xrootd_max_payload_for_request(uint16_t reqid)
{
    if (reqid == kXR_pgwrite || reqid == kXR_write || reqid == kXR_writev
        || reqid == kXR_chkpoint) {
        return XROOTD_MAX_WRITE_PAYLOAD;
    }

    if (reqid == kXR_readv) {
        /* Each segment is XROOTD_READV_SEGSIZE (16) bytes. */
        return XROOTD_READV_MAXSEGS * XROOTD_READV_SEGSIZE;
    }

    if (reqid == kXR_auth) {
        return XROOTD_MAX_AUTH_PAYLOAD;
    }

    if (reqid == kXR_prepare) {
        return XROOTD_MAX_PREPARE_PAYLOAD;
    }

    /* All other requests carry only a path (XROOTD_MAX_PATH) plus a small
     * fixed-size body.  The +64 covers opcode-specific extras (e.g. the
     * kXR_login info field that follows the username in the payload). */
    return XROOTD_MAX_PATH + 64;
}

/* xrootd_ensure_payload_buffer: allocate/resize payload buffer for incoming request data
 * WHAT: Ensures ctx->payload_buf has sufficient capacity (dlen + 1 bytes) and points ctx->payload to it. The extra byte is pre-zeroed as a C-string NUL terminator guarantee. Uses heap allocation (ngx_alloc), NOT pool-allocated, so the buffer can grow across multiple requests on the same connection without fragmenting the nginx pool. On resize: frees old buffer, allocates new one. Returns NGX_OK if capacity sufficient or successfully resized, NGX_ERROR on overflow check failure or allocation failure.
 *
 * WHY: Payload buffers must survive across multiple requests on a persistent TCP connection (pool-allocated buffers would fragment under repeated large allocations). Heap allocation (ngx_alloc) allows resizing without pool pressure and is freed explicitly when the connection closes via xrootd_on_disconnect(). The pre-zeroed NUL byte ensures ctx->payload always has a valid C-string terminator even for zero-length payloads.
 *
 * HOW: First checks if existing buffer has sufficient capacity (ctx->payload_buf_size >= need), reuses it and sets payload pointer. If insufficient, frees old buffer via ngx_free(), allocates new one via ngx_alloc(need), sets ctx->payload_buf/payload_buf_size/payload, pre-zeroes byte at position dlen. Returns NGX_OK or NGX_ERROR. */
static ngx_int_t
xrootd_ensure_payload_buffer(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint32_t dlen)
{
    u_char  *buf;
    size_t   need;

    if (dlen > (uint32_t) (SIZE_MAX - 1)) {
        return NGX_ERROR;
    }
    need = (size_t) dlen + 1;

    if (ctx->payload_buf != NULL && ctx->payload_buf_size >= need) {
        ctx->payload = ctx->payload_buf;
        ctx->payload[dlen] = '\0';
        return NGX_OK;
    }

    buf = ngx_alloc(need, c->log);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (ctx->payload_buf != NULL) {
        ngx_free(ctx->payload_buf);
    }

    ctx->payload_buf = buf;
    ctx->payload_buf_size = need;
    ctx->payload = buf;
    ctx->payload[dlen] = '\0';

    return NGX_OK;
}

 /*
 *
 * WHAT: The core async recv loop that drives the XRootD protocol lifecycle on each TCP connection. Called by nginx whenever data is available or timeout fires.
 *
 * WHY: Every XRootD request requires byte-level framing before dispatch — handshake validates client identity, header extracts routing fields (streamid/reqid), payload accumulates opcode-specific data. Without this loop, dispatch would receive partial or misaligned wire data causing protocol errors. The suspend-state design prevents recv from reading while send/AIO/upstream subsystems own the connection.
 *
 * HOW: On each read-ready event, checks ctx->state to determine expected bytes (handshake=20, header=24, payload=dlen), calls c->recv(), accumulates into hdr_buf/payload_buf, dispatches when complete, resets state for next request. Suspend states return immediately without reading. Timeout handling: CMS wait timeout sends retry response; other timeouts disconnect.
 * */
/* Pre-loop teardown/deadline gate for the recv handler: handles a graceful-
 * shutdown close (c->close) and the three read-timeout cases (WAITING_CMS,
 * WAITING_FRM, and the steady-state read deadline).  Returns 1 when it has
 * finalized or parked the connection and the caller must return; 0 to proceed
 * into the recv loop.  Every original early-return path maps to `return 1`. */
static int
xrootd_recv_pre_loop(ngx_stream_session_t *s, ngx_connection_t *c,
    xrootd_ctx_t *ctx, ngx_event_t *rev)
{

    /*
     * Graceful shutdown signal: ngx_close_idle_connections() set c->close on a
     * connection we had marked idle.  Tear it down through the normal disconnect
     * funnel — a clean FIN is the correct retry signal: the client's resilient
     * layer treats it as a transport sever and reconnects to the new worker,
     * resuming the transfer from its last offset.  (kXR_wait would stall the
     * client ≥1s on the dying worker; a self-redirect trips its loop guard.)
     */
    if (c->close) {
        if (xrootd_defer_teardown_if_writing(ctx, c, NGX_STREAM_OK)) {
            return 1;
        }
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return 1;
    }

    if (rev->timedout) {
        if (ctx->state == XRD_ST_WAITING_CMS) {
            /* kYR_select did not arrive in time - tell client to retry. */
            rev->timedout = 0;
            xrootd_pending_remove(ctx->cms_wait_streamid, ngx_pid);
            ctx->state = XRD_ST_REQ_HEADER;
            xrootd_send_wait(ctx, c, 5);
            xrootd_schedule_read_resume(c);
            return 1;
        }
        if (ctx->state == XRD_ST_WAITING_FRM) {
            /* The async recall took longer than stage_ttl — drop the parked
             * waiter and ask the client to retry (it will re-poll residency:
             * a hit if staged, or a fresh park otherwise). */
            rev->timedout = 0;
            frm_waiter_drop_conn(c->fd, c->number);
            ctx->state = XRD_ST_REQ_HEADER;
            xrootd_send_wait(ctx, c, 5);
            xrootd_schedule_read_resume(c);
            return 1;
        }
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "xrootd: client connection timed out");
        /* Phase 39: our steady-state read deadline fired — it is the only c->read
         * timer armed outside the WAITING_CMS/FRM states handled above.  Attribute
         * it (pre-auth handshake vs in-flight PDU) and tear down via the single
         * disconnect funnel. */
        ctx->read_deadline_armed = 0;
        if (ctx->auth_done) {
            XROOTD_SRV_METRIC_INC(ctx, read_pdu_timeouts_total);
        } else {
            XROOTD_SRV_METRIC_INC(ctx, handshake_timeouts_total);
        }
        if (xrootd_defer_teardown_if_writing(ctx, c, NGX_STREAM_OK)) {
            return 1;
        }
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return 1;
    }


    return 0;
}

/* Result of the recv-loop handoff gate (xrootd_recv_handoff_state). */
enum {
    XROOTD_RECV_PROCEED = 0,  /* not a handoff state — read/parse a PDU */
    XROOTD_RECV_RETURN,       /* connection yielded — return from the handler */
    XROOTD_RECV_BREAK         /* read-event re-arm failed — break the recv loop */
};

/* Connection-handoff gate at the top of the recv loop: when the connection is
 * currently owned by another subsystem (SENDING / AIO / UPSTREAM / PROXY /
 * WAITING_CMS|FRM / TLS_HANDSHAKE) the recv loop must yield rather than read
 * more bytes.  The four "yield until its event fires" states share one body
 * (re-arm the read event, then return).  Returns XROOTD_RECV_RETURN to return
 * from the handler, XROOTD_RECV_BREAK to break the loop, or XROOTD_RECV_PROCEED
 * when no handoff applies and the caller should read/parse the next PDU. */
static int
xrootd_recv_handoff_state(xrootd_ctx_t *ctx, ngx_event_t *rev)
{
    if (ctx->state == XRD_ST_SENDING || ctx->state == XRD_ST_TLS_HANDSHAKE) {
        return XROOTD_RECV_RETURN;
    }

    if (ctx->state == XRD_ST_AIO
        || ctx->state == XRD_ST_UPSTREAM
        || ctx->state == XRD_ST_PROXY
        || ctx->state == XRD_ST_WAITING_CMS
        || ctx->state == XRD_ST_WAITING_FRM)
    {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            return XROOTD_RECV_BREAK;
        }
        return XROOTD_RECV_RETURN;
    }

    return XROOTD_RECV_PROCEED;
}

void
ngx_stream_xrootd_recv(ngx_event_t *rev)
{
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_xrootd_srv_conf_t  *conf;
    xrootd_ctx_t                  *ctx;
    ssize_t                        n;
    ngx_int_t                      rc;
    size_t                         rx_pending;

    c = rev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);

    /*
     * Fast teardown: we are about to service this connection, so clear the
     * idle marker for the duration of this handler run.  It is re-set at the
     * request boundary below whenever we park waiting for the next request, so
     * that a graceful quit's ngx_close_idle_connections() can drop a parked
     * keepalive connection at once instead of holding it until worker exit.
     */
    c->idle = 0;
    if (xrootd_recv_pre_loop(s, c, ctx, rev)) {
        return;
    }

    rx_pending = 0;

    for (;;) {
        u_char *dest;
        size_t  need;
        size_t  avail;

        if (ctx->recv_deferred) {
            /*
             * Phase 29 drain barrier: a non-pipelinable request was fully read
             * (header in cur_*, any payload in payload_buf) while pipelined reads
             * OR writes were still in flight.  It must run with the connection
             * quiescent, so keep it parked until BOTH the ack/response queue
             * (out_count) and the in-flight pwrites (wr_inflight) have drained — a
             * write completion (schedule_read_resume) or the send-side drain
             * re-enters recv to re-check.  This is what lets a kXR_close safely
             * follow a burst of pipelined writes: every pwrite has landed before
             * the handle is retired.
             */
            if (ctx->out_count > 0 || ctx->wr_inflight > 0) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    break;
                }
                return;
            }
            ctx->recv_deferred = 0;
            XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
            rx_pending = 0;
            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                break;
            }
            if (ctx->state == XRD_ST_AIO) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    break;
                }
                return;
            }
            if (ctx->state != XRD_ST_SENDING) {
                if (ctx->tls_pending) {
                    xrootd_start_tls(ctx, c, conf);
                    return;
                }
                ctx->state = XRD_ST_REQ_HEADER;
                ctx->hdr_pos = 0;
            }
            continue;
        }

        {
            int hr = xrootd_recv_handoff_state(ctx, rev);
            if (hr == XROOTD_RECV_RETURN) {
                return;
            }
            if (hr == XROOTD_RECV_BREAK) {
                break;   /* breaks the recv for-loop */
            }
            /* XROOTD_RECV_PROCEED: not a handoff state — read/parse a PDU. */
        }

        if (ctx->state == XRD_ST_HANDSHAKE) {
            dest = ctx->hdr_buf + ctx->hdr_pos;
            need = XRD_HANDSHAKE_LEN - ctx->hdr_pos;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {
            if (ctx->hdr_pos == 0) {
                /*
                 * Phase 29 pipelining backpressure: if pipeline_depth
                 * responses are already queued/draining (out_count) OR pwrites
                 * are still in flight (wr_inflight, write pipelining), stop
                 * reading new requests and suspend with state=SENDING.  The write
                 * event re-enters recv once the output queue drains; a write
                 * completion queues its ack (which schedules that write event) and
                 * also nudges the read side.  Bounding out_count + wr_inflight at
                 * ctx->pipeline_depth caps BOTH the in-flight pwrites and the
                 * queued acks, so the out_ring (pipeline_depth slots) can
                 * never overflow.  (Both counters are 0 here for the common serial
                 * read/write case, so this is a no-op there.)
                 */
                if (ctx->out_count + ctx->wr_inflight >= ctx->pipeline_depth) {
                    ctx->state = XRD_ST_SENDING;
                    XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
                    return;
                }

                /*
                 * Top of a fresh request with the queue empty — the previous
                 * response is fully sent, so no chain references the scratch
                 * buffers.
                 *
                 * Phase 31: trim any scratch a prior large read/pgwrite grew
                 * back to the streaming window so an idle session does not pin
                 * request-max heap.  Gated on out_count==0 so a pipelined read
                 * still in flight (whose sendfile chain is file-backed, not
                 * scratch-backed) is never disturbed.  The scratch buffers are
                 * RAW heap (ngx_alloc/ngx_free, see src/aio/buffers.c), which
                 * makes the trim safe.
                 */
                if (ctx->out_count == 0 && ctx->wr_inflight == 0) {
                    xrootd_trim_scratch(ctx, c);

                    /* Phase 31 W4: reconcile this connection's transfer-heap
                     * footprint with the SHM-global budget after the trim. */
                    xrootd_budget_sync(ctx);

                    /*
                     * Fast teardown: the worker is draining and this connection
                     * is quiescent at a fresh request boundary (no queued
                     * response, no in-flight pwrite — so teardown is safe).
                     * Close it now rather than parking on the next request; the
                     * client reconnects to the new worker and resumes.  This
                     * also catches a connection that finished its current op
                     * *after* the quit began (which ngx_close_idle_connections,
                     * a one-shot at quit, would have missed).
                     */
                    if (ngx_exiting) {
                        xrootd_on_disconnect(ctx, c);
                        xrootd_close_all_files(ctx);
                        ngx_stream_finalize_session(s, NGX_STREAM_OK);
                        return;
                    }

                    /*
                     * Mark idle so a graceful quit's ngx_close_idle_connections()
                     * drops this parked keepalive connection immediately instead
                     * of leaving it open until the worker finally exits.  Cleared
                     * at the top of this handler the moment we service it again.
                     */
                    c->idle = 1;
                }
            }
            dest = ctx->hdr_buf + ctx->hdr_pos;
            need = XRD_REQUEST_HDR_LEN - ctx->hdr_pos;

        } else {
            dest = ctx->payload + ctx->payload_pos;
            need = ctx->cur_dlen - ctx->payload_pos;
        }

        if (need > 0) {
            rev->available = -1;
            n = c->recv(c, dest, need);

            if (n == NGX_AGAIN) {
                ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                              "xrootd: recv AGAIN st=%d hdr_pos=%uz avail=%d"
                              " ready=%d active=%d",
                              (int) ctx->state, ctx->hdr_pos,
                              rev->available, (int) rev->ready,
                              (int) rev->active);
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    break;
                }
                /* Phase 39: genuine incompletion — we are suspending to wait for
                 * the rest of this PDU (or the unauth phase to finish).  Arm the
                 * read deadline once; it is idempotent so repeated partial reads
                 * of the same PDU do NOT reset it (the deadline bounds time-to-
                 * complete, defeating a 1-byte-per-readWait slowloris). */
                xrootd_arm_read_deadline(c, ctx);
                XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
                return;
            }

            if (n == NGX_ERROR || n == 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                               "xrootd: client disconnected");
                if (xrootd_defer_teardown_if_writing(ctx, c, NGX_STREAM_OK)) {
                    return;
                }
                xrootd_on_disconnect(ctx, c);
                xrootd_close_all_files(ctx);
                ngx_stream_finalize_session(s, NGX_STREAM_OK);
                return;
            }

            avail = (size_t) n;
            rx_pending += avail;

            if (ctx->state == XRD_ST_HANDSHAKE) {
                ctx->hdr_pos += avail;

                if (ctx->hdr_pos >= 1 && ctx->hdr_buf[0] != 0) {
                    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                                   "xrootd: non-XRootD client (first byte 0x%02xd)"
                                   " closing immediately",
                                   (unsigned) ctx->hdr_buf[0]);
                    break;
                }

            } else if (ctx->state == XRD_ST_REQ_HEADER) {
                ctx->hdr_pos += avail;

            } else {
                ctx->payload_pos += avail;
            }

            if (avail < need) {
                continue;
            }
        }

        /* Phase 39: a full PDU unit (handshake / header / payload) just arrived,
         * so the current read obligation is satisfied — disarm the deadline before
         * any dispatch, which may hand the connection off to AIO/SENDING/UPSTREAM/
         * PROXY/WAITING_*.  Idempotent: a no-op on the healthy pipelined path where
         * the timer was never armed.  This is the single point that guarantees the
         * read timer is never live across a sub-system handoff (the UAF rule). */
        xrootd_disarm_read_deadline(c, ctx);

        if (ctx->state == XRD_ST_HANDSHAKE) {
            rc = xrootd_process_handshake(ctx, c);
            if (rc != NGX_OK) {
                break;
            }
            ctx->state = XRD_ST_REQ_HEADER;
            ctx->hdr_pos = 0;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {
            ClientRequestHdr *hdr = (ClientRequestHdr *) ctx->hdr_buf;
            uint32_t          max_pl;

            /*
             * Decode the fixed 24-byte ClientRequestHdr now sitting in hdr_buf
             * (wire layout, see XProtocol.hh: streamid[2] @0, requestid @2,
             * body[16] @4, dlen @20).  streamid is an opaque client tag echoed
             * verbatim in the reply — copied byte-for-byte, never byte-swapped.
             * requestid and dlen are big-endian on the wire, so ntohs/ntohl them
             * to host order.  cur_body is the raw 16-byte opcode argument block
             * (its meaning is opcode-specific, e.g. fhandle+offset for kXR_read)
             * and is handed to dispatch untouched for the handler to interpret.
             */
            ctx->cur_streamid[0] = hdr->streamid[0];
            ctx->cur_streamid[1] = hdr->streamid[1];
            ctx->cur_reqid = ntohs(hdr->requestid);
            ngx_memcpy(ctx->cur_body, hdr->body, 16);
            ctx->cur_dlen = (uint32_t) ntohl(hdr->dlen);
            XROOTD_SRV_METRIC_INC(ctx, request_frames_total);
            XROOTD_SRV_METRIC_ADD(ctx, request_payload_bytes_total,
                                  ctx->cur_dlen);

            ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                          "xrootd: req sid=[%02xd%02xd] reqid=%04xd dlen=%uz"
                          " avail=%d ready=%d",
                          (int) ctx->cur_streamid[0],
                          (int) ctx->cur_streamid[1],
                          (int) ctx->cur_reqid, (size_t) ctx->cur_dlen,
                          c->read->available, (int) c->read->ready);

            /* dlen is untrusted client input — reject before any allocation. */
            max_pl = xrootd_max_payload_for_request(ctx->cur_reqid);
            if (ctx->cur_dlen > max_pl) {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "xrootd: payload too large (%uz), closing",
                              (size_t) ctx->cur_dlen);
                XROOTD_SRV_METRIC_INC(ctx, oversized_payloads_total);
                break;
            }

            if (ctx->cur_dlen > 0) {
                if (xrootd_ensure_payload_buffer(ctx, c, ctx->cur_dlen)
                    != NGX_OK)
                {
                    break;
                }
                ctx->payload_pos = 0;
                ctx->state = XRD_ST_REQ_PAYLOAD;
                ctx->hdr_pos = 0;
                continue;
            }

            ctx->payload = NULL;

            /*
             * Phase 29 drain barrier (extended for write pipelining): kXR_read
             * and kXR_write both pipeline.  Any other opcode arriving while reads
             * or writes are still in flight must run with the connection quiescent
             * (e.g. a kXR_close could free a handle an in-flight sendfile chain or
             * pwrite still references).  Defer it until both out_count and
             * wr_inflight drain; the recv loop re-dispatches it then.
             */
            if ((ctx->out_count > 0 || ctx->wr_inflight > 0)
                && ctx->cur_reqid != kXR_read
                && ctx->cur_reqid != kXR_write)
            {
                ctx->recv_deferred = 1;
                ctx->state = XRD_ST_SENDING;
                XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
                return;
            }

            /*
             * Reset the pipelinable marker before dispatch; only the single-chunk
             * sendfile read builder sets it back to 1.  A read served from the
             * memory/window path (TLS, non-regular) thus stays non-pipelinable
             * (its header/data live in the shared scratch buffers).
             */
            ctx->resp_pipelinable = 0;

            XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
            rx_pending = 0;
            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                break;
            }

            if (ctx->state == XRD_ST_AIO) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    break;
                }
                return;
            }

            /*
             * Phase 29 pipelining: a cleartext sendfile kXR_read parked its
             * response (state SENDING, not a windowed read) and we are below the
             * in-flight cap.  Keep reading so the next read's sendfile span
             * queues behind this one and the link stays full instead of idling
             * while the prior response drains.
             *
             * All four conjuncts must hold.  resp_pipelinable and !rd_win_active
             * are NOT redundant: resp_pipelinable says the builder emitted a
             * single self-contained sendfile span (header in its own slot, safe
             * to queue another behind), while rd_win_active flags a *multi*-window
             * read still streaming chunks out of the shared read_scratch — that
             * one must stay serial because the next window would clobber the
             * buffer mid-send.  out_count < cap is the in-flight backpressure
             * bound.
             */
            if (ctx->state == XRD_ST_SENDING
                && ctx->cur_reqid == kXR_read
                && ctx->resp_pipelinable
                && !ctx->rd_win_active
                && ctx->out_count < ctx->pipeline_depth)
            {
                ctx->state = XRD_ST_REQ_HEADER;
                ctx->hdr_pos = 0;
            }

            if (ctx->state != XRD_ST_SENDING) {
                if (ctx->tls_pending) {
                    xrootd_start_tls(ctx, c, conf);
                    return;
                }

                ctx->state = XRD_ST_REQ_HEADER;
                ctx->hdr_pos = 0;
            }

        } else {
            /*
             * Phase 29 drain barrier (extended for write pipelining): kXR_read
             * and kXR_write both pipeline, so they are NOT deferred.  Every other
             * opcode (close, sync, pgwrite, …) must run with the connection
             * quiescent, so defer it until BOTH the response/ack queue (out_count)
             * and the in-flight pwrites (wr_inflight) have drained — e.g. a
             * kXR_close must not retire a handle a pwrite is still writing.
             */
            if ((ctx->out_count > 0 || ctx->wr_inflight > 0)
                && ctx->cur_reqid != kXR_read
                && ctx->cur_reqid != kXR_write)
            {
                ctx->recv_deferred = 1;
                ctx->state = XRD_ST_SENDING;
                XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
                return;
            }

            ctx->state = XRD_ST_REQ_HEADER;
            ctx->hdr_pos = 0;

            /* Only the single-chunk sendfile read builder re-sets this. */
            ctx->resp_pipelinable = 0;

            XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_rx_total, rx_pending);
            rx_pending = 0;
            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                break;
            }

            if (ctx->state == XRD_ST_AIO) {
                /*
                 * Write pipelining: a plain kXR_write just posted its pwrite to
                 * the thread pool (wr_inflight bumped in xrootd_handle_write).
                 * Instead of suspending until it completes — which would serialize
                 * the next chunk's network receive behind this chunk's disk write
                 * — keep receiving.  The backpressure boundary (out_count +
                 * wr_inflight >= pipeline_depth) caps the depth, and the
                 * completion callback queues the ack asynchronously and nudges the
                 * read side.  Every other AIO op (read, pgwrite, …) still suspends.
                 */
                if (ctx->cur_reqid == kXR_write && ctx->wr_inflight > 0) {
                    ctx->state = XRD_ST_REQ_HEADER;
                    ctx->hdr_pos = 0;
                    continue;
                }
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    break;
                }
                return;
            }

            /*
             * Phase 29 pipelining (payload-bearing kXR_read with a read-ahead
             * list): identical to the dlen==0 read path — keep reading so the
             * next read's sendfile span queues behind this one.
             */
            if (ctx->state == XRD_ST_SENDING
                && ctx->cur_reqid == kXR_read
                && ctx->resp_pipelinable
                && !ctx->rd_win_active
                && ctx->out_count < ctx->pipeline_depth)
            {
                ctx->state = XRD_ST_REQ_HEADER;
                ctx->hdr_pos = 0;
                continue;
            }

            if (ctx->state == XRD_ST_SENDING) {
                return;
            }
        }
    }

    if (xrootd_defer_teardown_if_writing(ctx, c,
                                         NGX_STREAM_INTERNAL_SERVER_ERROR)) {
        return;
    }
    xrootd_on_disconnect(ctx, c);
    xrootd_close_all_files(ctx);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}
