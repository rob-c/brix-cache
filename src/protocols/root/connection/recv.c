#include "core/ngx_brix_module.h"
#include "disconnect.h"
#include "fd_table.h"
#include "tls.h"
#include "budget.h"
#include "deadline.h"
#include "net/manager/pending.h"
#include "fs/xfer/stage_waiter.h"
#include "protocols/root/handoff/handoff.h"
#include "recv_frame.h"

/* File: recv.c — TCP read-event loop and request framing state machine
 * WHAT: The core async recv loop that drives the XRootD protocol lifecycle on
 * each TCP connection.  It frames the 20-byte ClientInitHandShake, the 24-byte
 * ClientRequestHdr, and payload bytes into a deterministic state machine —
 * HANDSHAKE → REQ_HEADER → REQ_PAYLOAD → dispatch, with suspend states for
 * SENDING/AIO/UPSTREAM/TLS.  Security invariant: dlen must pass
 * brix_max_payload_for_request() BEFORE any allocation.
 *
 * WHY: Every XRootD request flows through this framing layer before dispatch, so
 * dispatch always receives a complete, validated request with streamid/reqid/
 * dlen extracted from the wire header.
 *
 * HOW: This file holds only the event-loop skeleton (pre-loop teardown gate,
 * handoff gate, and the for-loop that sequences read → process).  The per-PDU
 * framing phases live in recv_frame.c and return a brix_recv_step_t telling the
 * loop whether to continue / return / break.
 */

/* Pre-loop teardown/deadline gate for the recv handler: handles a graceful-
 * shutdown close (c->close) and the three read-timeout cases (WAITING_CMS,
 * WAITING_FRM, and the steady-state read deadline).  Returns 1 when it has
 * finalized or parked the connection and the caller must return; 0 to proceed
 * into the recv loop.  Every original early-return path maps to `return 1`. */
static int
brix_recv_pre_loop(ngx_stream_session_t *s, ngx_connection_t *c,
    brix_ctx_t *ctx, ngx_event_t *rev)
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
        if (brix_defer_teardown_if_writing(ctx, c, NGX_STREAM_OK)) {
            return 1;
        }
        brix_on_disconnect(ctx, c);
        brix_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return 1;
    }

    if (rev->timedout) {
        if (ctx->state == XRD_ST_WAITING_CMS) {
            /* kYR_select did not arrive in time - tell client to retry. */
            rev->timedout = 0;
            brix_pending_remove(ctx->cms_wait_streamid, ngx_pid);
            ctx->state = XRD_ST_REQ_HEADER;
            brix_send_wait(ctx, c, 5);
            brix_schedule_read_resume(c);
            return 1;
        }
        if (ctx->state == XRD_ST_WAITING_FRM) {
            /* The async recall took longer than stage_ttl — drop the parked
             * waiter and ask the client to retry (it will re-poll residency:
             * a hit if staged, or a fresh park otherwise). */
            rev->timedout = 0;
            brix_stage_waiter_drop_conn(c->fd, c->number);
            ctx->state = XRD_ST_REQ_HEADER;
            brix_send_wait(ctx, c, 5);
            brix_schedule_read_resume(c);
            return 1;
        }
        if (ctx->state == XRD_ST_WAITING_BAQ) {
            /* The backend-async flush took longer than the park deadline (a stuck
             * backend). The mutation is durably journaled and will be replayed at
             * the next flush or at boot, so tear the connection down: the parked
             * waker is dropped by the disconnect funnel (brix_baq_drop_client) and
             * never fires on freed memory. The client sees a transport sever and
             * retries — the replay makes the eventual result idempotent. */
            rev->timedout = 0;
            ctx->deadline.read_armed = 0;
            BRIX_SRV_METRIC_INC(ctx, read_pdu_timeouts_total);
            brix_on_disconnect(ctx, c);
            brix_close_all_files(ctx);
            ngx_stream_finalize_session(s, NGX_STREAM_OK);
            return 1;
        }
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "brix: client connection timed out");
        /* Phase 39: our steady-state read deadline fired — it is the only c->read
         * timer armed outside the WAITING_CMS/FRM states handled above.  Attribute
         * it (pre-auth handshake vs in-flight PDU) and tear down via the single
         * disconnect funnel. */
        ctx->deadline.read_armed = 0;
        if (ctx->login.auth_done) {
            BRIX_SRV_METRIC_INC(ctx, read_pdu_timeouts_total);
        } else {
            BRIX_SRV_METRIC_INC(ctx, handshake_timeouts_total);
        }
        if (brix_defer_teardown_if_writing(ctx, c, NGX_STREAM_OK)) {
            return 1;
        }
        brix_on_disconnect(ctx, c);
        brix_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return 1;
    }


    return 0;
}

/* Result of the recv-loop handoff gate (brix_recv_handoff_state). */
enum {
    BRIX_RECV_PROCEED = 0,  /* not a handoff state — read/parse a PDU */
    BRIX_RECV_RETURN,       /* connection yielded — return from the handler */
    BRIX_RECV_BREAK         /* read-event re-arm failed — break the recv loop */
};

/* Connection-handoff gate at the top of the recv loop: when the connection is
 * currently owned by another subsystem (SENDING / AIO / UPSTREAM / PROXY /
 * WAITING_CMS|FRM / TLS_HANDSHAKE) the recv loop must yield rather than read
 * more bytes.  The four "yield until its event fires" states share one body
 * (re-arm the read event, then return).  Returns BRIX_RECV_RETURN to return
 * from the handler, BRIX_RECV_BREAK to break the loop, or BRIX_RECV_PROCEED
 * when no handoff applies and the caller should read/parse the next PDU. */
static int
brix_recv_handoff_state(brix_ctx_t *ctx, ngx_event_t *rev)
{
    if (ctx->state == XRD_ST_SENDING || ctx->state == XRD_ST_TLS_HANDSHAKE) {
        return BRIX_RECV_RETURN;
    }

    if (ctx->state == XRD_ST_AIO
        || ctx->state == XRD_ST_UPSTREAM
        || ctx->state == XRD_ST_PROXY
        || ctx->state == XRD_ST_WAITING_CMS
        || ctx->state == XRD_ST_WAITING_FRM
        || ctx->state == XRD_ST_WAITING_BAQ)
    {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            return BRIX_RECV_BREAK;
        }
        return BRIX_RECV_RETURN;
    }

    return BRIX_RECV_PROCEED;
}

/*
 * WHAT: the core async recv loop that drives the XRootD protocol lifecycle on
 * each TCP connection.  Called by nginx whenever data is available or a timeout
 * fires.
 *
 * HOW: after the pre-loop teardown/deadline gate, the for-loop repeatedly (1)
 * runs a deferred non-pipelinable request once the queues drain, (2) yields on a
 * handoff state, (3) reads the next PDU chunk, and (4) processes a completed PDU
 * — each phase in recv_frame.c and reporting back a brix_recv_step_t.  The read
 * deadline is disarmed at the single point between read-complete and process, so
 * the timer is never live across a sub-system handoff (the UAF rule).
 */
void
ngx_stream_brix_recv(ngx_event_t *rev)
{
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_brix_srv_conf_t  *conf;
    brix_ctx_t                  *ctx;
    size_t                         rx_pending;

    c = rev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_brix_module);
    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_brix_module);

    /*
     * Fast teardown: we are about to service this connection, so clear the idle
     * marker for the duration of this handler run.  It is re-set at the request
     * boundary (brix_recv_header_prep) whenever we park waiting for the next
     * request, so a graceful quit's ngx_close_idle_connections() can drop a
     * parked keepalive at once instead of holding it until worker exit.
     */
    c->idle = 0;
    if (brix_recv_pre_loop(s, c, ctx, rev)) {
        return;
    }

    rx_pending = 0;

    for (;;) {
        brix_recv_step_t step;

        /* Phase 29 drain barrier: run a fully-read non-pipelinable request once
         * the response/ack queue and in-flight pwrites have drained. */
        if (ctx->out.recv_deferred) {
            step = brix_recv_run_deferred(s, c, conf, ctx, rev, &rx_pending);
            if (step == BRIX_RECV_STEP_RETURN) {
                return;
            }
            if (step == BRIX_RECV_STEP_BREAK) {
                break;
            }
            continue;
        }

        {
            int hr = brix_recv_handoff_state(ctx, rev);
            if (hr == BRIX_RECV_RETURN) {
                return;
            }
            if (hr == BRIX_RECV_BREAK) {
                break;   /* breaks the recv for-loop */
            }
            /* BRIX_RECV_PROCEED: not a handoff state — read/parse a PDU. */
        }

        step = brix_recv_read_frame(s, c, conf, ctx, rev, &rx_pending);
        if (step == BRIX_RECV_STEP_RETURN) {
            return;
        }
        if (step == BRIX_RECV_STEP_BREAK) {
            break;
        }
        if (step == BRIX_RECV_STEP_CONTINUE) {
            continue;
        }

        /* Phase 39: a full PDU unit just arrived, so the read obligation is
         * satisfied — disarm the deadline before any dispatch, which may hand the
         * connection off to AIO/SENDING/UPSTREAM/PROXY/WAITING_*.  Idempotent on
         * the healthy pipelined path where the timer was never armed.  This is
         * the single point guaranteeing the read timer is never live across a
         * sub-system handoff (the UAF rule). */
        brix_disarm_read_deadline(c, ctx);

        step = brix_recv_process_frame(s, c, conf, ctx, rev, &rx_pending);
        if (step == BRIX_RECV_STEP_RETURN) {
            return;
        }
        if (step == BRIX_RECV_STEP_BREAK) {
            break;
        }
        /* BRIX_RECV_STEP_CONTINUE / _NEXT: proceed to the next loop iteration. */
    }

    if (brix_defer_teardown_if_writing(ctx, c,
                                         NGX_STREAM_INTERNAL_SERVER_ERROR)) {
        return;
    }
    brix_on_disconnect(ctx, c);
    brix_close_all_files(ctx);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}
