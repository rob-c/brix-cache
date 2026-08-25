#include "core/ngx_brix_module.h"
#include "disconnect.h"
#include "fd_table.h"
#include "tls.h"
#include "budget.h"
#include "deadline.h"
#include "shutdown_hold.h"  /* retain active work across graceful reload */
#include "net/manager/pending.h"
#include "net/manager/loc_cache.h"   /* §2.6: negative entry on fan-out expiry */
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
            /* kYR_select did not arrive in time - tell client to retry.
             * §2.6: a kYR_state fan-out that expired with NO kYR_have proved
             * (within this window) that no probed node holds the path —
             * record a negative location entry so the client's retry answers
             * immediately instead of re-parking.  Only state fan-outs carry a
             * probe path; CMS-parent locates never poison the cache. */
            char probe_path[1024];

            rev->timedout = 0;
            if (brix_pending_take_path(ctx->cms_wait_streamid, ngx_pid,
                                         probe_path, sizeof(probe_path)))
            {
                brix_loc_cache_insert_negative(probe_path);
            }
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
    /* §1.16 admin pause: yield without reading OR re-arming — unread requests
     * back up in the kernel buffer (TCP backpressure) until `cont` / the pause
     * timer clears the flag and posts this read event to resume. In-flight
     * responses keep draining via the write path, untouched. */
    if (ctx->admin_paused) {
        return BRIX_RECV_RETURN;
    }

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
 * Deferred-teardown gate.  brix_defer_teardown_if_writing() parks a close behind
 * an in-flight pwrite/pread by setting ctx->out.finalize_pending (and destroyed);
 * once the last brix_write_aio_done / brix_read_aio_done lands,
 * brix_run_deferred_teardown() frees the pool (and ctx with it).  While that
 * finalize is pending the recv loop MUST NOT read or dispatch another PDU: a
 * pipelined kXR_writev would flatten ctx->files[hidx].fd out of memory the
 * completion is about to free (the writev_try_aio use-after-free).  This is the
 * "recv loop stops" that brix_defer_teardown_if_writing documents but never
 * enforced.  The completion owns the finalize, so this gate only yields — it must
 * NOT finalize here (that would destroy the pool twice).
 *
 * Keyed on finalize_pending, NOT ctx->destroyed: brix_on_disconnect() sets
 * destroyed as its AIO-late-callback guard, and kXR_endsess (session/lifecycle.c)
 * runs that full teardown while deliberately leaving the TCP connection OPEN so
 * the dispatcher can reject further requests on the de-authenticated session.
 * Such a connection has no finalize pending and must flow through normally.
 * Reading the flag is UAF-safe: nginx's own fd==-1 / instance guards never
 * deliver an event to a connection whose pool is already freed.
 *
 * Returns 1 when the gate handled the connection (caller must return), else 0.
 */
static int
brix_recv_teardown_pending_gate(brix_ctx_t *ctx)
{
    return ctx->out.finalize_pending ? 1 : 0;
}

/*
 * One iteration's pre-read gate, run at the top of the recv loop.  Two ordered
 * bails before another PDU is touched: (1) a deferred teardown is parked behind
 * an in-flight AIO completion (finalize_pending) that will free the pool — stop
 * now (see brix_recv_teardown_pending_gate); (2) the Phase-29 drain barrier — a
 * fully-read non-pipelinable request runs once the response/ack queue and
 * in-flight pwrites have drained (recv_deferred).  Returns a brix_recv_step_t the
 * caller acts on; BRIX_RECV_STEP_NEXT means no gate fired — read the next PDU.
 */
static brix_recv_step_t
brix_recv_loop_gate(ngx_stream_session_t *s, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_ctx_t *ctx, ngx_event_t *rev,
    size_t *rx_pending)
{
    brix_recv_step_t step;

    if (ctx->out.finalize_pending) {
        return BRIX_RECV_STEP_RETURN;
    }

    if (!ctx->out.recv_deferred) {
        return BRIX_RECV_STEP_NEXT;
    }

    /* Ran one deferred request: loop again unless it asked to stop the loop. */
    step = brix_recv_run_deferred(s, c, conf, ctx, rev, rx_pending);
    if (step == BRIX_RECV_STEP_RETURN || step == BRIX_RECV_STEP_BREAK) {
        return step;
    }
    return BRIX_RECV_STEP_CONTINUE;
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

    /* Stop before touching a connection whose teardown is parked behind an
     * in-flight AIO completion — the completion frees the pool, so never
     * read/dispatch another PDU on it here. */
    if (brix_recv_teardown_pending_gate(ctx)) {
        return;
    }

    /* A non-header state represents an active protocol obligation (handshake,
     * response drain, AIO, or an upstream/cache handoff).  Keep a retiring
     * worker alive for it even when no file handle has been installed yet. */
    brix_shutdown_hold_sync(c, ctx, ctx->state != XRD_ST_REQ_HEADER);

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

        /* Top-of-loop gate: bail on a parked teardown (finalize_pending — the AIO
         * completion frees the pool, so a pipelined kXR_writev must never flatten
         * ctx->files[hidx].fd out from under it) and run any Phase-29 deferred
         * request.  Keyed on finalize_pending, not ctx->destroyed, so an endsess
         * that de-authenticated but left the socket open still reads (and rejects)
         * the client's next request. */
        step = brix_recv_loop_gate(s, c, conf, ctx, rev, &rx_pending);
        if (step == BRIX_RECV_STEP_RETURN) {
            return;
        }
        if (step == BRIX_RECV_STEP_BREAK) {
            break;
        }
        if (step == BRIX_RECV_STEP_CONTINUE) {
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
        brix_shutdown_hold_sync(c, ctx, ctx->state != XRD_ST_REQ_HEADER);
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
