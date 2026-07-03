/*
 * deadline.h — Phase 39 network-fault resilience: steady-state per-connection
 * read / send deadlines for the root:// stream plane.
 *
 * WHAT: small, idempotent helpers that arm/disarm the client read (c->read) and
 *   write (c->write) timers used to shed slowloris / silently-stalled / half-open
 *   peers.  Every helper is a no-op unless the operator enabled the matching
 *   directive (brix_handshake_timeout / brix_read_timeout / brix_send_timeout),
 *   whose merged value is cached on ctx at accept (src/connection/handler.c).
 *
 * WHY: official XRootD arms no steady-state deadline — a 1-byte-per-readWait
 *   trickle, a half-open peer, or a silent mid-PDU stall is never timed out, so it
 *   pins ctx + scratch heap + fds + budget + a concurrency slot indefinitely.
 *   These deadlines bound that, and so exceed official's behaviour under loss.
 *
 * HOW: read_deadline_armed / send_deadline_armed track OUR ownership of the timer,
 *   so arm/disarm are idempotent.  The read deadline is armed ONLY at a genuine
 *   incompletion (the recv loop's NGX_AGAIN suspend) and disarmed at the
 *   PDU-complete boundary; under healthy back-to-back pipelined reads (which never
 *   block mid-PDU) it is never armed, so the Phase-29 keep-reading branches never
 *   touch the worker timer rbtree.  Because the recv loop always disarms at the
 *   PDU-complete boundary — which precedes every dispatch/sub-system handoff — the
 *   read timer is provably never armed while in XRD_ST_AIO/SENDING/UPSTREAM/PROXY/
 *   WAITING_*, so rev->timedout can never fire and finalize the session while an
 *   in-flight AIO task still references ctx (the documented UAF hazard).
 */
#ifndef NGX_BRIX_CONNECTION_DEADLINE_H
#define NGX_BRIX_CONNECTION_DEADLINE_H

#include <ngx_core.h>
#include <ngx_event.h>
#include "core/types/context.h"
#include "core/types/state.h"

/*
 * Arm c->read's deadline for an in-progress obligation, if we have not already
 * armed it and the relevant deadline is enabled.
 *   - Pre-auth: bound the WHOLE unauthenticated phase (handshake_timeout_ms) — any
 *     wait while unauthenticated is suspicious, so an unauthenticated stall cannot
 *     squat a connection slot.
 *   - Authed: bound only an IN-PROGRESS partial PDU (read_timeout_ms).  An idle
 *     keepalive connection sitting at a fresh request boundary (REQ_HEADER,
 *     hdr_pos == 0) is deliberately left alone so long-lived xrdcp sessions that
 *     pause between operations are not killed.
 * Idempotent: a no-op when already armed, so it never resets the deadline on each
 * partial byte (the slowloris-resistant property — the deadline measures time to
 * COMPLETE the PDU, not time since the last byte).
 */
static ngx_inline void
brix_arm_read_deadline(ngx_connection_t *c, brix_ctx_t *ctx)
{
    ngx_msec_t t;

    if (ctx->read_deadline_armed) {
        return;
    }

    if (ctx->auth_done) {
        if (ctx->state == XRD_ST_REQ_HEADER && ctx->hdr_pos == 0) {
            return;  /* idle between requests — allow keepalive */
        }
        t = ctx->read_timeout_ms;
    } else {
        t = ctx->handshake_timeout_ms;
    }

    if (t == 0) {
        return;  /* deadline disabled */
    }

    ngx_add_timer(c->read, t);
    ctx->read_deadline_armed = 1;
}

/* Disarm the read deadline we armed (idempotent; never touches a timer we did not
 * arm — e.g. the CMS/FRM WAITING timers that share c->read). */
static ngx_inline void
brix_disarm_read_deadline(ngx_connection_t *c, brix_ctx_t *ctx)
{
    if (!ctx->read_deadline_armed) {
        return;
    }
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    ctx->read_deadline_armed = 0;
}

/*
 * Arm / refresh c->write's response-drain deadline.  Called from
 * brix_schedule_write_resume on every park and re-park — i.e. once per write
 * event that still has queued data to drain — so the deadline RESETS on each
 * drain-progress opportunity (an EPOLLOUT means the socket accepted more bytes).
 * It therefore fires only after send_timeout_ms with NO progress at all (a stuck /
 * half-open consumer that has stopped reading), and never false-fires on a
 * legitimate slow-but-steady large/pipelined transfer.  Reset frequency is
 * per-write-event (per socket-buffer refill), never per-byte or per-slot, so the
 * bulk-throughput drain takes one cheap rbtree reposition per refill cycle.
 * Disarmed by brix_disarm_send_deadline when the output queue fully drains.
 * Bounds a slow / half-open consumer that would otherwise pin the parked out_ring
 * slots + the read_scratch windows they reference forever.
 */
static ngx_inline void
brix_arm_send_deadline(ngx_connection_t *c, brix_ctx_t *ctx)
{
    if (ctx->send_timeout_ms == 0) {
        return;  /* deadline disabled */
    }
    ngx_add_timer(c->write, ctx->send_timeout_ms);
    ctx->send_deadline_armed = 1;
}

static ngx_inline void
brix_disarm_send_deadline(ngx_connection_t *c, brix_ctx_t *ctx)
{
    if (!ctx->send_deadline_armed) {
        return;
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    ctx->send_deadline_armed = 0;
}

#endif /* NGX_BRIX_CONNECTION_DEADLINE_H */
