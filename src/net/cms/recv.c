/*
 * cms/recv.c — read/framing event loop for the CMS client-side (manager)
 * connection.
 *
 * WHAT: ngx_brix_cms_read_handler is the nginx read event handler for our
 * connection UP to a CMS manager: it accumulates bytes into ctx->inbuf one
 * complete frame at a time (cms_recv_accumulate), hands each frame to the opcode
 * router (ngx_brix_cms_process_frame, in recv_frame.c), enforces the read/idle
 * deadline, and applies the per-wakeup fairness cap.  cms_conn_fail is the
 * shared read-side teardown-and-retry epilogue.
 *
 * WHY: This is the framing state machine — the "recv" core of the manager
 * connection.  It was split (Phase-79 file-size split) from the opcode frame
 * handlers + dispatch table (recv_frame.c) and the Plane-B forwarded-namespace-
 * op executor (recv_forward.c) so each concern is a focused, independently
 * reviewable file under the size guideline.  The cross-file entry point it calls
 * (ngx_brix_cms_process_frame) is declared in recv_internal.h.
 *
 * HOW: cms_recv_accumulate performs recv() steps and grows in_need from the
 * fixed header to the full frame; ngx_brix_cms_read_handler drives it in a loop,
 * dispatches each completed frame, re-arms the silence deadline, and yields the
 * worker after a bounded number of frames.
 */

#include "cms_internal.h"
#include "recv_internal.h"
#include "observability/metrics/metrics_macros.h"   /* Phase 51 (A1): resilience counters */

/* cms_conn_fail — shared manager-connection teardown: record why the session
 * ended, drop the connection, and schedule the reconnect backoff.  The three
 * always travel together on every read-side failure path; callers do their own
 * logging/metrics first (the hint is the only per-site variation). */
static void
cms_conn_fail(ngx_brix_cms_ctx_t *ctx, brix_sess_end_t end_hint)
{
    ngx_brix_cms_set_end_hint(ctx, end_hint);
    ngx_brix_cms_disconnect(ctx);
    ngx_brix_cms_schedule_retry(ctx);
}

/* cms_recv_accumulate — buffer/framing half of the read handler: recv into
 * ctx->inbuf until one complete frame (header + dlen payload) is buffered,
 * growing ctx->in_need from header-size to full-frame-size once the header's
 * dlen is known and rejecting oversized frames.  Returns NGX_OK with a complete
 * frame in ctx->inbuf[0..in_need), NGX_AGAIN when the socket drains first, or
 * NGX_ERROR after tearing the connection down itself (EOF/error/too-large).
 * Splitting accumulation from dispatch keeps each half independently
 * reviewable. */
static ngx_int_t
cms_recv_accumulate(ngx_brix_cms_ctx_t *ctx, ngx_connection_t *c,
    ngx_event_t *ev)
{
    ssize_t   n;
    uint16_t  dlen;

    for ( ;; ) {
        n = c->recv(c, ctx->inbuf + ctx->in_pos,
                    ctx->in_need - ctx->in_pos);

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                           "brix: CMS recv EOF/error, disconnecting");
            cms_conn_fail(ctx, n == 0 ? BRIX_SESS_END_SERVER
                                      : BRIX_SESS_END_ERROR);
            return NGX_ERROR;
        }

        ctx->in_pos += (size_t) n;

        if (ctx->in_pos < ctx->in_need) {
            continue;
        }

        if (ctx->in_need == NGX_BRIX_CMS_HDR_LEN) {
            dlen = ngx_brix_cms_get16(ctx->inbuf + 6);

            if ((size_t) dlen + NGX_BRIX_CMS_HDR_LEN
                > NGX_BRIX_CMS_MAX_FRAME)
            {
                ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                              "brix: CMS frame too large: %ui",
                              (ngx_uint_t) dlen);
                cms_conn_fail(ctx, BRIX_SESS_END_ERROR);
                return NGX_ERROR;
            }

            ctx->in_need = NGX_BRIX_CMS_HDR_LEN + dlen;
            if (ctx->in_pos < ctx->in_need) {
                continue;
            }
        }

        return NGX_OK;
    }
}

/* ngx_brix_cms_read_handler — read event handler for the manager connection:
 * accumulate bytes to a complete frame via cms_recv_accumulate() and dispatch
 * each frame via ngx_brix_cms_process_frame(); disconnect and retry on
 * timeout/error. */

void
ngx_brix_cms_read_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_brix_cms_ctx_t  *ctx;
    ngx_int_t              rc;
    ngx_uint_t             processed = 0;

    c = ev->data;
    ctx = c->data;

    if (ctx == NULL || ctx->connection != c) {
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "brix: CMS read handler timedout=%d in_pos=%uz in_need=%uz",
                   (int) ev->timedout, ctx->in_pos, ctx->in_need);

    if (ev->timedout) {
        /*
         * WS1: the manager went silent past cms_read_timeout (black-holed /
         * half-open).  Tear down and reconnect with backoff so we fail over
         * instead of heartbeating into a dead socket forever.
         */
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "brix: CMS manager silent past read timeout — "
                      "reconnecting");
        BRIX_RESIL_METRIC_INC(cms_read_timeouts_total);
        cms_conn_fail(ctx, BRIX_SESS_END_TIMEOUT);
        return;
    }

    for ( ;; ) {
        rc = cms_recv_accumulate(ctx, c, ev);
        if (rc == NGX_AGAIN) {
            break;
        }
        if (rc != NGX_OK) {
            return;   /* accumulate already tore the connection down */
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "brix: CMS process_frame code=%ui",
                       (ngx_uint_t) ctx->inbuf[4]);

        if (ngx_brix_cms_process_frame(ctx) != NGX_OK) {
            cms_conn_fail(ctx, BRIX_SESS_END_ERROR);
            return;
        }

        ctx->in_pos = 0;
        ctx->in_need = NGX_BRIX_CMS_HDR_LEN;

        /* WS1: a frame from the manager proves it is alive — reset the silence
         * deadline so a responsive manager is never reconnected. */
        ngx_brix_cms_arm_read_deadline(ctx);

        /* A2: fairness — after a bounded number of frames, yield the worker to
         * other connections and resume via a posted read event, so a flooding
         * manager cannot monopolise the event loop. */
        if (++processed >= NGX_BRIX_CMS_MAX_FRAMES_PER_WAKEUP) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                cms_conn_fail(ctx, BRIX_SESS_END_ERROR);
                return;
            }
            BRIX_RESIL_METRIC_INC(cms_frame_yields_total);
            ngx_post_event(c->read, &ngx_posted_events);
            return;
        }
    }

    if (ctx->connection != NULL
        && ngx_handle_read_event(c->read, 0) != NGX_OK)
    {
        cms_conn_fail(ctx, BRIX_SESS_END_ERROR);
    }
}
