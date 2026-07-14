/*
 * cms/server_recv.c — CMS server-side read/write event loop + frame framing.
 *
 * WHAT: The nginx read/write event handlers for an accepted CMS data-server
 * connection.  brix_cms_srv_read accumulates bytes into ctx->inbuf a header
 * then a dlen-sized payload at a time, hands each complete frame to the opcode
 * router (cms_srv_process_frame), and enforces the read/idle deadlines and the
 * per-wakeup fairness cap; brix_cms_srv_write is a write-timeout guard.
 *
 * WHY: This is the framing state machine — the "recv" core of the module.  It
 * was split (Phase-79 file-size split) from the connection teardown/audit
 * (server_recv_lifecycle.c), the pure payload decoders (server_recv_parse.c),
 * and the opcode handlers + dispatch table (server_recv_frame.c) so each
 * concern is a focused, independently reviewable file under the size guideline.
 * The cross-file entry points it calls are declared in server_recv_internal.h.
 *
 * HOW: cms_srv_read_accumulate performs one recv() step and grows in_need from
 * the fixed header to the full frame; cms_srv_dispatch_frame routes a completed
 * frame and re-arms the idle watchdog; brix_cms_srv_read drives both in a loop
 * with a bounded per-wakeup yield.  A handler that closes the connection leaves
 * ctx->c NULL, which every step re-checks.
 */

#include "server.h"
#include "server_recv_internal.h"
#include "observability/metrics/metrics_macros.h"   /* Phase 51 (A1): resilience counters */

/* Read handler */

/* brix_cms_srv_write — CMS server write event handler: a pure timeout guard.
 * All writes are synchronous via send_ping() (driven by the ping timer), so this
 * only closes the connection (brix_cms_srv_close) on a timeout. */

void
brix_cms_srv_write(ngx_event_t *ev)
{
    /* We send synchronously via send_ping; nothing to flush here. */
    ngx_connection_t      *c   = ev->data;
    brix_cms_srv_ctx_t  *ctx = c->data;

    if (ev->timedout) {
        cms_srv_set_end_hint(ctx, BRIX_SESS_END_TIMEOUT);
        brix_cms_srv_close(ctx);
    }
}

/* brix_cms_srv_read — read event handler for connected data-server clients
 * (server-side counterpart to recv.c): accumulate bytes to a complete header, read
 * the dlen payload, and dispatch each frame (LOGIN→register, LOAD/AVAIL→update load,
 * PONG→log, GONE→unregister) via cms_srv_process_frame(); disconnect on
 * timeout/error or a frame over NGX_BRIX_CMS_MAX_FRAME. */

/*
 * cms_srv_read_timeout — the c->read timer fired.  A1: distinguish the
 * LOGIN-handshake deadline from the post-login idle watchdog (both fire the
 * read handler via the same timer), count the right resilience metric, and
 * close the connection.
 */
static void
cms_srv_read_timeout(brix_cms_srv_ctx_t *ctx)
{
    if (ctx->logged_in) {
        BRIX_RESIL_METRIC_INC(cms_idle_closes_total);
    } else {
        BRIX_RESIL_METRIC_INC(cms_login_timeouts_total);
    }
    cms_srv_fail_close(ctx, BRIX_SESS_END_TIMEOUT);
}

/*
 * cms_srv_read_accumulate — one recv() step of the frame accumulator: pull
 * bytes into ctx->inbuf, and once the fixed header is complete extend
 * ctx->in_need to the full frame length (rejecting frames over
 * NGX_BRIX_CMS_MAX_FRAME).  Splitting accumulation from dispatch keeps the
 * framing state machine in one place.  Returns NGX_AGAIN (socket drained),
 * NGX_DONE (progress made, frame still incomplete — call again), NGX_OK (a
 * complete frame sits in ctx->inbuf), or NGX_ERROR (peer EOF / recv error /
 * oversized frame — the connection has been closed).
 */
static ngx_int_t
cms_srv_read_accumulate(brix_cms_srv_ctx_t *ctx, ngx_connection_t *c)
{
    ssize_t   n;
    uint16_t  dlen;

    n = c->recv(c, ctx->inbuf + ctx->in_pos,
                ctx->in_need - ctx->in_pos);

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (n == NGX_ERROR || n == 0) {
        cms_srv_fail_close(ctx, n == 0 ? BRIX_SESS_END_CLIENT
                                       : BRIX_SESS_END_ERROR);
        return NGX_ERROR;
    }

    ctx->in_pos += (size_t) n;

    if (ctx->in_pos < ctx->in_need) {
        return NGX_DONE;
    }

    /* Completed reading the header — extend to full frame if needed. */
    if (ctx->in_need == NGX_BRIX_CMS_HDR_LEN) {
        dlen = ngx_brix_cms_get16(ctx->inbuf + 6);

        if ((size_t) dlen + NGX_BRIX_CMS_HDR_LEN
            > NGX_BRIX_CMS_MAX_FRAME)
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: CMS server: frame too large (%ui) "
                          "from %s", (ngx_uint_t) dlen, ctx->host);
            cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
            return NGX_ERROR;
        }

        ctx->in_need = NGX_BRIX_CMS_HDR_LEN + dlen;
        if (ctx->in_pos < ctx->in_need) {
            return NGX_DONE;
        }
    }

    return NGX_OK;
}

/*
 * cms_srv_dispatch_frame — hand the complete frame in ctx->inbuf to the
 * opcode router, then reset the accumulator for the next header and re-arm
 * the idle watchdog.  WS3: a complete frame proves the node is alive — reset
 * the post-login idle watchdog.  Pre-login the absolute LOGIN deadline armed
 * at accept is deliberately NOT reset here, so a slowloris that completes one
 * frame cannot extend its handshake window.  Returns NGX_ERROR if the frame
 * handler closed the connection (ctx->c is NULL), NGX_OK otherwise.
 */
static ngx_int_t
cms_srv_dispatch_frame(brix_cms_srv_ctx_t *ctx)
{
    u_char    code;
    uint16_t  dlen;

    code = ctx->inbuf[4];
    dlen = ngx_brix_cms_get16(ctx->inbuf + 6);
    cms_srv_process_frame(ctx, code, ngx_brix_cms_get32(ctx->inbuf),
                          ctx->inbuf + NGX_BRIX_CMS_HDR_LEN, dlen);

    /* ctx->c may be NULL if the frame handler closed the connection. */
    if (ctx->c == NULL) {
        return NGX_ERROR;
    }

    ctx->in_pos  = 0;
    ctx->in_need = NGX_BRIX_CMS_HDR_LEN;

    if (ctx->logged_in && ctx->idle_timeout_ms > 0) {
        ngx_add_timer(ctx->c->read, ctx->idle_timeout_ms);
    }

    return NGX_OK;
}

/*
 * cms_srv_read_yield — A2 fairness: after a bounded number of frames, re-arm
 * the read event and resume via a posted read event, so a flooding data node
 * cannot monopolise the event loop.  Closes the connection if the event
 * cannot be re-armed; either way the caller returns.
 */
static void
cms_srv_read_yield(brix_cms_srv_ctx_t *ctx, ngx_connection_t *c)
{
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
        return;
    }
    BRIX_RESIL_METRIC_INC(cms_frame_yields_total);
    ngx_post_event(c->read, &ngx_posted_events);
}

void
brix_cms_srv_read(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    brix_cms_srv_ctx_t  *ctx;
    ngx_int_t              rc;
    ngx_uint_t             processed = 0;

    c   = ev->data;
    ctx = c->data;

    if (ev->timedout) {
        cms_srv_read_timeout(ctx);
        return;
    }

    for ( ;; ) {
        rc = cms_srv_read_accumulate(ctx, c);

        if (rc == NGX_AGAIN) {
            break;
        }
        if (rc == NGX_ERROR) {
            return;
        }
        if (rc == NGX_DONE) {
            continue;
        }

        /* Full frame received — dispatch. */
        if (cms_srv_dispatch_frame(ctx) != NGX_OK) {
            return;
        }

        if (++processed >= NGX_BRIX_CMS_MAX_FRAMES_PER_WAKEUP) {
            cms_srv_read_yield(ctx, c);
            return;
        }
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
    }
}
