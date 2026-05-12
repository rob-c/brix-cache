#include "write_helpers.h"
#include "chain_helpers.h"
#include <ngx_event.h>
#include <ngx_event_posted.h>
#include <ngx_stream.h>

/*
 * xrootd_tcp_push — flush any TCP_CORK / TCP_NOPUSH batching after a chain
 * send completes.
 *
 * nginx may enable TCP_NOPUSH (Linux: TCP_CORK) before sendfile to batch
 * headers with the first data segment.  This helper clears the cork and
 * optionally enables TCP_NODELAY so that the final partial segment is sent
 * without a 200 ms Nagle delay.
 */
static void
xrootd_tcp_push(ngx_connection_t *c)
{
    if (c->tcp_nopush != NGX_TCP_NOPUSH_SET) {
        return;
    }

    (void) ngx_tcp_push(c->fd);
    c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;

    if (c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {
        (void) ngx_tcp_nodelay(c);
        c->tcp_nodelay = NGX_TCP_NODELAY_SET;
    }
}

/*
 * xrootd_note_chain_progress — account for bytes just transmitted and
 * update the per-session wire-bytes-sent metric.
 *
 * nginx's c->sent counter may not increment for every send_chain() call
 * (it depends on the filter chain), so we cross-check against the remaining
 * chain size as a fallback.
 *
 * Returns 1 if any bytes were counted (progress was made), 0 otherwise.
 */
static ngx_flag_t
xrootd_note_chain_progress(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_chain_t *out, off_t sent_before, off_t *pending)
{
    off_t sent, after;

    if (*pending <= 0) {
        return 0;
    }

    if (c->sent > sent_before) {
        sent = c->sent - sent_before;
        if (sent > *pending) {
            sent = *pending;
        }
        if (sent > 0) {
            XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_tx_total, (size_t) sent);
            *pending -= sent;
            return 1;
        }
    }

    if (out == NULL) {
        return 0;
    }

    after = (off_t) xrootd_chain_pending_bytes(out);
    if (after < *pending) {
        XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                              (size_t) (*pending - after));
        *pending = after;
        return 1;
    }

    return 0;
}

/*
 * xrootd_release_pending_buffer — free an owned backing buffer stored in
 * *buffer_base (set by queue_response_base / queue_response_chain on EAGAIN).
 *
 * Uses xrootd_release_read_buffer() which handles both malloc'd and
 * pool-borrowed buffers.  Clears *buffer_base to prevent double-free.
 * No-op if *buffer_base is already NULL.
 */
static void
xrootd_release_pending_buffer(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char **buffer_base)
{
    if (*buffer_base == NULL) {
        return;
    }

    xrootd_release_read_buffer(ctx, c, *buffer_base);
    *buffer_base = NULL;
}


ngx_int_t
xrootd_queue_response_base(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buffer, size_t buffer_len, u_char *owned_base)
{
    ssize_t bytes_sent;

    XROOTD_SRV_METRIC_INC(ctx, response_frames_total);

    while (buffer_len > 0) {
        bytes_sent = c->send(c, buffer, buffer_len);
        if (bytes_sent > 0) {
            XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                                  (size_t) bytes_sent);
            buffer += bytes_sent;
            buffer_len -= (size_t) bytes_sent;
            continue;
        }

        if (bytes_sent == NGX_AGAIN) {
            XROOTD_SRV_METRIC_INC(ctx, response_write_stalls_total);
            ctx->wbuf      = buffer;
            ctx->wbuf_len  = buffer_len;
            ctx->wbuf_pos  = 0;
            ctx->wbuf_base = owned_base;
            ctx->state     = XRD_ST_SENDING;
            if (xrootd_schedule_write_resume(c) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_OK;
        }

        XROOTD_SRV_METRIC_INC(ctx, response_write_errors_total);
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
xrootd_queue_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buffer, size_t buffer_len)
{
    return xrootd_queue_response_base(ctx, c, buffer, buffer_len, NULL);
}

ngx_int_t
xrootd_queue_response_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_chain_t *chain, u_char *owned_base)
{
    ngx_chain_t *unsent = chain;
    ngx_uint_t  spin_count = 0;
    off_t       pending, sent_before;
    ngx_flag_t  progressed;

    XROOTD_SRV_METRIC_INC(ctx, response_frames_total);

    pending = (off_t) xrootd_chain_pending_bytes(unsent);

    for (;;) {
        sent_before = c->sent;
        unsent = c->send_chain(c, unsent, 0);
        if (unsent == NGX_CHAIN_ERROR) {
            XROOTD_SRV_METRIC_INC(ctx, response_write_errors_total);
            return NGX_ERROR;
        }

        progressed = xrootd_note_chain_progress(ctx, c, unsent, sent_before,
                                                &pending);
        if (unsent == NULL) {
            if (pending > 0) {
                XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                                      (size_t) pending);
            }
            ctx->wchain_pending = 0;
            xrootd_tcp_push(c);
            return NGX_OK;
        }

        if (progressed && ++spin_count < XROOTD_SEND_CHAIN_SPIN_MAX) {
            continue;
        }

        XROOTD_SRV_METRIC_INC(ctx, response_write_stalls_total);
        ctx->wchain = unsent;
        ctx->wchain_pending = pending;
        ctx->wchain_base = owned_base;
        ctx->state = XRD_ST_SENDING;
        if (xrootd_schedule_write_resume(c) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }
}

ngx_int_t
xrootd_flush_pending(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ssize_t      bytes_sent;
    ngx_chain_t *unsent;

    if (ctx->wchain != NULL) {
        ngx_uint_t spin_count = 0;
        off_t      pending, sent_before;
        ngx_flag_t progressed;

        pending = ctx->wchain_pending;
        if (pending <= 0) {
            pending = (off_t) xrootd_chain_pending_bytes(ctx->wchain);
        }

        for (;;) {
            sent_before = c->sent;
            unsent = c->send_chain(c, ctx->wchain, 0);
            if (unsent == NGX_CHAIN_ERROR) {
                XROOTD_SRV_METRIC_INC(ctx, response_write_errors_total);
                return NGX_ERROR;
            }

            progressed = xrootd_note_chain_progress(ctx, c, unsent, sent_before,
                                                    &pending);
            if (unsent == NULL) {
                if (pending > 0) {
                    XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                                          (size_t) pending);
                }
                break;
            }

            ctx->wchain = unsent;
            ctx->wchain_pending = pending;
            if (progressed && ++spin_count < XROOTD_SEND_CHAIN_SPIN_MAX) {
                continue;
            }

            XROOTD_SRV_METRIC_INC(ctx, response_write_stalls_total);
            if (xrootd_schedule_write_resume(c) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        xrootd_tcp_push(c);
        xrootd_release_pending_buffer(ctx, c, &ctx->wchain_base);
        ctx->wchain = NULL;
        ctx->wchain_pending = 0;
        return NGX_OK;
    }

    while (ctx->wbuf_pos < ctx->wbuf_len) {
        bytes_sent = c->send(c, ctx->wbuf + ctx->wbuf_pos,
                             ctx->wbuf_len - ctx->wbuf_pos);
        if (bytes_sent > 0) {
            XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                                  (size_t) bytes_sent);
            ctx->wbuf_pos += (size_t) bytes_sent;
            continue;
        }

        if (bytes_sent == NGX_AGAIN) {
            XROOTD_SRV_METRIC_INC(ctx, response_write_stalls_total);
            if (xrootd_schedule_write_resume(c) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        XROOTD_SRV_METRIC_INC(ctx, response_write_errors_total);
        return NGX_ERROR;
    }

    xrootd_release_pending_buffer(ctx, c, &ctx->wbuf_base);
    ctx->wbuf     = NULL;
    ctx->wbuf_len = 0;
    ctx->wbuf_pos = 0;
    ctx->wchain   = NULL;
    ctx->wchain_pending = 0;
    return NGX_OK;
}
