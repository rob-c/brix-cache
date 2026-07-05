#include "write_helpers.h"
#include "chain_helpers.h"
#include "deadline.h"
#include <ngx_event.h>
#include <ngx_event_posted.h>
#include <ngx_stream.h>

/*
 * brix_tcp_push — flush any TCP_CORK / TCP_NOPUSH batching after a chain
 * send completes.
 *
 * nginx may enable TCP_NOPUSH (Linux: TCP_CORK) before sendfile to batch
 * headers with the first data segment.  This helper clears the cork and
 * optionally enables TCP_NODELAY so that the final partial segment is sent
 * without a 200 ms Nagle delay.
 */
static void
brix_tcp_push(ngx_connection_t *c)
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
 * brix_note_chain_progress — account for bytes just transmitted and
 * update the per-session wire-bytes-sent metric.
 *
 * nginx's c->sent counter may not increment for every send_chain() call
 * (it depends on the filter chain), so we cross-check against the remaining
 * chain size as a fallback.
 *
 * Returns 1 if any bytes were counted (progress was made), 0 otherwise.
 */
static ngx_flag_t
brix_note_chain_progress(brix_ctx_t *ctx, ngx_connection_t *c,
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
            BRIX_SRV_METRIC_ADD(ctx, wire_bytes_tx_total, (size_t) sent);
            *pending -= sent;
            return 1;
        }
    }

    if (out == NULL) {
        return 0;
    }

    after = (off_t) brix_chain_pending_bytes(out);
    if (after < *pending) {
        BRIX_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                              (size_t) (*pending - after));
        *pending = after;
        return 1;
    }

    return 0;
}

/*
 * brix_release_pending_buffer — free an owned backing buffer stored in
 * *buffer_base (set by queue_response_base / queue_response_chain on EAGAIN).
 *
 * Uses brix_release_read_buffer() which handles both malloc'd and
 * pool-borrowed buffers.  Clears *buffer_base to prevent double-free.
 * No-op if *buffer_base is already NULL.
 */
static void
brix_release_pending_buffer(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char **buffer_base)
{
    if (*buffer_base == NULL) {
        return;
    }

    brix_release_read_buffer(ctx, c, *buffer_base);
    *buffer_base = NULL;
}

/* Core response-queue: place a response (memory buf or chain) on the connection's
 * out-ring and kick the writer — the shared backend of the typed helpers below. */
ngx_int_t
brix_queue_response_base(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *buffer, size_t buffer_len, u_char *owned_base)
{
    ssize_t bytes_sent;
    brix_resp_slot_t *slot = &ctx->out.ring[ctx->out.tail];

    BRIX_SRV_METRIC_INC(ctx, response_frames_total);

    /*
     * Write pipelining (async ack): the pipelined kXR_write completion callback
     * sets resp_async while the recv loop may be mid-receiving the next request.
     * Park the ack in the out_ring and arm the write event WITHOUT touching the
     * socket or ctx->state — the ack drains head-first on the write event while
     * recv continues uninterrupted.  out_count + wr_inflight < ctx->out.pipeline_depth
     * is enforced at the recv boundary, so the ring always has a free slot here.
     */
    if (ctx->out.resp_async) {
        slot->wbuf      = buffer;
        slot->wbuf_len  = buffer_len;
        slot->wbuf_pos  = 0;
        slot->wbuf_base = owned_base;
        ctx->out.tail   = (ctx->out.tail + 1) % ctx->out.pipeline_depth;
        ctx->out.count++;
        if (brix_schedule_write_resume(c) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    /*
     * Pipelining (Phase 29): if an earlier slot is still draining to the socket
     * (out_count > 0), we must NOT touch the socket here — response frames cannot
     * interleave on the wire.  Park this response in its tail slot and commit it
     * to the ring; brix_flush_pending() drains slots strictly head-first.
     */
    if (ctx->out.count > 0) {
        slot->wbuf      = buffer;
        slot->wbuf_len  = buffer_len;
        slot->wbuf_pos  = 0;
        slot->wbuf_base = owned_base;
        ctx->out.tail   = (ctx->out.tail + 1) % ctx->out.pipeline_depth;
        ctx->out.count++;
        ctx->state      = XRD_ST_SENDING;
        if (brix_schedule_write_resume(c) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    while (buffer_len > 0) {
        bytes_sent = c->send(c, buffer, buffer_len);
        if (bytes_sent > 0) {
            BRIX_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                                  (size_t) bytes_sent);
            buffer += bytes_sent;
            buffer_len -= (size_t) bytes_sent;
            continue;
        }

        if (bytes_sent == NGX_AGAIN) {
            BRIX_SRV_METRIC_INC(ctx, response_write_stalls_total);
            slot->wbuf      = buffer;
            slot->wbuf_len  = buffer_len;
            slot->wbuf_pos  = 0;
            slot->wbuf_base = owned_base;
            ctx->out.tail   = (ctx->out.tail + 1) % ctx->out.pipeline_depth;
            ctx->out.count++;
            ctx->state      = XRD_ST_SENDING;
            if (brix_schedule_write_resume(c) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_OK;
        }

        BRIX_SRV_METRIC_INC(ctx, response_write_errors_total);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Queue a single in-memory response buffer to the client. */
ngx_int_t
brix_queue_response(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *buffer, size_t buffer_len)
{
    return brix_queue_response_base(ctx, c, buffer, buffer_len, NULL);
}

/* Queue an ngx_chain_t response (e.g. a sendfile chain); owned_base is released
 * when the out-ring slot drains. */
ngx_int_t
brix_queue_response_chain(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_chain_t *chain, u_char *owned_base)
{
    ngx_chain_t *unsent = chain;
    ngx_uint_t  spin_count = 0;
    off_t       pending, sent_before;
    ngx_flag_t  progressed;
    brix_resp_slot_t *slot = &ctx->out.ring[ctx->out.tail];

    BRIX_SRV_METRIC_INC(ctx, response_frames_total);

    /*
     * Pipelining (Phase 29): an earlier slot is still draining — park this whole
     * chain in its tail slot and commit it to the ring without touching the
     * socket (frames must not interleave).  flush_pending drains head-first and
     * will send this chain from the start once it becomes the head slot.
     */
    if (ctx->out.count > 0) {
        slot->wchain         = chain;
        slot->wchain_pending = (off_t) brix_chain_pending_bytes(chain);
        slot->wchain_base    = owned_base;
        ctx->out.tail        = (ctx->out.tail + 1) % ctx->out.pipeline_depth;
        ctx->out.count++;
        ctx->state           = XRD_ST_SENDING;
        if (brix_schedule_write_resume(c) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    pending = (off_t) brix_chain_pending_bytes(unsent);

    for (;;) {
        sent_before = c->sent;
        unsent = c->send_chain(c, unsent, 0);
        if (unsent == NGX_CHAIN_ERROR) {
            BRIX_SRV_METRIC_INC(ctx, response_write_errors_total);
            return NGX_ERROR;
        }

        progressed = brix_note_chain_progress(ctx, c, unsent, sent_before,
                                                &pending);
        if (unsent == NULL) {
            if (pending > 0) {
                BRIX_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                                      (size_t) pending);
            }
            slot->wchain_pending = 0;
            brix_tcp_push(c);
            return NGX_OK;
        }

        if (progressed && ++spin_count < BRIX_SEND_CHAIN_SPIN_MAX) {
            continue;
        }

        BRIX_SRV_METRIC_INC(ctx, response_write_stalls_total);
        slot->wchain = unsent;
        slot->wchain_pending = pending;
        slot->wchain_base = owned_base;
        ctx->out.tail = (ctx->out.tail + 1) % ctx->out.pipeline_depth;
        ctx->out.count++;
        ctx->state = XRD_ST_SENDING;
        if (brix_schedule_write_resume(c) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }
}

/* Flush as much of the connection's pending out-ring to the socket as the kernel
 * accepts; re-arms the write event on a partial flush. */
ngx_int_t
brix_flush_pending(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ssize_t      bytes_sent;
    ngx_chain_t *unsent;

    /*
     * Pipelining (Phase 29): drain slots strictly head-first.  Each iteration
     * fully sends one head slot's response (chain or flat buffer), then advances
     * out_head and decrements out_count so the next-queued response becomes the
     * new head.  A partial send (NGX_AGAIN) on any slot leaves it as the head and
     * returns so the next write event resumes exactly there — frames never
     * interleave on the wire because only the head slot ever touches the socket.
     */
    while (ctx->out.count > 0) {
        brix_resp_slot_t *slot = &ctx->out.ring[ctx->out.head];

        if (slot->wchain != NULL) {
            ngx_uint_t spin_count = 0;
            off_t      pending, sent_before;
            ngx_flag_t progressed;

            pending = slot->wchain_pending;
            if (pending <= 0) {
                pending = (off_t) brix_chain_pending_bytes(slot->wchain);
            }

            for (;;) {
                sent_before = c->sent;
                unsent = c->send_chain(c, slot->wchain, 0);
                if (unsent == NGX_CHAIN_ERROR) {
                    BRIX_SRV_METRIC_INC(ctx, response_write_errors_total);
                    return NGX_ERROR;
                }

                progressed = brix_note_chain_progress(ctx, c, unsent,
                                                        sent_before, &pending);
                if (unsent == NULL) {
                    if (pending > 0) {
                        BRIX_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                                              (size_t) pending);
                    }
                    break;
                }

                slot->wchain = unsent;
                slot->wchain_pending = pending;
                if (progressed && ++spin_count < BRIX_SEND_CHAIN_SPIN_MAX) {
                    continue;
                }

                BRIX_SRV_METRIC_INC(ctx, response_write_stalls_total);
                if (brix_schedule_write_resume(c) != NGX_OK) {
                    return NGX_ERROR;
                }
                return NGX_AGAIN;
            }

            brix_tcp_push(c);
            brix_release_pending_buffer(ctx, c, &slot->wchain_base);
            slot->wchain = NULL;
            slot->wchain_pending = 0;

        } else {
            while (slot->wbuf_pos < slot->wbuf_len) {
                bytes_sent = c->send(c, slot->wbuf + slot->wbuf_pos,
                                     slot->wbuf_len - slot->wbuf_pos);
                if (bytes_sent > 0) {
                    BRIX_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                                          (size_t) bytes_sent);
                    slot->wbuf_pos += (size_t) bytes_sent;
                    continue;
                }

                if (bytes_sent == NGX_AGAIN) {
                    BRIX_SRV_METRIC_INC(ctx, response_write_stalls_total);
                    if (brix_schedule_write_resume(c) != NGX_OK) {
                        return NGX_ERROR;
                    }
                    return NGX_AGAIN;
                }

                BRIX_SRV_METRIC_INC(ctx, response_write_errors_total);
                return NGX_ERROR;
            }

            brix_release_pending_buffer(ctx, c, &slot->wbuf_base);
            slot->wbuf     = NULL;
            slot->wbuf_len = 0;
            slot->wbuf_pos = 0;
        }

        /* Head slot fully drained — retire it and advance to the next. */
        slot->wchain = NULL;
        slot->wchain_pending = 0;
        ctx->out.head = (ctx->out.head + 1) % ctx->out.pipeline_depth;
        ctx->out.count--;
    }

    /* Phase 39: the output queue fully drained (reached only on the NGX_OK exit;
     * the NGX_AGAIN re-park paths above leave the deadline armed/refreshed via
     * brix_schedule_write_resume).  Disarm the response-drain deadline. */
    brix_disarm_send_deadline(c, ctx);

    return NGX_OK;
}
