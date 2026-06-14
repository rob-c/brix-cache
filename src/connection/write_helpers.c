/* ---- File: write_helpers.c — response buffer flush helpers for async write cycles ----
 *
 * WHAT: This file implements helper functions for flushing response buffers to the client socket during async write cycles. Includes TCP_CORK clearing, chain progress accounting with metric updates, pending buffer cleanup on EAGAIN completion, and two-phase queue/flush pattern for both base-buffer and chain-based responses.
 *
 * WHY: nginx's send_chain() returns NGX_AGAIN when the kernel socket buffer is full — these helpers manage the partial-send lifecycle: storing unsent state in ctx write fields, spinning briefly to drain any remaining capacity, then scheduling write resume via event re-arming. Consistency invariant: all chain helpers use xrootd_chain_pending_bytes() for uniform flush thresholds.
 *
 * HOW: Queue functions (queue_response_base/chain) attempt immediate send; on NGX_AGAIN store unsent state and schedule_write_resume(). Flush pending resumes stalled writes with spin loop, then releases buffers and clears ctx write state. Caller: dispatch path → queue response → send.c drains chain via flush_pending.
 */
/* ------------------------------------------------------------------ */
/* Section: TCP Batch Control                                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_tcp_push() clears any TCP_CORK/TCP_NOPUSH batching that nginx may have enabled before sendfile to batch headers with the first data segment — releases cork and optionally enables TCP_NODELAY so the final partial segment is sent without a 200 ms Nagle delay. Called after chain send completion or flush pending when all buffered data has been transmitted. */

/* ---- Function: xrootd_tcp_push() (static) ----
 *
 * WHAT: Clears any TCP_CORK/TCP_NOPUSH batching that nginx may have enabled before sendfile to batch headers with the first data segment — releases cork via ngx_tcp_push(), sets tcp_nopush=UNSET, optionally enables TCP_NODELAY so the final partial segment is sent without a 200 ms Nagle delay. Called after chain send completion or flush pending when all buffered data has been transmitted. */

/* ---- WHY: TCP_CORK batching improves throughput by combining headers with first data segment into single packet — but must be released before sending final partial segments to avoid 200 ms Nagle delay on incomplete transfers. Enabling TCP_NODELAY after cork release ensures immediate delivery of any remaining buffered bytes rather than waiting for next full segment or idle timeout. ---- */
/* ---- HOW: Checks c->tcp_nopush state; if set, calls ngx_tcp_push() to clear cork, sets tcp_nopush=UNSET, optionally enables TCP_NODELAY via ngx_tcp_nodelay() when unset. ---- */

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

/* ------------------------------------------------------------------ */
/* Section: Chain Progress Accounting                                   */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_note_chain_progress() accounts for bytes just transmitted and updates the per-session wire-bytes-sent metric — cross-checks c->sent counter against chain pending bytes as fallback since nginx's c->sent may not increment for every send_chain() call depending on filter chain. Returns 1 if any bytes were counted (progress was made), 0 otherwise used by spin loop to determine whether to continue retrying or stall via schedule_write_resume(). */

/* ---- Function: xrootd_note_chain_progress() (static) ----
 *
 * WHAT: Accounts for bytes just transmitted and updates the per-session wire-bytes-sent metric — cross-checks c->sent counter against chain pending bytes as fallback since nginx's c->sent may not increment for every send_chain() call depending on filter chain. Returns 1 if any bytes were counted (progress was made), 0 otherwise used by spin loop to determine whether to continue retrying or stall via schedule_write_resume(). Updates wire_bytes_tx_total metric with actual transmitted bytes, adjusts pending counter downward accordingly. */

/* ---- WHY: Chain progress accounting ensures accurate byte-level metrics even when nginx's c->sent counter doesn't reliably track send_chain() calls — the fallback using xrootd_chain_pending_bytes() provides a consistent measurement regardless of filter chain behavior. Returns value enables spin loop optimization to continue retrying on partial progress or stall immediately when no bytes transmitted, preventing unnecessary event re-arming cycles. ---- */
/* ---- HOW: Two-phase check → 1) if c->sent > sent_before, compute delta and cap against pending; update metric and decrement pending. 2) fallback: compare xrootd_chain_pending_bytes() before vs after send, compute reduction as transmitted bytes. Returns progress flag for spin loop decision. ---- */

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

/* ------------------------------------------------------------------ */
/* Section: Pending Buffer Cleanup                                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_release_pending_buffer() frees an owned backing buffer stored in *buffer_base (set by queue_response_base / queue_response_chain on EAGAIN) — uses xrootd_release_read_buffer() which handles both malloc'd and pool-borrowed buffers. Clears *buffer_base to prevent double-free after release. No-op if *buffer_base is already NULL called during flush pending when all data has been transmitted successfully. */

/* ---- Function: xrootd_release_pending_buffer() (static) ----
 *
 * WHAT: Frees an owned backing buffer stored in *buffer_base (set by queue_response_base / queue_response_chain on EAGAIN) — uses xrootd_release_read_buffer() which handles both malloc'd and pool-borrowed buffers. Clears *buffer_base to prevent double-free after release. No-op if *buffer_base is already NULL called during flush pending when all data has been transmitted successfully ensuring no memory leaks from partial send scenarios. */

/* ---- WHY: Pending buffer cleanup prevents memory leaks from EAGAIN scenarios where the write loop stalls and stores an owned buffer pointer for later continuation — without proper release during flush pending, these buffers would accumulate indefinitely across multiple connection sessions causing memory exhaustion over time. ---- */
/* ---- HOW: Checks if *buffer_base is non-NULL; calls xrootd_release_read_buffer() which handles both malloc'd and pool-borrowed buffers; sets *buffer_base = NULL. No-op when already NULL during flush pending completion. ---- */

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

/* ---- Function: xrootd_queue_response_base() — send buffer bytes with EAGAIN stall handling ----
 *
 * WHAT: Attempts to send a raw buffer to the client socket in a spin loop. On full success (all bytes sent): returns NGX_OK. On partial send (NGX_AGAIN): stores unsent buffer state in ctx->wbuf fields, sets state=XRD_ST_SENDING, schedules write resume via event re-arming, and returns NGX_OK for caller to continue later. On error: increments response_write_errors_total metric and returns NGX_ERROR.
 *
 * WHY: nginx's c->send() may return NGX_AGAIN when the kernel socket buffer is full — this helper captures the partial-send state so flush_pending can resume later without losing data. The owned_base pointer tracks whether the buffer was malloc'd (needs release) or pool-borrowed (no-op release).
 *
 * HOW: Spin loop → 1) call c->send() with remaining bytes; 2) if bytes_sent > 0, advance cursor and decrement length, continue; 3) if NGX_AGAIN, store ctx write state and schedule_write_resume(); 4) if error, return NGX_ERROR. Returns only on full drain or stall.
 */
ngx_int_t
xrootd_queue_response_base(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buffer, size_t buffer_len, u_char *owned_base)
{
    ssize_t bytes_sent;
    xrootd_resp_slot_t *slot = &ctx->out_ring[ctx->out_tail];

    XROOTD_SRV_METRIC_INC(ctx, response_frames_total);

    /*
     * Pipelining (Phase 29): if an earlier slot is still draining to the socket
     * (out_count > 0), we must NOT touch the socket here — response frames cannot
     * interleave on the wire.  Park this response in its tail slot and commit it
     * to the ring; xrootd_flush_pending() drains slots strictly head-first.
     */
    if (ctx->out_count > 0) {
        slot->wbuf      = buffer;
        slot->wbuf_len  = buffer_len;
        slot->wbuf_pos  = 0;
        slot->wbuf_base = owned_base;
        ctx->out_tail   = (ctx->out_tail + 1) % XROOTD_PIPELINE_MAX;
        ctx->out_count++;
        ctx->state      = XRD_ST_SENDING;
        if (xrootd_schedule_write_resume(c) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

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
            slot->wbuf      = buffer;
            slot->wbuf_len  = buffer_len;
            slot->wbuf_pos  = 0;
            slot->wbuf_base = owned_base;
            ctx->out_tail   = (ctx->out_tail + 1) % XROOTD_PIPELINE_MAX;
            ctx->out_count++;
            ctx->state      = XRD_ST_SENDING;
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

/* ---- Function: xrootd_queue_response() — convenience wrapper for single-buffer response ----
 *
 * WHAT: Thin wrapper around xrootd_queue_response_base() that passes NULL as owned_base (indicating pool-borrowed buffer, no release needed). Delegates all send/stall logic to queue_response_base.
 *
 * WHY: Most callers pass pool-allocated buffers that nginx will free automatically — this wrapper avoids requiring callers to track an owned_base pointer for simple single-buffer responses.
 *
 * HOW: Calls xrootd_queue_response_base(ctx, c, buffer, buffer_len, NULL).
 */
ngx_int_t
xrootd_queue_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buffer, size_t buffer_len)
{
    return xrootd_queue_response_base(ctx, c, buffer, buffer_len, NULL);
}

/* ---- Function: xrootd_queue_response_chain() — send ngx_chain_t with spin+stall handling ----
 *
 * WHAT: Attempts to send a response chain via c->send_chain() in a spin loop. On full success (chain fully drained): updates wire_bytes_tx_total metric, calls xrootd_tcp_push(), returns NGX_OK. On partial progress within XROOTD_SEND_CHAIN_SPIN_MAX iterations: continues spinning. On stall (no further progress or spin exhausted): stores unsent chain state in ctx->wchain fields, sets state=XRD_ST_SENDING, schedules write resume via event re-arming, and returns NGX_OK for caller to continue later.
 *
 * WHY: send_chain() may partially drain a large response — this helper implements the two-phase pattern (spin briefly then stall) that prevents unnecessary event re-arming cycles while ensuring stalled chains are resumed promptly. Uses xrootd_note_chain_progress() for accurate byte accounting regardless of filter chain behavior.
 *
 * HOW: 1) compute initial pending via xrootd_chain_pending_bytes(); 2) spin loop calling send_chain + note_chain_progress; 3) if unsent==NULL, complete and tcp_push; 4) if progressed within spin limit, continue; 5) else store ctx write state and schedule_write_resume().
 */
ngx_int_t
xrootd_queue_response_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_chain_t *chain, u_char *owned_base)
{
    ngx_chain_t *unsent = chain;
    ngx_uint_t  spin_count = 0;
    off_t       pending, sent_before;
    ngx_flag_t  progressed;
    xrootd_resp_slot_t *slot = &ctx->out_ring[ctx->out_tail];

    XROOTD_SRV_METRIC_INC(ctx, response_frames_total);

    /*
     * Pipelining (Phase 29): an earlier slot is still draining — park this whole
     * chain in its tail slot and commit it to the ring without touching the
     * socket (frames must not interleave).  flush_pending drains head-first and
     * will send this chain from the start once it becomes the head slot.
     */
    if (ctx->out_count > 0) {
        slot->wchain         = chain;
        slot->wchain_pending = (off_t) xrootd_chain_pending_bytes(chain);
        slot->wchain_base    = owned_base;
        ctx->out_tail        = (ctx->out_tail + 1) % XROOTD_PIPELINE_MAX;
        ctx->out_count++;
        ctx->state           = XRD_ST_SENDING;
        if (xrootd_schedule_write_resume(c) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

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
            slot->wchain_pending = 0;
            xrootd_tcp_push(c);
            return NGX_OK;
        }

        if (progressed && ++spin_count < XROOTD_SEND_CHAIN_SPIN_MAX) {
            continue;
        }

        XROOTD_SRV_METRIC_INC(ctx, response_write_stalls_total);
        slot->wchain = unsent;
        slot->wchain_pending = pending;
        slot->wchain_base = owned_base;
        ctx->out_tail = (ctx->out_tail + 1) % XROOTD_PIPELINE_MAX;
        ctx->out_count++;
        ctx->state = XRD_ST_SENDING;
        if (xrootd_schedule_write_resume(c) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }
}

/* ---- Function: xrootd_flush_pending() — resume stalled write and complete pending data ----
 *
 * WHAT: Resumes a previously-stalled write (from queue_response_base or queue_response_chain) by draining remaining buffered data. Handles two phases: chain flush (ctx->wchain) then buffer flush (ctx->wbuf). On full completion: updates metrics, calls xrootd_tcp_push(), releases pending buffers via xrootd_release_pending_buffer(), clears all ctx write state fields, returns NGX_OK.
 *
 * WHY: After queue functions store stalled state and schedule_write_resume(), this helper is called by the write event handler to resume draining. Must handle both chain and buffer write states since they may be interleaved across multiple requests on the same connection. Releases owned buffers to prevent memory leaks from repeated EAGAIN scenarios.
 *
 * HOW: Two-phase drain → 1) if ctx->wchain non-NULL, spin loop via send_chain + note_chain_progress until drained or stalled; on complete tcp_push and release chain buffer; 2) while ctx->wbuf_pos < wbuf_len, call c->send() in loop; on stall schedule_write_resume(); on complete release buffer. Clears all write state fields (wchain, wchain_pending, wchain_base, wbuf, wbuf_len, wbuf_pos).
 */
ngx_int_t
xrootd_flush_pending(xrootd_ctx_t *ctx, ngx_connection_t *c)
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
    while (ctx->out_count > 0) {
        xrootd_resp_slot_t *slot = &ctx->out_ring[ctx->out_head];

        if (slot->wchain != NULL) {
            ngx_uint_t spin_count = 0;
            off_t      pending, sent_before;
            ngx_flag_t progressed;

            pending = slot->wchain_pending;
            if (pending <= 0) {
                pending = (off_t) xrootd_chain_pending_bytes(slot->wchain);
            }

            for (;;) {
                sent_before = c->sent;
                unsent = c->send_chain(c, slot->wchain, 0);
                if (unsent == NGX_CHAIN_ERROR) {
                    XROOTD_SRV_METRIC_INC(ctx, response_write_errors_total);
                    return NGX_ERROR;
                }

                progressed = xrootd_note_chain_progress(ctx, c, unsent,
                                                        sent_before, &pending);
                if (unsent == NULL) {
                    if (pending > 0) {
                        XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                                              (size_t) pending);
                    }
                    break;
                }

                slot->wchain = unsent;
                slot->wchain_pending = pending;
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
            xrootd_release_pending_buffer(ctx, c, &slot->wchain_base);
            slot->wchain = NULL;
            slot->wchain_pending = 0;

        } else {
            while (slot->wbuf_pos < slot->wbuf_len) {
                bytes_sent = c->send(c, slot->wbuf + slot->wbuf_pos,
                                     slot->wbuf_len - slot->wbuf_pos);
                if (bytes_sent > 0) {
                    XROOTD_SRV_METRIC_ADD(ctx, wire_bytes_tx_total,
                                          (size_t) bytes_sent);
                    slot->wbuf_pos += (size_t) bytes_sent;
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

            xrootd_release_pending_buffer(ctx, c, &slot->wbuf_base);
            slot->wbuf     = NULL;
            slot->wbuf_len = 0;
            slot->wbuf_pos = 0;
        }

        /* Head slot fully drained — retire it and advance to the next. */
        slot->wchain = NULL;
        slot->wchain_pending = 0;
        ctx->out_head = (ctx->out_head + 1) % XROOTD_PIPELINE_MAX;
        ctx->out_count--;
    }

    return NGX_OK;
}
