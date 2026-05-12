#ifndef XROOTD_CONN_WRITE_HELPERS_H
#define XROOTD_CONN_WRITE_HELPERS_H

#include "../ngx_xrootd_module.h"
#include "event_sched.h"

/*
 * xrootd_queue_response_base — attempt to send buffer immediately; if the
 * kernel socket buffer is full (EAGAIN), park the unsent tail in ctx->wbuf*,
 * transition to XRD_ST_SENDING, arm the write event, and return NGX_OK.
 *
 * owned_base: if non-NULL, this heap buffer is freed (via xrootd_release_read_buffer)
 *   after the send completes or at disconnect.  Pass NULL when the buffer is
 *   pool-allocated or statically owned.
 *
 * Returns NGX_OK (sent or parked), NGX_ERROR on I/O failure.
 */
ngx_int_t xrootd_queue_response_base(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buffer, size_t buffer_len, u_char *owned_base);

/*
 * xrootd_queue_response — convenience wrapper around xrootd_queue_response_base
 * when the buffer has no separately-owned backing allocation (owned_base = NULL).
 */
ngx_int_t xrootd_queue_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buffer, size_t buffer_len);

/*
 * xrootd_queue_response_chain — attempt to drain chain via c->send_chain().
 *
 * Spins up to XROOTD_SEND_CHAIN_SPIN_MAX times while progress is made; parks
 * the remaining chain in ctx->wchain on EAGAIN, transitions to XRD_ST_SENDING.
 *
 * owned_base: optional heap buffer freed when the chain is fully drained.
 *
 * Returns NGX_OK (fully sent or parked), NGX_ERROR on I/O failure.
 */
ngx_int_t xrootd_queue_response_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_chain_t *chain, u_char *owned_base);

/*
 * xrootd_flush_pending — resume draining a previously-parked wbuf or wchain.
 *
 * Called from the write event handler (ngx_stream_xrootd_send) after the
 * kernel signals that the socket send buffer has room again.
 *
 * Returns:
 *   NGX_OK    — all pending data sent; ctx->wbuf/wchain cleared.
 *   NGX_AGAIN — still blocked; write event re-armed; caller should return.
 *   NGX_ERROR — unrecoverable I/O error.
 */
ngx_int_t xrootd_flush_pending(xrootd_ctx_t *ctx, ngx_connection_t *c);

#endif /* XROOTD_CONN_WRITE_HELPERS_H */
