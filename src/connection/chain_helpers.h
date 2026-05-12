#ifndef XROOTD_CONN_CHAIN_HELPERS_H
#define XROOTD_CONN_CHAIN_HELPERS_H
#include <stddef.h>
#include <ngx_core.h>
#include <ngx_stream.h>

/*
 * xrootd_chain_pending_bytes — count the total unsent bytes remaining in a
 * buffer chain by summing ngx_buf_size(buf) across all links.
 *
 * Used to track how much data is still queued when c->send_chain() returns
 * EAGAIN, so that the write-stall metric can be updated accurately.
 *
 * Handles NULL chain gracefully (returns 0).
 */
size_t xrootd_chain_pending_bytes(ngx_chain_t *cl);

#endif /* XROOTD_CONN_CHAIN_HELPERS_H */
