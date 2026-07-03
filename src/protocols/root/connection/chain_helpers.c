/*
 *
 * WHAT: Summation helper that iterates all ngx_chain_t nodes and accumulates buf sizes via ngx_buf_size(). Returns the total pending byte count for a buffered data chain. NULL nodes are skipped during iteration to prevent crashes on malformed chains. Used by send/write helpers (connection/send.c, connection/write_helpers.c) to determine whether to flush a partial write or continue accumulating before sending over TCP/TLS connection.
 *
 * WHY: Chain buffer accumulation determines write strategy — small amounts may be buffered until reaching threshold for efficient single-send; large amounts need immediate flushing to prevent memory pressure and connection stalls. This helper provides the byte count metric needed by send/write decision logic without requiring callers to re-implement the iteration pattern each time. Consistency invariant: all chain helpers must use this same calculation method to ensure uniform flush thresholds across the codebase. Thread safety: reads only immutable data from provided chain — no shared state accessed.
 *
 * HOW: Initializes total=0, then iterates through ngx_chain_t linked list until NULL. For each node checks if buf pointer is non-NULL before calling ngx_buf_size() to accumulate. Returns final accumulated sum. Caller must provide valid ngx_chain_t pointer — NULL input returns 0 without error (defensive design). */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <stddef.h>
#include "core/ngx_brix_module.h"

size_t brix_chain_pending_bytes(ngx_chain_t *cl) {
    size_t total = 0;
    for (; cl != NULL; cl = cl->next) {
        if (cl->buf) {
            total += ngx_buf_size(cl->buf);
        }
    }
    return total;
}
