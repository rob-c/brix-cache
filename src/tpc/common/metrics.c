#include "metrics.h"
#include "observability/metrics/unified.h"

static brix_proto_t
brix_tpc_metric_proto(ngx_uint_t protocol)
{
    switch (protocol) {
    case BRIX_TPC_PROTO_WEBDAV:
        return BRIX_PROTO_WEBDAV;
    case BRIX_TPC_PROTO_STREAM:
    default:
        return BRIX_PROTO_ROOT;
    }
}

/*
 * brix_tpc_metric_book — the ONE place a terminal TPC outcome reaches the
 * unified counters.
 *
 * WHAT: Books the transfer twice over, into two families that answer different
 *       questions: brix_tpc_transfers_total/_bytes_total (TPC-specific, carries
 *       the pull/push direction) and brix_io_ops_total{op="tpc"} (the unified
 *       per-op ledger, so a TPC shows up alongside every other operation the
 *       server performed).
 * WHY:  `op="tpc"` was a declared-but-unreachable slot: the WebDAV op mapping
 *       named it for COPY, but the protocol-level op_done is deliberately
 *       restricted to the data plane (READ/WRITE) to avoid double-booking the
 *       VFS-observed namespace ops, so nothing ever incremented it. Booking it
 *       here — the single call site both transports already funnel through —
 *       gives the row exactly one owner (see the owner table in
 *       docs/08-metrics-monitoring/metrics-bug-patterns.md, Pattern 6).
 * HOW:  Count-only for the unified row: a TPC has no request-scoped duration
 *       to file (see brix_metric_op_count).
 */
static void
brix_tpc_metric_book(ngx_uint_t protocol, ngx_uint_t direction, size_t bytes,
    brix_err_class_t err)
{
    brix_proto_t proto = brix_tpc_metric_proto(protocol);

    brix_metric_tpc(proto, direction == BRIX_TPC_DIR_PUSH, bytes, err);
    brix_metric_op_count(proto, BRIX_METRIC_OP_TPC, err);
}

void
brix_tpc_metric_transfer(ngx_uint_t protocol, ngx_uint_t direction,
    ngx_uint_t event, size_t bytes, ngx_log_t *log)
{
    /*
     * Phase 6 promotes this hook to exported counters.  Keeping this as a
     * shared, low-cardinality call site now lets both transports move through
     * one API without changing existing WebDAV metric semantics.
     */
    ngx_log_debug4(NGX_LOG_DEBUG_CORE, log, 0,
                   "brix_tpc: metric protocol=%ui direction=%ui "
                   "event=%ui bytes=%uz",
                   protocol, direction, event, bytes);

    if (event == BRIX_TPC_METRIC_SUCCESS) {
        brix_tpc_metric_book(protocol, direction, bytes, BRIX_ERR_NONE);
    } else if (event == BRIX_TPC_METRIC_ERROR) {
        brix_tpc_metric_book(protocol, direction, bytes, BRIX_ERR_OTHER);
    }
}
