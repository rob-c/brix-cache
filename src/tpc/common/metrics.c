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
        brix_metric_tpc(brix_tpc_metric_proto(protocol),
                          direction == BRIX_TPC_DIR_PUSH,
                          bytes, BRIX_ERR_NONE);
    } else if (event == BRIX_TPC_METRIC_ERROR) {
        brix_metric_tpc(brix_tpc_metric_proto(protocol),
                          direction == BRIX_TPC_DIR_PUSH,
                          bytes, BRIX_ERR_OTHER);
    }
}
