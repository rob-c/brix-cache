#include "metrics.h"
#include "observability/metrics/unified.h"

static xrootd_proto_t
xrootd_tpc_metric_proto(ngx_uint_t protocol)
{
    switch (protocol) {
    case XROOTD_TPC_PROTO_WEBDAV:
        return XROOTD_PROTO_WEBDAV;
    case XROOTD_TPC_PROTO_STREAM:
    default:
        return XROOTD_PROTO_STREAM;
    }
}

void
xrootd_tpc_metric_transfer(ngx_uint_t protocol, ngx_uint_t direction,
    ngx_uint_t event, size_t bytes, ngx_log_t *log)
{
    /*
     * Phase 6 promotes this hook to exported counters.  Keeping this as a
     * shared, low-cardinality call site now lets both transports move through
     * one API without changing existing WebDAV metric semantics.
     */
    ngx_log_debug4(NGX_LOG_DEBUG_CORE, log, 0,
                   "xrootd_tpc: metric protocol=%ui direction=%ui "
                   "event=%ui bytes=%uz",
                   protocol, direction, event, bytes);

    if (event == XROOTD_TPC_METRIC_SUCCESS) {
        xrootd_metric_tpc(xrootd_tpc_metric_proto(protocol),
                          direction == XROOTD_TPC_DIR_PUSH,
                          bytes, XROOTD_ERR_NONE);
    } else if (event == XROOTD_TPC_METRIC_ERROR) {
        xrootd_metric_tpc(xrootd_tpc_metric_proto(protocol),
                          direction == XROOTD_TPC_DIR_PUSH,
                          bytes, XROOTD_ERR_OTHER);
    }
}
