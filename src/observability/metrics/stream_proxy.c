#include "metrics_internal.h"

/*
 * WHAT: Prometheus HTTP exporter for transparent XRootD proxy metrics — upstream connect/auth/op counters,
 *      per-upstream breakdowns, and path-based mutation statistics.
 * WHY: Proxy mode (nginx → root://backend) needs separate counter families from standalone server to distinguish
 *      client-side vs upstream-side behavior. Connect attempts, auth failures, open/read/write/close counts,
 *      relayed bytes, abandoned handles on disconnect, reconnects after idle drops, path ops (rm/mkdir/rmdir/mv),
 *      and absorbed kXR_wait responses all need observability.
 * HOW: BRIX_EXPORT_PROXY_COUNTER macro generates HELP/TYPE/value lines for each metric family. Iterates server
 *      slots then per-upstream arrays within each slot. Emits two rows per counter — aggregate row (all upstreams
 *      combined) plus individual upstream rows with upstream= label when _um->label[0] is set. Labels are port,
 *      auth, and optionally upstream name — bounded low-cardinality only.
 */

void
brix_export_stream_proxy_metrics(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    ngx_brix_srv_metrics_t *srv;
    ngx_uint_t                i;
    char                      port_str[16];

#define BRIX_EXPORT_PROXY_COUNTER(metric_name, help_text, field_name)       \
    do {                                                                      \
        ngx_uint_t _u;                                                        \
        mw_printf(mw, "# HELP " metric_name " " help_text "\n"             \
                      "# TYPE " metric_name " counter\n");                  \
        for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {                    \
            srv = &shm->servers[i];                                           \
            if (!srv->in_use) { continue; }                                   \
            ngx_snprintf((u_char *) port_str, sizeof(port_str),               \
                         "%ui%Z", srv->port);                                \
            /* Aggregate row (all upstreams combined) */                       \
            mw_printf(mw, metric_name "{port=\"%s\",auth=\"%s\"} %lu\n",    \
                      port_str, srv->auth,                                    \
                      (unsigned long) ngx_atomic_fetch_add(                   \
                          &srv->proxy.field_name, 0));                        \
            /* Per-upstream rows */                                            \
            for (_u = 0; _u < BRIX_PROXY_MAX_UPSTREAMS; _u++) {            \
                ngx_brix_proxy_upstream_metrics_t *_um =                    \
                    &srv->proxy.upstreams[_u];                                \
                if (!_um->label[0]) { continue; }                             \
                mw_printf(mw,                                                 \
                    metric_name                                               \
                    "{port=\"%s\",auth=\"%s\",upstream=\"%s\"} %lu\n",       \
                    port_str, srv->auth, _um->label,                          \
                    (unsigned long) ngx_atomic_fetch_add(&_um->field_name, 0)); \
            }                                                                 \
        }                                                                     \
    } while (0)

    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_upstream_connects_total",
        "Successful upstream TCP (or TLS) connects.",
        upstream_connects_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_upstream_connect_errors_total",
        "Upstream TCP connect or TLS handshake failures.",
        upstream_connect_errors);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_upstream_auth_errors_total",
        "Upstream login or token authentication failures.",
        upstream_auth_errors);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_opens_total",
        "kXR_open requests forwarded to upstream that succeeded.",
        opens_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_open_errors_total",
        "kXR_open requests forwarded to upstream that failed.",
        open_errors);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_reads_total",
        "kXR_read/pgread/readv requests forwarded to upstream.",
        reads_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_read_bytes_total",
        "Bytes relayed from upstream to client via proxy.",
        read_bytes_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_writes_total",
        "kXR_write/pgwrite/writev requests forwarded to upstream.",
        writes_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_write_bytes_total",
        "Bytes forwarded from client to upstream via proxy.",
        write_bytes_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_closes_total",
        "kXR_close requests forwarded to upstream.",
        closes_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_abandoned_handles_total",
        "Upstream file handles freed on client disconnect without an explicit close.",
        abandoned_handles_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_reconnects_total",
        "Upstream reconnect attempts after idle connection drop.",
        reconnects_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_path_ops_total",
        "Path-based mutation operations (rm/mkdir/rmdir/mv/chmod/truncate) that succeeded.",
        path_ops_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_path_op_errors_total",
        "Path-based mutation operations that received an error from upstream.",
        path_op_errors_total);
    BRIX_EXPORT_PROXY_COUNTER(
        "brix_proxy_wait_responses_total",
        "kXR_wait responses from upstream that were absorbed and retried transparently.",
        wait_responses_total);

#undef BRIX_EXPORT_PROXY_COUNTER
}
