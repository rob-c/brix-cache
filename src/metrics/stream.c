/*
 * stream.c — Prometheus exporter for native XRootD (stream-layer) counters.
 *
 * WHAT: Maps numeric operation slots to human-readable label strings
 *       (`xrootd_op_names[]`) and iterates the shared-memory metrics zone
 *       to emit Prometheus exposition-format lines for all stream-protocol
 *       counters — connections, bytes, wire frames, request/reject stats,
 *       per-operation ok/error counts, path-depth violations, registry full.
 *
 * WHY: The stream module writes counters into `ngx_xrootd_metrics_t` shared
 *      memory using atomic fields. This file is the HTTP-side exporter that
 *      reads those counters and formats them as Prometheus scrape output.
 *      The op-name mapping is a binary ABI between stream and HTTP modules:
 *      slot indices must stay aligned with `XROOTD_OP_*` constants in metrics.h.
 *
 * HOW: `xrootd_export_prometheus_metrics()` iterates all server slots, reads
 *      each atomic counter via `ngx_atomic_fetch_add(..., 0)` for an
 *      eventually-consistent snapshot, and writes HELP/TYPE/value lines via
 *      the `metrics_writer_t` interface. Uses macro templates to reduce
 *      repetition. Calls protocol-specific exporters (webdav, s3, proxy,
 *      tracking) at the end.
 */

#include "metrics_internal.h"

/*
 * Human-readable operation names exported as the Prometheus `op=` label.
 * Order must stay aligned with the XROOTD_OP_* constants in metrics.h because
 * the stream side records counters by numeric slot, not by string.
 */
static const char *xrootd_op_names[XROOTD_NOPS] = {
    "login",        /* XROOTD_OP_LOGIN        */
    "auth",         /* XROOTD_OP_AUTH         */
    "stat",         /* XROOTD_OP_STAT         */
    "open_rd",      /* XROOTD_OP_OPEN_RD      */
    "open_wr",      /* XROOTD_OP_OPEN_WR      */
    "read",         /* XROOTD_OP_READ         */
    "write",        /* XROOTD_OP_WRITE        */
    "sync",         /* XROOTD_OP_SYNC         */
    "close",        /* XROOTD_OP_CLOSE        */
    "dirlist",      /* XROOTD_OP_DIRLIST      */
    "mkdir",        /* XROOTD_OP_MKDIR        */
    "rmdir",        /* XROOTD_OP_RMDIR        */
    "rm",           /* XROOTD_OP_RM           */
    "mv",           /* XROOTD_OP_MV           */
    "chmod",        /* XROOTD_OP_CHMOD        */
    "truncate",     /* XROOTD_OP_TRUNCATE     */
    "ping",         /* XROOTD_OP_PING         */
    "query_cksum",  /* XROOTD_OP_QUERY_CKSUM  */
    "query_space",  /* XROOTD_OP_QUERY_SPACE  */
    "readv",        /* XROOTD_OP_READV        */
    "pgread",       /* XROOTD_OP_PGREAD       */
    "writev",       /* XROOTD_OP_WRITEV       */
    "locate",       /* XROOTD_OP_LOCATE       */
    "statx",        /* XROOTD_OP_STATX        */
    "fattr",        /* XROOTD_OP_FATTR        */
    "query_stats",  /* XROOTD_OP_QUERY_STATS  */
    "query_xattr",  /* XROOTD_OP_QUERY_XATTR  */
    "query_finfo",  /* XROOTD_OP_QUERY_FINFO  */
    "query_fsinfo", /* XROOTD_OP_QUERY_FSINFO */
    "set",          /* XROOTD_OP_SET          */
    "query_visa",   /* XROOTD_OP_QUERY_VISA   */
    "query_opaque", /* XROOTD_OP_QUERY_OPAQUE */
    "query_opaquf", /* XROOTD_OP_QUERY_OPAQUF */
    "query_opaqug", /* XROOTD_OP_QUERY_OPAQUG */
    "query_ckscan", /* XROOTD_OP_QUERY_CKSCAN */
    "clone",        /* XROOTD_OP_CLONE        */
    "chkpoint",     /* XROOTD_OP_CHKPOINT     */
};

void
xrootd_export_prometheus_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm)
{
    ngx_xrootd_srv_metrics_t *srv;
    ngx_uint_t                i, op;
    char                      port_str[16];

    /*
     * Export is intentionally eventually consistent rather than a single locked
     * snapshot: each counter is read atomically, but different lines may observe
     * slightly different moments in time while workers continue serving traffic.
     */

    mw_printf(mw,
        "# HELP xrootd_connections_total "
            "Total TCP connections accepted since process start.\n"
        "# TYPE xrootd_connections_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_connections_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->connections_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_connections_active "
            "Currently open XRootD connections.\n"
        "# TYPE xrootd_connections_active gauge\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_connections_active{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->connections_active, 0));
    }

    mw_printf(mw,
        "# DEPRECATED: use xrootd_io_bytes_written{proto=\"stream\"} "
            "for protocol-neutral write throughput.\n"
        "# HELP xrootd_bytes_rx_total "
            "Bytes received from clients (write payloads).\n"
        "# TYPE xrootd_bytes_rx_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_bytes_rx_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_rx_total, 0));
    }

    mw_printf(mw,
        "# DEPRECATED: use xrootd_io_bytes_read{proto=\"stream\"} "
            "for protocol-neutral read throughput.\n"
        "# HELP xrootd_bytes_tx_total "
            "Bytes sent to clients (read data).\n"
        "# TYPE xrootd_bytes_tx_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_bytes_tx_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_tx_total, 0));
    }

    /* Per-protocol byte counters — native XRootD stream-layer data only. */
    mw_printf(mw,
        "# DEPRECATED: use xrootd_io_bytes_written{proto=\"stream\"} "
            "for protocol-neutral write throughput.\n"
        "# HELP xrootd_bytes_root_rx_total "
            "Bytes received from clients via the native XRootD root:// protocol.\n"
        "# TYPE xrootd_bytes_root_rx_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_bytes_root_rx_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->proto_root_bytes_rx_total, 0));
    }

    mw_printf(mw,
        "# DEPRECATED: use xrootd_io_bytes_read{proto=\"stream\"} "
            "for protocol-neutral read throughput.\n"
        "# HELP xrootd_bytes_root_tx_total "
            "Bytes sent to clients via the native XRootD root:// protocol.\n"
        "# TYPE xrootd_bytes_root_tx_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_bytes_root_tx_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->proto_root_bytes_tx_total, 0));
    }

    /* Per-IP-version bandwidth counters — avoids high-cardinality label explosion. */
    mw_printf(mw,
        "# HELP xrootd_bytes_rx_ipv4_total "
            "Bytes received from IPv4 clients (stream layer).\n"
        "# TYPE xrootd_bytes_rx_ipv4_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_bytes_rx_ipv4_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_rx_ipv4_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_bytes_tx_ipv4_total "
            "Bytes sent to IPv4 clients (stream layer).\n"
        "# TYPE xrootd_bytes_tx_ipv4_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_bytes_tx_ipv4_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_tx_ipv4_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_bytes_rx_ipv6_total "
            "Bytes received from IPv6 clients (stream layer).\n"
        "# TYPE xrootd_bytes_rx_ipv6_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_bytes_rx_ipv6_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_rx_ipv6_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_bytes_tx_ipv6_total "
            "Bytes sent to IPv6 clients (stream layer).\n"
        "# TYPE xrootd_bytes_tx_ipv6_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_bytes_tx_ipv6_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_tx_ipv6_total, 0));
    }

#define XROOTD_EXPORT_SRV_COUNTER(metric_name, help_text, field_name)        \
    do {                                                                     \
        mw_printf(mw, "# HELP " metric_name " " help_text "\n"            \
                      "# TYPE " metric_name " counter\n");                 \
        for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {                   \
            srv = &shm->servers[i];                                          \
            if (!srv->in_use) { continue; }                                  \
            ngx_snprintf((u_char *) port_str, sizeof(port_str),              \
                         "%ui%Z", srv->port);                               \
            mw_printf(mw, metric_name "{port=\"%s\",auth=\"%s\"} %lu\n",   \
                      port_str, srv->auth,                                   \
                      (unsigned long) ngx_atomic_fetch_add(                  \
                          &srv->field_name, 0));                             \
        }                                                                    \
    } while (0)

    XROOTD_EXPORT_SRV_COUNTER("xrootd_wire_bytes_rx_total",
        "Raw socket bytes received from native XRootD clients.",
        wire_bytes_rx_total);
    XROOTD_EXPORT_SRV_COUNTER("xrootd_wire_bytes_tx_total",
        "Raw socket bytes sent to native XRootD clients.",
        wire_bytes_tx_total);
    XROOTD_EXPORT_SRV_COUNTER("xrootd_stream_request_frames_total",
        "Native XRootD request headers parsed by the stream module.",
        request_frames_total);
    XROOTD_EXPORT_SRV_COUNTER("xrootd_stream_request_payload_bytes_total",
        "Declared native XRootD request payload bytes parsed by the stream module.",
        request_payload_bytes_total);
    XROOTD_EXPORT_SRV_COUNTER("xrootd_stream_oversized_payloads_total",
        "Native XRootD requests rejected because their payload was too large.",
        oversized_payloads_total);
    XROOTD_EXPORT_SRV_COUNTER("xrootd_stream_response_frames_total",
        "Native XRootD response send attempts.",
        response_frames_total);
    XROOTD_EXPORT_SRV_COUNTER("xrootd_stream_response_write_stalls_total",
        "Native XRootD response sends that had to wait for socket writability.",
        response_write_stalls_total);
    XROOTD_EXPORT_SRV_COUNTER("xrootd_stream_response_write_errors_total",
        "Native XRootD response send or send_chain failures.",
        response_write_errors_total);

#undef XROOTD_EXPORT_SRV_COUNTER

    xrootd_export_stream_cache_metrics(mw, shm);

    /* Path depth violation counter — requests rejected due to excessive component count. */
#define XROOTD_EXPORT_DEPTH_VIOLATIONS                                             \
    do {                                                                         \
        mw_printf(mw, "# HELP "                                                  \
                     "xrootd_path_depth_violations_total "                       \
                         "Requests rejected because path depth exceeded "         \
                         "XROOTD_MAX_WALK_DEPTH. Prevents CPU exhaustion from "   \
                         "malicious symlink traversal chains or deep nesting.\n"  \
                     "# TYPE xrootd_path_depth_violations_total counter\n");     \
        for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {                        \
            srv = &shm->servers[i];                                              \
            if (!srv->in_use) { continue; }                                      \
            ngx_snprintf((u_char *) port_str, sizeof(port_str),                  \
                         "%ui%Z", srv->port);                                    \
            mw_printf(mw,                                                      \
                     "xrootd_path_depth_violations_total"                       \
                         "{port=\"%s\",auth=\"%s\"} %lu\n",                    \
                     port_str, srv->auth,                                       \
                     (unsigned long) ngx_atomic_fetch_add(                      \
                         &srv->path_depth_violations_total, 0));                 \
        }                                                                        \
    } while (0)

    XROOTD_EXPORT_DEPTH_VIOLATIONS;

#undef XROOTD_EXPORT_DEPTH_VIOLATIONS

    mw_printf(mw,
        "# HELP xrootd_registry_full_total "
            "Server registrations dropped because the registry was at capacity.\n"
        "# TYPE xrootd_registry_full_total counter\n"
        "xrootd_registry_full_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(&shm->registry_full_total, 0));

    mw_printf(mw,
        "# HELP xrootd_requests_total "
            "XRootD requests completed, by operation and status.\n"
        "# TYPE xrootd_requests_total counter\n");
    for (op = 0; op < XROOTD_NOPS; op++) {
        for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
            srv = &shm->servers[i];
            if (!srv->in_use) { continue; }
            ngx_snprintf((u_char *) port_str, sizeof(port_str),
                         "%ui%Z", srv->port);

            mw_printf(mw,
                "xrootd_requests_total"
                    "{port=\"%s\",auth=\"%s\",op=\"%s\",status=\"ok\"}"
                    " %lu\n",
                port_str, srv->auth, xrootd_op_names[op],
                (unsigned long) ngx_atomic_fetch_add(&srv->op_ok[op], 0));

            {
                ngx_atomic_t errs = ngx_atomic_fetch_add(&srv->op_err[op], 0);
                if (errs > 0) {
                    mw_printf(mw,
                        "xrootd_requests_total"
                            "{port=\"%s\",auth=\"%s\",op=\"%s\",status=\"error\"}"
                            " %lu\n",
                        port_str, srv->auth, xrootd_op_names[op],
                        (unsigned long) errs);
                }
            }
        }
    }

    xrootd_export_unified_metrics(mw, shm);

    xrootd_export_stream_proxy_metrics(mw, shm);
    xrootd_export_stream_tracking_metrics(mw, shm);

    xrootd_export_webdav_metrics(mw, shm);
    xrootd_export_s3_metrics(mw, shm);
    xrootd_export_cluster_metrics(mw);
}
