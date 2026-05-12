#include "metrics_internal.h"

#include <stdint.h>
#include <sys/statvfs.h>


static ngx_int_t
xrootd_cache_statvfs(const char *root, uint64_t *total, uint64_t *used,
    uint64_t *available, ngx_uint_t *occupancy_ppm)
{
    struct statvfs  vfs;
    uint64_t        block_size;
    uint64_t        blocks;
    uint64_t        avail_blocks;

    if (root == NULL || root[0] == '\0') {
        return NGX_ERROR;
    }

    if (statvfs(root, &vfs) != 0 || vfs.f_blocks == 0) {
        return NGX_ERROR;
    }

    block_size = vfs.f_frsize ? (uint64_t) vfs.f_frsize
                              : (uint64_t) vfs.f_bsize;
    blocks = (uint64_t) vfs.f_blocks;
    avail_blocks = (uint64_t) vfs.f_bavail;

    *total = blocks * block_size;
    *available = avail_blocks * block_size;
    *used = (blocks - avail_blocks) * block_size;
    *occupancy_ppm = (ngx_uint_t)
        (((long double) *used * 1000000.0L) / (long double) *total);

    return NGX_OK;
}


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

    mw_printf(mw,
        "# HELP xrootd_cache_occupancy_ratio "
            "Filesystem occupancy ratio for xrootd_cache_root.\n"
        "# TYPE xrootd_cache_occupancy_ratio gauge\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        uint64_t   total, used, available;
        ngx_uint_t occupancy_ppm;

        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        if (xrootd_cache_statvfs(srv->cache_root, &total, &used,
                                 &available, &occupancy_ppm) != NGX_OK)
        {
            continue;
        }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_occupancy_ratio{port=\"%s\",auth=\"%s\"} %0.6f\n",
            port_str, srv->auth, (double) occupancy_ppm / 1000000.0);
    }

    mw_printf(mw,
        "# HELP xrootd_cache_eviction_threshold_ratio "
            "Configured cache eviction high-water occupancy ratio.\n"
        "# TYPE xrootd_cache_eviction_threshold_ratio gauge\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_eviction_threshold_ratio"
                "{port=\"%s\",auth=\"%s\"} %0.6f\n",
            port_str, srv->auth,
            (double) srv->cache_eviction_threshold / 1000000.0);
    }

    mw_printf(mw,
        "# HELP xrootd_cache_bytes "
            "Cache filesystem bytes by state.\n"
        "# TYPE xrootd_cache_bytes gauge\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        uint64_t   total, used, available;
        ngx_uint_t occupancy_ppm;

        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        if (xrootd_cache_statvfs(srv->cache_root, &total, &used,
                                 &available, &occupancy_ppm) != NGX_OK)
        {
            continue;
        }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_bytes{port=\"%s\",auth=\"%s\",state=\"total\"} %llu\n",
            port_str, srv->auth, (unsigned long long) total);
        mw_printf(mw,
            "xrootd_cache_bytes{port=\"%s\",auth=\"%s\",state=\"used\"} %llu\n",
            port_str, srv->auth, (unsigned long long) used);
        mw_printf(mw,
            "xrootd_cache_bytes{port=\"%s\",auth=\"%s\",state=\"available\"} %llu\n",
            port_str, srv->auth, (unsigned long long) available);
    }

    mw_printf(mw,
        "# HELP xrootd_cache_evictions_total "
            "Files evicted from xrootd_cache_root.\n"
        "# TYPE xrootd_cache_evictions_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_evictions_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->cache_evictions_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_cache_evicted_bytes_total "
            "Bytes reclaimed by cache eviction.\n"
        "# TYPE xrootd_cache_evicted_bytes_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_evicted_bytes_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->cache_evicted_bytes_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_cache_eviction_errors_total "
            "Cache eviction maintenance errors.\n"
        "# TYPE xrootd_cache_eviction_errors_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use || !srv->cache_enabled) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "xrootd_cache_eviction_errors_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->cache_eviction_errors_total, 0));
    }

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

    /* ---- proxy metrics (only for proxy-enabled listeners) ---- */

#define XROOTD_EXPORT_PROXY_COUNTER(metric_name, help_text, field_name)       \
    do {                                                                      \
        ngx_uint_t _u;                                                        \
        mw_printf(mw, "# HELP " metric_name " " help_text "\n"             \
                      "# TYPE " metric_name " counter\n");                  \
        for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {                    \
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
            for (_u = 0; _u < XROOTD_PROXY_MAX_UPSTREAMS; _u++) {            \
                ngx_xrootd_proxy_upstream_metrics_t *_um =                    \
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

    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_upstream_connects_total",
        "Successful upstream TCP (or TLS) connects.",
        upstream_connects_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_upstream_connect_errors_total",
        "Upstream TCP connect or TLS handshake failures.",
        upstream_connect_errors);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_upstream_auth_errors_total",
        "Upstream login or token authentication failures.",
        upstream_auth_errors);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_opens_total",
        "kXR_open requests forwarded to upstream that succeeded.",
        opens_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_open_errors_total",
        "kXR_open requests forwarded to upstream that failed.",
        open_errors);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_reads_total",
        "kXR_read/pgread/readv requests forwarded to upstream.",
        reads_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_read_bytes_total",
        "Bytes relayed from upstream to client via proxy.",
        read_bytes_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_writes_total",
        "kXR_write/pgwrite/writev requests forwarded to upstream.",
        writes_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_write_bytes_total",
        "Bytes forwarded from client to upstream via proxy.",
        write_bytes_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_closes_total",
        "kXR_close requests forwarded to upstream.",
        closes_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_abandoned_handles_total",
        "Upstream file handles freed on client disconnect without an explicit close.",
        abandoned_handles_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_reconnects_total",
        "Upstream reconnect attempts after idle connection drop.",
        reconnects_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_path_ops_total",
        "Path-based mutation operations (rm/mkdir/rmdir/mv/chmod/truncate) that succeeded.",
        path_ops_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_path_op_errors_total",
        "Path-based mutation operations that received an error from upstream.",
        path_op_errors_total);
    XROOTD_EXPORT_PROXY_COUNTER(
        "xrootd_proxy_wait_responses_total",
        "kXR_wait responses from upstream that were absorbed and retried transparently.",
        wait_responses_total);

#undef XROOTD_EXPORT_PROXY_COUNTER

    /* ---- Extended metrics: per-VO traffic, unique users, protocol labels ---- */

    mw_printf(mw,
        "# HELP xrootd_vo_bytes_tx_total "
            "Bytes sent to clients grouped by virtual organisation. "
            "VO names are truncated to %d characters; the metric family has one entry per VO.\n"
        "# TYPE xrootd_vo_bytes_tx_total counter\n", XROOTD_VO_NAME_LEN - 1);
    for (i = 0; i < XROOTD_VO_MAX_TRACKED; i++) {
        ngx_xrootd_vo_slot_t *vo = &shm->vo_global.slots[i];
        if (!vo->name[0]) { continue; }
        mw_printf(mw, "xrootd_vo_bytes_tx_total{vo=\"%s\"} %lu\n",
                  vo->name, (unsigned long) ngx_atomic_fetch_add(&vo->bytes_tx_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_vo_bytes_rx_total "
            "Bytes received from clients grouped by virtual organisation. "
            "VO names are truncated to %d characters.\n"
        "# TYPE xrootd_vo_bytes_rx_total counter\n", XROOTD_VO_NAME_LEN - 1);
    for (i = 0; i < XROOTD_VO_MAX_TRACKED; i++) {
        ngx_xrootd_vo_slot_t *vo = &shm->vo_global.slots[i];
        if (!vo->name[0]) { continue; }
        mw_printf(mw, "xrootd_vo_bytes_rx_total{vo=\"%s\"} %lu\n",
                  vo->name, (unsigned long) ngx_atomic_fetch_add(&vo->bytes_rx_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_vo_requests_total "
            "Requests grouped by virtual organisation. VO names are truncated.\n"
        "# TYPE xrootd_vo_requests_total counter\n");
    for (i = 0; i < XROOTD_VO_MAX_TRACKED; i++) {
        ngx_xrootd_vo_slot_t *vo = &shm->vo_global.slots[i];
        if (!vo->name[0]) { continue; }
        mw_printf(mw, "xrootd_vo_requests_total{vo=\"%s\"} %lu\n",
                  vo->name, (unsigned long) ngx_atomic_fetch_add(&vo->requests_total, 0));
    }

    mw_printf(mw,
        "# HELP xrootd_vo_overflow_total "
            "VO entries that exceeded the tracking limit and were evicted.\n"
        "# TYPE xrootd_vo_overflow_total counter\n");
    mw_printf(mw, "xrootd_vo_overflow_total %lu\n",
              (unsigned long) ngx_atomic_fetch_add(&shm->vo_global.overflow_total, 0));

    mw_printf(mw,
        "# HELP xrootd_unique_users_current "
            "Currently tracked unique user identities (bounded LRU, max %d). "
            "Users are identified by DN or token sub via FNV-1a hash.\n"
        "# TYPE xrootd_unique_users_current gauge\n", XROOTD_USERS_MAX_TRACKED);
    mw_printf(mw, "xrootd_unique_users_current %lu\n",
              (unsigned long) ngx_atomic_fetch_add(&shm->user_tracking.unique_count, 0));

    mw_printf(mw,
        "# HELP xrootd_unique_users_total "
            "Lifetime unique user identities seen since process start. "
            "Never decremented.\n"
        "# TYPE xrootd_unique_users_total counter\n");
    mw_printf(mw, "xrootd_unique_users_total %lu\n",
              (unsigned long) ngx_atomic_fetch_add(&shm->user_tracking.total_unique, 0));

    mw_printf(mw,
        "# HELP xrootd_user_evictions_total "
            "User identity slots evicted from the tracking table.\n"
        "# TYPE xrootd_user_evictions_total counter\n");
    mw_printf(mw, "xrootd_user_evictions_total %lu\n",
              (unsigned long) ngx_atomic_fetch_add(&shm->user_tracking.evictions_total, 0));

    mw_printf(mw,
        "# HELP xrootd_user_sessions_total "
            "Sessions per tracked user identity. Sum across all entries equals total authenticated sessions.\n"
        "# TYPE xrootd_user_sessions_total gauge\n");
    for (i = 0; i < XROOTD_USERS_MAX_TRACKED; i++) {
        ngx_xrootd_user_slot_t *u = &shm->user_tracking.slots[i];
        if (!u->id_hash) { continue; }
        mw_printf(mw, "xrootd_user_sessions_total{hash=%08x} %lu\n",
                  u->id_hash, (unsigned long) ngx_atomic_fetch_add(&u->sessions_total, 0));
    }

    xrootd_export_webdav_metrics(mw, shm);
    xrootd_export_s3_metrics(mw, shm);
}
