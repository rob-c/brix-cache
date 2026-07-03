/*
 * stream.c — Prometheus exporter for native XRootD (stream-layer) counters.
 *
 * WHAT: Maps numeric operation slots to human-readable label strings
 *       (`brix_op_names[]`) and iterates the shared-memory metrics zone
 *       to emit Prometheus exposition-format lines for all stream-protocol
 *       counters — connections, bytes, wire frames, request/reject stats,
 *       per-operation ok/error counts, path-depth violations, registry full.
 *
 * WHY: The stream module writes counters into `ngx_brix_metrics_t` shared
 *      memory using atomic fields. This file is the HTTP-side exporter that
 *      reads those counters and formats them as Prometheus scrape output.
 *      The op-name mapping is a binary ABI between stream and HTTP modules:
 *      slot indices must stay aligned with `BRIX_OP_*` constants in metrics.h.
 *
 * HOW: `brix_export_prometheus_metrics()` iterates all server slots, reads
 *      each atomic counter via `ngx_atomic_fetch_add(..., 0)` for an
 *      eventually-consistent snapshot, and writes HELP/TYPE/value lines via
 *      the `metrics_writer_t` interface. Uses macro templates to reduce
 *      repetition. Calls protocol-specific exporters (webdav, s3, proxy,
 *      tracking) at the end.
 */

#include "metrics_internal.h"

/*
 * Human-readable operation names exported as the Prometheus `op=` label.
 * Order must stay aligned with the BRIX_OP_* constants in metrics.h because
 * the stream side records counters by numeric slot, not by string.
 */
static const char *brix_op_names[BRIX_NOPS] = {
    "login",        /* BRIX_OP_LOGIN        */
    "auth",         /* BRIX_OP_AUTH         */
    "stat",         /* BRIX_OP_STAT         */
    "open_rd",      /* BRIX_OP_OPEN_RD      */
    "open_wr",      /* BRIX_OP_OPEN_WR      */
    "read",         /* BRIX_OP_READ         */
    "write",        /* BRIX_OP_WRITE        */
    "sync",         /* BRIX_OP_SYNC         */
    "close",        /* BRIX_OP_CLOSE        */
    "dirlist",      /* BRIX_OP_DIRLIST      */
    "mkdir",        /* BRIX_OP_MKDIR        */
    "rmdir",        /* BRIX_OP_RMDIR        */
    "rm",           /* BRIX_OP_RM           */
    "mv",           /* BRIX_OP_MV           */
    "chmod",        /* BRIX_OP_CHMOD        */
    "truncate",     /* BRIX_OP_TRUNCATE     */
    "ping",         /* BRIX_OP_PING         */
    "query_cksum",  /* BRIX_OP_QUERY_CKSUM (== QUERY_SPACE: both share op slot
                     * 17, so this one series covers QChecksum + QSpace).  Do NOT
                     * add a separate "query_space" entry here — a second slot
                     * shifts every op from readv(18) down by one and mislabels
                     * the whole tail of the table (phase-44 metrics fix). */
    "readv",        /* BRIX_OP_READV        */
    "pgread",       /* BRIX_OP_PGREAD       */
    "writev",       /* BRIX_OP_WRITEV       */
    "locate",       /* BRIX_OP_LOCATE       */
    "statx",        /* BRIX_OP_STATX        */
    "fattr",        /* BRIX_OP_FATTR        */
    "query_stats",  /* BRIX_OP_QUERY_STATS  */
    "query_xattr",  /* BRIX_OP_QUERY_XATTR  */
    "query_finfo",  /* BRIX_OP_QUERY_FINFO  */
    "query_fsinfo", /* BRIX_OP_QUERY_FSINFO */
    "set",          /* BRIX_OP_SET          */
    "query_visa",   /* BRIX_OP_QUERY_VISA   */
    "query_opaque", /* BRIX_OP_QUERY_OPAQUE */
    "query_opaquf", /* BRIX_OP_QUERY_OPAQUF */
    "query_opaqug", /* BRIX_OP_QUERY_OPAQUG */
    "query_ckscan", /* BRIX_OP_QUERY_CKSCAN */
    "clone",        /* BRIX_OP_CLONE        */
    "chkpoint",     /* BRIX_OP_CHKPOINT     */
};

void
brix_export_prometheus_metrics(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    ngx_brix_srv_metrics_t *srv;
    ngx_uint_t                i, op;
    char                      port_str[16];

    /*
     * Export is intentionally eventually consistent rather than a single locked
     * snapshot: each counter is read atomically, but different lines may observe
     * slightly different moments in time while workers continue serving traffic.
     */

    /*
     * Config-reload signal: steps by one on every `nginx -s reload` (published by
     * the master in init_module).  Graph it to correlate behaviour changes with
     * config reloads, or alert when it moves unexpectedly.
     */
    mw_printf(mw,
        "# HELP brix_config_generation "
            "Config loads since master start (steps on each reload).\n"
        "# TYPE brix_config_generation gauge\n"
        "brix_config_generation %lu\n",
        (unsigned long) ngx_atomic_fetch_add(&shm->config_generation, 0));

    mw_printf(mw,
        "# HELP brix_connections_total "
            "Total TCP connections accepted since process start.\n"
        "# TYPE brix_connections_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_connections_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->connections_total, 0));
    }

    mw_printf(mw,
        "# HELP brix_connections_active "
            "Currently open XRootD connections.\n"
        "# TYPE brix_connections_active gauge\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_connections_active{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->connections_active, 0));
    }

    /* Phase 31 W4 — transfer-heap memory budget gauges/counter. */
    mw_printf(mw,
        "# HELP brix_xfer_heap_bytes "
            "Bytes currently held in per-connection transfer scratch buffers.\n"
        "# TYPE brix_xfer_heap_bytes gauge\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_xfer_heap_bytes{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->xfer_heap_in_use, 0));
    }

    mw_printf(mw,
        "# HELP brix_xfer_heap_high_water_bytes "
            "Peak transfer-heap bytes observed since start.\n"
        "# TYPE brix_xfer_heap_high_water_bytes gauge\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_xfer_heap_high_water_bytes{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->xfer_heap_high_water, 0));
    }

    mw_printf(mw,
        "# HELP brix_budget_waits_total "
            "Reads deferred with kXR_wait because they would exceed "
            "brix_memory_budget.\n"
        "# TYPE brix_budget_waits_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_budget_waits_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->budget_waits_total, 0));
    }

    mw_printf(mw,
        "# DEPRECATED: use brix_io_bytes_written{proto=\"stream\"} "
            "for protocol-neutral write throughput.\n"
        "# HELP brix_bytes_rx_total "
            "Bytes received from clients (write payloads).\n"
        "# TYPE brix_bytes_rx_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_bytes_rx_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_rx_total, 0));
    }

    mw_printf(mw,
        "# DEPRECATED: use brix_io_bytes_read{proto=\"stream\"} "
            "for protocol-neutral read throughput.\n"
        "# HELP brix_bytes_tx_total "
            "Bytes sent to clients (read data).\n"
        "# TYPE brix_bytes_tx_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_bytes_tx_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_tx_total, 0));
    }

    /* Per-protocol byte counters — native XRootD stream-layer data only. */
    mw_printf(mw,
        "# DEPRECATED: use brix_io_bytes_written{proto=\"stream\"} "
            "for protocol-neutral write throughput.\n"
        "# HELP brix_bytes_root_rx_total "
            "Bytes received from clients via the native XRootD root:// protocol.\n"
        "# TYPE brix_bytes_root_rx_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_bytes_root_rx_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->proto_root_bytes_rx_total, 0));
    }

    mw_printf(mw,
        "# DEPRECATED: use brix_io_bytes_read{proto=\"stream\"} "
            "for protocol-neutral read throughput.\n"
        "# HELP brix_bytes_root_tx_total "
            "Bytes sent to clients via the native XRootD root:// protocol.\n"
        "# TYPE brix_bytes_root_tx_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_bytes_root_tx_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->proto_root_bytes_tx_total, 0));
    }

    /* Per-IP-version bandwidth counters — avoids high-cardinality label explosion. */
    mw_printf(mw,
        "# HELP brix_bytes_rx_ipv4_total "
            "Bytes received from IPv4 clients (stream layer).\n"
        "# TYPE brix_bytes_rx_ipv4_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_bytes_rx_ipv4_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_rx_ipv4_total, 0));
    }

    mw_printf(mw,
        "# HELP brix_bytes_tx_ipv4_total "
            "Bytes sent to IPv4 clients (stream layer).\n"
        "# TYPE brix_bytes_tx_ipv4_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_bytes_tx_ipv4_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_tx_ipv4_total, 0));
    }

    mw_printf(mw,
        "# HELP brix_bytes_rx_ipv6_total "
            "Bytes received from IPv6 clients (stream layer).\n"
        "# TYPE brix_bytes_rx_ipv6_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_bytes_rx_ipv6_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_rx_ipv6_total, 0));
    }

    mw_printf(mw,
        "# HELP brix_bytes_tx_ipv6_total "
            "Bytes sent to IPv6 clients (stream layer).\n"
        "# TYPE brix_bytes_tx_ipv6_total counter\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
            "brix_bytes_tx_ipv6_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_tx_ipv6_total, 0));
    }

#define BRIX_EXPORT_SRV_COUNTER(metric_name, help_text, field_name)        \
    do {                                                                     \
        mw_printf(mw, "# HELP " metric_name " " help_text "\n"            \
                      "# TYPE " metric_name " counter\n");                 \
        for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {                   \
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

    BRIX_EXPORT_SRV_COUNTER("brix_wire_bytes_rx_total",
        "Raw socket bytes received from native XRootD clients.",
        wire_bytes_rx_total);
    BRIX_EXPORT_SRV_COUNTER("brix_wire_bytes_tx_total",
        "Raw socket bytes sent to native XRootD clients.",
        wire_bytes_tx_total);
    BRIX_EXPORT_SRV_COUNTER("brix_stream_request_frames_total",
        "Native XRootD request headers parsed by the stream module.",
        request_frames_total);
    BRIX_EXPORT_SRV_COUNTER("brix_stream_request_payload_bytes_total",
        "Declared native XRootD request payload bytes parsed by the stream module.",
        request_payload_bytes_total);
    BRIX_EXPORT_SRV_COUNTER("brix_stream_oversized_payloads_total",
        "Native XRootD requests rejected because their payload was too large.",
        oversized_payloads_total);
    BRIX_EXPORT_SRV_COUNTER("brix_stream_response_frames_total",
        "Native XRootD response send attempts.",
        response_frames_total);
    BRIX_EXPORT_SRV_COUNTER("brix_stream_response_write_stalls_total",
        "Native XRootD response sends that had to wait for socket writability.",
        response_write_stalls_total);
    BRIX_EXPORT_SRV_COUNTER("brix_stream_response_write_errors_total",
        "Native XRootD response send or send_chain failures.",
        response_write_errors_total);

    /* Phase 39: network-fault resilience timeout reaps (0 unless directives set). */
    BRIX_EXPORT_SRV_COUNTER("brix_stream_handshake_timeouts_total",
        "Connections dropped because the pre-auth handshake stalled past brix_handshake_timeout.",
        handshake_timeouts_total);
    BRIX_EXPORT_SRV_COUNTER("brix_stream_read_pdu_timeouts_total",
        "Connections dropped because an incomplete request PDU stalled past brix_read_timeout.",
        read_pdu_timeouts_total);
    BRIX_EXPORT_SRV_COUNTER("brix_stream_send_drain_timeouts_total",
        "Connections dropped because the response drain stalled past brix_send_timeout.",
        send_drain_timeouts_total);
    BRIX_EXPORT_SRV_COUNTER("brix_stream_connections_rejected_total",
        "Connections refused at accept because the listener was at brix_max_connections.",
        connections_rejected_total);

    /* Phase 44: optional io_uring disk-I/O backend (0 unless enabled). */
    BRIX_EXPORT_SRV_COUNTER("brix_stream_io_uring_ops_total",
        "Mapped disk ops (read/write/single-group readv/writev) submitted via the io_uring backend.",
        io_uring_ops_total);
    BRIX_EXPORT_SRV_COUNTER("brix_stream_io_uring_fallback_total",
        "Mapped disk ops that fell back to the thread pool because io_uring was full or runtime-disabled.",
        io_uring_fallback_total);

#undef BRIX_EXPORT_SRV_COUNTER

    /* Phase 44: io_uring active gauge (1 = a worker fronting this listener used
     * the ring; flips to 0 fleet-wide effect is observable via the ops/fallback
     * ratio after a kill-switch flip). */
    mw_printf(mw, "# HELP brix_stream_io_uring_active "
                  "1 if a worker fronting this listener has used the io_uring backend.\n"
                  "# TYPE brix_stream_io_uring_active gauge\n");
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str), "%ui%Z", srv->port);
        mw_printf(mw,
                  "brix_stream_io_uring_active{port=\"%s\",auth=\"%s\"} %lu\n",
                  port_str, srv->auth,
                  (unsigned long) ngx_atomic_fetch_add(&srv->io_uring_active, 0));
    }

    brix_export_stream_cache_metrics(mw, shm);

    /* Path depth violation counter — requests rejected due to excessive component count. */
#define BRIX_EXPORT_DEPTH_VIOLATIONS                                             \
    do {                                                                         \
        mw_printf(mw, "# HELP "                                                  \
                     "brix_path_depth_violations_total "                       \
                         "Requests rejected because path depth exceeded "         \
                         "BRIX_MAX_WALK_DEPTH. Prevents CPU exhaustion from "   \
                         "malicious symlink traversal chains or deep nesting.\n"  \
                     "# TYPE brix_path_depth_violations_total counter\n");     \
        for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {                        \
            srv = &shm->servers[i];                                              \
            if (!srv->in_use) { continue; }                                      \
            ngx_snprintf((u_char *) port_str, sizeof(port_str),                  \
                         "%ui%Z", srv->port);                                    \
            mw_printf(mw,                                                      \
                     "brix_path_depth_violations_total"                       \
                         "{port=\"%s\",auth=\"%s\"} %lu\n",                    \
                     port_str, srv->auth,                                       \
                     (unsigned long) ngx_atomic_fetch_add(                      \
                         &srv->path_depth_violations_total, 0));                 \
        }                                                                        \
    } while (0)

    BRIX_EXPORT_DEPTH_VIOLATIONS;

#undef BRIX_EXPORT_DEPTH_VIOLATIONS

    /* §7 XrdSsi service counters. */
#define BRIX_EXPORT_SSI_COUNTER(name, field, help)                          \
    do {                                                                      \
        mw_printf(mw, "# HELP " name " " help "\n# TYPE " name " counter\n"); \
        for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {                    \
            srv = &shm->servers[i];                                           \
            if (!srv->in_use) { continue; }                                   \
            ngx_snprintf((u_char *) port_str, sizeof(port_str),               \
                         "%ui%Z", srv->port);                                 \
            mw_printf(mw, name "{port=\"%s\",auth=\"%s\"} %lu\n",             \
                      port_str, srv->auth,                                     \
                      (unsigned long) ngx_atomic_fetch_add(&srv->field, 0));  \
        }                                                                     \
    } while (0)

    BRIX_EXPORT_SSI_COUNTER("brix_ssi_requests_total", ssi_requests_total,
                              "XrdSsi requests dispatched.");
    BRIX_EXPORT_SSI_COUNTER("brix_ssi_errors_total", ssi_errors_total,
                              "XrdSsi error responses.");
    BRIX_EXPORT_SSI_COUNTER("brix_ssi_alerts_pushed_total",
                              ssi_alerts_pushed_total,
                              "XrdSsi out-of-band alerts pushed to clients.");
    BRIX_EXPORT_SSI_COUNTER("brix_ssi_attn_push_failures_total",
                              ssi_attn_push_failures_total,
                              "XrdSsi kXR_attn pushes that failed to queue.");

#undef BRIX_EXPORT_SSI_COUNTER

    mw_printf(mw,
        "# HELP brix_registry_full_total "
            "Server registrations dropped because the registry was at capacity.\n"
        "# TYPE brix_registry_full_total counter\n"
        "brix_registry_full_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(&shm->registry_full_total, 0));

    /* Phase 27 F4 — session-registry anti-exhaustion. */
    mw_printf(mw,
        "# HELP brix_session_registry_full_total "
            "Logins rejected because the session table was full and nothing was reapable.\n"
        "# TYPE brix_session_registry_full_total counter\n"
        "brix_session_registry_full_total %lu\n"
        "# HELP brix_session_evict_total "
            "Idle sessions reaped (LRU) to admit a new login under table pressure.\n"
        "# TYPE brix_session_evict_total counter\n"
        "brix_session_evict_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(&shm->session_registry_full_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->session_evict_total, 0));

    mw_printf(mw,
        "# HELP brix_requests_total "
            "XRootD requests completed, by operation and status.\n"
        "# TYPE brix_requests_total counter\n");
    for (op = 0; op < BRIX_NOPS; op++) {
        if (brix_op_names[op] == NULL) {
            continue;   /* unused trailing slot (NOPS > distinct op count) */
        }
        for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
            srv = &shm->servers[i];
            if (!srv->in_use) { continue; }
            ngx_snprintf((u_char *) port_str, sizeof(port_str),
                         "%ui%Z", srv->port);

            mw_printf(mw,
                "brix_requests_total"
                    "{port=\"%s\",auth=\"%s\",op=\"%s\",status=\"ok\"}"
                    " %lu\n",
                port_str, srv->auth, brix_op_names[op],
                (unsigned long) ngx_atomic_fetch_add(&srv->op_ok[op], 0));

            {
                ngx_atomic_t errs = ngx_atomic_fetch_add(&srv->op_err[op], 0);
                if (errs > 0) {
                    mw_printf(mw,
                        "brix_requests_total"
                            "{port=\"%s\",auth=\"%s\",op=\"%s\",status=\"error\"}"
                            " %lu\n",
                        port_str, srv->auth, brix_op_names[op],
                        (unsigned long) errs);
                }
            }
        }
    }

    brix_export_unified_metrics(mw, shm);

    brix_export_stream_proxy_metrics(mw, shm);
    brix_export_stream_tracking_metrics(mw, shm);

    brix_export_webdav_metrics(mw, shm);
    brix_export_s3_metrics(mw, shm);
    brix_export_cvmfs_metrics(mw, shm);
    brix_export_cluster_metrics(mw);
    brix_export_ratelimit_metrics(mw, shm);
    brix_export_pmark_metrics(mw, shm);
    brix_export_frm_metrics(mw, shm);
    brix_export_resilience_metrics(mw, shm);

    /* Phase 24 — traffic-mirror counters (always exported; independent of the
     * cluster registry, unlike the health-check block in cluster.c). */
    mw_printf(mw,
        "# HELP brix_mirror_requests_total Mirror requests the shadow answered.\n"
        "# TYPE brix_mirror_requests_total counter\n"
        "brix_mirror_requests_total{surface=\"http\"} %lu\n"
        "brix_mirror_requests_total{surface=\"stream\"} %lu\n"
        "# HELP brix_mirror_errors_total Mirror requests that failed to reach the shadow.\n"
        "# TYPE brix_mirror_errors_total counter\n"
        "brix_mirror_errors_total{surface=\"http\"} %lu\n"
        "brix_mirror_errors_total{surface=\"stream\"} %lu\n"
        "# HELP brix_mirror_dropped_total Requests skipped by the mirror sampling/filter.\n"
        "# TYPE brix_mirror_dropped_total counter\n"
        "brix_mirror_dropped_total{surface=\"http\"} %lu\n"
        "brix_mirror_dropped_total{surface=\"stream\"} %lu\n"
        "# HELP brix_mirror_divergence_total Shadow status differed from the primary.\n"
        "# TYPE brix_mirror_divergence_total counter\n"
        "brix_mirror_divergence_total{surface=\"http\"} %lu\n"
        "brix_mirror_divergence_total{surface=\"stream\"} %lu\n",
        (unsigned long) ngx_atomic_fetch_add(&shm->mirror_http_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->mirror_stream_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->mirror_http_errors_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->mirror_stream_errors_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->mirror_http_dropped_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->mirror_stream_dropped_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->mirror_http_divergence_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->mirror_stream_divergence_total, 0));
}


/* public API: brix_export_pmark_metrics()
 * Phase 34 SciTags packet-marking aggregate counters.  All low-cardinality
 * scalars (no per-flow/exp/VO labels — INVARIANT #8); always exported. */
void
brix_export_pmark_metrics(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    mw_emit_scalar(mw, "brix_pmark_flows_started_total",
        "SciTags flows that mapped to (experiment,activity) and were marked.",
        &shm->pmark_flows_started_total);
    mw_emit_scalar(mw, "brix_pmark_flows_ended_total",
        "SciTags flows that emitted an end firefly.",
        &shm->pmark_flows_ended_total);
    mw_emit_scalar(mw, "brix_pmark_firefly_sent_total",
        "Firefly UDP datagrams sent successfully.",
        &shm->pmark_firefly_sent_total);
    mw_emit_scalar(mw, "brix_pmark_firefly_dropped_total",
        "Firefly UDP datagrams dropped on sendto error (fail-open).",
        &shm->pmark_firefly_dropped_total);
    mw_emit_scalar(mw, "brix_pmark_flowlabel_set_total",
        "IPv6 flow labels stamped on connections.",
        &shm->pmark_flowlabel_set_total);
    mw_emit_scalar(mw, "brix_pmark_flowlabel_failed_total",
        "IPv6 flow-label setsockopt refusals (kernel/permission; fail-open).",
        &shm->pmark_flowlabel_failed_total);
    mw_emit_scalar(mw, "brix_pmark_map_unresolved_total",
        "Opens with packet marking enabled but no (experiment,activity) mapping.",
        &shm->pmark_map_unresolved_total);
}

/* public API: brix_export_resilience_metrics()
 * Phase 51 cross-protocol resilience counters.  All low-cardinality scalars
 * (no per-host/path/identity labels — INVARIANT #8); always exported. */
void
brix_export_resilience_metrics(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    mw_emit_scalar(mw, "brix_cms_read_timeouts_total",
        "CMS client reconnects after the manager went silent past the read timeout.",
        &shm->cms_read_timeouts_total);
    mw_emit_scalar(mw, "brix_cms_login_timeouts_total",
        "CMS server connections closed for not completing LOGIN before the deadline.",
        &shm->cms_login_timeouts_total);
    mw_emit_scalar(mw, "brix_cms_idle_closes_total",
        "CMS server connections reaped by the post-login idle watchdog.",
        &shm->cms_idle_closes_total);
    mw_emit_scalar(mw, "brix_cms_cap_rejections_total",
        "CMS server connections refused by the global or per-IP admission cap.",
        &shm->cms_cap_rejections_total);
    mw_emit_scalar(mw, "brix_cms_frame_yields_total",
        "CMS read loops that yielded the worker after the per-wakeup frame cap.",
        &shm->cms_frame_yields_total);
    mw_emit_scalar(mw, "brix_ocsp_timeouts_total",
        "OCSP fetches that hit the socket deadline (connect/handshake/read).",
        &shm->ocsp_timeouts_total);
    mw_emit_scalar(mw, "brix_auth_l1_hits_total",
        "Auth-gate verdicts served from the per-worker L1 cache (no SHM lock).",
        &shm->auth_l1_hits_total);
    mw_emit_scalar(mw, "brix_auth_l1_misses_total",
        "Auth-gate L1 misses that fell through to the SHM L2 or full evaluation.",
        &shm->auth_l1_misses_total);
    mw_emit_scalar(mw, "brix_acc_nss_breaker_open_total",
        "Times the XrdAcc NSS group-lookup circuit breaker tripped open.",
        &shm->acc_nss_breaker_open_total);
    mw_emit_scalar(mw, "brix_acc_dns_breaker_open_total",
        "Times the XrdAcc reverse-DNS circuit breaker tripped open.",
        &shm->acc_dns_breaker_open_total);
}
