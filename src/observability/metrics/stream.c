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
 *      the `metrics_writer_t` interface. Per-server families are described by
 *      `srv_family_desc_t` tables (one table per metric family) fed through a
 *      single slot-scan emitter, so the exporter itself is a flat call
 *      sequence. Calls protocol-specific exporters (webdav, s3, proxy,
 *      tracking) at the end.
 */

#include "metrics_internal.h"
#include "stream_internal.h"

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

/*
 * metrics_emit_registry_health() — registry/session anti-exhaustion scalars.
 *
 * WHAT: Server registrations dropped at registry capacity, plus the
 *       Phase 27 F4 session-registry pressure counters (logins rejected with
 *       a full table, idle sessions LRU-reaped to admit a new login).
 * WHY: Non-zero values mean the fixed-slot tables are undersized for the
 *      deployment.
 * HOW: Zone-global unlabelled counters, verbatim exposition text.
 */
static void
metrics_emit_registry_health(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    mw_printf(mw,
        "# HELP brix_registry_full_total "
            "Server registrations dropped because the registry was at capacity.\n"
        "# TYPE brix_registry_full_total counter\n"
        "brix_registry_full_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(&shm->registry_full_total, 0));

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
}

/*
 * metrics_emit_request_ops() — per-operation request outcome family.
 *
 * WHAT: `brix_requests_total{port,auth,op,status}` — ok counts always, error
 *       counts only for op slots that have recorded at least one error.
 * WHY: The primary per-operation traffic/error breakdown; suppressing
 *      zero-error rows keeps the scrape small.
 * HOW: Outer loop over BRIX_NOPS name slots (NULL = unused trailing slot),
 *      inner loop over in-use server slots.
 */
static void
metrics_emit_request_ops(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_brix_srv_metrics_t *srv;
    ngx_uint_t                i, op;
    char                      port_str[16];

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
}

/*
 * metrics_emit_mirror() — traffic-mirror counters.
 *
 * WHAT: Phase 24 — mirror request/error/dropped/divergence totals for both
 *       the http and stream surfaces.
 * WHY: Always exported (independent of the cluster registry, unlike the
 *      health-check block in cluster.c) so shadow behaviour is graphable
 *      even before any node registers.
 * HOW: Zone-global counters, one verbatim exposition block.
 */
static void
metrics_emit_mirror(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
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

void
brix_export_prometheus_metrics(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    /*
     * Export is intentionally eventually consistent rather than a single locked
     * snapshot: each counter is read atomically, but different lines may observe
     * slightly different moments in time while workers continue serving traffic.
     *
     * Family emission order is FROZEN — dashboards parse this output.
     */
    metrics_emit_config_generation(mw, shm);
    metrics_emit_connections(mw, shm);
    metrics_emit_xfer_heap(mw, shm);       /* Phase 31 W4 memory budget */
    metrics_emit_bytes(mw, shm);
    metrics_emit_wire_frames(mw, shm);
    metrics_emit_fault_timeouts(mw, shm);  /* Phase 39 resilience reaps */
    metrics_emit_io_uring(mw, shm);        /* Phase 44 io_uring backend */

    brix_export_stream_cache_metrics(mw, shm);

    metrics_emit_path_depth(mw, shm);
    metrics_emit_ssi(mw, shm);
    metrics_emit_registry_health(mw, shm);
    metrics_emit_request_ops(mw, shm);

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

    /* Phase 24 — traffic-mirror counters. */
    metrics_emit_mirror(mw, shm);
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
