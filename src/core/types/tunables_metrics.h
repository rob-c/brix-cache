/* Histogram geometry, dashboard limits, and metric completion macros.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

/*
 * Metrics histogram bucket bounds for latency measurements.
 *
 * BRIX_LATENCY_BOUND_*: Histogram bucket upper bounds in microseconds.
 *                       Follows Prometheus convention: 1ms, 5ms, 10ms, 50ms,
 *                       100ms, 500ms, 1s, 5s, +Inf (9 buckets total).
 *                       Stored in µs, exported in seconds (%.6f format).
 * BRIX_LATENCY_BOUNDS_COUNT: Number of finite buckets (excludes +Inf)
 * BRIX_IO_LATENCY_BUCKETS: Total histogram slots including +Inf slot
 *
 * WHY: Named constants make histogram configuration explicit and auditable.
 *      Operators can adjust latency sensitivity without hunting magic numbers.
 *      Matches brix_cvmfs_upstream_fill_duration_seconds and
 *      brix_frm_stage_latency_seconds conventions (seconds unit, cumulative le).
 */
#define BRIX_LATENCY_BOUND_1MS       1000
#define BRIX_LATENCY_BOUND_5MS       5000
#define BRIX_LATENCY_BOUND_10MS      10000
#define BRIX_LATENCY_BOUND_50MS      50000
#define BRIX_LATENCY_BOUND_100MS     100000
#define BRIX_LATENCY_BOUND_500MS     500000
#define BRIX_LATENCY_BOUND_1S        1000000
#define BRIX_LATENCY_BOUND_5S        5000000
#define BRIX_LATENCY_BOUNDS_COUNT    8
#define BRIX_IO_LATENCY_BUCKETS      (BRIX_LATENCY_BOUNDS_COUNT + 1)

/*
 * Metrics buffer and export sizes.
 * Buffer capacities for metrics collection and Prometheus export.
 */
#define BRIX_METRICS_BUF_SIZE              65536  /* Main metrics buffer */
#define BRIX_METRICS_HEALTH_BUF          2048   /* Health check response buffer */
#define BRIX_METRICS_CONFIG_BUF            4096   /* Metrics config buffer */
#define BRIX_METRICS_ACCESS_LOG_PATH_BUF   1024   /* Access log path buffer */

/*
 * Metrics histogram bucket boundaries (microseconds).
 * Time-based buckets for latency histograms in unified metrics.
 * Covers sub-millisecond to 5-second range with logarithmic distribution.
 */
#define BRIX_METRICS_LATENCY_BUCKETS_US_COUNT  10
#define BRIX_METRICS_LATENCY_BUCKET_1_US       1000      /* 1 ms */
#define BRIX_METRICS_LATENCY_BUCKET_2_US       5000      /* 5 ms */
#define BRIX_METRICS_LATENCY_BUCKET_3_US       10000     /* 10 ms */
#define BRIX_METRICS_LATENCY_BUCKET_4_US       50000     /* 50 ms */
#define BRIX_METRICS_LATENCY_BUCKET_5_US       100000    /* 100 ms */
#define BRIX_METRICS_LATENCY_BUCKET_6_US       500000    /* 500 ms */
#define BRIX_METRICS_LATENCY_BUCKET_7_US       1000000   /* 1 second */
#define BRIX_METRICS_LATENCY_BUCKET_8_US       5000000   /* 5 seconds */

/*
 * CVMFS metrics histogram buckets (milliseconds).
 * Specialized buckets for CVMFS operation latency tracking.
 * Covers 5ms to 10s range appropriate for CVMFS operations.
 */
#define BRIX_CVMFS_BUCKET_COUNT            6
#define BRIX_CVMFS_BUCKET_1_MS             5       /* 5 ms */
#define BRIX_CVMFS_BUCKET_2_MS             25      /* 25 ms */
#define BRIX_CVMFS_BUCKET_3_MS             100     /* 100 ms */
#define BRIX_CVMFS_BUCKET_4_MS             500     /* 500 ms */
#define BRIX_CVMFS_BUCKET_5_MS             2000    /* 2 seconds */
#define BRIX_CVMFS_BUCKET_6_MS             10000   /* 10 seconds */
#define BRIX_CVMFS_QOS_TOKEN_DECREMENT     1000    /* QoS token decrement per fill */

/*
 * FRM (File Registry Manager) metrics histogram buckets (seconds).
 * Buckets for FRM operation latency tracking.
 * Covers 1s to 1 hour range for long-running FRM operations.
 */
#define BRIX_FRM_BUCKET_COUNT              8
#define BRIX_FRM_BUCKET_1_SEC              1       /* 1 second */
#define BRIX_FRM_BUCKET_2_SEC              10      /* 10 seconds */
#define BRIX_FRM_BUCKET_3_SEC              30      /* 30 seconds */
#define BRIX_FRM_BUCKET_4_SEC              60      /* 1 minute */
#define BRIX_FRM_BUCKET_5_SEC              300     /* 5 minutes */
#define BRIX_FRM_BUCKET_6_SEC              1800    /* 30 minutes */
#define BRIX_FRM_BUCKET_7_SEC              3600    /* 1 hour */

/*
 * Dashboard rate limiting constants.
 * Requests per minute limits for dashboard API endpoints.
 */
#define BRIX_DASHBOARD_READ_RL_PM          1200   /* Read requests per minute */
#define BRIX_DASHBOARD_WRITE_RL_PM         120    /* Write requests per minute */

/*
 * Dashboard scan and cluster limits.
 * Bounds for filesystem scan operations and cluster tracking.
 */
#define BRIX_DASHBOARD_SCAN_MAX_FILES      100000  /* Max files in scan */
#define BRIX_DASHBOARD_CLUSTER_MAX         256     /* Max cluster nodes tracked */

/*
 * Maximum entries in dashboard file listings.
 * Prevents unbounded JSON responses and browser hangs.
 * 10000 entries provides comprehensive view while bounding response size.
 */
#define BRIX_DASHBOARD_FILES_MAX               10000

/*
 * Metrics export buffer size (bytes).
 * Sized to hold complete Prometheus-format metric families without fragmentation.
 * 64 KB accommodates large metric families with multiple label combinations.
 */
#define BRIX_METRICS_EXPORT_BUF_SIZE           65536

/*
 * Metrics stream cache capacity (bytes).
 * Maximum memory for in-flight metric stream buffering.
 * 2 MB allows for high-throughput streaming without backpressure.
 */
#define BRIX_METRICS_STREAM_CACHE_SIZE         (2 * 1024 * 1024)

/*
 * Metrics occupancy threshold (parts per million).
 * Cache eviction triggers when occupancy exceeds this threshold.
 * 800000 ppm = 80% utilization threshold.
 */
#define BRIX_METRICS_OCCUPANCY_THRESHOLD_PPM   800000

/*
 * Access log timer interval (milliseconds).
 * Periodic flush interval for access log buffering.
 * 1000 ms = 1 second flush interval for timely log delivery.
 */
#define BRIX_ACCESS_LOG_TIMER_MS               1000

/*
 * Metrics histogram bucket count.
 * Standard Prometheus-style histogram buckets for latency tracking.
 * 8 buckets: 1, 10, 30, 60, 300, 1800, 3600, +Inf seconds.
 */
#define BRIX_METRICS_HISTOGRAM_BUCKETS         8

/*
 * Dashboard authentication secret maximum length (bytes).
 * Accommodates strong passwords and API keys with safety margin.
 * 4096 bytes allows for very long secrets while bounding allocation.
 */
#define BRIX_DASHBOARD_SECRET_MAX              4096

/*
 * Dashboard admin request body maximum (bytes).
 * Limits configuration upload and admin API payload sizes.
 * 64 KB accommodates complex configs while preventing abuse.
 */
#define BRIX_DASHBOARD_ADMIN_MAX_BODY          65536

/*
 * Dashboard session rate limit (requests per second).
 * Per-session request rate for API endpoints.
 * 100 requests/sec allows interactive use without abuse.
 */
#define BRIX_DASHBOARD_SESSION_RATE_LIMIT      100

/*
 * Dashboard password buffer size (bytes).
 * Maximum password length for authentication.
 * 1024 bytes accommodates very long passwords while bounding stack allocation.
 */
#define BRIX_DASHBOARD_PASSWORD_BUF            1025

/*
 * Dashboard CSS/JS inline buffer size (bytes).
 * Maximum size for inline stylesheet and script content.
 * 4096 bytes accommodates typical dashboard styling.
 */
#define BRIX_DASHBOARD_INLINE_STYLE_MAX        4096

/* Increment a per-operation metric counter.  No-op when metrics are disabled. */
#define BRIX_OP_OK(ctx, op)  \
    do { if ((ctx)->metrics) { \
        ngx_atomic_fetch_add(&(ctx)->metrics->op_ok[(op)], 1); \
    } } while (0)

#define BRIX_OP_ERR(ctx, op) \
    do { if ((ctx)->metrics) { \
        ngx_atomic_fetch_add(&(ctx)->metrics->op_err[(op)], 1); \
    } } while (0)

/*
 * Collapse the common three-line pattern into a single macro call.
 * Use only when brix_send_ok sends no body (NULL, 0).
 * Handlers that return a body (read data, pgwrite status, query results)
 * must keep the three lines explicit.
 */
#define BRIX_RETURN_OK(ctx, c, op, verb, path, detail, bytes)         \
    do {                                                                  \
        brix_log_access((ctx), (c), (verb), (path), (detail),         \
                          1, kXR_ok, NULL, (bytes));                     \
        BRIX_OP_OK((ctx), (op));                                       \
        return brix_send_ok((ctx), (c), NULL, 0);                      \
    } while (0)

#define BRIX_RETURN_ERR(ctx, c, op, verb, path, detail, code, msg)    \
    do {                                                                  \
        brix_log_access((ctx), (c), (verb), (path), (detail),         \
                          0, (code), (msg), 0);                          \
        BRIX_OP_ERR((ctx), (op));                                      \
        return brix_send_error((ctx), (c), (code), (msg));             \
    } while (0)

/*
 * Collapse: log_access + BRIX_OP_OK + return send_redirect.
 * Used wherever the outcome is a successful redirect (locate, manager, etc.)
 */
#define BRIX_RETURN_REDIR(ctx, c, op, verb, path, detail, host, port)  \
    do {                                                                  \
        brix_log_access((ctx), (c), (verb), (path), (detail),         \
                          1, kXR_ok, NULL, 0);                           \
        BRIX_OP_OK((ctx), (op));                                        \
        return brix_send_redirect((ctx), (c), (host), (port));         \
    } while (0)

/*
 * Selection answer (phase-115 W2.1): like BRIX_RETURN_REDIR but the answer is
 * the manager's `brix_cms_response` policy — kXR_redirect (default) or pin the
 * session to the selected server and proxy.  Use at dynamic selection sites
 * (registry / caches / stage); static manager_map redirects keep RETURN_REDIR.
 */
#define BRIX_RETURN_SELECTED(ctx, c, conf, op, verb, path, detail, host, port) \
    do {                                                                  \
        brix_log_access((ctx), (c), (verb), (path), (detail),         \
                          1, kXR_ok, NULL, 0);                           \
        BRIX_OP_OK((ctx), (op));                                        \
        return brix_cms_answer_selected((ctx), (c), (conf), (host), (port)); \
    } while (0)

/*
 * Collapse: log_access + BRIX_OP_ERR + *rc=send_error + return 0.
 * Used in helper functions (validate_handle, parse_op_path, etc.) that
 * signal failure to callers via an out-parameter and return int 0.
 */
#define BRIX_BAIL_ERR(ctx, c, op, verb, path, detail, code, msg, rc)   \
    do {                                                                  \
        brix_log_access((ctx), (c), (verb), (path), (detail),         \
                          0, (code), (msg), 0);                          \
        BRIX_OP_ERR((ctx), (op));                                      \
        *(rc) = brix_send_error((ctx), (c), (code), (msg));            \
        return 0;                                                         \
    } while (0)

/*
 * Dashboard and metrics constants.
 */
#define BRIX_DASHBOARD_LOGIN_PATH_MAX 256   /* Dashboard login path buffer */
#define BRIX_DASHBOARD_PAGE_BUF_MAX   4096  /* Dashboard page buffer */
#define BRIX_METRICS_TRACKING_BUF_MAX 1024  /* Metrics tracking buffer */
