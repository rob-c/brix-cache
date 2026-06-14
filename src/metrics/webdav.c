#include "metrics_internal.h"

/*
 * WHAT: Prometheus HTTP exporter for WebDAV protocol counters.
 * WHY: WebDAV requests (GET, PUT, COPY, PROPFIND, etc.) need their own counter families
 *      separate from native XRootD stream counters — different methods, auth paths, TPC model,
 *      CORS handling, fd cache, and range request semantics. All exported in Prometheus text
 *      exposition format on /metrics endpoint.
 * HOW: Static name-table arrays map enum indices to label strings (method, status class, auth result,
 *      range outcome, PUT body mode, TPC event, CORS decision, PROPFIND depth). xrootd_export_webdav_metrics()
 *      iterates each counter slot via ngx_atomic_fetch_add(..., 0) for lock-free reads, emits HELP/TYPE/value
 *      lines per metric family. Labels are low-cardinality enums only — no paths/bucket-names/DNs as labels.
 */

/*
 * Enum-index -> label-string tables. Each array is indexed by the matching
 * XROOTD_WEBDAV_* enum so the SHM counter slot and its Prometheus label string
 * stay in lockstep — keep array order identical to the enum in metrics_internal.h.
 * All label values are fixed low-cardinality enums (Invariant #8: never paths,
 * DNs, or bucket names as labels).
 */
static const char *xrootd_webdav_method_names[XROOTD_WEBDAV_NMETHODS] = {
    "OPTIONS",
    "HEAD",
    "GET",
    "PUT",
    "DELETE",
    "MKCOL",
    "COPY",
    "PROPFIND",
    "OTHER",
};

static const char *xrootd_webdav_auth_names[XROOTD_WEBDAV_NAUTH_RESULTS] = {
    "none",
    "cert_ok",
    "token_ok",
    "anonymous_fallback",
    "rejected",
};

static const char *xrootd_webdav_put_names[XROOTD_WEBDAV_NPUT_MODES] = {
    "empty",
    "memory",
    "spooled",
    "threaded",
};

static const char *xrootd_webdav_propfind_depth_names[
    XROOTD_WEBDAV_NPROPFIND_DEPTHS] =
{
    "0",
    "1",
    "infinity",
};

static const char *xrootd_webdav_tpc_names[XROOTD_WEBDAV_NTPC_EVENTS] = {
    "pull_started",
    "pull_success",
    "curl_started",
    "curl_success",
    "curl_error",
    "push_started",
    "push_success",
    "bad_request",
    "commit_error",
};

static const char *xrootd_webdav_cors_names[XROOTD_WEBDAV_NCORS_EVENTS] = {
    "no_origin",
    "allowed",
    "denied",
    "preflight",
};

static const char *xrootd_webdav_tpc_cred_names[XROOTD_WEBDAV_NTPC_CRED_EVENTS] = {
    "started",
    "success",
    "error",
    "unknown_mode",
    "parse_error",
};

/*
 * WHAT: Emit every WebDAV counter family to the Prometheus writer.
 * WHY:  WebDAV has its own counter set (distinct from native-stream metrics):
 *       per-method requests/responses, auth outcomes, byte tallies, range/PUT
 *       modes, PROPFIND depth, HTTP-TPC, CORS, and credential delegation.
 * HOW:  Most families are single-label (one axis), so they delegate to the
 *       mw_emit_labeled() helper, which iterates a counter array against a name
 *       table and emits the HELP/TYPE/rows block. The one exception is
 *       responses_total, which is TWO-dimensional (method x status_class) and so
 *       is hand-rolled below with a nested loop. mw_emit_labeled and mw_printf
 *       both read counters atomically (ngx_atomic_fetch_add(&x, 0) == lock-free
 *       load), so this scrape never blocks the request hot path.
 */
void
xrootd_export_webdav_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm)
{
    ngx_uint_t  method, status;

    mw_emit_labeled(mw,
        "xrootd_webdav_requests_total",
        "WebDAV requests received, by HTTP/WebDAV method.",
        "method",
        xrootd_webdav_method_names, XROOTD_WEBDAV_NMETHODS,
        shm->webdav.requests_total);

    /* responses_total: the only 2-D family (method x status_class), so it cannot
     * use mw_emit_labeled (single-axis). HELP/TYPE is emitted once, then the
     * nested loop emits one row per (method, status_class) cell of the SHM
     * matrix shm->webdav.responses_total[method][status]. */
    mw_printf(mw,
        "# HELP xrootd_webdav_responses_total "
            "WebDAV responses by method and HTTP status class.\n"
        "# TYPE xrootd_webdav_responses_total counter\n");
    for (method = 0; method < XROOTD_WEBDAV_NMETHODS; method++) {
        for (status = 0; status < XROOTD_HTTP_NSTATUS; status++) {
            mw_printf(mw,
                "xrootd_webdav_responses_total"
                    "{method=\"%s\",status_class=\"%s\"} %lu\n",
                xrootd_webdav_method_names[method],
                xrootd_http_status_names[status],
                (unsigned long) ngx_atomic_fetch_add(
                    &shm->webdav.responses_total[method][status], 0));
        }
    }

    mw_emit_labeled(mw,
        "xrootd_webdav_auth_total",
        "WebDAV authentication outcomes.",
        "result",
        xrootd_webdav_auth_names, XROOTD_WEBDAV_NAUTH_RESULTS,
        shm->webdav.auth_total);

    /* Legacy scalar byte totals. Kept (and still incremented at the callsites)
     * for dashboard backward-compat, but superseded by the protocol-neutral
     * xrootd_io_bytes_{read,written}{proto="webdav"} families — hence the
     * # DEPRECATED line so scrapers/operators migrate off them. */
    mw_printf(mw,
        "# DEPRECATED: use xrootd_io_bytes_written{proto=\"webdav\"} "
            "for protocol-neutral write throughput.\n"
        "# HELP xrootd_webdav_bytes_rx_total "
            "Bytes received into WebDAV storage writes.\n"
        "# TYPE xrootd_webdav_bytes_rx_total counter\n"
        "xrootd_webdav_bytes_rx_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->webdav.bytes_rx_total, 0));

    mw_printf(mw,
        "# DEPRECATED: use xrootd_io_bytes_read{proto=\"webdav\"} "
            "for protocol-neutral read throughput.\n"
        "# HELP xrootd_webdav_bytes_tx_total "
            "Bytes sent from WebDAV GET and PROPFIND responses.\n"
        "# TYPE xrootd_webdav_bytes_tx_total counter\n"
        "xrootd_webdav_bytes_tx_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->webdav.bytes_tx_total, 0));

    mw_emit_scalar(mw,
        "xrootd_webdav_bytes_rx_ipv4_total",
        "Bytes received from IPv4 clients via WebDAV PUT.",
        &shm->webdav.bytes_rx_ipv4_total);

    mw_emit_scalar(mw,
        "xrootd_webdav_bytes_tx_ipv4_total",
        "Bytes sent to IPv4 clients via WebDAV GET and PROPFIND.",
        &shm->webdav.bytes_tx_ipv4_total);

    mw_emit_scalar(mw,
        "xrootd_webdav_bytes_rx_ipv6_total",
        "Bytes received from IPv6 clients via WebDAV PUT.",
        &shm->webdav.bytes_rx_ipv6_total);

    mw_emit_scalar(mw,
        "xrootd_webdav_bytes_tx_ipv6_total",
        "Bytes sent to IPv6 clients via WebDAV GET and PROPFIND.",
        &shm->webdav.bytes_tx_ipv6_total);

    mw_emit_labeled(mw,
        "xrootd_webdav_range_requests_total",
        "WebDAV GET range handling outcomes.",
        "result",
        xrootd_http_range_result_names, XROOTD_WEBDAV_NRANGE_RESULTS,
        shm->webdav.range_total);

    mw_emit_labeled(mw,
        "xrootd_webdav_put_bodies_total",
        "WebDAV PUT body storage modes.",
        "mode",
        xrootd_webdav_put_names, XROOTD_WEBDAV_NPUT_MODES,
        shm->webdav.put_body_total);

    mw_emit_labeled(mw,
        "xrootd_webdav_propfind_depth_total",
        "WebDAV PROPFIND requests by Depth header bucket.",
        "depth",
        xrootd_webdav_propfind_depth_names, XROOTD_WEBDAV_NPROPFIND_DEPTHS,
        shm->webdav.propfind_depth_total);

    mw_emit_scalar(mw,
        "xrootd_webdav_propfind_entries_total",
        "WebDAV PROPFIND response entries emitted.",
        &shm->webdav.propfind_entries_total);

    mw_emit_labeled(mw,
        "xrootd_webdav_tpc_total",
        "WebDAV HTTP-TPC COPY pull, push, and helper events.",
        "event",
        xrootd_webdav_tpc_names, XROOTD_WEBDAV_NTPC_EVENTS,
        shm->webdav.tpc_total);

    mw_emit_labeled(mw,
        "xrootd_webdav_cors_total",
        "WebDAV CORS request/header decisions.",
        "event",
        xrootd_webdav_cors_names, XROOTD_WEBDAV_NCORS_EVENTS,
        shm->webdav.cors_total);

    mw_emit_labeled(mw,
        "xrootd_webdav_tpc_cred_total",
        "WebDAV HTTP-TPC OAuth2/OIDC credential delegation events.",
        "event",
        xrootd_webdav_tpc_cred_names, XROOTD_WEBDAV_NTPC_CRED_EVENTS,
        shm->webdav.tpc_cred_total);
}
