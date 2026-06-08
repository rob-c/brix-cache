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

static const char *xrootd_http_status_names[XROOTD_HTTP_NSTATUS] = {
    "1xx",
    "2xx",
    "3xx",
    "4xx",
    "5xx",
    "other",
};

static const char *xrootd_webdav_auth_names[XROOTD_WEBDAV_NAUTH_RESULTS] = {
    "none",
    "cert_ok",
    "token_ok",
    "anonymous_fallback",
    "rejected",
};

static const char *xrootd_webdav_range_names[XROOTD_WEBDAV_NRANGE_RESULTS] = {
    "full",
    "partial",
    "unsatisfied",
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

void
xrootd_export_webdav_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm)
{
    ngx_uint_t  i, method, status;

    mw_printf(mw,
        "# HELP xrootd_webdav_requests_total "
            "WebDAV requests received, by HTTP/WebDAV method.\n"
        "# TYPE xrootd_webdav_requests_total counter\n");
    for (method = 0; method < XROOTD_WEBDAV_NMETHODS; method++) {
        mw_printf(mw,
            "xrootd_webdav_requests_total{method=\"%s\"} %lu\n",
            xrootd_webdav_method_names[method],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->webdav.requests_total[method], 0));
    }

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

    mw_printf(mw,
        "# HELP xrootd_webdav_auth_total "
            "WebDAV authentication outcomes.\n"
        "# TYPE xrootd_webdav_auth_total counter\n");
    for (i = 0; i < XROOTD_WEBDAV_NAUTH_RESULTS; i++) {
        mw_printf(mw,
            "xrootd_webdav_auth_total{result=\"%s\"} %lu\n",
            xrootd_webdav_auth_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->webdav.auth_total[i], 0));
    }

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

    mw_printf(mw,
        "# HELP xrootd_webdav_bytes_rx_ipv4_total "
            "Bytes received from IPv4 clients via WebDAV PUT.\n"
        "# TYPE xrootd_webdav_bytes_rx_ipv4_total counter\n"
        "xrootd_webdav_bytes_rx_ipv4_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->webdav.bytes_rx_ipv4_total, 0));

    mw_printf(mw,
        "# HELP xrootd_webdav_bytes_tx_ipv4_total "
            "Bytes sent to IPv4 clients via WebDAV GET and PROPFIND.\n"
        "# TYPE xrootd_webdav_bytes_tx_ipv4_total counter\n"
        "xrootd_webdav_bytes_tx_ipv4_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->webdav.bytes_tx_ipv4_total, 0));

    mw_printf(mw,
        "# HELP xrootd_webdav_bytes_rx_ipv6_total "
            "Bytes received from IPv6 clients via WebDAV PUT.\n"
        "# TYPE xrootd_webdav_bytes_rx_ipv6_total counter\n"
        "xrootd_webdav_bytes_rx_ipv6_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->webdav.bytes_rx_ipv6_total, 0));

    mw_printf(mw,
        "# HELP xrootd_webdav_bytes_tx_ipv6_total "
            "Bytes sent to IPv6 clients via WebDAV GET and PROPFIND.\n"
        "# TYPE xrootd_webdav_bytes_tx_ipv6_total counter\n"
        "xrootd_webdav_bytes_tx_ipv6_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->webdav.bytes_tx_ipv6_total, 0));

    mw_printf(mw,
        "# HELP xrootd_webdav_range_requests_total "
            "WebDAV GET range handling outcomes.\n"
        "# TYPE xrootd_webdav_range_requests_total counter\n");
    for (i = 0; i < XROOTD_WEBDAV_NRANGE_RESULTS; i++) {
        mw_printf(mw,
            "xrootd_webdav_range_requests_total{result=\"%s\"} %lu\n",
            xrootd_webdav_range_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->webdav.range_total[i], 0));
    }

    mw_printf(mw,
        "# HELP xrootd_webdav_put_bodies_total "
            "WebDAV PUT body storage modes.\n"
        "# TYPE xrootd_webdav_put_bodies_total counter\n");
    for (i = 0; i < XROOTD_WEBDAV_NPUT_MODES; i++) {
        mw_printf(mw,
            "xrootd_webdav_put_bodies_total{mode=\"%s\"} %lu\n",
            xrootd_webdav_put_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->webdav.put_body_total[i], 0));
    }

    mw_printf(mw,
        "# HELP xrootd_webdav_propfind_depth_total "
            "WebDAV PROPFIND requests by Depth header bucket.\n"
        "# TYPE xrootd_webdav_propfind_depth_total counter\n");
    for (i = 0; i < XROOTD_WEBDAV_NPROPFIND_DEPTHS; i++) {
        mw_printf(mw,
            "xrootd_webdav_propfind_depth_total{depth=\"%s\"} %lu\n",
            xrootd_webdav_propfind_depth_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->webdav.propfind_depth_total[i], 0));
    }

    mw_printf(mw,
        "# HELP xrootd_webdav_propfind_entries_total "
            "WebDAV PROPFIND response entries emitted.\n"
        "# TYPE xrootd_webdav_propfind_entries_total counter\n"
        "xrootd_webdav_propfind_entries_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->webdav.propfind_entries_total, 0));

    mw_printf(mw,
        "# HELP xrootd_webdav_tpc_total "
            "WebDAV HTTP-TPC COPY pull, push, and helper events.\n"
        "# TYPE xrootd_webdav_tpc_total counter\n");
    for (i = 0; i < XROOTD_WEBDAV_NTPC_EVENTS; i++) {
        mw_printf(mw,
            "xrootd_webdav_tpc_total{event=\"%s\"} %lu\n",
            xrootd_webdav_tpc_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->webdav.tpc_total[i], 0));
    }

    mw_printf(mw,
        "# HELP xrootd_webdav_cors_total "
            "WebDAV CORS request/header decisions.\n"
        "# TYPE xrootd_webdav_cors_total counter\n");
    for (i = 0; i < XROOTD_WEBDAV_NCORS_EVENTS; i++) {
        mw_printf(mw,
            "xrootd_webdav_cors_total{event=\"%s\"} %lu\n",
            xrootd_webdav_cors_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->webdav.cors_total[i], 0));
    }

    mw_printf(mw,
        "# HELP xrootd_webdav_tpc_cred_total "
            "WebDAV HTTP-TPC OAuth2/OIDC credential delegation events.\n"
        "# TYPE xrootd_webdav_tpc_cred_total counter\n");
    for (i = 0; i < XROOTD_WEBDAV_NTPC_CRED_EVENTS; i++) {
        mw_printf(mw,
            "xrootd_webdav_tpc_cred_total{event=\"%s\"} %lu\n",
            xrootd_webdav_tpc_cred_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->webdav.tpc_cred_total[i], 0));
    }
}
