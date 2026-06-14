#include "metrics_internal.h"

/*
 * WHAT: Prometheus metrics export for the S3-compatible HTTP endpoint.
 * WHY: The S3 endpoint receives requests from XrdClS3, aws s3 CLI, and other S3-compatible clients.
 *      These counters track request volume, response status classes, authentication outcomes (SigV4 vs anonymous),
 *      data transfer volumes, range handling, PUT body modes, diagnostic events, and ListObjectsV2 pagination stats.
 * HOW: Five static string tables map slot indices to low-cardinality label strings per INVARIANT #8; one public function
 *      iterates all counters via ngx_atomic_fetch_add(..., 0) for eventually-consistent Prometheus snapshots.
 *      Each metric line includes HELP description and TYPE counter declaration before the actual data line.
 */

/* ---- static table: S3 HTTP method names ----
 * WHAT: Label strings for xrootd_s3_requests_total and xrootd_s3_responses_total counters by operation type.
 * WHY: Prometheus label values must be low-cardinality (INVARIANT #8) — fixed enum prevents bucket-name or request-type explosion. */

static const char *xrootd_s3_method_names[XROOTD_S3_NMETHODS] = {
    "GET",
    "HEAD",
    "PUT",
    "DELETE",
    "LIST",
    "POST",
    "OPTIONS",
    "OTHER",
};

/* ---- static table: S3 authentication result names ----
 * WHAT: Label strings for xrootd_s3_auth_total counters. SigV4-specific results (signature_mismatch, bad_access_key) are tracked separately per INVARIANT #6. */

static const char *xrootd_s3_auth_names[XROOTD_S3_NAUTH_RESULTS] = {
    "anonymous",
    "sigv4_ok",
    "missing",
    "malformed",
    "bad_access_key",
    "bad_date",
    "signature_mismatch",
    "internal_error",
};

/* ---- static table: S3 PUT body storage mode names ----
 * WHAT: Label strings for xrootd_s3_put_bodies_total counters. Tracks whether PUT body was stored in memory, spooled to disk, or mixed modes after successful write. */

static const char *xrootd_s3_put_names[XROOTD_S3_NPUT_MODES] = {
    "empty",
    "memory",
    "spooled",
    "mixed",
};

/* ---- static table: S3 diagnostic event names ----
 * WHAT: Label strings for xrootd_s3_events_total low-cardinality counter. Tracks endpoint-level diagnostics (URI validation failures, access denied, write disabled). */

static const char *xrootd_s3_event_names[XROOTD_S3_NEVENTS] = {
    "invalid_uri",
    "access_denied",
    "no_such_key",
    "write_disabled",
    "method_not_allowed",
    "internal_error",
    "dir_sentinel",
    "delete_missing",
};

/* ---- public API: xrootd_export_s3_metrics() ----
 * WHAT: Export all S3-compatible endpoint Prometheus metrics into the writer buffer chain.
 * WHY: The HTTP metrics handler reads counters from shm->s3 using ngx_atomic_fetch_add(..., 0) for an eventually-consistent snapshot.
 *      Each metric line includes HELP description and TYPE counter declaration before the actual data line, following Prometheus text exposition format (0.0.4).
 * HOW: Iterate counter families via static name tables: requests_total, responses_total[method][status_class], auth_total, bytes_rx_tx, range_total, put_body_total, events_total, plus three ListObjectsV2 stats. All counters are unsigned long values cast from ngx_atomic_t fields. */

void
xrootd_export_s3_metrics(metrics_writer_t *mw, ngx_xrootd_metrics_t *shm)
{
    ngx_uint_t  method, status;

    mw_emit_labeled(mw,
        "xrootd_s3_requests_total",
        "S3-compatible endpoint requests received, by operation.",
        "method",
        xrootd_s3_method_names, XROOTD_S3_NMETHODS,
        shm->s3.requests_total);

    mw_printf(mw,
        "# HELP xrootd_s3_responses_total "
            "S3-compatible endpoint responses by operation and HTTP status class.\n"
        "# TYPE xrootd_s3_responses_total counter\n");
    for (method = 0; method < XROOTD_S3_NMETHODS; method++) {
        for (status = 0; status < XROOTD_HTTP_NSTATUS; status++) {
            mw_printf(mw,
                "xrootd_s3_responses_total"
                    "{method=\"%s\",status_class=\"%s\"} %lu\n",
                xrootd_s3_method_names[method],
                xrootd_http_status_names[status],
                (unsigned long) ngx_atomic_fetch_add(
                    &shm->s3.responses_total[method][status], 0));
        }
    }

    mw_emit_labeled(mw,
        "xrootd_s3_auth_total",
        "S3 SigV4 or anonymous authentication outcomes.",
        "result",
        xrootd_s3_auth_names, XROOTD_S3_NAUTH_RESULTS,
        shm->s3.auth_total);

    mw_printf(mw,
        "# DEPRECATED: use xrootd_io_bytes_written{proto=\"s3\"} "
            "for protocol-neutral write throughput.\n"
        "# HELP xrootd_s3_bytes_rx_total "
            "Bytes accepted into successful S3-compatible PUT writes.\n"
        "# TYPE xrootd_s3_bytes_rx_total counter\n"
        "xrootd_s3_bytes_rx_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->s3.bytes_rx_total, 0));

    mw_printf(mw,
        "# DEPRECATED: use xrootd_io_bytes_read{proto=\"s3\"} "
            "for protocol-neutral read throughput.\n"
        "# HELP xrootd_s3_bytes_tx_total "
            "Bytes emitted by S3-compatible GET, LIST, and XML error responses.\n"
        "# TYPE xrootd_s3_bytes_tx_total counter\n"
        "xrootd_s3_bytes_tx_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->s3.bytes_tx_total, 0));

    mw_emit_scalar(mw,
        "xrootd_s3_bytes_rx_ipv4_total",
        "Bytes received from IPv4 clients via S3-compatible PUT.",
        &shm->s3.bytes_rx_ipv4_total);

    mw_emit_scalar(mw,
        "xrootd_s3_bytes_tx_ipv4_total",
        "Bytes sent to IPv4 clients via S3-compatible GET.",
        &shm->s3.bytes_tx_ipv4_total);

    mw_emit_labeled(mw,
        "xrootd_s3_range_requests_total",
        "S3-compatible GET range handling outcomes.",
        "result",
        xrootd_http_range_result_names, XROOTD_S3_NRANGE_RESULTS,
        shm->s3.range_total);

    mw_emit_labeled(mw,
        "xrootd_s3_put_bodies_total",
        "S3-compatible PUT body storage modes observed after successful writes.",
        "mode",
        xrootd_s3_put_names, XROOTD_S3_NPUT_MODES,
        shm->s3.put_body_total);

    mw_emit_labeled(mw,
        "xrootd_s3_events_total",
        "Low-cardinality S3-compatible endpoint diagnostic events.",
        "event",
        xrootd_s3_event_names, XROOTD_S3_NEVENTS,
        shm->s3.events_total);

    mw_emit_scalar(mw,
        "xrootd_s3_list_contents_total",
        "S3 ListObjectsV2 Contents entries emitted.",
        &shm->s3.list_contents_total);

    mw_emit_scalar(mw,
        "xrootd_s3_list_common_prefixes_total",
        "S3 ListObjectsV2 CommonPrefixes entries emitted.",
        &shm->s3.list_common_prefixes_total);

    mw_emit_scalar(mw,
        "xrootd_s3_list_truncated_total",
        "S3 ListObjectsV2 responses that returned a continuation token.",
        &shm->s3.list_truncated_total);
}
