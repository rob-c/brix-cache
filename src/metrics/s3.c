#include "metrics_internal.h"

/*
 * WHAT: Prometheus metrics export for the S3-compatible HTTP endpoint.
 * WHY: The S3 endpoint receives requests from XrdClS3, aws s3 CLI, and other S3-compatible clients.
 *      These counters track request volume, response status classes, authentication outcomes (SigV4 vs anonymous),
 *      data transfer volumes, range handling, PUT body modes, diagnostic events, and ListObjectsV2 pagination stats.
 * HOW: Seven static string tables map slot indices to low-cardinality label strings per INVARIANT #8; one public function
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
    "OTHER",
};

/* ---- static table: HTTP status class names ----
 * WHAT: Label strings for xrootd_s3_responses_total{status_class} counters.
 * WHY: Grouping into 1xx/2xx/3xx/4xx/5xx prevents individual status-code label explosion while preserving error visibility. */

static const char *xrootd_s3_status_names[XROOTD_HTTP_NSTATUS] = {
    "1xx",
    "2xx",
    "3xx",
    "4xx",
    "5xx",
    "other",
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

/* ---- static table: S3 range request result names ----
 * WHAT: Label strings for xrootd_s3_range_requests_total counters. Tracks full vs partial GET responses and unsatisfied Range header conditions. */

static const char *xrootd_s3_range_names[XROOTD_S3_NRANGE_RESULTS] = {
    "full",
    "partial",
    "unsatisfied",
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
 * HOW: Iterate seven counter families via static name tables: requests_total, responses_total[method][status_class], auth_total, bytes_rx_tx, range_total, put_body_total, events_total, plus three ListObjectsV2 stats. All counters are unsigned long values cast from ngx_atomic_t fields. */

void
xrootd_export_s3_metrics(metrics_writer_t *mw, ngx_xrootd_metrics_t *shm)
{
    ngx_uint_t  i, method, status;

    mw_printf(mw,
        "# HELP xrootd_s3_requests_total "
            "S3-compatible endpoint requests received, by operation.\n"
        "# TYPE xrootd_s3_requests_total counter\n");
    for (method = 0; method < XROOTD_S3_NMETHODS; method++) {
        mw_printf(mw,
            "xrootd_s3_requests_total{method=\"%s\"} %lu\n",
            xrootd_s3_method_names[method],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->s3.requests_total[method], 0));
    }

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
                xrootd_s3_status_names[status],
                (unsigned long) ngx_atomic_fetch_add(
                    &shm->s3.responses_total[method][status], 0));
        }
    }

    mw_printf(mw,
        "# HELP xrootd_s3_auth_total "
            "S3 SigV4 or anonymous authentication outcomes.\n"
        "# TYPE xrootd_s3_auth_total counter\n");
    for (i = 0; i < XROOTD_S3_NAUTH_RESULTS; i++) {
        mw_printf(mw,
            "xrootd_s3_auth_total{result=\"%s\"} %lu\n",
            xrootd_s3_auth_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->s3.auth_total[i], 0));
    }

    mw_printf(mw,
        "# HELP xrootd_s3_bytes_rx_total "
            "Bytes accepted into successful S3-compatible PUT writes.\n"
        "# TYPE xrootd_s3_bytes_rx_total counter\n"
        "xrootd_s3_bytes_rx_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->s3.bytes_rx_total, 0));

    mw_printf(mw,
        "# HELP xrootd_s3_bytes_tx_total "
            "Bytes emitted by S3-compatible GET, LIST, and XML error responses.\n"
        "# TYPE xrootd_s3_bytes_tx_total counter\n"
        "xrootd_s3_bytes_tx_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->s3.bytes_tx_total, 0));

    mw_printf(mw,
        "# HELP xrootd_s3_range_requests_total "
            "S3-compatible GET range handling outcomes.\n"
        "# TYPE xrootd_s3_range_requests_total counter\n");
    for (i = 0; i < XROOTD_S3_NRANGE_RESULTS; i++) {
        mw_printf(mw,
            "xrootd_s3_range_requests_total{result=\"%s\"} %lu\n",
            xrootd_s3_range_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->s3.range_total[i], 0));
    }

    mw_printf(mw,
        "# HELP xrootd_s3_put_bodies_total "
            "S3-compatible PUT body storage modes observed after successful writes.\n"
        "# TYPE xrootd_s3_put_bodies_total counter\n");
    for (i = 0; i < XROOTD_S3_NPUT_MODES; i++) {
        mw_printf(mw,
            "xrootd_s3_put_bodies_total{mode=\"%s\"} %lu\n",
            xrootd_s3_put_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->s3.put_body_total[i], 0));
    }

    mw_printf(mw,
        "# HELP xrootd_s3_events_total "
            "Low-cardinality S3-compatible endpoint diagnostic events.\n"
        "# TYPE xrootd_s3_events_total counter\n");
    for (i = 0; i < XROOTD_S3_NEVENTS; i++) {
        mw_printf(mw,
            "xrootd_s3_events_total{event=\"%s\"} %lu\n",
            xrootd_s3_event_names[i],
            (unsigned long) ngx_atomic_fetch_add(
                &shm->s3.events_total[i], 0));
    }

    mw_printf(mw,
        "# HELP xrootd_s3_list_contents_total "
            "S3 ListObjectsV2 Contents entries emitted.\n"
        "# TYPE xrootd_s3_list_contents_total counter\n"
        "xrootd_s3_list_contents_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->s3.list_contents_total, 0));

    mw_printf(mw,
        "# HELP xrootd_s3_list_common_prefixes_total "
            "S3 ListObjectsV2 CommonPrefixes entries emitted.\n"
        "# TYPE xrootd_s3_list_common_prefixes_total counter\n"
        "xrootd_s3_list_common_prefixes_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->s3.list_common_prefixes_total, 0));

    mw_printf(mw,
        "# HELP xrootd_s3_list_truncated_total "
            "S3 ListObjectsV2 responses that returned a continuation token.\n"
        "# TYPE xrootd_s3_list_truncated_total counter\n"
        "xrootd_s3_list_truncated_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->s3.list_truncated_total, 0));
}
