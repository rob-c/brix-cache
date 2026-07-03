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

/* S3 HTTP method name labels for the requests_total / responses_total counters.
 * A fixed enum keeps the labels low-cardinality (INVARIANT #8) — no bucket-name or
 * request-type explosion. */

static const char *brix_s3_method_names[BRIX_S3_NMETHODS] = {
    "GET",
    "HEAD",
    "PUT",
    "DELETE",
    "LIST",
    "POST",
    "OPTIONS",
    "OTHER",
};

/* S3 auth-result name labels for the auth_total counters; SigV4-specific results
 * (signature_mismatch, bad_access_key) are tracked separately per INVARIANT #6. */

static const char *brix_s3_auth_names[BRIX_S3_NAUTH_RESULTS] = {
    "anonymous",
    "sigv4_ok",
    "missing",
    "malformed",
    "bad_access_key",
    "bad_date",
    "signature_mismatch",
    "internal_error",
};

/* S3 PUT body storage-mode labels for the put_bodies_total counters (in memory,
 * spooled to disk, or mixed, after a successful write). */

static const char *brix_s3_put_names[BRIX_S3_NPUT_MODES] = {
    "empty",
    "memory",
    "spooled",
    "mixed",
};

/* S3 diagnostic-event labels for the low-cardinality events_total counter
 * (URI validation failures, access denied, write disabled). */

static const char *brix_s3_event_names[BRIX_S3_NEVENTS] = {
    "invalid_uri",
    "access_denied",
    "no_such_key",
    "write_disabled",
    "method_not_allowed",
    "internal_error",
    "dir_sentinel",
    "delete_missing",
};

/* brix_export_s3_metrics — write all S3-endpoint Prometheus metrics (HELP/TYPE +
 * data, text format 0.0.4) into the writer buffer chain, reading shm->s3 counters
 * via ngx_atomic_fetch_add(...,0) for an eventually-consistent snapshot. Iterates
 * the counter families (requests/responses[method][class], auth, bytes, range, put
 * body, events, + the ListObjectsV2 stats) using the static name tables above. */

void
brix_export_s3_metrics(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t  method, status;

    mw_emit_labeled(mw,
        "brix_s3_requests_total",
        "S3-compatible endpoint requests received, by operation.",
        "method",
        brix_s3_method_names, BRIX_S3_NMETHODS,
        shm->s3.requests_total);

    mw_printf(mw,
        "# HELP brix_s3_responses_total "
            "S3-compatible endpoint responses by operation and HTTP status class.\n"
        "# TYPE brix_s3_responses_total counter\n");
    for (method = 0; method < BRIX_S3_NMETHODS; method++) {
        for (status = 0; status < BRIX_HTTP_NSTATUS; status++) {
            mw_printf(mw,
                "brix_s3_responses_total"
                    "{method=\"%s\",status_class=\"%s\"} %lu\n",
                brix_s3_method_names[method],
                brix_http_status_names[status],
                (unsigned long) ngx_atomic_fetch_add(
                    &shm->s3.responses_total[method][status], 0));
        }
    }

    mw_emit_labeled(mw,
        "brix_s3_auth_total",
        "S3 SigV4 or anonymous authentication outcomes.",
        "result",
        brix_s3_auth_names, BRIX_S3_NAUTH_RESULTS,
        shm->s3.auth_total);

    mw_printf(mw,
        "# DEPRECATED: use brix_io_bytes_written{proto=\"s3\"} "
            "for protocol-neutral write throughput.\n"
        "# HELP brix_s3_bytes_rx_total "
            "Bytes accepted into successful S3-compatible PUT writes.\n"
        "# TYPE brix_s3_bytes_rx_total counter\n"
        "brix_s3_bytes_rx_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->s3.bytes_rx_total, 0));

    mw_printf(mw,
        "# DEPRECATED: use brix_io_bytes_read{proto=\"s3\"} "
            "for protocol-neutral read throughput.\n"
        "# HELP brix_s3_bytes_tx_total "
            "Bytes emitted by S3-compatible GET, LIST, and XML error responses.\n"
        "# TYPE brix_s3_bytes_tx_total counter\n"
        "brix_s3_bytes_tx_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(
            &shm->s3.bytes_tx_total, 0));

    mw_emit_scalar(mw,
        "brix_s3_bytes_rx_ipv4_total",
        "Bytes received from IPv4 clients via S3-compatible PUT.",
        &shm->s3.bytes_rx_ipv4_total);

    mw_emit_scalar(mw,
        "brix_s3_bytes_tx_ipv4_total",
        "Bytes sent to IPv4 clients via S3-compatible GET.",
        &shm->s3.bytes_tx_ipv4_total);

    mw_emit_labeled(mw,
        "brix_s3_range_requests_total",
        "S3-compatible GET range handling outcomes.",
        "result",
        brix_http_range_result_names, BRIX_S3_NRANGE_RESULTS,
        shm->s3.range_total);

    mw_emit_labeled(mw,
        "brix_s3_put_bodies_total",
        "S3-compatible PUT body storage modes observed after successful writes.",
        "mode",
        brix_s3_put_names, BRIX_S3_NPUT_MODES,
        shm->s3.put_body_total);

    mw_emit_labeled(mw,
        "brix_s3_events_total",
        "Low-cardinality S3-compatible endpoint diagnostic events.",
        "event",
        brix_s3_event_names, BRIX_S3_NEVENTS,
        shm->s3.events_total);

    mw_emit_scalar(mw,
        "brix_s3_list_contents_total",
        "S3 ListObjectsV2 Contents entries emitted.",
        &shm->s3.list_contents_total);

    mw_emit_scalar(mw,
        "brix_s3_list_common_prefixes_total",
        "S3 ListObjectsV2 CommonPrefixes entries emitted.",
        &shm->s3.list_common_prefixes_total);

    mw_emit_scalar(mw,
        "brix_s3_list_truncated_total",
        "S3 ListObjectsV2 responses that returned a continuation token.",
        &shm->s3.list_truncated_total);
}
