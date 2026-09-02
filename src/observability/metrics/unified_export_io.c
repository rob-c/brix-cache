#include "unified_internal.h"

#include <string.h>

/*
 * unified_export_io.c — scrape-time exporter for the unified brix_io_* families
 * plus the shared counter-reader and the legacy per-server stream fold.
 *
 * WHAT: Renders the three brix_io_* Prometheus families — io_bytes_{read,
 *       written}, io_ops_total, and the io_latency_usec histogram — and hosts
 *       the two helpers shared with the rest of the exporter: brix_metric_value
 *       (lock-free counter load) and the legacy-bridge functions that fold the
 *       predating per-server stream counters (servers[].op_ok/op_err/bytes_*,
 *       auth string) into the unified stream-protocol rows, including the
 *       export-time auth fold (brix_unified_legacy_auth) called from the auth
 *       exporter in unified_export.c.
 * WHY:  The exporter half of unified.c grew past the file-size budget; the io
 *       families plus the legacy-bridge machinery form one cohesive cluster,
 *       distinct from the cred/cache/auth/tpc families in unified_export.c.
 * HOW:  Each emitter reads its region of *shm with brix_metric_value, folds in
 *       the matching legacy stream totals for root:// (and the webdav/s3 per-
 *       server tx/rx totals for io_bytes), and prints HELP/TYPE + per-label
 *       lines. The latency histogram is stored NON-cumulative, so the series
 *       helper cumulates buckets as it emits them (Prometheus `le` semantics).
 *       Exposition bytes and emission order are frozen against the prior form.
 */

/* Lock-free read of an atomic counter (fetch-add of 0) as an unsigned long long. */
unsigned long long
brix_metric_value(ngx_atomic_t *counter)
{
    return (unsigned long long) ngx_atomic_fetch_add(counter, 0);
}

/*
 * Legacy-bridge helpers (brix_unified_legacy_*): the stream protocol predates
 * the unified counters and still records into the per-server servers[] slots
 * (op_ok/op_err/bytes_rx/bytes_tx and the auth string). These functions sum the
 * matching in-use servers[] slots so the exporter can fold legacy stream activity
 * into the unified stream-protocol values, keeping /metrics output continuous.
 * They are export-time read-only aggregations — never used on the record path.
 * The op fold is restricted to READ/WRITE: namespace ops are observed by the
 * VFS layer into the unified counters directly, so folding their wire-ledger
 * slots too would double-count every stat/delete/mkdir/rename/dirlist.
 */
static unsigned long long
brix_unified_legacy_stream_bytes(ngx_brix_metrics_t *shm,
    unsigned int is_write)
{
    ngx_brix_srv_metrics_t *srv;
    ngx_uint_t                i;
    unsigned long long        total;

    total = 0;
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) {
            continue;
        }
        total += is_write
            ? brix_metric_value(&srv->bytes_rx_total)
            : brix_metric_value(&srv->bytes_tx_total);
    }

    return total;
}

static unsigned long long
brix_unified_legacy_stream_op_slot(ngx_brix_metrics_t *shm,
    ngx_uint_t slot, unsigned int ok)
{
    ngx_brix_srv_metrics_t *srv;
    ngx_uint_t                i;
    unsigned long long        total;

    if (slot >= BRIX_NOPS) {
        return 0;
    }

    total = 0;
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) {
            continue;
        }
        total += ok ? brix_metric_value(&srv->op_ok[slot])
                    : brix_metric_value(&srv->op_err[slot]);
    }

    return total;
}

static unsigned long long
brix_unified_legacy_stream_op(ngx_brix_metrics_t *shm,
    brix_metric_op_t op, unsigned int ok)
{
    switch (op) {
    case BRIX_METRIC_OP_READ:
        return brix_unified_legacy_stream_op_slot(shm, BRIX_OP_READ, ok)
             + brix_unified_legacy_stream_op_slot(shm, BRIX_OP_READV, ok)
             + brix_unified_legacy_stream_op_slot(shm, BRIX_OP_PGREAD, ok);
    case BRIX_METRIC_OP_WRITE:
        return brix_unified_legacy_stream_op_slot(shm, BRIX_OP_WRITE, ok)
             + brix_unified_legacy_stream_op_slot(shm, BRIX_OP_WRITEV, ok);
    default:
        /* Namespace ops (stat/delete/mkdir/rename/dirlist/...) are observed
         * once by the VFS layer for every protocol including root://; folding
         * the wire ledger for them here would count each op twice. Only the
         * AIO data plane (READ/WRITE) bypasses VFS observation and needs the
         * legacy fold. */
        return 0;
    }
}

static ngx_uint_t
brix_unified_srv_auth_slot(const char *auth)
{
    if (auth == NULL) {
        return BRIX_METRIC_AUTH_NONE;
    }
    if (strncmp(auth, "gsi", 3) == 0) {
        return BRIX_METRIC_AUTH_GSI;
    }
    if (strncmp(auth, "sss", 3) == 0) {
        return BRIX_METRIC_AUTH_SSS;
    }
    if (strncmp(auth, "token", 5) == 0) {
        return BRIX_METRIC_AUTH_TOKEN;
    }
    if (strncmp(auth, "unix", 4) == 0) {
        return BRIX_METRIC_AUTH_UNIX;
    }
    if (strncmp(auth, "krb5", 4) == 0) {
        return BRIX_METRIC_AUTH_KRB5;
    }

    return BRIX_METRIC_AUTH_NONE;
}

static unsigned long long
brix_unified_legacy_stream_auth(ngx_brix_metrics_t *shm,
    ngx_uint_t method, ngx_uint_t status)
{
    ngx_brix_srv_metrics_t *srv;
    ngx_uint_t                i;
    unsigned long long        total;

    total = 0;
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use || brix_unified_srv_auth_slot(srv->auth) != method) {
            continue;
        }
        total += status == BRIX_METRIC_AUTH_OK
            ? brix_metric_value(&srv->op_ok[BRIX_OP_AUTH])
            : brix_metric_value(&srv->op_err[BRIX_OP_AUTH]);
    }

    return total;
}

unsigned long long
brix_unified_legacy_auth(ngx_brix_metrics_t *shm, brix_proto_t proto,
    ngx_uint_t method, ngx_uint_t status)
{
    if (proto == BRIX_PROTO_ROOT) {
        return brix_unified_legacy_stream_auth(shm, method, status);
    }

    (void) method;
    (void) status;
    return 0;
}

/*
 * unified_emit_io_bytes — render the brix_io_bytes_read + brix_io_bytes_written
 * families (per-protocol byte totals).
 *
 * WHAT: Emits both io_bytes_{read,written} HELP/TYPE + per-proto lines.
 * WHY:  The two directions share the same shape (unified total + a per-proto
 *       legacy/http fold), so one helper keeps their emission logic together.
 * HOW:  For each proto, read the unified counter then fold in the legacy stream
 *       bytes (root) or the webdav/s3 per-server tx/rx totals; note read folds
 *       the *tx* side and written folds the *rx* side (client-perspective naming).
 */
void
unified_emit_io_bytes(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t          proto;
    unsigned long long  value;

    mw_printf(mw,
        "# HELP brix_io_bytes_read Total bytes read from storage, by protocol.\n"
        "# TYPE brix_io_bytes_read counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        value = brix_metric_value(&shm->unified.io_bytes_read[proto]);
        if (proto == BRIX_PROTO_ROOT) {
            value += brix_unified_legacy_stream_bytes(shm, 0);
        } else if (proto == BRIX_PROTO_WEBDAV) {
            value += brix_metric_value(&shm->webdav.bytes_tx_total);
        } else if (proto == BRIX_PROTO_S3) {
            value += brix_metric_value(&shm->s3.bytes_tx_total);
        }
        mw_printf(mw, "brix_io_bytes_read{proto=\"%s\"} %llu\n",
                  brix_metric_proto_name((brix_proto_t) proto), value);
    }

    mw_printf(mw,
        "# HELP brix_io_bytes_written Total bytes written to storage, by protocol.\n"
        "# TYPE brix_io_bytes_written counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        value = brix_metric_value(&shm->unified.io_bytes_written[proto]);
        if (proto == BRIX_PROTO_ROOT) {
            value += brix_unified_legacy_stream_bytes(shm, 1);
        } else if (proto == BRIX_PROTO_WEBDAV) {
            value += brix_metric_value(&shm->webdav.bytes_rx_total);
        } else if (proto == BRIX_PROTO_S3) {
            value += brix_metric_value(&shm->s3.bytes_rx_total);
        }
        mw_printf(mw, "brix_io_bytes_written{proto=\"%s\"} %llu\n",
                  brix_metric_proto_name((brix_proto_t) proto), value);
    }
}

/*
 * unified_emit_io_ops — render the brix_io_ops_total family
 * (per-proto/op/status operation counters).
 *
 * WHAT: Emits the HELP/TYPE header + one line per (proto, op, status) triple.
 * WHY:  Isolates the triple-nested loop and the root:// legacy fold from the
 *       exporter orchestrator.
 * HOW:  For root:// the ok(err==NONE) and error(err==OTHER) legacy stream op
 *       totals are added in — matching the legacy ok/err split — before printing.
 */
void
unified_emit_io_ops(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t          proto, op, err;
    unsigned long long  value;

    mw_printf(mw,
        "# HELP brix_io_ops_total I/O operations completed, by protocol, operation, and status.\n"
        "# TYPE brix_io_ops_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (op = 0; op < BRIX_METRIC_OP_COUNT; op++) {
            for (err = 0; err < BRIX_ERR_COUNT; err++) {
                value = brix_metric_value(
                    &shm->unified.io_ops_total[proto][op][err]);
                if (proto == BRIX_PROTO_ROOT) {
                    if (err == BRIX_ERR_NONE) {
                        value += brix_unified_legacy_stream_op(
                            shm, (brix_metric_op_t) op, 1);
                    } else if (err == BRIX_ERR_OTHER) {
                        value += brix_unified_legacy_stream_op(
                            shm, (brix_metric_op_t) op, 0);
                    }
                }
                mw_printf(mw,
                    "brix_io_ops_total"
                    "{proto=\"%s\",op=\"%s\",status=\"%s\"} %llu\n",
                    brix_metric_proto_name((brix_proto_t) proto),
                    brix_metric_op_name((brix_metric_op_t) op),
                    brix_metric_err_name((brix_err_class_t) err),
                    value);
            }
        }
    }
}

/*
 * unified_emit_io_latency_series — render the bucket/sum/count lines for ONE
 * (proto, op) latency series.
 *
 * WHAT: Emits the cumulative le="…" buckets, the le="+Inf" bucket, and the
 *       _sum/_count lines for a single protocol+operation.
 * WHY:  The per-series cumulation is the only stateful part of the histogram;
 *       confining it here keeps unified_emit_io_latency a flat double loop.
 * HOW:  Storage is NON-cumulative (each I/O bumps only its own bucket), so the
 *       running `value` accumulates lower buckets as they are emitted; the +Inf
 *       bucket then equals the total count. Byte-frozen against the prior inline
 *       form.
 */
/* Emit one histogram bucket line, le rendered in the family's unit
 * (µs integer, or seconds with %.6f — phase-110 W11). */
static void
unified_emit_latency_bucket(metrics_writer_t *mw, const char *fam,
    const char *pn, const char *opn, ngx_msec_t bound_usec, int seconds,
    unsigned long long value)
{
    if (seconds) {
        mw_printf(mw, "%s_bucket{proto=\"%s\",op=\"%s\",le=\"%.6f\"} %llu\n",
                  fam, pn, opn, (double) bound_usec / 1000000.0, value);
    } else {
        mw_printf(mw, "%s_bucket{proto=\"%s\",op=\"%s\",le=\"%llu\"} %llu\n",
                  fam, pn, opn, (unsigned long long) bound_usec, value);
    }
}


/* One (proto, op) latency series under `fam`, in µs (seconds==0) or seconds
 * (seconds==1). phase-110 W11 renders the SAME SHM histogram in the uniform
 * `_seconds` unit beside the deprecated `_usec` family. */
static void
unified_emit_io_latency_series(metrics_writer_t *mw, ngx_brix_metrics_t *shm,
    ngx_uint_t proto, ngx_uint_t op, const char *fam, int seconds)
{
    const char         *pn = brix_metric_proto_name((brix_proto_t) proto);
    const char         *opn = brix_metric_op_name((brix_metric_op_t) op);
    unsigned long long  sum_usec;
    ngx_uint_t          bucket;
    unsigned long long  value;

    value = 0;
    for (bucket = 0; bucket < BRIX_IO_LATENCY_BUCKETS - 1; bucket++) {
        value += brix_metric_value(&shm->unified.io_latency_bucket
            [proto][op][bucket]);
        unified_emit_latency_bucket(mw, fam, pn, opn,
            brix_latency_bounds[bucket], seconds, value);
    }
    value += brix_metric_value(&shm->unified.io_latency_bucket
        [proto][op][BRIX_IO_LATENCY_BUCKETS - 1]);
    mw_printf(mw, "%s_bucket{proto=\"%s\",op=\"%s\",le=\"+Inf\"} %llu\n",
              fam, pn, opn, value);

    sum_usec = brix_metric_value(&shm->unified.io_latency_sum_usec[proto][op]);
    if (seconds) {
        mw_printf(mw, "%s_sum{proto=\"%s\",op=\"%s\"} %.6f\n",
                  fam, pn, opn, (double) sum_usec / 1000000.0);
    } else {
        mw_printf(mw, "%s_sum{proto=\"%s\",op=\"%s\"} %llu\n",
                  fam, pn, opn, sum_usec);
    }
    mw_printf(mw, "%s_count{proto=\"%s\",op=\"%s\"} %llu\n",
              fam, pn, opn,
              brix_metric_value(&shm->unified.io_latency_count[proto][op]));
}

/*
 * unified_emit_io_latency — render the brix_io_latency_usec histogram family.
 *
 * WHAT: Emits the HELP/TYPE header then delegates each (proto, op) series to
 *       unified_emit_io_latency_series.
 * WHY:  Splitting the per-series cumulation out keeps this a flat iterator.
 * HOW:  Double loop over proto × op; one helper call per series.
 */
void
unified_emit_io_latency(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t  proto, op;

    /* phase-110 W11: the canonical family in SECONDS (the uniform latency unit
     * — every latency histogram now carries the _seconds suffix, matching
     * brix_cvmfs_upstream_fill_duration_seconds / brix_frm_stage_latency_seconds
     * and the Prometheus convention). */
    mw_printf(mw,
        "# HELP brix_io_latency_seconds I/O operation latency in seconds.\n"
        "# TYPE brix_io_latency_seconds histogram\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (op = 0; op < BRIX_METRIC_OP_COUNT; op++) {
            unified_emit_io_latency_series(mw, shm, proto, op,
                "brix_io_latency_seconds", 1);
        }
    }

    /* DEPRECATED (removal phase-112): the µs-unit family, kept for one release
     * so existing dashboards/alerts on brix_io_latency_usec keep working. */
    mw_printf(mw,
        "# HELP brix_io_latency_usec I/O operation latency in microseconds "
        "(DEPRECATED — use brix_io_latency_seconds).\n"
        "# TYPE brix_io_latency_usec histogram\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (op = 0; op < BRIX_METRIC_OP_COUNT; op++) {
            unified_emit_io_latency_series(mw, shm, proto, op,
                "brix_io_latency_usec", 0);
        }
    }
}

/*
 * unified_emit_io_slowop — render the §3.15 OssStats slowop classifier family.
 *
 * WHAT: A gauge for the armed latency threshold, then one counter per
 *       (proto, op) whose slow-op tally is non-zero.
 * WHY:  Stock OssStats reports slow-op counts as a first-class figure, distinct
 *       from the latency distribution: a dashboard alerts on the counter without
 *       re-deriving it from histogram buckets (whose boundaries are fixed, not
 *       the operator's threshold). The gauge makes the armed threshold visible
 *       so a scrape is self-describing.
 * HOW:  Emit the gauge unconditionally (0 = disabled); then skip zero counters
 *       so the family stays empty until a slow op is actually booked.
 */
void
unified_emit_io_slowop(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t          proto, op;
    unsigned long long  v;

    mw_printf(mw,
        "# HELP brix_io_slowop_threshold_usec Armed slow-op latency threshold "
        "in microseconds (0 = classifier disabled).\n"
        "# TYPE brix_io_slowop_threshold_usec gauge\n"
        "brix_io_slowop_threshold_usec %llu\n",
        (unsigned long long)
            brix_metric_value(&shm->unified.slowop_threshold_usec));

    mw_printf(mw,
        "# HELP brix_io_slowop_total Completed I/O ops whose latency met or "
        "exceeded brix_io_slowop_threshold_usec.\n"
        "# TYPE brix_io_slowop_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (op = 0; op < BRIX_METRIC_OP_COUNT; op++) {
            v = brix_metric_value(&shm->unified.io_slowop_total[proto][op]);
            if (v == 0) {
                continue;
            }
            mw_printf(mw,
                "brix_io_slowop_total{proto=\"%s\",op=\"%s\"} %llu\n",
                brix_metric_proto_name((brix_proto_t) proto),
                brix_metric_op_name((brix_metric_op_t) op),
                v);
        }
    }
}

/*
 * unified_emit_io_offload — render the §1.1 pathid response-offload counter: one
 * line per protocol that has routed at least one read-family response over a
 * bound secondary data channel. Absent (all-zero) when no client requested
 * offloading, so /metrics stays byte-identical for the common case.
 */
void
unified_emit_io_offload(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t          proto;
    unsigned long long  v;

    mw_printf(mw,
        "# HELP brix_io_offload_total Read-family responses (read/readv/pgread) "
        "routed over a bound secondary data channel (pathid response "
        "offloading).\n"
        "# TYPE brix_io_offload_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        v = brix_metric_value(&shm->unified.io_offload_total[proto]);
        if (v == 0) {
            continue;
        }
        mw_printf(mw,
            "brix_io_offload_total{proto=\"%s\"} %llu\n",
            brix_metric_proto_name((brix_proto_t) proto), v);
    }
}
