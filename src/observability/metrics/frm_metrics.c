/*
 * frm/metrics.c — Prometheus exporter for the FRM tape-stage subsystem.
 *
 * WHAT: Emits the brix_frm_* metric families from the shared metrics block:
 *   stage requests/dedup/reject counters, success and fail-by-reason counters,
 *   the in-flight gauge, the evict/migrate/purge/cmsd-have/async counters, and a
 *   coarse seconds-scale stage-latency histogram.
 *
 * WHY: Tape staging is the one FRM operation an operator must watch (recall rate,
 *   failure rate, queue saturation, recall latency). These counters are the
 *   observability surface promised by Phase 1's Definition of Done. Like every
 *   other exporter the labels are strictly low-cardinality (a fixed fail reason);
 *   never a path/DN/reqid (INVARIANT #8).
 *
 * HOW: Counters are written lock-free by the stream-side FRM engine (queue.c /
 *   stage.c) via the BRIX_FRM_METRIC_* macros into shm->frm; this file only
 *   READS them (ngx_atomic_fetch_add(..., 0)) at scrape time, so the snapshot is
 *   eventually consistent. The histogram is stored non-cumulative in SHM and
 *   cumulated into Prometheus `le` buckets here, exactly like unified.c. This unit
 *   is compiled into the HTTP metrics module (it runs at /metrics request time),
 *   so it must NOT call stream-module symbols (frm_index_count etc.) — every
 *   value comes from the shared SHM block alone.
 */

#include "metrics_internal.h"

/* Fail-reason labels — order matches BRIX_FRM_FAIL_* in metrics.h. */
static const char *brix_frm_fail_names[BRIX_FRM_NFAIL] = {
    "copycmd",
    "dispatch",
    "timeout",
    "verify",
    "other",
};

/* Histogram upper bounds in seconds; the final (+Inf) bucket is implicit. */
static const unsigned long
brix_frm_latency_bounds[BRIX_FRM_LATENCY_BUCKETS - 1] = {
    1, 10, 30, 60, 300, 1800, 3600,
};

void
brix_export_frm_metrics(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    unsigned long long  value;
    ngx_uint_t          b;

    mw_emit_scalar(mw, "brix_frm_requests_total",
        "Tape stage requests admitted to the FRM durable queue.",
        &shm->frm.requests_total);
    mw_emit_scalar(mw, "brix_frm_dedup_hits_total",
        "Stage opens collapsed onto an already in-flight recall.",
        &shm->frm.dedup_hits_total);
    mw_emit_scalar(mw, "brix_frm_reject_inflight_total",
        "Stage requests refused because the queue was at max_inflight.",
        &shm->frm.reject_inflight_total);
    mw_emit_scalar(mw, "brix_frm_stage_success_total",
        "Recalls that completed and brought the file online.",
        &shm->frm.stage_success_total);

    mw_emit_labeled(mw, "brix_frm_stage_fail_total",
        "Recalls that failed, by coarse reason.",
        "reason", brix_frm_fail_names, BRIX_FRM_NFAIL,
        shm->frm.stage_fail_total);

    mw_emit_scalar(mw, "brix_frm_evict_total",
        "kXR_evict / Tape-REST release marks applied.",
        &shm->frm.evict_total);
    mw_emit_scalar(mw, "brix_frm_waitresp_total",
        "Async stalled opens parked with kXR_waitresp.",
        &shm->frm.waitresp_total);
    mw_emit_scalar(mw, "brix_frm_asynresp_total",
        "Async stage completions delivered via kXR_attn(asynresp).",
        &shm->frm.asynresp_total);
    mw_emit_scalar(mw, "brix_frm_cmsd_have_total",
        "Now-resident paths registered with the manager (cmsd Have).",
        &shm->frm.cmsd_have_total);
    mw_emit_scalar(mw, "brix_frm_migrate_total",
        "Category-2 migrate-out attempts (scaffolding).",
        &shm->frm.migrate_total);
    mw_emit_scalar(mw, "brix_frm_purge_total",
        "Category-2 purge decisions logged (scaffolding).",
        &shm->frm.purge_total);

    /* in_flight is a GAUGE — mw_emit_scalar declares TYPE counter, so emit the
     * gauge banner + value by hand (the stream.c pattern). */
    mw_printf(mw,
        "# HELP brix_frm_in_flight Stage requests currently QUEUED or STAGING.\n"
        "# TYPE brix_frm_in_flight gauge\n"
        "brix_frm_in_flight %lu\n",
        (unsigned long) ngx_atomic_fetch_add(&shm->frm.in_flight, 0));

    /*
     * Stage-latency histogram (seconds). The write side increments only the one
     * bucket each recall lands in; Prometheus `le` buckets are cumulative, so the
     * running sum is reported per bucket and the +Inf bucket equals the count.
     */
    mw_printf(mw,
        "# HELP brix_frm_stage_latency_seconds Tape recall latency in seconds.\n"
        "# TYPE brix_frm_stage_latency_seconds histogram\n");
    value = 0;
    for (b = 0; b < BRIX_FRM_LATENCY_BUCKETS - 1; b++) {
        value += (unsigned long long)
            ngx_atomic_fetch_add(&shm->frm.stage_latency_bucket[b], 0);
        mw_printf(mw,
            "brix_frm_stage_latency_seconds_bucket{le=\"%lu\"} %llu\n",
            brix_frm_latency_bounds[b], value);
    }
    value += (unsigned long long) ngx_atomic_fetch_add(
        &shm->frm.stage_latency_bucket[BRIX_FRM_LATENCY_BUCKETS - 1], 0);
    mw_printf(mw,
        "brix_frm_stage_latency_seconds_bucket{le=\"+Inf\"} %llu\n", value);
    mw_printf(mw,
        "brix_frm_stage_latency_seconds_sum %llu\n"
        "brix_frm_stage_latency_seconds_count %llu\n",
        (unsigned long long) ngx_atomic_fetch_add(
            &shm->frm.stage_latency_sum_sec, 0),
        (unsigned long long) ngx_atomic_fetch_add(
            &shm->frm.stage_latency_count, 0));
}
