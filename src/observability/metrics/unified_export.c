#include "unified_internal.h"

/*
 * unified_export.c — scrape-time exporter for the non-io unified families and
 * the top-level brix_export_unified_metrics orchestrator.
 *
 * WHAT: Renders the cred_select, cache (hits/misses/evicted + watermark reaper),
 *       write-back staging, auth, and tpc Prometheus families, and hosts the
 *       brix_export_unified_metrics entry point that fans out over every
 *       unified_emit_<family> helper (the io families live in
 *       unified_export_io.c). Also provides unified_emit_proto_counter, the
 *       generic per-proto counter renderer these families share.
 * WHY:  The exporter half of unified.c exceeded the file-size budget; this file
 *       owns the credential/cache/auth/tpc families and the orchestrator, while
 *       unified_export_io.c owns the byte/op/latency families and the legacy
 *       fold — two cohesive clusters, each in its own file (coding-standards §1).
 * HOW:  Each emitter reads its region of *shm via brix_metric_value and prints
 *       HELP/TYPE + per-label lines; labels stay low-cardinality (INVARIANT #8).
 *       The auth family folds in brix_unified_legacy_auth (root:// only). The
 *       orchestrator is a flat call sequence with frozen emission order/bytes.
 */

/*
 * unified_emit_proto_counter — emit a single HELP/TYPE header followed by one
 * per-protocol line reading counter values from `field`.
 *
 * WHAT: Generic per-proto counter renderer (proto label only, no fold).
 * WHY:  The cred_select and cache hit/miss/evicted families are all identical
 *       "HELP/TYPE + per-proto value" shapes; a shared emitter removes the
 *       copy-paste while keeping exposition bytes frozen.
 * HOW:  Caller passes the pre-formatted HELP/TYPE block and the per-proto
 *       counter array base; we print `metric_name{proto="…"} <value>` per proto.
 */
static void
unified_emit_proto_counter(metrics_writer_t *mw, const char *help_type,
    const char *metric_name, ngx_atomic_t *field)
{
    ngx_uint_t  proto;

    mw_printf(mw, "%s", help_type);
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        mw_printf(mw, "%s{proto=\"%s\"} %llu\n", metric_name,
                  brix_metric_proto_name((brix_proto_t) proto),
                  brix_metric_value(&field[proto]));
    }
}

/*
 * unified_emit_cred_select — render the three brix_cred_select_* families
 * (user / fallback / deny), each a per-protocol counter (Phase 2 Task 3).
 *
 * WHAT: Emits user, fallback, and deny credential-gate outcome counters.
 * WHY:  Groups the one credential-gate concern; labels stay low-cardinality
 *       (proto only — no DNs, keys, or principals, INVARIANT #8).
 * HOW:  Three unified_emit_proto_counter calls over the matching SHM arrays.
 */
static void
unified_emit_cred_select(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    unified_emit_proto_counter(mw,
        "# HELP brix_cred_select_user_total "
            "Per-user backend credential selected and used, by protocol.\n"
        "# TYPE brix_cred_select_user_total counter\n",
        "brix_cred_select_user_total",
        shm->unified.cred_select_user_total);

    unified_emit_proto_counter(mw,
        "# HELP brix_cred_select_fallback_total "
            "Service-credential fallback allowed (no/expired user cred or driver "
            "incapable; fallback_deny=0), by protocol.\n"
        "# TYPE brix_cred_select_fallback_total counter\n",
        "brix_cred_select_fallback_total",
        shm->unified.cred_select_fallback_total);

    unified_emit_proto_counter(mw,
        "# HELP brix_cred_select_deny_total "
            "Request rejected at the credential gate (EACCES; fallback_deny=1), "
            "by protocol.\n"
        "# TYPE brix_cred_select_deny_total counter\n",
        "brix_cred_select_deny_total",
        shm->unified.cred_select_deny_total);
}

/*
 * unified_emit_cache — render the per-protocol cache families
 * (hits / misses / bytes_evicted).
 *
 * WHAT: Emits the three per-proto cache counters.
 * WHY:  Groups the cache-lookup outcome concern behind one call.
 * HOW:  Three unified_emit_proto_counter calls over the matching SHM arrays.
 */
static void
unified_emit_cache(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    unified_emit_proto_counter(mw,
        "# HELP brix_cache_hits_total Cache hits by protocol.\n"
        "# TYPE brix_cache_hits_total counter\n",
        "brix_cache_hits_total", shm->unified.cache_hits);

    unified_emit_proto_counter(mw,
        "# HELP brix_cache_misses_total Cache misses by protocol.\n"
        "# TYPE brix_cache_misses_total counter\n",
        "brix_cache_misses_total", shm->unified.cache_misses);

    unified_emit_proto_counter(mw,
        "# HELP brix_cache_bytes_evicted_total Cache bytes evicted, by protocol.\n"
        "# TYPE brix_cache_bytes_evicted_total counter\n",
        "brix_cache_bytes_evicted_total", shm->unified.cache_bytes_evicted);
}

/*
 * unified_emit_cache_watermark — render the watermark-reaper cache families.
 *
 * WHAT: Emits the usage_ratio gauge plus the purges/evicted-files/evicted-bytes
 *       counters produced by the background watermark reaper.
 * WHY:  The connection-less reaper has a dedicated series so it never collides
 *       with the per-proto/per-server eviction counters.
 * HOW:  usage_ratio is a ppm-stored gauge rendered as a 0-1 double; the rest are
 *       plain single-value counters.
 */
static void
unified_emit_cache_watermark(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    mw_printf(mw,
        "# HELP brix_cache_usage_ratio Cache filesystem occupancy (0-1).\n"
        "# TYPE brix_cache_usage_ratio gauge\n"
        "brix_cache_usage_ratio %.6f\n",
        (double) brix_metric_value(&shm->unified.cache_usage_ratio_ppm)
            / 1000000.0);

    mw_printf(mw,
        "# HELP brix_cache_watermark_purges_total Watermark reaper purge runs that reclaimed space.\n"
        "# TYPE brix_cache_watermark_purges_total counter\n"
        "brix_cache_watermark_purges_total %llu\n",
        brix_metric_value(&shm->unified.cache_watermark_purges));

    mw_printf(mw,
        "# HELP brix_cache_watermark_evicted_files_total Files reaped by the watermark reaper.\n"
        "# TYPE brix_cache_watermark_evicted_files_total counter\n"
        "brix_cache_watermark_evicted_files_total %llu\n",
        brix_metric_value(&shm->unified.cache_watermark_evicted_files));

    mw_printf(mw,
        "# HELP brix_cache_watermark_evicted_bytes_total Bytes reaped by the watermark reaper.\n"
        "# TYPE brix_cache_watermark_evicted_bytes_total counter\n"
        "brix_cache_watermark_evicted_bytes_total %llu\n",
        brix_metric_value(&shm->unified.cache_watermark_evicted_bytes));
}

/*
 * unified_emit_wt_stage — render the write-back-staging backpressure families.
 *
 * WHAT: Emits the wt_stage usage_ratio gauge and the throttled_total counter
 *       (split by wait vs reject action).
 * WHY:  Groups the staging-backpressure concern behind one call.
 * HOW:  usage_ratio is a ppm-stored gauge rendered 0-1; throttled_total carries
 *       an action label for the two shed outcomes.
 */
static void
unified_emit_wt_stage(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    mw_printf(mw,
        "# HELP brix_wt_stage_usage_ratio Write-back staging filesystem occupancy (0-1).\n"
        "# TYPE brix_wt_stage_usage_ratio gauge\n"
        "brix_wt_stage_usage_ratio %.6f\n",
        (double) brix_metric_value(&shm->unified.wt_stage_usage_ratio_ppm)
            / 1000000.0);

    mw_printf(mw,
        "# HELP brix_wt_stage_throttled_total Writes shed by staging backpressure, by action.\n"
        "# TYPE brix_wt_stage_throttled_total counter\n"
        "brix_wt_stage_throttled_total{action=\"wait\"} %llu\n"
        "brix_wt_stage_throttled_total{action=\"reject\"} %llu\n",
        brix_metric_value(&shm->unified.wt_stage_throttled_wait),
        brix_metric_value(&shm->unified.wt_stage_throttled_reject));
}

/*
 * unified_emit_auth — render the brix_auth_total family
 * (per-proto/method/status authentication counters).
 *
 * WHAT: Emits the HELP/TYPE header + one line per (proto, method, status) cell.
 * WHY:  Isolates the triple-nested loop and the root:// legacy auth fold.
 * HOW:  Each cell folds in brix_unified_legacy_auth (non-zero for root:// only)
 *       before printing; method/status labels come from the shared name tables.
 */
static void
unified_emit_auth(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t          proto, method, status;
    unsigned long long  value;

    mw_printf(mw,
        "# HELP brix_auth_total Authentication attempts by protocol, method, and status.\n"
        "# TYPE brix_auth_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (method = 0; method < BRIX_METRIC_AUTH_COUNT; method++) {
            for (status = 0; status < BRIX_METRIC_AUTH_STATUS_COUNT; status++) {
                value = brix_metric_value(
                    &shm->unified.auth_total[proto][method][status]);
                value += brix_unified_legacy_auth(
                    shm, (brix_proto_t) proto, method, status);
                mw_printf(mw,
                    "brix_auth_total"
                    "{proto=\"%s\",method=\"%s\",status=\"%s\"} %llu\n",
                    brix_metric_proto_name((brix_proto_t) proto),
                    brix_unified_auth_names[method],
                    status == BRIX_METRIC_AUTH_OK ? "ok" : "fail",
                    value);
            }
        }
    }
}

/*
 * unified_emit_tpc — render the brix_tpc_transfers_total + brix_tpc_bytes_total
 * families (third-party-copy outcomes and successful bytes).
 *
 * WHAT: Emits the per-(proto, direction, status) transfer counters and the
 *       per-(proto, direction) successful-byte counters.
 * WHY:  The two TPC families share the proto × direction iteration, so one
 *       helper keeps them together.
 * HOW:  Two loops: transfers add the status dimension, bytes do not.
 */
static void
unified_emit_tpc(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t  proto, direction, err;

    mw_printf(mw,
        "# HELP brix_tpc_transfers_total Third-party-copy transfer outcomes.\n"
        "# TYPE brix_tpc_transfers_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (direction = 0; direction < BRIX_METRIC_TPC_DIRECTION_COUNT;
             direction++)
        {
            for (err = 0; err < BRIX_ERR_COUNT; err++) {
                mw_printf(mw,
                    "brix_tpc_transfers_total"
                    "{proto=\"%s\",direction=\"%s\",status=\"%s\"} %llu\n",
                    brix_metric_proto_name((brix_proto_t) proto),
                    brix_unified_tpc_direction_names[direction],
                    brix_metric_err_name((brix_err_class_t) err),
                    brix_metric_value(&shm->unified.tpc_transfers
                        [proto][direction][err]));
            }
        }
    }

    mw_printf(mw,
        "# HELP brix_tpc_bytes_total Successful third-party-copy bytes.\n"
        "# TYPE brix_tpc_bytes_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (direction = 0; direction < BRIX_METRIC_TPC_DIRECTION_COUNT;
             direction++)
        {
            mw_printf(mw,
                "brix_tpc_bytes_total{proto=\"%s\",direction=\"%s\"} %llu\n",
                brix_metric_proto_name((brix_proto_t) proto),
                brix_unified_tpc_direction_names[direction],
                brix_metric_value(&shm->unified.tpc_bytes[proto][direction]));
        }
    }
}

/*
 * brix_export_unified_metrics — render all unified counter families to the
 * Prometheus text writer: io bytes read/written, io_ops_total, the io latency
 * histogram (cumulated from non-cumulative storage), cache hits/misses/evicted,
 * auth_total, and tpc transfers/bytes — each as HELP/TYPE plus per-label lines.
 * Legacy per-server stream counters are folded into the stream-protocol values.
 * The body is a flat call sequence over one unified_emit_<family> helper per
 * metric family; emission order and exposition bytes are frozen. The io families
 * live in unified_export_io.c; the rest are defined above.
 */
void
brix_export_unified_metrics(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    unified_emit_io_bytes(mw, shm);
    unified_emit_io_ops(mw, shm);
    unified_emit_io_latency(mw, shm);
    unified_emit_cred_select(mw, shm);
    unified_emit_cache(mw, shm);
    unified_emit_cache_watermark(mw, shm);
    unified_emit_wt_stage(mw, shm);
    unified_emit_auth(mw, shm);
    unified_emit_tpc(mw, shm);
}
