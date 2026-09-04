#include "unified_internal.h"

/*
 * unified_export.c — scrape-time exporter for the non-io unified families and
 * the top-level brix_export_unified_metrics orchestrator.
 *
 * WHAT: Renders the cred_select, cache (hits/misses/evicted + watermark reaper),
 *       write-back staging, auth, and tpc Prometheus families, and hosts the
 *       brix_export_unified_metrics entry point that fans out over every
 *       unified_emit_<family> helper (the io families live in
 *       unified_export_io.c, the phase-107 VFS-verb families in
 *       unified_export_vfs.c). Also provides unified_emit_proto_counter, the
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
 * unified_emit_cred_deleg — render the phase-70 delegation-gate families
 * (P90-70.6): brix_cred_deleg_total{proto,mode,outcome} and
 * brix_cred_deleg_fail_total{proto,reason}.
 *
 * WHAT: Emits the per-mode outcome cube and the closed failure-reason counters.
 * WHY:  cred_select_* only sees the SELECT path; these make the live-bag
 *       terminals (passthrough/exchange/…) observable per configured mode.
 *       All three label vocabularies are fixed enums (INVARIANT #8).
 * HOW:  Two nested loops over the SHM arrays, outcome names hardcoded to the
 *       three-value vocabulary cred_select_* already splits into families.
 */
static void
unified_emit_cred_deleg(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const char *outcome_names[BRIX_CRED_OUTCOME_COUNT] = {
        "user", "fallback", "deny",
    };
    ngx_uint_t  proto, mode, outcome, reason;

    mw_printf(mw,
        "# HELP brix_cred_deleg_total Delegation-gate terminal outcomes, by "
            "protocol, configured delegation mode, and outcome.\n"
        "# TYPE brix_cred_deleg_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (mode = 0; mode < BRIX_CRED_MODE_METRIC_COUNT; mode++) {
            for (outcome = 0; outcome < BRIX_CRED_OUTCOME_COUNT; outcome++) {
                mw_printf(mw,
                    "brix_cred_deleg_total"
                    "{proto=\"%s\",mode=\"%s\",outcome=\"%s\"} %llu\n",
                    brix_metric_proto_name((brix_proto_t) proto),
                    brix_metric_cred_mode_name(mode),
                    outcome_names[outcome],
                    brix_metric_value(
                        &shm->unified.cred_deleg_total[proto][mode][outcome]));
            }
        }
    }

    mw_printf(mw,
        "# HELP brix_cred_deleg_fail_total Delegation-gate failures by "
            "protocol and reason (closed vocabulary).\n"
        "# TYPE brix_cred_deleg_fail_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (reason = 0; reason < BRIX_CRED_FAIL_COUNT; reason++) {
            mw_printf(mw,
                "brix_cred_deleg_fail_total{proto=\"%s\",reason=\"%s\"} %llu\n",
                brix_metric_proto_name((brix_proto_t) proto),
                brix_metric_cred_fail_name((brix_cred_fail_t) reason),
                brix_metric_value(
                    &shm->unified.cred_deleg_fail_total[proto][reason]));
        }
    }
}

/*
 * unified_emit_vfs_mutation_denied — render the phase-105 read-only denial
 * family: brix_vfs_mutation_denied_total{proto,op,reason}.
 *
 * WHAT: Emits one counter per (protocol, bounded mutation operation), always
 *       with reason="read_only".
 * WHY:  Operators need to see that an endpoint configured read-only is actually
 *       refusing writes, and which family of write is being attempted, without
 *       the path/subject/key that would make the series unbounded.
 * HOW:  Two nested loops over the SHM cube; the reason label is a literal
 *       because EROFS is the sole VFS read-only mutation result.
 */
static void
unified_emit_vfs_mutation_denied(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t  proto, op;

    mw_printf(mw,
        "# HELP brix_vfs_mutation_denied_total Export mutations refused by the "
            "VFS read-only policy, by protocol and operation.\n"
        "# TYPE brix_vfs_mutation_denied_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (op = 0; op < BRIX_VFS_MUTATE_OP_METRIC_COUNT; op++) {
            mw_printf(mw,
                "brix_vfs_mutation_denied_total"
                "{proto=\"%s\",op=\"%s\",reason=\"read_only\"} %llu\n",
                brix_metric_proto_name((brix_proto_t) proto),
                brix_metric_vfs_mutate_op_name(op),
                brix_metric_value(
                    &shm->unified.vfs_mutation_denied_total[proto][op]));
        }
    }
}

/*
 * unified_emit_vfs_domain_mutation — render the phase-107 §7.5 domain axis:
 * brix_vfs_domain_mutation_total{domain,op}.
 *
 * WHAT: Emits one counter per (bounded storage domain, bounded mutation
 *       operation) — the service-storage mutations that passed the typed
 *       domain assert.
 * WHY:  Phase-108 §6.5: a consolidation that moves a write from a hand-rolled
 *       copy onto a domain-aware verb must show as a shift between two
 *       series; the export row stays zero by design (the export data path
 *       never books success-side — see unified_record_vfs.c).
 * HOW:  Two nested loops over the SHM cube; both label sets are compile-time
 *       bounded mirrors of the fs layer's enums (INVARIANT #8).
 */
static void
unified_emit_vfs_domain_mutation(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    ngx_uint_t  domain, op;

    mw_printf(mw,
        "# HELP brix_vfs_domain_mutation_total Service-storage mutations "
            "passed by the typed domain assert, by storage domain and "
            "operation.\n"
        "# TYPE brix_vfs_domain_mutation_total counter\n");
    for (domain = 0; domain < BRIX_VFS_DOMAIN_METRIC_COUNT; domain++) {
        for (op = 0; op < BRIX_VFS_MUTATE_OP_METRIC_COUNT; op++) {
            mw_printf(mw,
                "brix_vfs_domain_mutation_total"
                "{domain=\"%s\",op=\"%s\"} %llu\n",
                brix_metric_vfs_domain_name(domain),
                brix_metric_vfs_mutate_op_name(op),
                brix_metric_value(
                    &shm->unified.vfs_domain_mutation_total[domain][op]));
        }
    }
}

/*
 * unified_emit_vfs_authz_backstop — render the phase-108 C12 authorization
 * backstop family.
 *
 * WHAT: Emits vfs_authz_backstop_total{proto,result} across every protocol and
 *       the four bounded results.
 * WHY:  observe-mode evidence: enforce is a one-line flip once `edge_missing`
 *       (the backstop would have refused a request the edge allowed) and
 *       `unbound` (a ctx reached a mutation without a bound rule set) have been
 *       flat across the fleet for a release. AGREE is emitted too so the ratio
 *       is readable.
 * HOW:  Nested loops over the proto x result cube; both label sets are
 *       compile-time bounded mirrors of the fs layer's enums (INVARIANT #8).
 */
static void
unified_emit_vfs_authz_backstop(metrics_writer_t *mw,
    ngx_brix_metrics_t *shm)
{
    ngx_uint_t  proto, result;

    mw_printf(mw,
        "# HELP brix_vfs_authz_backstop_total VFS authorization-backstop "
            "evaluations, by protocol and result (agree|edge_missing|no_rules|"
            "unbound).\n"
        "# TYPE brix_vfs_authz_backstop_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        for (result = 0; result < BRIX_AUTHZ_BACKSTOP_RESULT_COUNT; result++) {
            mw_printf(mw,
                "brix_vfs_authz_backstop_total"
                "{proto=\"%s\",result=\"%s\"} %llu\n",
                brix_metric_proto_name(proto),
                brix_metric_vfs_authz_backstop_result_name(result),
                brix_metric_value(
                    &shm->unified.vfs_authz_backstop_total[proto][result]));
        }
    }
}

/*
 * unified_emit_vfs_spill — render the phase-107 C1 writer-spill families.
 *
 * WHAT: Emits the per-proto spill bytes/refused counters and the process-wide
 *       open-spill gauge.
 * WHY:  Distinguishes "no client reorders on this site" from "reordered
 *       uploads are being refused for want of spill scratch" — the operator
 *       signal behind the brix_vfs_spill_path/_max directives.
 * HOW:  Two unified_emit_proto_counter calls plus one single-line gauge.
 */
static void
unified_emit_vfs_spill(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    unified_emit_proto_counter(mw,
        "# HELP brix_vfs_spill_bytes_total "
            "Bytes absorbed into the writer's out-of-order spill scratch, "
            "by protocol.\n"
        "# TYPE brix_vfs_spill_bytes_total counter\n",
        "brix_vfs_spill_bytes_total",
        shm->unified.vfs_spill_bytes_total);

    unified_emit_proto_counter(mw,
        "# HELP brix_vfs_spill_refused_total "
            "Reordered uploads the spill could not serve (no scratch, "
            "capacity, overlap, or coverage hole), by protocol.\n"
        "# TYPE brix_vfs_spill_refused_total counter\n",
        "brix_vfs_spill_refused_total",
        shm->unified.vfs_spill_refused_total);

    mw_printf(mw,
        "# HELP brix_vfs_spill_active Writer spill scratches currently open.\n"
        "# TYPE brix_vfs_spill_active gauge\n"
        "brix_vfs_spill_active %llu\n",
        brix_metric_value(&shm->unified.vfs_spill_active));
}

/*
 * unified_emit_cache — render the per-protocol cache families
 * (requests-by-disposition / bytes_evicted).
 *
 * WHAT: Emits the labelled cache-lookup counter and the eviction counter.
 * WHY:  Groups the cache-lookup outcome concern behind one call.
 * HOW:  One proto x disposition loop, then one unified_emit_proto_counter.
 */
static void
unified_emit_cache(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t  proto;

    /* phase-110 W1: cache lookups carry the disposition as a LABEL VALUE from
     * brix_metric_cache_status_name(), i.e. the identical word
     * $brix_cache_status logs and the JSON "cache_status" key prints, so a
     * PromQL selector and a log grep share one string. Rendered from the SAME
     * SHM fields the removed brix_cache_{hits,misses}_total counters read (no
     * new counter, no layout change): HIT ← cache_hits, MISS ← cache_misses.
     * BYPASS has no counter and emits no series — an absent series is honest,
     * a zero one would claim a measurement. Phase 112 removed the two
     * one-fact-per-family counters this view replaced. */
    mw_printf(mw, "%s",
        "# HELP brix_cache_requests_total Cache lookups by protocol and "
        "disposition (HIT/MISS — the $brix_cache_status vocabulary).\n"
        "# TYPE brix_cache_requests_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        const char *pn = brix_metric_proto_name((brix_proto_t) proto);

        mw_printf(mw, "brix_cache_requests_total{proto=\"%s\","
                      "cache_status=\"%s\"} %llu\n", pn,
                  brix_metric_cache_status_name(BRIX_CACHE_STATUS_HIT),
                  brix_metric_value(&shm->unified.cache_hits[proto]));
        mw_printf(mw, "brix_cache_requests_total{proto=\"%s\","
                      "cache_status=\"%s\"} %llu\n", pn,
                  brix_metric_cache_status_name(BRIX_CACHE_STATUS_MISS),
                  brix_metric_value(&shm->unified.cache_misses[proto]));
        /* phase-110 W10: the NEGHIT series, from the unified neghit slot —
         * so a fleet-wide negative-hit rate is one query across every plane
         * (was only cvmfs's own negative_hits_total). */
        mw_printf(mw, "brix_cache_requests_total{proto=\"%s\","
                      "cache_status=\"%s\"} %llu\n", pn,
                  brix_metric_cache_status_name(BRIX_CACHE_STATUS_NEGHIT),
                  brix_metric_value(&shm->unified.cache_neghits[proto]));
    }

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
 * unified_emit_cache_prefetch — render the background block-prefetch families.
 *
 * WHAT: Emits the three sd_cache_prefetch.c counters (jobs posted, blocks
 *       filled, failed jobs).
 * WHY:  Process-wide like the watermark group — the detached thread-pool jobs
 *       carry no per-proto/per-server context. Sole owner: sd_cache_prefetch.c.
 * HOW:  Three unlabeled monotonic counters straight from the unified SHM.
 */
static void
unified_emit_cache_prefetch(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    mw_printf(mw,
        "# HELP brix_cache_prefetch_jobs_total Background cache prefetch jobs posted.\n"
        "# TYPE brix_cache_prefetch_jobs_total counter\n"
        "brix_cache_prefetch_jobs_total %llu\n",
        brix_metric_value(&shm->unified.cache_prefetch_jobs_total));

    mw_printf(mw,
        "# HELP brix_cache_prefetch_blocks_total Cache blocks filled by background prefetch.\n"
        "# TYPE brix_cache_prefetch_blocks_total counter\n"
        "brix_cache_prefetch_blocks_total %llu\n",
        brix_metric_value(&shm->unified.cache_prefetch_blocks_total));

    mw_printf(mw,
        "# HELP brix_cache_prefetch_failures_total Background cache prefetch jobs that failed.\n"
        "# TYPE brix_cache_prefetch_failures_total counter\n"
        "brix_cache_prefetch_failures_total %llu\n",
        brix_metric_value(&shm->unified.cache_prefetch_failures_total));
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
 * unified_emit_tpc_gsi_deleg — render brix_tpc_gsi_delegated_total, the outbound
 * native-TPC GSI proxy-delegation credential-selection outcomes (phase-58 §5.8).
 *
 * WHAT: Emits one counter per delegation result (ok / expired / absent).
 * WHY:  Operators need to see whether delegated pulls authenticate as the user
 *       (ok), get refused on an expired proxy (expired), or silently fall back to
 *       the gateway cert (absent) — a single low-cardinality {result} family.
 * HOW:  One loop over brix_tpc_deleg_result_t indexing the shared names table.
 */
static void
unified_emit_tpc_gsi_deleg(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    ngx_uint_t  result;

    mw_printf(mw,
        "# HELP brix_tpc_gsi_delegated_total Outbound TPC GSI proxy-delegation "
        "credential-selection outcomes.\n"
        "# TYPE brix_tpc_gsi_delegated_total counter\n");
    for (result = 0; result < BRIX_TPC_DELEG_RESULT_COUNT; result++) {
        mw_printf(mw,
            "brix_tpc_gsi_delegated_total{result=\"%s\"} %llu\n",
            brix_unified_tpc_deleg_result_names[result],
            brix_metric_value(&shm->unified.tpc_gsi_deleg_total[result]));
    }
}

/*
 * brix_export_unified_metrics — render all unified counter families to the
 * Prometheus text writer: io bytes read/written, io_ops_total, the io latency
 * histogram (cumulated from non-cumulative storage), cache hits/misses/evicted,
 * auth_total, tpc transfers/bytes, and tpc GSI proxy-delegation outcomes — each
 * as HELP/TYPE plus per-label lines.
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
    unified_emit_io_slowop(mw, shm);
    unified_emit_io_offload(mw, shm);
    unified_emit_cred_select(mw, shm);
    unified_emit_cred_deleg(mw, shm);
    unified_emit_vfs_mutation_denied(mw, shm);
    unified_emit_vfs_domain_mutation(mw, shm);
    unified_emit_vfs_authz_backstop(mw, shm);
    unified_emit_vfs_spill(mw, shm);
    unified_emit_vfs_bulk_delete(mw, shm);
    unified_emit_vfs_recall_evict(mw, shm);
    unified_emit_vfs_precond(mw, shm);
    unified_emit_vfs_lock(mw, shm);
    unified_emit_cache(mw, shm);
    unified_emit_cache_watermark(mw, shm);
    unified_emit_cache_prefetch(mw, shm);
    unified_emit_wt_stage(mw, shm);
    unified_emit_auth(mw, shm);
    unified_emit_tpc(mw, shm);
    unified_emit_tpc_gsi_deleg(mw, shm);
}
