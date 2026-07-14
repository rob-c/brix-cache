#include "unified_internal.h"

/*
 * unified_record.c — record-side mutators for the unified metrics vocabulary.
 *
 * WHAT: Implements the hot-path record helpers protocol handlers call to bump
 *       the unified SHM counters — brix_metric_op_done (io ops/bytes/latency),
 *       brix_metric_backend_bytes (per-backend byte totals),
 *       brix_metric_cache_result / _cred_result / _cache_usage_ratio /
 *       _cache_watermark_purge (cache + watermark reaper), the write-back
 *       staging gauges (_wt_stage_usage_ratio / _wt_stage_throttled), and the
 *       auth / tpc outcome recorders — all declared in unified.h.
 * WHY:  These are the write side of the unified series; keeping them in their
 *       own file separates the lock-free hot-path mutators from the record-side
 *       classification helpers (unified.c) and the scrape-time exporter
 *       (unified_export*.c), so each file owns one concern (coding-standards §1).
 * HOW:  Each helper resolves the SHM block via brix_metrics_shared(), validates
 *       its proto/op/err triple, then bumps counters with the lock-free
 *       BRIX_ATOMIC_* macros. The latency histogram is stored NON-cumulative
 *       (each sample increments only the single bucket it falls in, via the
 *       shared brix_latency_bounds table); the exporter cumulates at scrape time.
 */

/*
 * brix_metric_op_done — record one completed I/O operation: bump the
 * io_ops_total[proto][op][err] counter, add bytes to the read/write totals for
 * read/write ops, and update the latency histogram (single bucket + count + sum).
 * Validates the proto/op/err triple and no-ops if the SHM zone is unavailable.
 */
void
brix_metric_op_done(brix_proto_t proto, brix_metric_op_t op,
    size_t bytes, ngx_msec_t latency_usec, brix_err_class_t err)
{
    ngx_brix_metrics_t *shm;
    ngx_uint_t            i;

    if (proto >= BRIX_PROTO_COUNT || op >= BRIX_METRIC_OP_COUNT
        || err >= BRIX_ERR_COUNT)
    {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    BRIX_ATOMIC_INC(&shm->unified.io_ops_total[proto][op][err]);

    if (op == BRIX_METRIC_OP_READ) {
        BRIX_ATOMIC_ADD(&shm->unified.io_bytes_read[proto], bytes);
    } else if (op == BRIX_METRIC_OP_WRITE) {
        BRIX_ATOMIC_ADD(&shm->unified.io_bytes_written[proto], bytes);
    }

    /*
     * Non-cumulative histogram: increment ONLY the single bucket this sample
     * falls into, not every bucket whose bound it satisfies.  This bounds the
     * hot path to a fixed 3 atomics (one bucket + count + sum) instead of up to
     * BRIX_IO_LATENCY_BUCKETS atomics per I/O.  The exporter cumulates the
     * per-bucket counts at scrape time (Prometheus `le` buckets stay cumulative
     * and +Inf still equals count), so /metrics output is byte-identical.
     */
    for (i = 0; i < BRIX_IO_LATENCY_BUCKETS - 1; i++) {
        if (latency_usec <= brix_latency_bounds[i]) {
            break;
        }
    }
    /* i is the matching finite bucket, or BUCKETS-1 (the +Inf bucket). */
    BRIX_ATOMIC_INC(&shm->unified.io_latency_bucket[proto][op][i]);
    BRIX_ATOMIC_INC(&shm->unified.io_latency_count[proto][op]);
    BRIX_ATOMIC_ADD(&shm->unified.io_latency_sum_usec[proto][op],
                      latency_usec);
}

/*
 * brix_metric_backend_bytes — add a completed data op's byte count to the
 * per-backend storage totals. Resolves the driver's census name to its
 * brix_fs_id_t slot (NULL ⇒ "posix", the default-instance convention) and
 * adds to the read or write array. Pure lock-free SHM atomics so it is safe
 * from thread-pool workers; silently no-ops on unknown names, non-data ops,
 * zero bytes, or a detached SHM zone.
 */
void
brix_metric_backend_bytes(const char *backend_name, brix_metric_op_t op,
    size_t bytes)
{
    ngx_brix_metrics_t *shm;
    int                   id;

    if (bytes == 0
        || (op != BRIX_METRIC_OP_READ && op != BRIX_METRIC_OP_WRITE))
    {
        return;
    }

    id = brix_fs_id_from_name(backend_name != NULL ? backend_name : "posix");
    if (id < 0) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    if (op == BRIX_METRIC_OP_READ) {
        BRIX_ATOMIC_ADD(&shm->unified.io_bytes_read_backend[id], bytes);
    } else {
        BRIX_ATOMIC_ADD(&shm->unified.io_bytes_written_backend[id], bytes);
    }
}

/*
 * brix_metric_cache_result — record a cache lookup outcome for proto:
 * increment cache_hits or cache_misses per hit, and add bytes_evicted to the
 * per-protocol eviction total.
 */
void
brix_metric_cache_result(brix_proto_t proto, unsigned int hit,
    size_t bytes_evicted)
{
    ngx_brix_metrics_t *shm;

    if (proto >= BRIX_PROTO_COUNT) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    if (hit) {
        BRIX_ATOMIC_INC(&shm->unified.cache_hits[proto]);
    } else {
        BRIX_ATOMIC_INC(&shm->unified.cache_misses[proto]);
    }
    BRIX_ATOMIC_ADD(&shm->unified.cache_bytes_evicted[proto], bytes_evicted);
}

/*
 * brix_metric_cred_result — record a VFS credential-gate terminal outcome.
 *
 * WHAT: Bumps one of three per-proto counters in shm->unified:
 *         USER     → cred_select_user_total[proto]
 *         FALLBACK → cred_select_fallback_total[proto]
 *         DENY     → cred_select_deny_total[proto]
 *
 * WHY:  Prometheus-grade observability for the credential gate without building
 *       a per-connection reporting path.  Per-proto granularity mirrors
 *       brix_metric_cache_result so operators can correlate with cache metrics.
 *
 * HOW:  Mirrors brix_metric_cache_result exactly: range-check proto, resolve the
 *       SHM, switch on outcome, atomic-increment the matching counter.  Unknown
 *       outcomes are silently dropped (defensive — callers use the enum).
 */
void
brix_metric_cred_result(brix_proto_t proto, brix_cred_outcome_t outcome)
{
    ngx_brix_metrics_t *shm;

    if (proto >= BRIX_PROTO_COUNT) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    switch (outcome) {
    case BRIX_CRED_OUTCOME_USER:
        BRIX_ATOMIC_INC(&shm->unified.cred_select_user_total[proto]);
        break;
    case BRIX_CRED_OUTCOME_FALLBACK:
        BRIX_ATOMIC_INC(&shm->unified.cred_select_fallback_total[proto]);
        break;
    case BRIX_CRED_OUTCOME_DENY:
        BRIX_ATOMIC_INC(&shm->unified.cred_select_deny_total[proto]);
        break;
    default:
        break;
    }
}

/*
 * brix_metric_cache_usage_ratio — publish the current cache_root occupancy
 * (ppm, 0-1e6) as a process-wide gauge. Called from the watermark reaper timer
 * each tick. A plain aligned-word store is atomic on the platforms nginx targets;
 * no read-modify-write is needed for a gauge.
 */
void
brix_metric_cache_usage_ratio(ngx_uint_t occupancy_ppm)
{
    ngx_brix_metrics_t *shm = brix_metrics_shared();

    if (shm != NULL) {
        shm->unified.cache_usage_ratio_ppm = (ngx_atomic_t) occupancy_ppm;
    }
}

/*
 * brix_metric_cache_watermark_purge — account one watermark-reaper purge that
 * reclaimed space: bumps the purge-run counter and adds the evicted file/byte
 * totals. The connection-less reaper cannot feed the per-proto/per-server
 * eviction series, so this dedicated family is its sole reporting path.
 */
void
brix_metric_cache_watermark_purge(ngx_uint_t files, uint64_t bytes)
{
    ngx_brix_metrics_t *shm = brix_metrics_shared();

    if (shm == NULL || files == 0) {
        return;
    }
    BRIX_ATOMIC_INC(&shm->unified.cache_watermark_purges);
    BRIX_ATOMIC_ADD(&shm->unified.cache_watermark_evicted_files, files);
    BRIX_ATOMIC_ADD(&shm->unified.cache_watermark_evicted_bytes, bytes);
}

/*
 * brix_metric_wt_stage_usage_ratio — publish write-back staging occupancy (ppm)
 * as a process-wide gauge. Called from the admission gate each time it samples.
 */
void
brix_metric_wt_stage_usage_ratio(ngx_uint_t occupancy_ppm)
{
    ngx_brix_metrics_t *shm = brix_metrics_shared();

    if (shm != NULL) {
        shm->unified.wt_stage_usage_ratio_ppm = (ngx_atomic_t) occupancy_ppm;
    }
}

/*
 * brix_metric_wt_stage_throttled — count a write shed by staging backpressure:
 * reject != 0 → hard-cap rejection, else a soft-band delay.
 */
void
brix_metric_wt_stage_throttled(int reject)
{
    ngx_brix_metrics_t *shm = brix_metrics_shared();

    if (shm == NULL) {
        return;
    }
    if (reject) {
        BRIX_ATOMIC_INC(&shm->unified.wt_stage_throttled_reject);
    } else {
        BRIX_ATOMIC_INC(&shm->unified.wt_stage_throttled_wait);
    }
}

/*
 * brix_metric_auth — record an authentication attempt: map auth_method to its
 * slot, then bump auth_total[proto][method][ok|fail] according to success.
 */
void
brix_metric_auth(brix_proto_t proto, ngx_uint_t auth_method,
    unsigned int success)
{
    ngx_brix_metrics_t *shm;
    ngx_uint_t            method;
    ngx_uint_t            status;

    if (proto >= BRIX_PROTO_COUNT) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    method = brix_metric_auth_slot(auth_method);
    status = success ? BRIX_METRIC_AUTH_OK : BRIX_METRIC_AUTH_FAIL;
    BRIX_ATOMIC_INC(&shm->unified.auth_total[proto][method][status]);
}

/*
 * brix_metric_tpc — record a third-party-copy transfer outcome: bump
 * tpc_transfers[proto][pull|push][err], and on success add bytes to
 * tpc_bytes[proto][direction]. is_push selects push vs pull direction.
 */
void
brix_metric_tpc(brix_proto_t proto, unsigned int is_push,
    size_t bytes, brix_err_class_t err)
{
    ngx_brix_metrics_t *shm;
    ngx_uint_t            direction;

    if (proto >= BRIX_PROTO_COUNT || err >= BRIX_ERR_COUNT) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    direction = is_push ? BRIX_METRIC_TPC_PUSH : BRIX_METRIC_TPC_PULL;
    BRIX_ATOMIC_INC(&shm->unified.tpc_transfers[proto][direction][err]);
    if (err == BRIX_ERR_NONE) {
        BRIX_ATOMIC_ADD(&shm->unified.tpc_bytes[proto][direction], bytes);
    }
}
