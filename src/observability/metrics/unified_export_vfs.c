#include "unified_internal.h"

/*
 * unified_export_vfs.c — scrape-time exporter for the phase-107 VFS-verb
 * families.
 *
 * WHAT: Renders the batch-delete pair (C4), the recall/evict lifecycle pair
 *       (C2), the publish-precondition refusal pair (C6), and the lock-gate
 *       refusal counter (C7) — seven families, each with its zero rows
 *       emitted so a scraper has every series before the first event.
 * WHY:  unified_export.c reached the file-size budget when the C6 pair landed;
 *       the VFS-verb emitters are one cohesive cluster (bounded driver/kind/
 *       result axes over the vfs_* SHM regions), split out the same way the io
 *       families went to unified_export_io.c (coding-standards §1).
 * HOW:  Each emitter reads its region of *shm via brix_metric_value and prints
 *       HELP/TYPE + per-label lines; every axis is a fixed table or
 *       BRIX_FS_ID_COUNT, so labels stay low-cardinality (INVARIANT #8).
 */

/*
 * unified_emit_vfs_bulk_delete — render the phase-107 C4 batch-delete pair.
 *
 * WHAT: Per-driver batches-flushed and keys-removed counters for the
 *       unlink_many path. Zero rows are emitted too, so a scraper has the
 *       series before the first DeleteObjects arrives.
 * WHY:  keys/batches is the amplification ratio that separates "batching" from
 *       "looping"; the driver label is bounded by BRIX_FS_ID_COUNT.
 * HOW:  Two HELP/TYPE pairs, one mw_printf row per registered driver id.
 */
void
unified_emit_vfs_bulk_delete(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    int id;

    mw_printf(mw,
        "# HELP brix_vfs_bulk_delete_batches_total "
            "unlink_many batches flushed, by leaf driver.\n"
        "# TYPE brix_vfs_bulk_delete_batches_total counter\n");
    for (id = 0; id < BRIX_FS_ID_COUNT; id++) {
        mw_printf(mw,
            "brix_vfs_bulk_delete_batches_total{driver=\"%s\"} %llu\n",
            brix_fs_id_name(id),
            brix_metric_value(
                &shm->unified.vfs_bulk_delete_batches_total[id]));
    }

    mw_printf(mw,
        "# HELP brix_vfs_bulk_delete_keys_total "
            "Keys removed via the batch delete path, by leaf driver.\n"
        "# TYPE brix_vfs_bulk_delete_keys_total counter\n");
    for (id = 0; id < BRIX_FS_ID_COUNT; id++) {
        mw_printf(mw,
            "brix_vfs_bulk_delete_keys_total{driver=\"%s\"} %llu\n",
            brix_fs_id_name(id),
            brix_metric_value(&shm->unified.vfs_bulk_delete_keys_total[id]));
    }
}

/*
 * unified_emit_vfs_recall_evict — render the phase-107 C2 lifecycle pair.
 *
 * WHAT: Recall outcomes by result class and evicted bytes by driver.
 * WHY:  queued/joined is the registry's dedup ratio; evict bytes by driver
 *       separates a cache reclaim from a nearline release. Zero rows are
 *       emitted too, so a scraper has the series before the first prepare.
 * HOW:  Fixed four-entry result table (mirrors brix_vfs_recall_result_t —
 *       recorder carries the _Static_assert), then one row per driver id.
 */
void
unified_emit_vfs_recall_evict(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const char *results[4] = { "queued", "joined", "online", "error" };
    int                r, id;

    mw_printf(mw,
        "# HELP brix_vfs_recall_total "
            "Nearline recall (prestage) outcomes, by result class.\n"
        "# TYPE brix_vfs_recall_total counter\n");
    for (r = 0; r < 4; r++) {
        mw_printf(mw,
            "brix_vfs_recall_total{result=\"%s\"} %llu\n",
            results[r],
            brix_metric_value(&shm->unified.vfs_recall_total[r]));
    }

    mw_printf(mw,
        "# HELP brix_vfs_evict_bytes_total "
            "Bytes reclaimed by the VFS evict verb, by dispatching driver.\n"
        "# TYPE brix_vfs_evict_bytes_total counter\n");
    for (id = 0; id < BRIX_FS_ID_COUNT; id++) {
        mw_printf(mw,
            "brix_vfs_evict_bytes_total{driver=\"%s\"} %llu\n",
            brix_fs_id_name(id),
            brix_metric_value(&shm->unified.vfs_evict_bytes_total[id]));
    }
}

/*
 * unified_emit_vfs_precond — render the phase-107 C6 refusal pair.
 *
 * WHAT: Refused publish preconditions by kind, and refusals answered without
 *       a storage-side atomic decision, by driver.
 * WHY:  advisory/failed is the honesty ratio: a 412 decided by a stat-compare
 *       instead of at the storage may not claim RFC 7232 semantics, and the
 *       driver label says which backend is approximating. Zero rows are
 *       emitted too, so a scraper has the series before the first refusal.
 * HOW:  Fixed three-entry kind table (mirrors brix_sd_precond_kind_t minus
 *       NONE — vfs_staged.c carries the _Static_assert), then one row per
 *       driver id.
 */
void
unified_emit_vfs_precond(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    static const char *kinds[3] = { "absent", "etag", "meta" };
    int                k, id;

    mw_printf(mw,
        "# HELP brix_vfs_precond_failed_total "
            "Publish preconditions refused (412), by kind.\n"
        "# TYPE brix_vfs_precond_failed_total counter\n");
    for (k = 0; k < 3; k++) {
        mw_printf(mw,
            "brix_vfs_precond_failed_total{kind=\"%s\"} %llu\n",
            kinds[k],
            brix_metric_value(&shm->unified.vfs_precond_failed_total[k]));
    }

    mw_printf(mw,
        "# HELP brix_vfs_precond_advisory_total "
            "Precondition refusals decided non-atomically "
            "(check-then-act), by driver.\n"
        "# TYPE brix_vfs_precond_advisory_total counter\n");
    for (id = 0; id < BRIX_FS_ID_COUNT; id++) {
        mw_printf(mw,
            "brix_vfs_precond_advisory_total{driver=\"%s\"} %llu\n",
            brix_fs_id_name(id),
            brix_metric_value(&shm->unified.vfs_precond_advisory_total[id]));
    }
}

/*
 * unified_emit_vfs_lock — render the phase-107 C7 lock-gate counter.
 *
 * WHAT: Mutations that arrived under a live foreign lock, by protocol.
 * WHY:  In strict enforcement these are EBUSY refusals; in advisory they are
 *       breaches warned through — a non-zero rate on a relaxed export is the
 *       signal to tighten it. Zero rows are emitted too, so a scraper has
 *       every proto series before the first contention.
 * HOW:  One row per protocol over the BRIX_PROTO_COUNT-bounded axis.
 */
void
unified_emit_vfs_lock(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    int  proto;

    mw_printf(mw,
        "# HELP brix_vfs_lock_refused_total "
            "Mutations arriving under a live foreign lock (refused in "
            "strict enforcement, warned through in advisory), by protocol.\n"
        "# TYPE brix_vfs_lock_refused_total counter\n");
    for (proto = 0; proto < BRIX_PROTO_COUNT; proto++) {
        mw_printf(mw,
            "brix_vfs_lock_refused_total{proto=\"%s\"} %llu\n",
            brix_metric_proto_name((brix_proto_t) proto),
            brix_metric_value(&shm->unified.vfs_lock_refused_total[proto]));
    }
}
