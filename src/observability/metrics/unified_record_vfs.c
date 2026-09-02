#include "unified_internal.h"

/*
 * unified_record_vfs.c — record-side mutators for the VFS mutation-surface
 * metric families.
 *
 * WHAT: Implements the brix_metric_vfs_* record helpers the fs layer calls to
 *       bump the unified SHM counters for its mutation surface:
 *       _vfs_mutation_denied (phase-105 read-only refusals), the phase-107 C1
 *       writer-spill trio (_vfs_spill_bytes / _vfs_spill_refused /
 *       _vfs_spill_active), and the phase-107 C4 bulk-delete pair
 *       (_vfs_bulk_delete) — all declared in unified.h.
 * WHY:  The vfs family grew unified_record.c past the 600-line file budget
 *       (coding-standards §1); it is also the one recorder group keyed by the
 *       fs layer's own enums (mutate-op table, BRIX_FS_ID_COUNT driver ids)
 *       rather than by protocol-plane labels, so it forms its own unit the
 *       same way the exporter side split into unified_export/_io.
 * HOW:  Identical contract to the unified_record.c mutators: resolve the SHM
 *       block via brix_metrics_shared(), range-check every index against its
 *       compile-time-bounded enum, then bump with the lock-free BRIX_ATOMIC_*
 *       macros. No function here ever takes a path, subject, or key.
 */

/*
 * brix_metric_vfs_mutation_denied — record one phase-105 read-only denial.
 *
 * WHAT: Bumps vfs_mutation_denied_total[proto][op]. No-op on an out-of-range
 *       protocol or operation, or on detached SHM.
 *
 * WHY:  A read-only export that is silently refusing writes is indistinguishable
 *       from one nobody is writing to. This is the counter that tells the two
 *       apart, at fixed cardinality: the reason is constant ("read_only",
 *       rendered by the exporter) because EROFS is the only VFS read-only
 *       result, and no path, subject, or key ever becomes a label.
 *
 * HOW:  Same contract as brix_metric_cred_fail: range-check both indices,
 *       resolve the SHM, atomic-increment. `op` arrives as ngx_uint_t (the
 *       fs-layer enum value); vfs_policy.c carries the compile-time size check.
 */
void
brix_metric_vfs_mutation_denied(brix_proto_t proto, ngx_uint_t op)
{
    ngx_brix_metrics_t *shm;

    if (proto >= BRIX_PROTO_COUNT || op >= BRIX_VFS_MUTATE_OP_METRIC_COUNT) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    BRIX_ATOMIC_INC(&shm->unified.vfs_mutation_denied_total[proto][op]);
}

/*
 * brix_metric_vfs_spill_* — phase-107 C1 writer-spill telemetry.
 *
 * WHAT: spill_bytes adds `bytes` absorbed into the reorder scratch;
 *       spill_refused bumps one reordered upload the spill could not serve;
 *       spill_active moves the open-scratch gauge by +/-1 at create/discard.
 *
 * WHY:  A site whose clients reorder (GridFTP mode E, multi-stream xrdcp) but
 *       whose spill root is missing or undersized fails uploads with ENOSPC;
 *       these three families are what separates "nobody reorders here" from
 *       "every reordered upload is being refused", at fixed cardinality.
 *
 * HOW:  Counters follow brix_metric_vfs_mutation_denied (range-check, resolve
 *       SHM, atomic add). The gauge cannot use a plain store like
 *       cache_usage_ratio: workers race create/discard, so it moves by atomic
 *       increment/decrement instead.
 */
void
brix_metric_vfs_spill_bytes(brix_proto_t proto, size_t bytes)
{
    ngx_brix_metrics_t *shm;

    if (proto >= BRIX_PROTO_COUNT || bytes == 0) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    BRIX_ATOMIC_ADD(&shm->unified.vfs_spill_bytes_total[proto], bytes);
}

void
brix_metric_vfs_spill_refused(brix_proto_t proto)
{
    ngx_brix_metrics_t *shm = brix_metric_shm_for_proto(proto);

    if (shm == NULL) {
        return;
    }

    BRIX_ATOMIC_INC(&shm->unified.vfs_spill_refused_total[proto]);
}

void
brix_metric_vfs_spill_active(int delta)
{
    ngx_brix_metrics_t *shm = brix_metrics_shared();

    if (shm == NULL || delta == 0) {
        return;
    }

    if (delta > 0) {
        BRIX_ATOMIC_INC(&shm->unified.vfs_spill_active);
    } else {
        BRIX_ATOMIC_DEC(&shm->unified.vfs_spill_active);
    }
}

/*
 * brix_metric_vfs_bulk_delete — phase-107 C4: one completed unlink_many batch.
 *
 * WHAT: Bumps the per-driver batch counter and adds the batch's successfully
 *       removed key count to the key total.
 * WHY:  keys/batches is the amplification ratio — a remote export whose
 *       DeleteObjects books 1,000 keys per batch is working; one that books 1
 *       is looping. The key count lives in the metric's VALUE; the only label
 *       is the BRIX_FS_ID_COUNT-bounded driver name (INVARIANT #8).
 * HOW:  Same name→slot resolution as brix_metric_backend_bytes; a batch that
 *       removed nothing still counts as a batch (the ratio's denominator).
 */
void
brix_metric_vfs_bulk_delete(const char *driver_name, size_t keys)
{
    ngx_brix_metrics_t *shm;
    int                   id;

    id = brix_fs_id_from_name(driver_name != NULL ? driver_name : "posix");
    if (id < 0) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    BRIX_ATOMIC_INC(&shm->unified.vfs_bulk_delete_batches_total[id]);
    if (keys > 0) {
        BRIX_ATOMIC_ADD(&shm->unified.vfs_bulk_delete_keys_total[id], keys);
    }
}

/*
 * brix_metric_vfs_recall / brix_metric_vfs_evict — phase-107 C2 lifecycle pair.
 *
 * WHAT: _recall books one recall outcome by result class; _evict adds the
 *       driver-reported reclaimed bytes under the bounded driver label.
 * WHY:  queued/joined is the dedup ratio of the join-not-duplicate registry
 *       lifecycle (a joined recall did no new MSS work); evict bytes by driver
 *       says which tier the reclaim actually came from — a cache evict and a
 *       nearline release are different capacity events.
 * HOW:  Same contract as the recorders above: bounded-enum range check, SHM
 *       resolve, lock-free bump. An evict that reclaimed nothing moves no
 *       counter (idempotent success on an absent object is not a reclaim).
 */
/* The SHM block sizes the result axis as a plain [4] so metrics.h keeps no
 * dependency on the recorder enum; if a result class is appended the SHM
 * mirror must grow with it. */
_Static_assert((int) BRIX_VFS_RECALL_RESULT_COUNT == 4,
    "brix_vfs_recall_result_t and the vfs_recall_total SHM axis disagree");

void
brix_metric_vfs_recall(brix_vfs_recall_result_t result)
{
    ngx_brix_metrics_t *shm;

    if ((unsigned) result >= BRIX_VFS_RECALL_RESULT_COUNT) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    BRIX_ATOMIC_INC(&shm->unified.vfs_recall_total[result]);
}

void
brix_metric_vfs_evict(const char *driver_name, uint64_t bytes)
{
    ngx_brix_metrics_t *shm;
    int                   id;

    if (bytes == 0) {
        return;
    }

    id = brix_fs_id_from_name(driver_name != NULL ? driver_name : "posix");
    if (id < 0) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    BRIX_ATOMIC_ADD(&shm->unified.vfs_evict_bytes_total[id], bytes);
}

/*
 * brix_metric_vfs_precond_failed / _advisory — phase-107 C6 refusal pair.
 *
 * WHAT: _failed books one refused publish precondition by kind (the 1-based
 *       fs enum, stored at kind-1: absent/etag/meta); _advisory books one
 *       refusal that was decided by a check-then-act compare rather than at
 *       the storage (pre->atomic == 0), by deciding driver.
 * WHY:  failed says conditional writers are being told "no"; advisory/failed
 *       is the honesty ratio — a 412 answered non-atomically may not claim
 *       RFC 7232 semantics (§3.5), and this is the counter that tells an
 *       operator which exports hold the atomic guarantee and which only
 *       approximate it.
 * HOW:  Same contract as the recorders above: bounded range check, SHM
 *       resolve, lock-free bump. `kind` arrives as ngx_uint_t (the fs enum
 *       value); vfs_staged.c carries the compile-time size check. NONE (0)
 *       never refuses and no-ops here.
 */
void
brix_metric_vfs_precond_failed(ngx_uint_t kind)
{
    ngx_brix_metrics_t *shm;

    if (kind < 1 || kind > 3) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    BRIX_ATOMIC_INC(&shm->unified.vfs_precond_failed_total[kind - 1]);
}

void
brix_metric_vfs_precond_advisory(const char *driver_name)
{
    ngx_brix_metrics_t *shm;
    int                   id;

    id = brix_fs_id_from_name(driver_name != NULL ? driver_name : "posix");
    if (id < 0) {
        return;
    }

    shm = brix_metrics_shared();
    if (shm == NULL) {
        return;
    }

    BRIX_ATOMIC_INC(&shm->unified.vfs_precond_advisory_total[id]);
}

/*
 * brix_metric_vfs_lock_refused — phase-107 C7 lock-gate detection.
 *
 * WHAT: Books one mutation that arrived under a live foreign lock, by
 *       protocol.
 * WHY:  In strict enforcement this counts refusals (EBUSY); in advisory it
 *       counts breaches that were warned through — the number that says the
 *       relaxed mode is masking real cross-protocol contention. A lock the
 *       gate never trips on costs nothing here.
 * HOW:  Same contract as the recorders above: bounded range check, SHM
 *       resolve, lock-free bump. No path, token, or owner is ever recorded
 *       (INVARIANT #8).
 */
void
brix_metric_vfs_lock_refused(brix_proto_t proto)
{
    ngx_brix_metrics_t *shm = brix_metric_shm_for_proto(proto);

    if (shm == NULL) {
        return;
    }

    BRIX_ATOMIC_INC(&shm->unified.vfs_lock_refused_total[proto]);
}
