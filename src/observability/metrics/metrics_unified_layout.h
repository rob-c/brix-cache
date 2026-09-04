/* Fixed shared-memory layout for protocol-neutral observability counters. */
#ifndef BRIX_METRICS_UNIFIED_LAYOUT_H
#define BRIX_METRICS_UNIFIED_LAYOUT_H

#include <ngx_core.h>

#include "core/types/fs_list.h"
#include "unified.h"

/*
 * Phase 6 unified observability counters.  These counters are intentionally
 * op-centric and protocol-labeled; legacy per-protocol counters remain
 * exported until callers can cut over their dashboards.
 */
typedef struct {
    ngx_atomic_t  io_bytes_read[BRIX_PROTO_COUNT];
    ngx_atomic_t  io_bytes_written[BRIX_PROTO_COUNT];

    /* Per-BACKEND byte totals (storage plane): bytes the storage-driver
     * instance moved, attributed at the VFS observe chokepoint (staged-commit
     * writes), brix_vfs_io_execute (root:// data plane), and the shared HTTP
     * serve helper (sendfile/memory/compressed GET). Indexed by the census
     * enum brix_fs_id_t (core/types/fs_list.h) — bounded, INVARIANT #8. A
     * staged upload counts into BOTH the stage store and the final backend at
     * promote: the semantic is bytes each backend performed, not client bytes. */
    ngx_atomic_t  io_bytes_read_backend[BRIX_FS_ID_COUNT];
    ngx_atomic_t  io_bytes_written_backend[BRIX_FS_ID_COUNT];
    ngx_atomic_t  io_ops_total[BRIX_PROTO_COUNT]
                                  [BRIX_METRIC_OP_COUNT]
                                  [BRIX_ERR_COUNT];
    ngx_atomic_t  io_latency_bucket[BRIX_PROTO_COUNT]
                                      [BRIX_METRIC_OP_COUNT]
                                      [BRIX_IO_LATENCY_BUCKETS];
    ngx_atomic_t  io_latency_count[BRIX_PROTO_COUNT]
                                      [BRIX_METRIC_OP_COUNT];
    ngx_atomic_t  io_latency_sum_usec[BRIX_PROTO_COUNT]
                                         [BRIX_METRIC_OP_COUNT];

    /* §3.15 OssStats `slowop` classifier — per proto/op count of COMPLETED ops
     * whose measured latency met or exceeded slowop_threshold_usec. The
     * threshold is stamped once per config load from brix_metrics_slowop
     * (init_module, master); 0 disables classification (no counter movement),
     * byte-identical to the pre-knob behaviour. Read lock-free in the latency
     * record path, so a slow op is booked the moment its latency is filed —
     * distinct from the histogram, which only bins the same sample. */
    ngx_atomic_t  io_slowop_total[BRIX_PROTO_COUNT][BRIX_METRIC_OP_COUNT];
    ngx_atomic_t  slowop_threshold_usec;

    /* §1.1 pathid response offloading — per-proto count of read-family responses
     * (kXR_read/readv/pgread) routed over a bound SECONDARY data channel instead
     * of the primary control stream. Lets an operator confirm multi-stream
     * offloading is actually happening and measure its rate; 0 everywhere when no
     * client requests offloading (byte-identical to before the counter). */
    ngx_atomic_t  io_offload_total[BRIX_PROTO_COUNT];

    ngx_atomic_t  cache_hits[BRIX_PROTO_COUNT];
    ngx_atomic_t  cache_misses[BRIX_PROTO_COUNT];
    /* phase-110 W10: negative-cache hits, per protocol — the NEGHIT disposition
     * of the shared cache vocabulary. Kept beside hits/misses so the unified
     * brix_cache_requests_total{cache_status} family covers every plane's
     * NEGHIT (previously only cvmfs's own negative_hits_total). */
    ngx_atomic_t  cache_neghits[BRIX_PROTO_COUNT];
    ngx_atomic_t  cache_bytes_evicted[BRIX_PROTO_COUNT];

    /* Per-user backend credential gate outcomes (Phase 2 Task 3).  Indexed by
     * brix_proto_t — the same proto the VFS ctx carries (brix_vfs_metrics_proto).
     * Bumped at the terminal branches of vfs_backend_cred_decide:
     *   cred_select_user_total     — user credential used (ucred_select OK + cap_ok)
     *   cred_select_fallback_total — service-cred fallback allowed (no cred or not
     *                                capable, but fallback_deny=0); includes both
     *                                the "cap not present" and "missing/expired cred"
     *                                allowed-fallback branches.
     *   cred_select_deny_total     — request rejected EACCES (fallback_deny=1 and
     *                                either no/expired cred or driver lacks capability)
     * Feature-off early return (storage_cred_dir unset) is NOT counted — that is not
     * a credential decision.  Flush-deny (stage_engine BRIX_XFER_DENIED) is NOT
     * counted here; it is observable via the xfer audit ledger result=denied line. */
    ngx_atomic_t  cred_select_user_total[BRIX_PROTO_COUNT];
    ngx_atomic_t  cred_select_fallback_total[BRIX_PROTO_COUNT];
    ngx_atomic_t  cred_select_deny_total[BRIX_PROTO_COUNT];

    /* Phase-70 delegation-gate outcomes by configured mode (P90-70.6): the
     * live-bag terminals in vfs_deleg.c (PASSTHROUGH/EXCHANGE, plus DELEGATE
     * once P90-70.8 drives it) and mint success in vfs_cred.c. The fail family
     * records WHY a gate terminal denied/fell back — closed reason enum, one
     * bump per failure alongside the outcome bump (INVARIANT #8). */
    ngx_atomic_t  cred_deleg_total[BRIX_PROTO_COUNT]
                                  [BRIX_CRED_MODE_METRIC_COUNT]
                                  [BRIX_CRED_OUTCOME_COUNT];
    ngx_atomic_t  cred_deleg_fail_total[BRIX_PROTO_COUNT]
                                       [BRIX_CRED_FAIL_COUNT];

    /* Phase-105 read-only endpoint denials: one bump per mutation the VFS
     * policy kernel refused with EROFS, by protocol and bounded operation. The
     * reason is constant ("read_only") and is rendered as a label rather than
     * stored, so the cube stays proto x op (INVARIANT #8). */
    ngx_atomic_t  vfs_mutation_denied_total[BRIX_PROTO_COUNT]
                                           [BRIX_VFS_MUTATE_OP_METRIC_COUNT];

    /* Phase-108 §6.5: service-storage mutations past the typed domain assert,
     * by bounded domain × op — the series a consolidation must MOVE. Export
     * data-path writes never book here (refusals go to _denied_total above). */
    ngx_atomic_t  vfs_domain_mutation_total[BRIX_VFS_DOMAIN_METRIC_COUNT]
                                           [BRIX_VFS_MUTATE_OP_METRIC_COUNT];

    /* Phase-108 C12: the VFS authorization backstop, by protocol × result
     * (agree | edge_missing | no_rules | unbound — BRIX_AUTHZ_BACKSTOP_RESULT_
     * COUNT). This is the observe-mode evidence the enforce flip waits on:
     * `edge_missing` (the backstop would have refused but the edge allowed) and
     * `unbound` (a ctx reached a mutation without binding a rule set) must be
     * flat across the fleet before enforce. The result is the only added label
     * and it is a bounded enum — no path/subject/key ever becomes one
     * (INVARIANT #8). */
    ngx_atomic_t  vfs_authz_backstop_total[BRIX_PROTO_COUNT]
                                          [BRIX_AUTHZ_BACKSTOP_RESULT_COUNT];

    /* Phase-107 C1 writer spill (out-of-order extents on a staged-only
     * backend): bytes absorbed into the local reorder scratch and reordered
     * uploads refused (no scratch, capacity, overlap, coverage hole), by
     * protocol; plus one process-wide gauge of spills currently open. No path,
     * export, or size ever becomes a label (INVARIANT #8). */
    ngx_atomic_t  vfs_spill_bytes_total[BRIX_PROTO_COUNT];
    ngx_atomic_t  vfs_spill_refused_total[BRIX_PROTO_COUNT];
    ngx_atomic_t  vfs_spill_active;              /* gauge: open spill scratches */

    /* Phase-107 C4 bulk delete: batches flushed through the unlink_many path
     * and keys successfully removed by them, by leaf driver (label bounded by
     * BRIX_FS_ID_COUNT). keys/batches is the amplification ratio — the number
     * that says whether DeleteObjects is actually batching. */
    ngx_atomic_t  vfs_bulk_delete_batches_total[BRIX_FS_ID_COUNT];
    ngx_atomic_t  vfs_bulk_delete_keys_total[BRIX_FS_ID_COUNT];

    /* Phase-107 C2 prestage/evict: recall outcomes by result class (bounded by
     * BRIX_VFS_RECALL_RESULT_COUNT — queued/joined/online/error) and bytes
     * reclaimed by the evict verb, by dispatching driver (BRIX_FS_ID_COUNT).
     * queued/joined separates new MSS work from joins on an in-flight recall
     * — whether the join-not-duplicate lifecycle actually deduplicates. */
    ngx_atomic_t  vfs_recall_total[4];
    ngx_atomic_t  vfs_evict_bytes_total[BRIX_FS_ID_COUNT];

    /* Phase-107 C6 publish preconditions: refusals by kind (bounded 3-value
     * axis — absent/etag/meta; NONE never refuses) and refusals decided
     * WITHOUT storage-side atomicity (pre->atomic == 0: a check-then-act
     * compare), by deciding driver (BRIX_FS_ID_COUNT). advisory/failed is the
     * honesty ratio: whether this site's 412s carry RFC 7232 semantics. */
    ngx_atomic_t  vfs_precond_failed_total[3];
    ngx_atomic_t  vfs_precond_advisory_total[BRIX_FS_ID_COUNT];

    /* Phase-107 C7 cross-protocol lock gate: mutations that arrived under a
     * live foreign lock, by protocol. Booked in strict mode (the mutation was
     * refused EBUSY) AND advisory mode (it was warned through) — the advisory
     * count is what says the relaxed mode is masking real contention. No
     * path, token, or owner ever becomes a label (INVARIANT #8). */
    ngx_atomic_t  vfs_lock_refused_total[BRIX_PROTO_COUNT];

    /* Watermark-driven LRU reaper (reap_watermark.c). Process-wide, connection-
     * less: the background timer has no per-proto/per-server context. usage_ratio
     * is a GAUGE in ppm (0-1e6), emitted as a 0-1 ratio; the rest are counters. */
    ngx_atomic_t  cache_usage_ratio_ppm;         /* gauge: cache_root occupancy, ppm */
    ngx_atomic_t  cache_watermark_purges;        /* counter: purge runs that did work */
    ngx_atomic_t  cache_watermark_evicted_files; /* counter: files reaped by the reaper */
    ngx_atomic_t  cache_watermark_evicted_bytes; /* counter: bytes reaped by the reaper */

    /* Background block prefetch (sd_cache_prefetch.c — sole owner). Process-
     * wide: the detached thread-pool jobs carry no per-proto/per-server
     * context, like the watermark reaper above. */
    ngx_atomic_t  cache_prefetch_jobs_total;     /* counter: background jobs posted */
    ngx_atomic_t  cache_prefetch_blocks_total;   /* counter: blocks filled by prefetch */
    ngx_atomic_t  cache_prefetch_failures_total; /* counter: jobs that failed (open/fill) */

    /* Write-back-staging backpressure (stage_admit.c). usage_ratio is a GAUGE in
     * ppm (staging filesystem occupancy); the throttle counters split by action. */
    ngx_atomic_t  wt_stage_usage_ratio_ppm;      /* gauge: staging fs occupancy, ppm */
    ngx_atomic_t  wt_stage_throttled_wait;       /* counter: writes delayed (soft band) */
    ngx_atomic_t  wt_stage_throttled_reject;     /* counter: writes rejected (hard cap) */

    ngx_atomic_t  auth_total[BRIX_PROTO_COUNT]
                            [BRIX_METRIC_AUTH_COUNT]
                            [BRIX_METRIC_AUTH_STATUS_COUNT];

    ngx_atomic_t  tpc_transfers[BRIX_PROTO_COUNT]
                               [BRIX_METRIC_TPC_DIRECTION_COUNT]
                               [BRIX_ERR_COUNT];
    ngx_atomic_t  tpc_bytes[BRIX_PROTO_COUNT]
                           [BRIX_METRIC_TPC_DIRECTION_COUNT];

    /* Outbound native-TPC GSI proxy-delegation credential selection (§5.8):
     * ok = captured proxy attached; expired = past NotAfter, pull refused;
     * absent = delegation on but nothing captured (gateway-cert fallback). */
    ngx_atomic_t  tpc_gsi_deleg_total[BRIX_TPC_DELEG_RESULT_COUNT];
} ngx_brix_unified_metrics_t;


#endif /* BRIX_METRICS_UNIFIED_LAYOUT_H */
