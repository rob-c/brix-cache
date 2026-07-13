/*
 * unified.h — cross-protocol metric vocabulary and record-side API.
 *
 * WHAT: Declares the enums that give stream, WebDAV, and S3 a single shared
 *       label vocabulary — brix_proto_t (stream/webdav/s3), brix_metric_op_t
 *       (read/write/stat/delete/mkdir/rename/dirlist/tpc), and brix_err_class_t
 *       (ok/not_found/forbidden/io_error/other) — plus the AUTH_*, TPC_*, and
 *       latency-bucket slot constants. It also declares the record-side helpers
 *       (brix_metric_op_done / _cache_result / _auth / _tpc) every protocol
 *       handler calls, and the name/classification helpers (proto/op/err/auth
 *       name lookups, errno→err and http-status→err mappers, auth-slot mapper).
 * WHY:  Per-protocol metric modules historically each defined their own labels,
 *       producing inconsistent dashboards. Funnelling all three protocols through
 *       one enum set keeps Prometheus labels low-cardinality (INVARIANT #8) and
 *       lets a single exporter (brix_export_unified_metrics in unified.c) emit
 *       directly comparable brix_io_* / brix_auth_total / brix_tpc_* series.
 * HOW:  Enum members are dense 0-based so they index fixed-size SHM counter arrays
 *       directly; the trailing *_COUNT member sizes those arrays. The implementation
 *       lives in unified.c; consumers include this header to record an event with a
 *       proto/op/err triple rather than touching SHM fields by hand.
 */
#ifndef BRIX_METRICS_UNIFIED_H
#define BRIX_METRICS_UNIFIED_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "core/types/proto_list.h"

/* Generated from THE central protocol declaration (one row per plane —
 * add protocols there, never here). Values are row indices and persist in
 * SHM: the list is append-only. */
typedef enum {
#define X(ID, metric_label, dash_name, http_plane) BRIX_PROTO_##ID,
    BRIX_PROTO_LIST(X)
#undef X
    BRIX_PROTO_COUNT
} brix_proto_t;

typedef enum {
    BRIX_METRIC_OP_READ    = 0,
    BRIX_METRIC_OP_WRITE   = 1,
    BRIX_METRIC_OP_STAT    = 2,
    BRIX_METRIC_OP_DELETE  = 3,
    BRIX_METRIC_OP_MKDIR   = 4,
    BRIX_METRIC_OP_RENAME  = 5,
    BRIX_METRIC_OP_DIRLIST = 6,
    BRIX_METRIC_OP_TPC     = 7,
    BRIX_METRIC_OP_XATTR   = 8,
    BRIX_METRIC_OP_COPY    = 9,
    BRIX_METRIC_OP_COUNT   = 10
} brix_metric_op_t;

typedef enum {
    BRIX_ERR_NONE      = 0,
    BRIX_ERR_NOT_FOUND = 1,
    BRIX_ERR_FORBIDDEN = 2,
    BRIX_ERR_IO        = 3,
    BRIX_ERR_OTHER     = 4,
    BRIX_ERR_COUNT     = 5
} brix_err_class_t;

#define BRIX_METRIC_AUTH_NONE    0
#define BRIX_METRIC_AUTH_GSI     1
#define BRIX_METRIC_AUTH_TOKEN   2
#define BRIX_METRIC_AUTH_SSS     3
#define BRIX_METRIC_AUTH_S3KEY   4
#define BRIX_METRIC_AUTH_UNIX    5
#define BRIX_METRIC_AUTH_KRB5    6
#define BRIX_METRIC_AUTH_HOST    7
#define BRIX_METRIC_AUTH_PWD     8
#define BRIX_METRIC_AUTH_COUNT   9

#define BRIX_METRIC_AUTH_FAIL    0
#define BRIX_METRIC_AUTH_OK      1
#define BRIX_METRIC_AUTH_STATUS_COUNT 2

#define BRIX_METRIC_TPC_PULL     0
#define BRIX_METRIC_TPC_PUSH     1
#define BRIX_METRIC_TPC_DIRECTION_COUNT 2

/* Eight finite buckets plus +Inf, all in microseconds. */
#define BRIX_IO_LATENCY_BUCKETS  9

/*
 * Map a proto/op/err enum to its Prometheus label string. The returned pointer
 * is a borrowed static literal (never freed by the caller); out-of-range input
 * yields the literal "unknown" (proto/op) or "other" (err) rather than NULL.
 */
const char *brix_metric_proto_name(brix_proto_t proto);
const char *brix_metric_op_name(brix_metric_op_t op);
const char *brix_metric_err_name(brix_err_class_t err);
/*
 * Label string for an identity auth_method BITMASK (not a slot): resolves the
 * mask via brix_metric_auth_slot() then names it. Borrowed static literal;
 * an empty/unknown mask yields "none". Never returns NULL.
 */
const char *brix_metric_auth_method_name(ngx_uint_t auth_method);

/*
 * Classify a POSIX errno into an brix_err_class_t bucket: 0 -> NONE,
 * ENOENT/ENOTDIR -> NOT_FOUND, EACCES/EPERM -> FORBIDDEN,
 * EIO/ENOMEM/ENOSPC -> IO, everything else -> OTHER.
 */
brix_err_class_t brix_metric_err_from_errno(int sys_errno);
/*
 * Classify an HTTP status into an brix_err_class_t bucket: 2xx AND 3xx -> NONE,
 * 404 -> NOT_FOUND, 401/403 -> FORBIDDEN, 5xx -> IO, everything else -> OTHER.
 */
brix_err_class_t brix_metric_err_from_http_status(ngx_uint_t status);
/*
 * Reduce an identity auth_method bitmask to a single BRIX_METRIC_AUTH_* slot,
 * tested in priority order GSI > TOKEN > SSS > S3KEY > UNIX > KRB5; returns
 * BRIX_METRIC_AUTH_NONE when no known bit is set. Pure, no side effects.
 */
ngx_uint_t brix_metric_auth_slot(ngx_uint_t auth_method);

/*
 * Record one completed I/O op into the shared counters: bumps
 * io_ops_total[proto][op][err], adds bytes to io_bytes_read/written (only for
 * READ/WRITE ops; ignored otherwise), and files latency_usec (microseconds)
 * into the single matching histogram bucket plus count and sum. Lock-free via
 * atomics. Silently no-ops on an out-of-range proto/op/err triple or when the
 * metrics SHM zone is not yet attached.
 */
void brix_metric_op_done(brix_proto_t proto, brix_metric_op_t op,
    size_t bytes, ngx_msec_t latency_usec, brix_err_class_t err);
/*
 * brix_metric_backend_bytes — add a completed data op's byte count to the
 * per-backend storage totals (io_bytes_{read,written}_backend). backend_name
 * is the storage driver's census name (fs_list.h); NULL ⇒ "posix" (the
 * default-instance convention everywhere in the VFS). Pure lock-free SHM
 * atomics — safe from thread-pool workers (no pools, logs, or request state).
 * No-ops on unknown names, non-READ/WRITE ops, zero bytes, or missing SHM.
 */
void brix_metric_backend_bytes(const char *backend_name,
    brix_metric_op_t op, size_t bytes);
/*
 * Record a cache lookup outcome: bumps cache_hits or cache_misses[proto] by hit
 * (treated as boolean) and adds bytes_evicted to cache_bytes_evicted[proto].
 * Lock-free; no-ops on out-of-range proto or detached SHM.
 */
void brix_metric_cache_result(brix_proto_t proto, unsigned int hit,
    size_t bytes_evicted);
/*
 * Credential-gate terminal outcomes (Phase 2 Task 3).
 *
 * BRIX_CRED_OUTCOME_USER     — a per-user credential was selected and used.
 * BRIX_CRED_OUTCOME_FALLBACK — no valid user credential; service-cred fallback
 *                              allowed (fallback_deny == 0).  Covers both the
 *                              "driver incapable" and "missing/expired cred" branches.
 * BRIX_CRED_OUTCOME_DENY     — request rejected (EACCES): fallback_deny == 1
 *                              and either no/expired user cred or driver lacks the
 *                              *_cred capability.
 *
 * Feature-off (storage_cred_dir unset) is NOT counted — not a credential decision.
 * Flush-deny (stage_engine BRIX_XFER_DENIED) is observable via the xfer audit
 * ledger result=denied line and is NOT counted here.
 */
typedef enum {
    BRIX_CRED_OUTCOME_USER     = 0,
    BRIX_CRED_OUTCOME_FALLBACK = 1,
    BRIX_CRED_OUTCOME_DENY     = 2,
    BRIX_CRED_OUTCOME_COUNT    = 3
} brix_cred_outcome_t;
/*
 * Bump the per-proto credential-gate outcome counter for the given outcome.
 * Mirrors brix_metric_cache_result: resolves shm->unified.cred_select_*[proto]
 * and performs a lock-free atomic increment.  No-ops on out-of-range proto,
 * unknown outcome, or detached SHM.
 */
void brix_metric_cred_result(brix_proto_t proto, brix_cred_outcome_t outcome);
/*
 * Watermark-driven LRU reaper telemetry (connection-less, process-wide):
 *  - cache_usage_ratio publishes cache_root occupancy (ppm) as a gauge each tick;
 *  - cache_watermark_purge accounts one purge run that reclaimed `files`/`bytes`.
 * Lock-free; no-ops on detached SHM (and purge no-ops when files == 0).
 */
void brix_metric_cache_usage_ratio(ngx_uint_t occupancy_ppm);
void brix_metric_cache_watermark_purge(ngx_uint_t files, uint64_t bytes);
/*
 * Write-back-staging backpressure telemetry: usage_ratio publishes staging
 * occupancy (ppm) as a gauge; throttled records one shed write (reject != 0 →
 * hard-cap rejection, else a soft-band delay). Lock-free; no-op on detached SHM.
 */
void brix_metric_wt_stage_usage_ratio(ngx_uint_t occupancy_ppm);
void brix_metric_wt_stage_throttled(int reject);
/*
 * Record one auth attempt: maps auth_method (a bitmask) to its slot via
 * brix_metric_auth_slot(), then bumps auth_total[proto][slot][ok|fail] keyed
 * by success (boolean). Lock-free; no-ops on out-of-range proto or detached SHM.
 */
void brix_metric_auth(brix_proto_t proto, ngx_uint_t auth_method,
    unsigned int success);
/*
 * Record a third-party-copy outcome: bumps tpc_transfers[proto][dir][err] where
 * dir is push when is_push is nonzero else pull, and ONLY on err==BRIX_ERR_NONE
 * adds bytes to tpc_bytes[proto][dir]. Lock-free; no-ops on out-of-range
 * proto/err or detached SHM.
 */
void brix_metric_tpc(brix_proto_t proto, unsigned int is_push,
    size_t bytes, brix_err_class_t err);

#endif /* BRIX_METRICS_UNIFIED_H */
