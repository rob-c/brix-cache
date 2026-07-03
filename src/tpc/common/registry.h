#ifndef BRIX_TPC_COMMON_REGISTRY_H
#define BRIX_TPC_COMMON_REGISTRY_H

/* ---- Module: Shared TPC Transfer Registry ----
 *
 * WHAT: Public interface to the cross-process registry of in-flight third-party
 *       copies. Declares the lifecycle calls (configure / add / update / remove /
 *       find), the snapshot reader, and the progress-emit shim, plus the
 *       flattened brix_tpc_transfer_snapshot_t used to copy a transfer out of
 *       shared memory with its src_url/dst_path inlined as fixed-size char[].
 *
 * WHY: Both transports and the dashboard/metrics readers need a single, stable
 *      view of active transfers that survives across nginx worker processes. The
 *      snapshot type deliberately mirrors brix_tpc_transfer_t but with embedded
 *      char buffers so callers can read a consistent copy without holding the
 *      registry lock or pointing into shared memory.
 *
 * HOW: brix_tpc_registry_configure() reserves the shared-memory zone at config
 *      time; brix_tpc_registry_add() publishes a transfer and returns its id;
 *      update/remove/find mutate or look up by id; brix_tpc_registry_snapshot()
 *      bulk-copies up to max_transfers entries; brix_tpc_progress_emit() is the
 *      thin progress hook that forwards bytes_done/state to the registry. The
 *      implementation lives in registry.c (and progress.c for the shim).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "transfer.h"

typedef struct {
    uint64_t       id;
    ngx_uint_t     protocol;
    ngx_uint_t     direction;
    off_t          bytes_total;
    off_t          bytes_done;
    time_t         started_at;
    time_t         updated_at;
    ngx_uint_t     state;
    char           src_url[BRIX_TPC_SRC_URL_MAX];
    char           dst_path[BRIX_TPC_DST_PATH_MAX];
} brix_tpc_transfer_snapshot_t;

/* Reserve the "brix_tpc_transfers" shared-memory zone and register its init
 * callback; must be called once at config time before any other registry call.
 * Returns NGX_OK, or NGX_ERROR if the zone could not be added. */
ngx_int_t brix_tpc_registry_configure(ngx_conf_t *cf);

/* Publish a transfer into a free slot. Copies src_url/dst_path into slot-owned
 * storage (caller keeps ownership of *transfer; nothing in it is referenced
 * after return) and stamps a fresh id, started_at/updated_at, and a default
 * PENDING state when state is 0. Returns the assigned non-zero id, or 0 if the
 * registry is unavailable or full. Takes the registry lock. */
uint64_t brix_tpc_registry_add(const brix_tpc_transfer_t *transfer,
    ngx_log_t *log);

/* Set bytes_done on the transfer with the given id and refresh updated_at; also
 * sets state when state != 0 (a 0 state leaves the existing state unchanged).
 * id == 0 is a no-op returning NGX_OK. Returns NGX_OK on success, NGX_DECLINED
 * if the registry is unavailable or id is not found. Takes the registry lock. */
ngx_int_t brix_tpc_registry_update(uint64_t id, off_t bytes_done,
    ngx_uint_t state, ngx_log_t *log);

/* Free the slot holding the transfer with the given id (zeroed for reuse).
 * id == 0 is a no-op returning NGX_OK. Returns NGX_OK on success, NGX_DECLINED
 * if the registry is unavailable or id is not found. log is currently unused.
 * Takes the registry lock. */
ngx_int_t brix_tpc_registry_remove(uint64_t id, ngx_log_t *log);

/* Best-effort, lock-free lookup by id. Returns a pointer directly into the
 * shared-memory slot, valid only while that slot remains in use (may be mutated
 * or freed by another worker at any time) — for read-only inspection, never to
 * be retained. Returns NULL if id == 0, not found, or registry unavailable. */
const brix_tpc_transfer_t *brix_tpc_registry_find(uint64_t id);

/* Copy up to max_transfers in-use slots into caller-provided out[] as flattened
 * snapshots (src_url/dst_path inlined and NUL-terminated); out must hold at
 * least max_transfers entries. Taken under the lock for a consistent view.
 * Returns the number of snapshots written (0 if out is NULL, max_transfers is
 * 0, or the registry is unavailable). */
ngx_uint_t brix_tpc_registry_snapshot(brix_tpc_transfer_snapshot_t *out,
    ngx_uint_t max_transfers);

/* Progress-reporting shim: forwards bytes_done and state to
 * brix_tpc_registry_update() for transfer id and returns its result.
 * bytes_total is accepted for forward compatibility but currently ignored. */
ngx_int_t brix_tpc_progress_emit(uint64_t id, off_t bytes_done,
    off_t bytes_total, ngx_uint_t state, ngx_log_t *log);

/* Phase 39 (WS5): set the abandoned-slot reaper max age (seconds); 0 = disabled.
 * Call once per server block at config time (before fork) from
 * brix_tpc_transfer_max_age.  Guards on value > 0 so a 0-default block does not
 * clobber an enabling one. */
void brix_tpc_registry_set_max_age(time_t secs);

/* Phase 39 (WS5): mark transfer `id` cancelled so the curl progress callback
 * aborts it promptly (read lock-free via registry_find).  No-op if id not found. */
ngx_int_t brix_tpc_registry_request_cancel(uint64_t id);

/* Reclaim in-use slots with no progress for > max_age (abandoned transfers),
 * preventing permanent "registry full" 503 starvation.  Takes the lock; returns
 * the number reclaimed (0 if disabled/unavailable).  Also driven inline when a
 * registry_add hits a full table. */
ngx_uint_t brix_tpc_registry_reap_stale(ngx_log_t *log);

#endif /* BRIX_TPC_COMMON_REGISTRY_H */
