#include "registry.h"

/*
 * registry.c — shared-memory registry of in-flight third-party copies
 * (the registry.h lifecycle: configure/publish/update/remove/find/snapshot).
 *
 * WHY: TPC state must be visible across all workers (a transfer started by one
 *      may be queried/reported by another, and by dashboard/metrics readers) —
 *      a fixed slot array (BRIX_TPC_REGISTRY_SLOTS) under one shared shmtx.
 *
 * HOW: shm_init zeroes the table + creates the shmtx on first map (re-attached
 *      on reload). Slots inline fixed-size src_url/dst_path storage (caller
 *      strings copied in, so a published brix_tpc_transfer_t never points at
 *      caller memory). IDs = time<<32 ^ pid<<16 ^ process-local seq (unique
 *      across workers). Mutations take the mutex; find() reads lock-free and
 *      returns a shared-memory pointer for best-effort lookups.
 */

#include "core/ngx_brix_module.h"
#include "core/compat/shm_slots.h"

#include <string.h>

typedef struct {
    ngx_uint_t              in_use;
    brix_tpc_transfer_t   transfer;
    u_char                  src_url_data[BRIX_TPC_SRC_URL_MAX];
    u_char                  dst_path_data[BRIX_TPC_DST_PATH_MAX];
} brix_tpc_registry_entry_t;

typedef struct {
    ngx_shmtx_sh_t              lock;
    brix_tpc_registry_entry_t slots[BRIX_TPC_REGISTRY_SLOTS];
} brix_tpc_registry_table_t;

static ngx_shm_zone_t *brix_tpc_registry_shm_zone;
static ngx_shmtx_t     brix_tpc_registry_mutex;
static uint64_t        brix_tpc_registry_sequence;

/*
 * Phase 39 (WS5): max age (seconds since updated_at) after which an in-flight
 * registry slot is considered abandoned and may be reclaimed.  0 = disabled (no
 * reaping; current behaviour).  Set once at config time from
 * brix_tpc_transfer_max_age (carried into workers by fork).  Healthy transfers
 * refresh updated_at via brix_tpc_registry_update() on every progress emit
 * (native source.c per 1 MiB chunk; curl per progress callback), so a slot older
 * than max_age has made no progress at all and is genuinely stuck.
 *
 * Reclaim is safe without a separate generation counter: every mutation matches
 * on the unique 64-bit transfer id under this mutex, so a stale worker that later
 * calls update/remove for a reaped (or reused-with-a-new-id) slot simply fails to
 * find its id and no-ops — there is no raw-pointer retention (registry_find is
 * read-only and unused).
 */
static time_t          brix_tpc_registry_max_age;

static brix_tpc_registry_table_t *
brix_tpc_registry_table(void)
{
    if (brix_tpc_registry_shm_zone == NULL
        || brix_tpc_registry_shm_zone->data == NULL
        || brix_tpc_registry_shm_zone->data == (void *) 1)
    {
        return NULL;
    }

    return (brix_tpc_registry_table_t *) brix_tpc_registry_shm_zone->data;
}

static ngx_int_t
brix_tpc_registry_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t                   fresh;
    brix_tpc_registry_table_t *tbl;

    /*
     * Allocate the slot table FROM the slab pool (never over shm.addr) so the
     * ngx_slab_pool_t header survives; nginx's ngx_unlock_mutexes() force-unlocks
     * that header's mutex on every child death and would SIGSEGV the master if it
     * were clobbered. The helper zeroes the table and creates the process-local
     * mutex from its first member (the ngx_shmtx_sh_t lock).
     */
    tbl = brix_shm_table_alloc(shm_zone, data,
                                 sizeof(brix_tpc_registry_table_t),
                                 &brix_tpc_registry_mutex, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    /*
     * No fresh-only field inits are required: every slot is reset by the
     * helper's memzero on first allocation, and the slot capacity is the
     * compile-time constant BRIX_TPC_REGISTRY_SLOTS. On reuse (fresh == 0) the
     * live slot contents are deliberately preserved.
     */
    (void) fresh;

    return NGX_OK;
}

/*
 * Reserve the "brix_tpc_transfers" shared-memory zone (sized for the slot
 * table plus a page) and wire up its init callback. Called at config time.
 * Returns NGX_OK or NGX_ERROR if the zone could not be added.
 */
ngx_int_t
brix_tpc_registry_configure(ngx_conf_t *cf)
{
    ngx_str_t zone_name = ngx_string("brix_tpc_transfers");
    size_t    zone_size;

    zone_size = brix_shm_zone_size(sizeof(brix_tpc_registry_table_t));
    brix_tpc_registry_shm_zone = ngx_shared_memory_add(
        cf, &zone_name, zone_size, &ngx_stream_brix_module);

    if (brix_tpc_registry_shm_zone == NULL) {
        return NGX_ERROR;
    }

    brix_tpc_registry_shm_zone->init = brix_tpc_registry_shm_init;
    brix_tpc_registry_shm_zone->data = (void *) 1;

    return NGX_OK;
}

static uint64_t
brix_tpc_registry_next_id(void)
{
    uint64_t id;

    brix_tpc_registry_sequence++;
    id = (((uint64_t) ngx_time()) << 32)
         ^ (((uint64_t) ngx_pid) << 16)
         ^ brix_tpc_registry_sequence;

    return id == 0 ? 1 : id;
}

static void
brix_tpc_registry_copy_str(ngx_str_t *dst, u_char *storage,
    size_t storage_len, const ngx_str_t *src)
{
    size_t copy_len;

    if (dst == NULL || storage == NULL || storage_len == 0) {
        return;
    }

    dst->data = storage;
    dst->len = 0;
    storage[0] = '\0';

    if (src == NULL || src->data == NULL || src->len == 0) {
        return;
    }

    copy_len = src->len;
    if (copy_len >= storage_len) {
        copy_len = storage_len - 1;
    }

    ngx_memcpy(storage, src->data, copy_len);
    storage[copy_len] = '\0';
    dst->len = copy_len;
}

/*
 * Phase 39 (WS5): set the abandoned-slot max age (seconds).  Called once per
 * server block at config time (before fork) from brix_tpc_transfer_max_age;
 * 0 = disabled.  Last enabling block wins (callers guard on value > 0).
 */
void
brix_tpc_registry_set_max_age(time_t secs)
{
    brix_tpc_registry_max_age = secs;
}

/*
 * Reclaim every in-use slot whose updated_at is older than max_age (no progress
 * for that long ⇒ abandoned).  MUST be called with the registry mutex held.
 * Returns the number of slots reclaimed.  No-op (returns 0) when reaping is
 * disabled.  Reclaim is by memzero, identical to a normal remove — safe because
 * all other access is by unique id under this same lock (see the max_age note).
 */
static ngx_uint_t
brix_tpc_registry_reap_locked(brix_tpc_registry_table_t *tbl, time_t now)
{
    ngx_uint_t i;
    ngx_uint_t reaped = 0;

    if (brix_tpc_registry_max_age <= 0) {
        return 0;
    }

    for (i = 0; i < BRIX_TPC_REGISTRY_SLOTS; i++) {
        if (tbl->slots[i].in_use
            && (now - tbl->slots[i].transfer.updated_at)
               > brix_tpc_registry_max_age)
        {
            ngx_memzero(&tbl->slots[i], sizeof(tbl->slots[i]));
            reaped++;
        }
    }

    return reaped;
}

/*
 * Public periodic-reaper entry point: reclaim abandoned slots under the lock.
 * Returns the number reclaimed (0 if disabled / unavailable).  Safe to call from
 * any worker; intended for a coarse timer but also driven inline on a full add.
 */
ngx_uint_t
brix_tpc_registry_reap_stale(ngx_log_t *log)
{
    brix_tpc_registry_table_t *tbl;
    ngx_uint_t                   reaped;

    if (brix_tpc_registry_max_age <= 0) {
        return 0;
    }

    tbl = brix_tpc_registry_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_tpc_registry_mutex);
    reaped = brix_tpc_registry_reap_locked(tbl, ngx_time());
    ngx_shmtx_unlock(&brix_tpc_registry_mutex);

    if (reaped > 0 && log != NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_tpc: reaped %ui abandoned transfer slot(s) "
                      "(no progress for >%T s)",
                      reaped, brix_tpc_registry_max_age);
    }

    return reaped;
}

/*
 * Publish a new transfer into a free slot, copying its src_url/dst_path into
 * slot-owned storage and stamping a fresh id, started/updated time, and a
 * default PENDING state. Returns the assigned non-zero id, or 0 if the registry
 * is unavailable, full, or already at the caller's max_active cap.
 *
 * max_active (§6.9 `xfr <n>` explicit concurrency cap): when > 0, refuse a new
 * transfer once this many slots are already in use, EVEN IF free slots remain
 * below the compile-time BRIX_TPC_REGISTRY_SLOTS ceiling — the operator's
 * per-server transfer limit. 0 = no extra cap (the historical behaviour: bound
 * only by the slot ceiling). The count is taken under the same lock as the
 * free-slot scan, so it is a consistent process-wide view.
 */

/* One pass over the slot table (caller holds the lock): returns the in-use
 * count and sets *free_slot to the first free index (or SLOTS if none). */
static ngx_uint_t
tpc_scan_slots(const brix_tpc_registry_table_t *tbl, ngx_uint_t *free_slot)
{
    ngx_uint_t in_use = 0, i;

    *free_slot = BRIX_TPC_REGISTRY_SLOTS;
    for (i = 0; i < BRIX_TPC_REGISTRY_SLOTS; i++) {
        if (!tbl->slots[i].in_use) {
            if (*free_slot == BRIX_TPC_REGISTRY_SLOTS) {
                *free_slot = i;
            }
        } else {
            in_use++;
        }
    }
    return in_use;
}

uint64_t
brix_tpc_registry_add(const brix_tpc_transfer_t *transfer, ngx_log_t *log,
    ngx_uint_t max_active)
{
    brix_tpc_registry_table_t *tbl;
    brix_tpc_registry_entry_t *entry;
    ngx_uint_t                   i;
    ngx_uint_t                   free_slot;
    ngx_uint_t                   in_use;
    time_t                       now;
    uint64_t                     id;

    tbl = brix_tpc_registry_table();
    if (tbl == NULL || transfer == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_tpc: transfer registry is unavailable");
        return 0;
    }

    now = ngx_time();
    id = brix_tpc_registry_next_id();

    ngx_shmtx_lock(&brix_tpc_registry_mutex);

    in_use = tpc_scan_slots(tbl, &free_slot);

    /* §6.9 explicit concurrency cap: refuse before claiming a slot when the
     * caller's active-transfer limit is already met. A reap first, so an
     * abandoned transfer does not permanently count against the cap; then
     * recount in-use and re-find a free slot under the same lock. */
    if (max_active > 0 && in_use >= max_active) {
        (void) brix_tpc_registry_reap_locked(tbl, now);
        in_use = tpc_scan_slots(tbl, &free_slot);
        if (in_use >= max_active) {
            ngx_shmtx_unlock(&brix_tpc_registry_mutex);
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix_tpc: at the configured concurrency cap "
                          "(%ui active) — refusing new transfer", max_active);
            return 0;
        }
    }

    if (free_slot == BRIX_TPC_REGISTRY_SLOTS) {
        /*
         * Phase 39 (WS5): registry full — reclaim abandoned slots (no progress
         * for > brix_tpc_transfer_max_age) and retry once, so a flood of stalled
         * transfers self-heals instead of permanently 503-ing every new TPC.
         * No-op when reaping is disabled.  Runs under the lock already held.
         */
        if (brix_tpc_registry_reap_locked(tbl, now) > 0) {
            for (i = 0; i < BRIX_TPC_REGISTRY_SLOTS; i++) {
                if (!tbl->slots[i].in_use) {
                    free_slot = i;
                    break;
                }
            }
        }
    }

    if (free_slot == BRIX_TPC_REGISTRY_SLOTS) {
        ngx_shmtx_unlock(&brix_tpc_registry_mutex);
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix_tpc: transfer registry is full");
        return 0;
    }

    entry = &tbl->slots[free_slot];
    ngx_memzero(entry, sizeof(*entry));

    entry->in_use = 1;
    entry->transfer = *transfer;
    entry->transfer.id = id;
    entry->transfer.started_at = now;
    entry->transfer.updated_at = now;
    if (entry->transfer.state == 0) {
        entry->transfer.state = BRIX_TPC_STATE_PENDING;
    }

    brix_tpc_registry_copy_str(&entry->transfer.src_url,
                                 entry->src_url_data,
                                 sizeof(entry->src_url_data),
                                 &transfer->src_url);
    brix_tpc_registry_copy_str(&entry->transfer.dst_path,
                                 entry->dst_path_data,
                                 sizeof(entry->dst_path_data),
                                 &transfer->dst_path);

    ngx_shmtx_unlock(&brix_tpc_registry_mutex);

    return id;
}

/*
 * Shared core for the two update entry points: set bytes_done (and, when state is
 * non-zero, state) on the transfer with the given id, refreshing updated_at. When
 * set_total is non-zero AND bytes_total is positive the transfer's bytes_total is
 * refreshed too — this lets a transport whose total size only becomes known
 * mid-flight (an HTTP Content-Length discovered by the curl progress callback)
 * publish an accurate total without clobbering a total already stamped at add time
 * with a stale 0. id == 0 is a no-op returning NGX_OK; NGX_DECLINED if the
 * registry is unavailable or the id is not found.
 */
static ngx_int_t
brix_tpc_registry_update_core(uint64_t id, off_t bytes_done, off_t bytes_total,
    ngx_uint_t set_total, ngx_uint_t state, ngx_log_t *log)
{
    brix_tpc_registry_table_t *tbl;
    brix_tpc_registry_entry_t *entry;
    ngx_uint_t                   i;

    if (id == 0) {
        return NGX_OK;
    }

    tbl = brix_tpc_registry_table();
    if (tbl == NULL) {
        return NGX_DECLINED;
    }

    ngx_shmtx_lock(&brix_tpc_registry_mutex);

    for (i = 0; i < BRIX_TPC_REGISTRY_SLOTS; i++) {
        entry = &tbl->slots[i];
        if (entry->in_use && entry->transfer.id == id) {
            entry->transfer.bytes_done = bytes_done;
            if (set_total && bytes_total > 0) {
                entry->transfer.bytes_total = bytes_total;
            }
            if (state != 0) {
                entry->transfer.state = state;
            }
            entry->transfer.updated_at = ngx_time();
            ngx_shmtx_unlock(&brix_tpc_registry_mutex);
            return NGX_OK;
        }
    }

    ngx_shmtx_unlock(&brix_tpc_registry_mutex);
    if (log != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
                       "brix_tpc: transfer id %uL not found for update",
                       id);
    }
    return NGX_DECLINED;
}

/*
 * Update the bytes_done (and, if non-zero, the state) of the transfer with the
 * given id, refreshing updated_at. id == 0 is a no-op returning NGX_OK; returns
 * NGX_DECLINED if the registry is unavailable or the id is not found.
 */
ngx_int_t
brix_tpc_registry_update(uint64_t id, off_t bytes_done, ngx_uint_t state,
    ngx_log_t *log)
{
    return brix_tpc_registry_update_core(id, bytes_done, 0, 0, state, log);
}

/*
 * As brix_tpc_registry_update, but also refresh bytes_total when it is positive
 * (a 0 leaves any existing total untouched). Used by the progress-emit shim so a
 * mid-flight-discovered total reaches the dashboard.
 */
ngx_int_t
brix_tpc_registry_update_progress(uint64_t id, off_t bytes_done,
    off_t bytes_total, ngx_uint_t state, ngx_log_t *log)
{
    return brix_tpc_registry_update_core(id, bytes_done, bytes_total, 1, state,
                                          log);
}

/*
 * Phase 39 (WS5): mark the transfer with the given id as cancelled (by-id under
 * the lock).  The curl progress callback reads transfer.cancelled lock-free via
 * registry_find and aborts promptly.  id == 0 / not found is a no-op.
 */
ngx_int_t
brix_tpc_registry_request_cancel(uint64_t id)
{
    brix_tpc_registry_table_t *tbl;
    ngx_uint_t                   i;

    if (id == 0) {
        return NGX_DECLINED;
    }
    tbl = brix_tpc_registry_table();
    if (tbl == NULL) {
        return NGX_DECLINED;
    }

    ngx_shmtx_lock(&brix_tpc_registry_mutex);
    for (i = 0; i < BRIX_TPC_REGISTRY_SLOTS; i++) {
        if (tbl->slots[i].in_use && tbl->slots[i].transfer.id == id) {
            tbl->slots[i].transfer.cancelled = 1;
            ngx_shmtx_unlock(&brix_tpc_registry_mutex);
            return NGX_OK;
        }
    }
    ngx_shmtx_unlock(&brix_tpc_registry_mutex);
    return NGX_DECLINED;
}

/*
 * Free the slot holding the transfer with the given id (zeroing it for reuse).
 * id == 0 is a no-op returning NGX_OK; returns NGX_DECLINED if the registry is
 * unavailable or the id is not found.
 */
ngx_int_t
brix_tpc_registry_remove(uint64_t id, ngx_log_t *log)
{
    brix_tpc_registry_table_t *tbl;
    ngx_uint_t                   i;

    (void) log;

    if (id == 0) {
        return NGX_OK;
    }

    tbl = brix_tpc_registry_table();
    if (tbl == NULL) {
        return NGX_DECLINED;
    }

    ngx_shmtx_lock(&brix_tpc_registry_mutex);

    for (i = 0; i < BRIX_TPC_REGISTRY_SLOTS; i++) {
        if (tbl->slots[i].in_use && tbl->slots[i].transfer.id == id) {
            ngx_memzero(&tbl->slots[i], sizeof(tbl->slots[i]));
            ngx_shmtx_unlock(&brix_tpc_registry_mutex);
            return NGX_OK;
        }
    }

    ngx_shmtx_unlock(&brix_tpc_registry_mutex);
    return NGX_DECLINED;
}

/*
 * Copy up to max_transfers in-use slots into the caller's out[] array as flat
 * snapshots (src_url/dst_path inlined and NUL-terminated). Taken under the lock
 * for a consistent view. Returns the number of transfers written.
 */
ngx_uint_t
brix_tpc_registry_snapshot(brix_tpc_transfer_snapshot_t *out,
    ngx_uint_t max_transfers)
{
    brix_tpc_registry_table_t *tbl;
    brix_tpc_registry_entry_t *entry;
    ngx_uint_t                   i;
    ngx_uint_t                   n;

    if (out == NULL || max_transfers == 0) {
        return 0;
    }

    tbl = brix_tpc_registry_table();
    if (tbl == NULL) {
        return 0;
    }

    n = 0;
    ngx_shmtx_lock(&brix_tpc_registry_mutex);

    for (i = 0; i < BRIX_TPC_REGISTRY_SLOTS && n < max_transfers; i++) {
        entry = &tbl->slots[i];
        if (!entry->in_use) {
            continue;
        }

        out[n].id = entry->transfer.id;
        out[n].protocol = entry->transfer.protocol;
        out[n].direction = entry->transfer.direction;
        out[n].bytes_total = entry->transfer.bytes_total;
        out[n].bytes_done = entry->transfer.bytes_done;
        out[n].started_at = entry->transfer.started_at;
        out[n].updated_at = entry->transfer.updated_at;
        out[n].state = entry->transfer.state;

        ngx_memcpy(out[n].src_url, entry->src_url_data,
                   sizeof(out[n].src_url));
        ngx_memcpy(out[n].dst_path, entry->dst_path_data,
                   sizeof(out[n].dst_path));
        out[n].src_url[sizeof(out[n].src_url) - 1] = '\0';
        out[n].dst_path[sizeof(out[n].dst_path) - 1] = '\0';
        n++;
    }

    ngx_shmtx_unlock(&brix_tpc_registry_mutex);

    return n;
}

/*
 * Best-effort, lock-free lookup of a transfer by id. Returns a pointer into the
 * shared-memory slot (valid only while that slot stays in use) or NULL if not
 * found / registry unavailable. Intended for read-only inspection.
 */
const brix_tpc_transfer_t *
brix_tpc_registry_find(uint64_t id)
{
    brix_tpc_registry_table_t *tbl;
    ngx_uint_t                   i;

    if (id == 0) {
        return NULL;
    }

    tbl = brix_tpc_registry_table();
    if (tbl == NULL) {
        return NULL;
    }

    for (i = 0; i < BRIX_TPC_REGISTRY_SLOTS; i++) {
        if (tbl->slots[i].in_use && tbl->slots[i].transfer.id == id) {
            return &tbl->slots[i].transfer;
        }
    }

    return NULL;
}
