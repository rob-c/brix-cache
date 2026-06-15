/*
 * index.c — the SHM hot index over the durable queue (the cache, not the truth).
 *
 * WHAT: A shared-memory table of the active records' identity + offset, so any
 *   worker can resolve a reqid (or an lfn) to a file offset without scanning the
 *   file. Rebuilt from the file by frm_reconcile() at master start; thereafter
 *   patched in lock-step with every durable mutation (queue.c). A linear-scan
 *   table (cloned from src/tpc/key_registry.c) — capacities here are O(hundreds),
 *   so a hash table would not pay for itself.
 *
 * WHY: "file = truth, SHM = cache." If the index and the file ever disagree
 *   (e.g. a torn reconciliation), the file wins: the index carries the file
 *   header's generation, and a worker that sees a stale generation can force a
 *   re-read. On a full table the oldest (LRU) entry is evicted and
 *   reconcile_full_total is bumped — the index degrades to "miss → read the
 *   file", never to incorrectness.
 *
 * Phase 0: a single configured queue → a single file-static zone + mutex, exactly
 * like the key registry. The zone-init callback also drives the master-start
 * reconciliation against the file (it runs once in the master, before fork).
 */

#include "frm_internal.h"

#include "../compat/shm_slots.h"

#include <string.h>


static ngx_shm_zone_t  *frm_index_zone;
static ngx_shmtx_t      frm_index_mtx_v;
static ngx_uint_t       frm_index_slots;   /* requested capacity (configure→init) */


frm_index_table_t *
frm_index_table(void)
{
    if (frm_index_zone == NULL
        || frm_index_zone->data == NULL
        || frm_index_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (frm_index_table_t *) frm_index_zone->data;
}

ngx_shmtx_t *
frm_index_mutex(void)
{
    return &frm_index_mtx_v;
}

uint64_t
frm_lfn_hash(const char *lfn)
{
    uint64_t h = 1469598103934665603ULL;   /* FNV-1a 64 offset basis */
    const unsigned char *p = (const unsigned char *) lfn;
    if (lfn == NULL) {
        return 0;
    }
    while (*p) {
        h ^= (uint64_t) *p++;
        h *= 1099511628211ULL;
    }
    return h;
}


/*
 * Zone init: lay out the table, create the mutex, and (on a fresh start, not a
 * reload) drive reconciliation from the file. Mirrors xrootd_tpc_key_shm_init_zone
 * but with a variable-capacity flexible array and the reconcile step.
 */
static ngx_int_t
frm_index_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    frm_index_table_t *tbl;
    ngx_uint_t         capacity = frm_index_slots;
    ngx_flag_t         fresh;

    if (capacity == 0) {
        capacity = 256;
    }

    /*
     * CRITICAL: allocate the table FROM the slab pool — do NOT overwrite the
     * slab-pool header at shm.addr. nginx's ngx_unlock_mutexes() (run on every
     * child death, e.g. the stage copycmd) treats shm.addr as an
     * ngx_slab_pool_t and dereferences sp->mutex; clobbering that header would
     * SIGSEGV the master whenever a stage child exits. xrootd_shm_table_alloc()
     * handles reload (data != NULL) and re-attach, zeroes the table, creates the
     * mutex from the table's first member (->lock), and publishes it via
     * shm_zone->data. *fresh is set only on a brand-new allocation.
     */
    tbl = xrootd_shm_table_alloc(shm_zone, data,
                                 sizeof(frm_index_table_t)
                                     + (size_t) capacity
                                         * sizeof(frm_index_entry_t),
                                 &frm_index_mtx_v, &fresh);
    if (tbl == NULL) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                      "frm: index slab alloc failed (zone too small)");
        return NGX_ERROR;
    }

    if (fresh) {
        /* Brand-new table: initialise capacity/counters (the helper already
         * zeroed the whole table, so count/generation/slots are clean) and
         * drive master-start reconciliation from the file of record. On a
         * reload/re-attach we keep the live table as-is. */
        tbl->capacity   = capacity;
        tbl->count      = 0;
        tbl->generation = 0;

        /* Master-start reconciliation: rebuild the index from the file. */
        {
            frm_queue_t *q = frm_singleton_queue();
            if (q != NULL) {
                if (frm_file_open(q, ngx_cycle->log) != NGX_OK
                    || frm_reconcile(q, ngx_cycle->log) != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                                  "frm: reconciliation of \"%V\" failed",
                                  &q->path);
                    frm_file_close(q);
                    return NGX_ERROR;
                }
                frm_file_close(q);      /* workers reopen their own fds */
            }
        }
    }

    return NGX_OK;
}

ngx_int_t
frm_index_configure(ngx_conf_t *cf, const ngx_str_t *path, ngx_uint_t slots)
{
    ngx_str_t  zone_name = ngx_string("xrootd_frm_index");
    size_t     zone_size;

    (void) path;
    if (slots == 0) {
        slots = 256;
    }
    frm_index_slots = slots;
    /* table + slots, plus headroom for the slab-pool header/page management
     * (the table is ngx_slab_alloc'd, so the zone must hold both). The
     * TABLE_BYTES here MUST equal the value passed to xrootd_shm_table_alloc()
     * in frm_index_init_zone(). */
    zone_size = xrootd_shm_zone_size(sizeof(frm_index_table_t)
                                     + (size_t) slots
                                         * sizeof(frm_index_entry_t));

    frm_index_zone = ngx_shared_memory_add(cf, &zone_name, zone_size,
                                           &ngx_stream_xrootd_module);
    if (frm_index_zone == NULL) {
        return NGX_ERROR;
    }
    frm_index_zone->init = frm_index_init_zone;
    frm_index_zone->data = (void *) 1;
    return NGX_OK;
}


/* ---- mutations (caller holds NO lock; we take the index mutex) -------------*/

static frm_index_entry_t *
frm_index_find(frm_index_table_t *tbl, const char *reqid)
{
    ngx_uint_t i;
    for (i = 0; i < tbl->capacity; i++) {
        frm_index_entry_t *e = &tbl->slots[i];
        if (e->in_use && ngx_strcmp(e->reqid, reqid) == 0) {
            return e;
        }
    }
    return NULL;
}

void
frm_index_insert(const frm_record_t *rec)
{
    frm_index_table_t *tbl = frm_index_table();
    frm_index_entry_t *e, *victim;
    ngx_uint_t         i;
    ngx_msec_t         now, oldest;

    if (tbl == NULL || rec == NULL) {
        return;
    }
    now = ngx_current_msec;

    ngx_shmtx_lock(&frm_index_mtx_v);

    e = frm_index_find(tbl, rec->reqid);     /* update-in-place if present */
    if (e == NULL) {
        /* find a free slot, else LRU-evict */
        victim = NULL;
        oldest = 0;
        for (i = 0; i < tbl->capacity; i++) {
            frm_index_entry_t *s = &tbl->slots[i];
            if (!s->in_use) { e = s; break; }
            if (victim == NULL || s->last_seen < oldest) {
                victim = s; oldest = s->last_seen;
            }
        }
        if (e == NULL) {                     /* table full → reap LRU */
            e = victim;
            tbl->reconcile_full_total++;
        } else {
            tbl->count++;
        }
        if (e == NULL) {                     /* capacity 0 — give up */
            ngx_shmtx_unlock(&frm_index_mtx_v);
            return;
        }
        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->reqid, (u_char *) rec->reqid, sizeof(e->reqid));
    }

    e->lfn_hash   = frm_lfn_hash(rec->lfn);
    e->file_off   = rec->self;
    e->tod_added  = rec->tod_added;
    e->tod_expire = rec->tod_expire;
    e->status     = rec->status;
    e->priority   = rec->priority;
    e->queue      = rec->queue;
    e->last_seen  = now;
    e->in_use     = 1;

    ngx_shmtx_unlock(&frm_index_mtx_v);
}

int
frm_index_lookup(const char *reqid, int64_t *file_off_out)
{
    frm_index_table_t *tbl = frm_index_table();
    frm_index_entry_t *e;
    int                found = 0;

    if (tbl == NULL || reqid == NULL || reqid[0] == '\0') {
        return 0;
    }
    ngx_shmtx_lock(&frm_index_mtx_v);
    e = frm_index_find(tbl, reqid);
    if (e != NULL) {
        if (file_off_out) { *file_off_out = e->file_off; }
        e->last_seen = ngx_current_msec;
        found = 1;
    }
    ngx_shmtx_unlock(&frm_index_mtx_v);
    return found;
}

/* Newest live request for an lfn hash (caller re-verifies the lfn via the file). */
int
frm_index_lookup_path(uint64_t lfn_hash, int wantlive, int64_t *file_off_out)
{
    frm_index_table_t *tbl = frm_index_table();
    ngx_uint_t         i;
    int64_t            best_off = -1;
    int64_t            best_tod = -1;

    if (tbl == NULL) {
        return 0;
    }
    ngx_shmtx_lock(&frm_index_mtx_v);
    for (i = 0; i < tbl->capacity; i++) {
        frm_index_entry_t *e = &tbl->slots[i];
        if (!e->in_use || e->lfn_hash != lfn_hash) {
            continue;
        }
        if (wantlive
            && e->status != FRM_ST_QUEUED
            && e->status != FRM_ST_STAGING
            && e->status != FRM_ST_ONLINE)
        {
            continue;
        }
        if (e->tod_added >= best_tod) {
            best_tod = e->tod_added;
            best_off = e->file_off;
        }
    }
    ngx_shmtx_unlock(&frm_index_mtx_v);
    if (best_off >= 0 && file_off_out) {
        *file_off_out = best_off;
    }
    return best_off >= 0;
}

void
frm_index_remove(const char *reqid)
{
    frm_index_table_t *tbl = frm_index_table();
    frm_index_entry_t *e;

    if (tbl == NULL || reqid == NULL) {
        return;
    }
    ngx_shmtx_lock(&frm_index_mtx_v);
    e = frm_index_find(tbl, reqid);
    if (e != NULL) {
        ngx_memzero(e, sizeof(*e));
        if (tbl->count > 0) { tbl->count--; }
    }
    ngx_shmtx_unlock(&frm_index_mtx_v);
}

void
frm_index_update(const char *reqid, uint8_t status, int64_t tod_expire)
{
    frm_index_table_t *tbl = frm_index_table();
    frm_index_entry_t *e;

    if (tbl == NULL || reqid == NULL) {
        return;
    }
    ngx_shmtx_lock(&frm_index_mtx_v);
    e = frm_index_find(tbl, reqid);
    if (e != NULL) {
        e->status     = status;
        e->tod_expire = tod_expire;
        e->last_seen  = ngx_current_msec;
    }
    ngx_shmtx_unlock(&frm_index_mtx_v);
}

void
frm_index_clear(void)
{
    frm_index_table_t *tbl = frm_index_table();
    if (tbl == NULL) {
        return;
    }
    ngx_shmtx_lock(&frm_index_mtx_v);
    ngx_memzero(tbl->slots,
                (size_t) tbl->capacity * sizeof(frm_index_entry_t));
    tbl->count = 0;
    ngx_shmtx_unlock(&frm_index_mtx_v);
}

ngx_uint_t
frm_index_count(void)
{
    frm_index_table_t *tbl = frm_index_table();
    return tbl ? tbl->count : 0;
}
