/*
 * shm_slots.c — slab-safe SHM table allocation.
 *
 * See shm_slots.h for the rationale: every nginx shared_memory zone is a slab
 * pool, and nginx's ngx_unlock_mutexes() (run on every child death) dereferences
 * each zone's slab-pool header. A zone that overwrites that header crashes the
 * master the instant any worker child exits. These helpers allocate the table
 * FROM the slab pool so the header survives.
 */

#include "shm_slots.h"


/*
 * xrootd_shm_table_mutex_create — bind the table's process-local mutex to the
 * slab pool's OWN lock word (&sp->lock), in spin+yield-only mode.
 *
 * WHY BIND TO &sp->lock (dead-holder recovery): nginx's ngx_unlock_mutexes(),
 * run on EVERY worker death, force-unlocks exactly &((ngx_slab_pool_t *)
 * shm.addr)->mutex — which points at &sp->lock — for every registered zone. It
 * has no knowledge of a mutex laid over the table data elsewhere in the zone. A
 * table mutex bound to its own embedded lock word is therefore NEVER recovered:
 * a worker SIGKILLed mid-critical-section (e.g. at reload's
 * worker_shutdown_timeout) while holding it strands the lock forever, and the
 * spin+yield path below has no timeout to escape. Across many reload/restart
 * cycles that coincidence becomes a near-certainty, the stale lock survives
 * reload via the persisted slab pool, and every subsequent kXR_open freezes its
 * whole worker. Sharing &sp->lock inherits nginx's per-zone recovery for free.
 * It cannot self-deadlock: every consumer holds this lock only for fixed-slot
 * table scans that never call ngx_slab_alloc/free (the only other &sp->lock
 * taker).
 *
 * WHY spin+yield (no POSIX semaphore): ngx_shmtx's semaphore wakeup path is
 * lost-wakeup-prone under heavy cross-worker contention (and sem_wait/sem_post
 * is unreliable on some kernels, notably WSL2): a worker can block in sem_wait
 * indefinitely with the lock ALREADY free — lock==0, wait==0, yet a thread
 * parked in __futex_abstimed_wait_common — because no later unlock posts the
 * semaphore (wakeup posts only when wait>0). That freezes the whole worker,
 * stalling every pinned connection. These are microsecond fixed-slot scans, so
 * spin-then-ngx_sched_yield is correct, cheaper than a syscall, and immune to
 * the lost wakeup. ngx_shmtx_create() enables the semaphore unconditionally when
 * NGX_HAVE_POSIX_SEM is set, so we clear ->semaphore on BOTH our handle and the
 * shared sp->mutex (both point at &sp->lock): neither our ngx_shmtx_lock nor
 * nginx's force-unlock wakeup must ever touch a semaphore.
 */
static ngx_int_t
xrootd_shm_table_mutex_create(ngx_shmtx_t *mtx, ngx_slab_pool_t *sp)
{
    if (ngx_shmtx_create(mtx, &sp->lock, NULL) != NGX_OK) {
        return NGX_ERROR;
    }
#if (NGX_HAVE_POSIX_SEM)
    mtx->semaphore      = 0;
    sp->mutex.semaphore = 0;
#endif
    return NGX_OK;
}


void *
xrootd_shm_table_alloc(ngx_shm_zone_t *shm_zone, void *data, size_t table_bytes,
                       ngx_shmtx_t *mtx, ngx_flag_t *fresh)
{
    ngx_slab_pool_t *sp;
    void            *tbl;

    if (fresh) {
        *fresh = 0;
    }

    /* The table mutex always binds to the slab pool's own lock word (&sp->lock),
     * so nginx's per-zone force-unlock recovers it on worker death (see
     * xrootd_shm_table_mutex_create). shm.addr is the slab pool in every path —
     * fresh, reload, and re-attach. */
    sp = (ngx_slab_pool_t *) shm_zone->shm.addr;

    /* Reload: nginx hands us the previous cycle's table via `data`. */
    if (data) {
        shm_zone->data = data;
        if (mtx && xrootd_shm_table_mutex_create(mtx, sp) != NGX_OK) {
            return NULL;
        }
        return data;
    }

    /* Re-attach to an already-populated segment (persisted slab ->data). */
    if (shm_zone->shm.exists && sp->data != NULL) {
        tbl = sp->data;
        shm_zone->data = tbl;
        if (mtx && xrootd_shm_table_mutex_create(mtx, sp) != NGX_OK) {
            return NULL;
        }
        return tbl;
    }

    /* Fresh allocation from the slab pool (header left intact). */
    tbl = ngx_slab_alloc(sp, table_bytes);
    if (tbl == NULL) {
        return NULL;
    }
    ngx_memzero(tbl, table_bytes);
    sp->data       = tbl;                    /* persist for reload re-attach */
    shm_zone->data = tbl;

    if (mtx && xrootd_shm_table_mutex_create(mtx, sp) != NGX_OK) {
        return NULL;
    }
    if (fresh) {
        *fresh = 1;
    }
    return tbl;
}


void
xrootd_shm_zone_warn_on_resize(ngx_conf_t *cf, ngx_shm_zone_t *zn,
                               const char *directive)
{
    ngx_cycle_t      *oc;
    ngx_list_part_t  *part;
    ngx_shm_zone_t   *old;
    ngx_uint_t        i;

    /*
     * During `nginx -s reload` the new cycle is built while the global ngx_cycle
     * still points at the running cycle, so its shared_memory list carries the
     * sizes the live workers are using.  If the operator changed a slot-count
     * directive, nginx cannot grow an existing zone — it allocates a brand-new
     * one and the old table's contents vanish.  Surface that as a WARN so the
     * reset is not silent.  On the very first start ngx_cycle is the bootstrap
     * cycle with an empty list, so this is a no-op (no false positives).
     */
    if (zn == NULL || ngx_cycle == NULL) {
        return;
    }

    oc   = (ngx_cycle_t *) ngx_cycle;   /* drop the global's volatile qualifier */
    part = &oc->shared_memory.part;
    old  = part->elts;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            old  = part->elts;
            i = 0;
        }

        if (old[i].shm.name.len != zn->shm.name.len
            || ngx_strncmp(old[i].shm.name.data, zn->shm.name.data,
                           zn->shm.name.len) != 0)
        {
            continue;
        }

        /* nginx keys zone identity on (name, tag); a different tag is a
         * different zone that merely shares a name. */
        if (old[i].tag != zn->tag) {
            continue;
        }

        if (old[i].shm.size != zn->shm.size) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "xrootd: %s changed across reload (shared zone \"%V\" "
                "%uz -> %uz bytes): nginx allocates a fresh zone, so entries "
                "live in this table are dropped for new connections "
                "(in-flight ones drain on the old workers). A full restart "
                "avoids the transient reset.",
                directive, &zn->shm.name,
                old[i].shm.size, zn->shm.size);
        }
        return;
    }
}


size_t
xrootd_shm_zone_size(size_t table_bytes)
{
    /*
     * The zone must hold the table plus the slab-pool overhead: the
     * ngx_slab_pool_t header, the per-page management array (~one
     * ngx_slab_page_t per page), and slack for slab rounding. A proportional
     * term (table/32) covers the page array for large tables; the fixed 3 pages
     * cover the header + small-table rounding.
     */
    return table_bytes + (table_bytes >> 5) + 3 * (size_t) ngx_pagesize;
}
