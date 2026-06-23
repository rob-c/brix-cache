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
 * xrootd_shm_table_mutex_create — create the table's process-local mutex in
 * spin+yield-only mode (POSIX semaphore disabled).
 *
 * WHY: ngx_shmtx's POSIX-semaphore wakeup path is lost-wakeup-prone under heavy
 * cross-worker contention (and the underlying sem_wait/sem_post is unreliable on
 * some kernels, notably WSL2): a worker can block in sem_wait indefinitely with
 * the lock ALREADY free — observed as lock==0, wait==0, yet a thread parked in
 * __futex_abstimed_wait_common — because no subsequent unlock ever posts the
 * semaphore (the unlock's wakeup only posts when wait>0).  That hangs the whole
 * worker (it stops running its event loop), stalling every connection pinned to
 * it.  These tables are tiny fixed-slot scans held for microseconds, so spinning
 * with sched_yield on contention is both correct and cheaper than a syscall —
 * and immune to the lost wakeup.  ngx_shmtx_create() initialises the semaphore
 * unconditionally when NGX_HAVE_POSIX_SEM is set, so we clear ->semaphore right
 * after; the lock then uses the spin-then-ngx_sched_yield path exclusively.
 */
static ngx_int_t
xrootd_shm_table_mutex_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr)
{
    if (ngx_shmtx_create(mtx, addr, NULL) != NGX_OK) {
        return NGX_ERROR;
    }
#if (NGX_HAVE_POSIX_SEM)
    mtx->semaphore = 0;
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

    /* Reload: nginx hands us the previous cycle's table via `data`. */
    if (data) {
        shm_zone->data = data;
        if (mtx
            && xrootd_shm_table_mutex_create(mtx, (ngx_shmtx_sh_t *) data)
               != NGX_OK)
        {
            return NULL;
        }
        return data;
    }

    sp = (ngx_slab_pool_t *) shm_zone->shm.addr;

    /* Re-attach to an already-populated segment (persisted slab ->data). */
    if (shm_zone->shm.exists && sp->data != NULL) {
        tbl = sp->data;
        shm_zone->data = tbl;
        if (mtx
            && xrootd_shm_table_mutex_create(mtx, (ngx_shmtx_sh_t *) tbl)
               != NGX_OK)
        {
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

    if (mtx
        && xrootd_shm_table_mutex_create(mtx, (ngx_shmtx_sh_t *) tbl) != NGX_OK)
    {
        return NULL;
    }
    if (fresh) {
        *fresh = 1;
    }
    return tbl;
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
