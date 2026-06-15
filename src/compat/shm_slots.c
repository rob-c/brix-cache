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
            && ngx_shmtx_create(mtx, (ngx_shmtx_sh_t *) data, NULL) != NGX_OK)
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
            && ngx_shmtx_create(mtx, (ngx_shmtx_sh_t *) tbl, NULL) != NGX_OK)
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
        && ngx_shmtx_create(mtx, (ngx_shmtx_sh_t *) tbl, NULL) != NGX_OK)
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
