#include "pending.h"
#include "core/compat/shm_slots.h"
#include <ngx_shmtx.h>

ngx_shm_zone_t *brix_pending_shm_zone;

static ngx_shmtx_t  brix_pending_mutex;

/**
 * WHAT: Retrieve the shared-memory pending-locate table pointer.
 * WHY: All operations in this module access a single shm_zone to track
 *      in-flight kXR_locate requests across workers. This helper centralizes
 *      NULL-check logic so callers don't repeat it.
 * HOW: Returns NULL if the shm_zone hasn't been allocated yet, is still at
 *      initialization sentinel ((void *) 1), or has no data attached. Otherwise
 *      casts and returns the zone->data pointer as brix_pending_table_t*.
 */
static brix_pending_table_t *
pending_table(void)
{
    if (brix_pending_shm_zone == NULL
        || brix_pending_shm_zone->data == NULL
        || brix_pending_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (brix_pending_table_t *) brix_pending_shm_zone->data;
}

/**
 * WHAT: Initialize the pending-locate shared-memory zone.
 * WHY: Called during nginx configuration to allocate the shared memory region
 *      that holds slots for in-flight kXR_locate requests. The mutex is created
 *      here so all workers can safely access the table.
 * HOW: Delegates fresh-alloc / reload / re-attach to brix_shm_table_alloc(),
 *      which allocates the table FROM the slab pool (leaving nginx's
 *      ngx_slab_pool_t header at shm.addr intact so ngx_unlock_mutexes() does
 *      not clobber it when a child exits) and publishes it via shm_zone->data.
 *      The mutex is created from the table's leading ngx_shmtx_sh_t lock. Only a
 *      brand-new allocation (fresh==1) zeroes the slot array; on reload/re-attach
 *      the live slot state is preserved. Returns NGX_OK or NGX_ERROR.
 */
static ngx_int_t
brix_pending_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t               fresh;
    brix_pending_table_t  *tbl;

    tbl = brix_shm_table_alloc(shm_zone, data,
                                 sizeof(brix_pending_table_t),
                                 &brix_pending_mutex, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    if (fresh) {
        ngx_memzero(tbl->slots, sizeof(tbl->slots));
    }

    return NGX_OK;
}

/**
 * WHAT: Configure the pending-locate shared-memory zone during nginx startup.
 * WHY: Creates a dedicated SHM region named "brix_pending_locate" that stores
 *      up to BRIX_PENDING_LOCATE_SLOTS (32) in-flight kXR_locate entries. Each
 *      entry tracks a worker's locate request until the CMS manager responds with
 *      a redirect host/port via kXR_select.
 * HOW: Adds a shared memory zone sized via brix_shm_zone_size() so the table
 *      can be slab-allocated alongside the slab-pool header (see
 *      brix_pending_shm_init_zone), registers brix_pending_shm_init_zone as
 *      the init callback (called after allocation), and sets data=(void *) 1 as
 *      an initialization sentinel so accessors know the zone is not yet ready.
 *      Returns NGX_OK or NGX_ERROR.
 */
ngx_int_t
brix_pending_configure(ngx_conf_t *cf)
{
    ngx_str_t  zone_name = ngx_string("brix_pending_locate");
    size_t     zone_size;

    zone_size = brix_shm_zone_size(sizeof(brix_pending_table_t));

    brix_pending_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                      zone_size,
                                                      &ngx_stream_brix_module);
    if (brix_pending_shm_zone == NULL) {
        return NGX_ERROR;
    }

    brix_pending_shm_zone->init = brix_pending_shm_init_zone;
    brix_pending_shm_zone->data = (void *) 1;

    return NGX_OK;
}

ngx_int_t
brix_pending_insert(uint32_t streamid, ngx_pid_t worker_pid,
    int conn_fd, ngx_atomic_uint_t conn_number,
    const u_char client_streamid[2], ngx_msec_t timeout_ms)
{
    brix_pending_table_t   *tbl;
    brix_pending_locate_t  *slot;
    ngx_uint_t                i, free_slot;

    tbl = pending_table();
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&brix_pending_mutex);

    free_slot = BRIX_PENDING_LOCATE_SLOTS;  /* sentinel: none found yet */

    for (i = 0; i < BRIX_PENDING_LOCATE_SLOTS; i++) {
        slot = &tbl->slots[i];

        if (!slot->in_use) {
            brix_shm_remember_free_slot(&free_slot,
                                          BRIX_PENDING_LOCATE_SLOTS, i);
            continue;
        }

        /* Reap expired slots so they can be reused. */
        if (brix_shm_slot_expired(ngx_current_msec, slot->expires)) {
            slot->in_use = 0;
            brix_shm_remember_free_slot(&free_slot,
                                          BRIX_PENDING_LOCATE_SLOTS, i);
            continue;
        }
    }

    if (free_slot == BRIX_PENDING_LOCATE_SLOTS) {
        ngx_shmtx_unlock(&brix_pending_mutex);
        return NGX_AGAIN;  /* table full */
    }

    slot = &tbl->slots[free_slot];
    slot->streamid    = streamid;
    slot->worker_pid  = worker_pid;
    slot->conn_fd     = conn_fd;
    slot->conn_number = conn_number;
    if (client_streamid != NULL) {
        slot->client_streamid[0] = client_streamid[0];
        slot->client_streamid[1] = client_streamid[1];
    } else {
        slot->client_streamid[0] = 0;
        slot->client_streamid[1] = 0;
    }
    slot->expires     = ngx_current_msec + timeout_ms;
    slot->redir_host[0] = '\0';
    slot->redir_port  = 0;
    slot->in_use      = 1;

    ngx_shmtx_unlock(&brix_pending_mutex);
    return NGX_OK;
}

brix_pending_locate_t *
brix_pending_lookup(uint32_t streamid, ngx_pid_t worker_pid)
{
    brix_pending_table_t   *tbl;
    brix_pending_locate_t  *slot;
    ngx_uint_t                i;

    tbl = pending_table();
    if (tbl == NULL) {
        return NULL;
    }

    ngx_shmtx_lock(&brix_pending_mutex);

    for (i = 0; i < BRIX_PENDING_LOCATE_SLOTS; i++) {
        slot = &tbl->slots[i];
        if (slot->in_use
            && slot->streamid == streamid
            && slot->worker_pid == worker_pid)
        {
            /* Caller must call brix_pending_unlock() after reading. */
            return slot;
        }
    }

    ngx_shmtx_unlock(&brix_pending_mutex);
    return NULL;
}

void
brix_pending_unlock(void)
{
    ngx_shmtx_unlock(&brix_pending_mutex);
}

ngx_uint_t
brix_pending_reap_expired(void)
{
    brix_pending_table_t   *tbl;
    brix_pending_locate_t  *slot;
    ngx_uint_t                i, reaped = 0;

    tbl = pending_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_pending_mutex);
    for (i = 0; i < BRIX_PENDING_LOCATE_SLOTS; i++) {
        slot = &tbl->slots[i];
        if (slot->in_use
            && brix_shm_slot_expired(ngx_current_msec, slot->expires))
        {
            slot->in_use = 0;          /* A4: reclaim an abandoned locate slot */
            reaped++;
        }
    }
    ngx_shmtx_unlock(&brix_pending_mutex);
    return reaped;
}

void
brix_pending_remove(uint32_t streamid, ngx_pid_t worker_pid)
{
    brix_pending_table_t   *tbl;
    brix_pending_locate_t  *slot;
    ngx_uint_t                i;

    tbl = pending_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_pending_mutex);

    for (i = 0; i < BRIX_PENDING_LOCATE_SLOTS; i++) {
        slot = &tbl->slots[i];
        if (slot->in_use
            && slot->streamid == streamid
            && slot->worker_pid == worker_pid)
        {
            slot->in_use = 0;
            break;
        }
    }

    ngx_shmtx_unlock(&brix_pending_mutex);
}
