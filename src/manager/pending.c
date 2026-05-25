#include "pending.h"
#include "../compat/shm_slots.h"
#include <ngx_shmtx.h>

ngx_shm_zone_t *xrootd_pending_shm_zone;

static ngx_shmtx_t  xrootd_pending_mutex;

/**
 * WHAT: Retrieve the shared-memory pending-locate table pointer.
 * WHY: All operations in this module access a single shm_zone to track
 *      in-flight kXR_locate requests across workers. This helper centralizes
 *      NULL-check logic so callers don't repeat it.
 * HOW: Returns NULL if the shm_zone hasn't been allocated yet, is still at
 *      initialization sentinel ((void *) 1), or has no data attached. Otherwise
 *      casts and returns the zone->data pointer as xrootd_pending_table_t*.
 */
static xrootd_pending_table_t *
pending_table(void)
{
    if (xrootd_pending_shm_zone == NULL
        || xrootd_pending_shm_zone->data == NULL
        || xrootd_pending_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (xrootd_pending_table_t *) xrootd_pending_shm_zone->data;
}

/**
 * WHAT: Initialize the pending-locate shared-memory zone.
 * WHY: Called during nginx configuration to allocate and zero-fill a shared
 *      memory region that holds slots for in-flight kXR_locate requests. The
 *      mutex is created here so all workers can safely access the table.
 * HOW: On first call (data==NULL) allocates from shm_zone->shm.addr, zeroes
 *      the slot array, creates the shared mutex via ngx_shmtx_create(), and
 *      sets zone->data to the new table pointer. On subsequent calls (shared
 *      across workers), copies existing data into zone->data and recreates
 *      the mutex from that copy. Returns NGX_OK or NGX_ERROR on failure.
 */
static ngx_int_t
xrootd_pending_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_pending_table_t *tbl;

    if (data) {
        shm_zone->data = data;
        tbl = (xrootd_pending_table_t *) data;
        if (ngx_shmtx_create(&xrootd_pending_mutex, &tbl->lock, NULL) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    tbl = (xrootd_pending_table_t *) shm_zone->shm.addr;
    ngx_memzero(tbl->slots, sizeof(tbl->slots));

    if (ngx_shmtx_create(&xrootd_pending_mutex, &tbl->lock, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    shm_zone->data = tbl;
    return NGX_OK;
}

/**
 * WHAT: Configure the pending-locate shared-memory zone during nginx startup.
 * WHY: Creates a dedicated SHM region named "xrootd_pending_locate" that stores
 *      up to XROOTD_PENDING_LOCATE_SLOTS (32) in-flight kXR_locate entries. Each
 *      entry tracks a worker's locate request until the CMS manager responds with
 *      a redirect host/port via kXR_select.
 * HOW: Adds a shared memory zone of size sizeof(xrootd_pending_table_t) + one page,
 *      registers xrootd_pending_shm_init_zone as the init callback (called after
 *      allocation), and sets data=(void *) 1 as an initialization sentinel so the
 *      init function knows this is its first invocation. Returns NGX_OK or NGX_ERROR.
 */
ngx_int_t
xrootd_pending_configure(ngx_conf_t *cf)
{
    ngx_str_t  zone_name = ngx_string("xrootd_pending_locate");
    size_t     zone_size;

    zone_size = sizeof(xrootd_pending_table_t) + ngx_pagesize;

    xrootd_pending_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                      zone_size,
                                                      &ngx_stream_xrootd_module);
    if (xrootd_pending_shm_zone == NULL) {
        return NGX_ERROR;
    }

    xrootd_pending_shm_zone->init = xrootd_pending_shm_init_zone;
    xrootd_pending_shm_zone->data = (void *) 1;

    return NGX_OK;
}

ngx_int_t
xrootd_pending_insert(uint32_t streamid, ngx_pid_t worker_pid,
    int conn_fd, ngx_atomic_uint_t conn_number,
    const u_char client_streamid[2], ngx_msec_t timeout_ms)
{
    xrootd_pending_table_t   *tbl;
    xrootd_pending_locate_t  *slot;
    ngx_uint_t                i, free_slot;

    tbl = pending_table();
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&xrootd_pending_mutex);

    free_slot = XROOTD_PENDING_LOCATE_SLOTS;  /* sentinel: none found yet */

    for (i = 0; i < XROOTD_PENDING_LOCATE_SLOTS; i++) {
        slot = &tbl->slots[i];

        if (!slot->in_use) {
            xrootd_shm_remember_free_slot(&free_slot,
                                          XROOTD_PENDING_LOCATE_SLOTS, i);
            continue;
        }

        /* Reap expired slots so they can be reused. */
        if (xrootd_shm_slot_expired(ngx_current_msec, slot->expires)) {
            slot->in_use = 0;
            xrootd_shm_remember_free_slot(&free_slot,
                                          XROOTD_PENDING_LOCATE_SLOTS, i);
            continue;
        }
    }

    if (free_slot == XROOTD_PENDING_LOCATE_SLOTS) {
        ngx_shmtx_unlock(&xrootd_pending_mutex);
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

    ngx_shmtx_unlock(&xrootd_pending_mutex);
    return NGX_OK;
}

xrootd_pending_locate_t *
xrootd_pending_lookup(uint32_t streamid, ngx_pid_t worker_pid)
{
    xrootd_pending_table_t   *tbl;
    xrootd_pending_locate_t  *slot;
    ngx_uint_t                i;

    tbl = pending_table();
    if (tbl == NULL) {
        return NULL;
    }

    ngx_shmtx_lock(&xrootd_pending_mutex);

    for (i = 0; i < XROOTD_PENDING_LOCATE_SLOTS; i++) {
        slot = &tbl->slots[i];
        if (slot->in_use
            && slot->streamid == streamid
            && slot->worker_pid == worker_pid)
        {
            /* Caller must call xrootd_pending_unlock() after reading. */
            return slot;
        }
    }

    ngx_shmtx_unlock(&xrootd_pending_mutex);
    return NULL;
}

void
xrootd_pending_unlock(void)
{
    ngx_shmtx_unlock(&xrootd_pending_mutex);
}

void
xrootd_pending_remove(uint32_t streamid, ngx_pid_t worker_pid)
{
    xrootd_pending_table_t   *tbl;
    xrootd_pending_locate_t  *slot;
    ngx_uint_t                i;

    tbl = pending_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_pending_mutex);

    for (i = 0; i < XROOTD_PENDING_LOCATE_SLOTS; i++) {
        slot = &tbl->slots[i];
        if (slot->in_use
            && slot->streamid == streamid
            && slot->worker_pid == worker_pid)
        {
            slot->in_use = 0;
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_pending_mutex);
}
