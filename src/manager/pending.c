#include "pending.h"
#include <ngx_shmtx.h>

ngx_shm_zone_t *xrootd_pending_shm_zone;

static ngx_shmtx_t  xrootd_pending_mutex;

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
    int conn_fd, ngx_msec_t timeout_ms)
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
            if (free_slot == XROOTD_PENDING_LOCATE_SLOTS) {
                free_slot = i;
            }
            continue;
        }

        /* Reap expired slots so they can be reused. */
        if (ngx_current_msec > slot->expires) {
            slot->in_use = 0;
            if (free_slot == XROOTD_PENDING_LOCATE_SLOTS) {
                free_slot = i;
            }
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
