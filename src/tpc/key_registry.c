/*
 * key_registry.c — shared-memory TPC key registry.
 *
 * Manages the in-flight TPC key table used for native root:// TPC rendezvous.
 * The registry is a fixed-size array in a shared memory zone protected by a
 * spinlock so that all nginx worker processes share the same key namespace.
 */

#include "key_registry.h"

#include <string.h>

static ngx_shm_zone_t  *xrootd_tpc_key_shm_zone;
static ngx_shmtx_t      xrootd_tpc_key_mutex;
static ngx_uint_t        tpc_key_seq;

static xrootd_tpc_key_table_t *
key_table(void)
{
    if (xrootd_tpc_key_shm_zone == NULL
        || xrootd_tpc_key_shm_zone->data == NULL
        || xrootd_tpc_key_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (xrootd_tpc_key_table_t *) xrootd_tpc_key_shm_zone->data;
}


static ngx_int_t
xrootd_tpc_key_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_tpc_key_table_t *tbl;

    if (data) {
        shm_zone->data = data;
        tbl = (xrootd_tpc_key_table_t *) data;
        if (ngx_shmtx_create(&xrootd_tpc_key_mutex, &tbl->lock, NULL) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    tbl = (xrootd_tpc_key_table_t *) shm_zone->shm.addr;
    ngx_memzero(tbl, sizeof(*tbl));

    if (ngx_shmtx_create(&xrootd_tpc_key_mutex, &tbl->lock, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    shm_zone->data = tbl;
    return NGX_OK;
}


ngx_int_t
xrootd_tpc_key_configure_registry(ngx_conf_t *cf)
{
    ngx_str_t  zone_name = ngx_string("xrootd_tpc_keys");
    size_t     zone_size;

    zone_size = sizeof(xrootd_tpc_key_table_t) + ngx_pagesize;
    xrootd_tpc_key_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                      zone_size,
                                                      &ngx_stream_xrootd_module);
    if (xrootd_tpc_key_shm_zone == NULL) {
        return NGX_ERROR;
    }

    xrootd_tpc_key_shm_zone->init = xrootd_tpc_key_shm_init_zone;
    xrootd_tpc_key_shm_zone->data = (void *) 1;

    return NGX_OK;
}


void
xrootd_tpc_generate_key(char *buf, size_t buf_sz)
{
    /* Unique per process (pid) × per call (seq).  No atomics needed —
     * this is always called from the single-threaded event loop. */
    tpc_key_seq++;
    (void) snprintf(buf, buf_sz, "%08lx%016lx",
                    (unsigned long) ngx_pid,
                    (unsigned long) tpc_key_seq);
}


void
xrootd_tpc_key_register(const char *key, ngx_msec_t ttl_ms)
{
    xrootd_tpc_key_table_t *tbl;
    xrootd_tpc_key_entry_t *e;
    ngx_uint_t               i, free_slot;
    ngx_msec_t               now;

    tbl = key_table();
    if (tbl == NULL || key == NULL || key[0] == '\0') {
        return;
    }

    now = ngx_current_msec;

    ngx_shmtx_lock(&xrootd_tpc_key_mutex);

    free_slot = XROOTD_TPC_KEY_SLOTS;
    for (i = 0; i < XROOTD_TPC_KEY_SLOTS; i++) {
        e = &tbl->slots[i];
        if (!e->in_use || now >= e->expiry) {
            if (free_slot == XROOTD_TPC_KEY_SLOTS) {
                free_slot = i;
            }
            if (e->in_use && now >= e->expiry) {
                ngx_memzero(e, sizeof(*e));
            }
            continue;
        }
        if (strcmp(e->key, key) == 0) {
            /* refresh expiry */
            e->expiry = now + ttl_ms;
            ngx_shmtx_unlock(&xrootd_tpc_key_mutex);
            return;
        }
    }

    if (free_slot < XROOTD_TPC_KEY_SLOTS) {
        e = &tbl->slots[free_slot];
        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->key, (u_char *) key, sizeof(e->key));
        e->expiry = now + ttl_ms;
        e->in_use = 1;
    }

    ngx_shmtx_unlock(&xrootd_tpc_key_mutex);
}


int
xrootd_tpc_key_validate(const char *key)
{
    xrootd_tpc_key_table_t *tbl;
    xrootd_tpc_key_entry_t *e;
    ngx_uint_t               i;
    ngx_msec_t               now;
    int                      found = 0;

    tbl = key_table();
    if (tbl == NULL || key == NULL || key[0] == '\0') {
        return 0;
    }

    now = ngx_current_msec;

    ngx_shmtx_lock(&xrootd_tpc_key_mutex);

    for (i = 0; i < XROOTD_TPC_KEY_SLOTS; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        if (now >= e->expiry) {
            ngx_memzero(e, sizeof(*e));
            continue;
        }
        if (strcmp(e->key, key) == 0) {
            found = 1;
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_tpc_key_mutex);
    return found;
}


int
xrootd_tpc_key_consume(const char *key)
{
    xrootd_tpc_key_table_t *tbl;
    xrootd_tpc_key_entry_t *e;
    ngx_uint_t               i;
    ngx_msec_t               now;
    int                      found = 0;

    tbl = key_table();
    if (tbl == NULL || key == NULL || key[0] == '\0') {
        return 0;
    }

    now = ngx_current_msec;

    ngx_shmtx_lock(&xrootd_tpc_key_mutex);

    for (i = 0; i < XROOTD_TPC_KEY_SLOTS; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        if (now >= e->expiry) {
            ngx_memzero(e, sizeof(*e));
            continue;
        }
        if (strcmp(e->key, key) == 0) {
            ngx_memzero(e, sizeof(*e));
            found = 1;
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_tpc_key_mutex);
    return found;
}


void
xrootd_tpc_key_remove(const char *key)
{
    xrootd_tpc_key_table_t *tbl;
    xrootd_tpc_key_entry_t *e;
    ngx_uint_t               i;

    tbl = key_table();
    if (tbl == NULL || key == NULL || key[0] == '\0') {
        return;
    }

    ngx_shmtx_lock(&xrootd_tpc_key_mutex);

    for (i = 0; i < XROOTD_TPC_KEY_SLOTS; i++) {
        e = &tbl->slots[i];
        if (e->in_use && strcmp(e->key, key) == 0) {
            ngx_memzero(e, sizeof(*e));
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_tpc_key_mutex);
}
