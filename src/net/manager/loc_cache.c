/*
 * loc_cache.c — dynamic file-location cache (Phase-89 W3).
 *
 * See loc_cache.h for the contract.  Mirrors pending.c: zone creation via
 * ngx_shared_memory_add + brix_shm_table_alloc (slab header preserved, mutex
 * bound to the pool's recoverable lock word), all access under the process-
 * local mutex handle, spin+yield semantics from ngx_shmtx (INVARIANT #10).
 */

#include "loc_cache.h"
#include "core/ngx_brix_module.h"     /* ngx_stream_brix_module (zone tag) */
#include "core/fnv.h"                 /* BRIX_FNV1A32_* hash constants      */
#include "core/compat/shm_slots.h"

ngx_shm_zone_t *brix_loc_cache_shm_zone;

static ngx_shmtx_t  brix_loc_cache_mutex;

/* loc_table — resolve the zone to the live table, or NULL when the zone has
 * not been allocated / is still at its (void *) 1 init sentinel. */
static brix_loc_table_t *
loc_table(void)
{
    if (brix_loc_cache_shm_zone == NULL
        || brix_loc_cache_shm_zone->data == NULL
        || brix_loc_cache_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (brix_loc_table_t *) brix_loc_cache_shm_zone->data;
}

/* loc_hash — fnv1a over the NUL-terminated path (the design-of-record hash;
 * cheap, decent avalanche for path-shaped keys). */
static uint32_t
loc_hash(const char *path)
{
    uint32_t  h = BRIX_FNV1A32_OFFSET_BASIS;

    while (*path != '\0') {
        h ^= (uint32_t) (u_char) *path++;
        h *= BRIX_FNV1A32_PRIME;
    }
    return h;
}

static ngx_int_t
loc_cache_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    brix_loc_table_t  *tbl;
    ngx_flag_t         fresh;

    tbl = brix_shm_table_alloc(shm_zone, data, sizeof(brix_loc_table_t),
                                 &brix_loc_cache_mutex, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    if (fresh) {
        ngx_memzero(tbl->slots, sizeof(tbl->slots));
    }

    return NGX_OK;
}

ngx_int_t
brix_loc_cache_configure(ngx_conf_t *cf)
{
    ngx_str_t  zone_name = ngx_string("brix_loc_cache");

    brix_loc_cache_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                brix_shm_zone_size(sizeof(brix_loc_table_t)),
                                &ngx_stream_brix_module);
    if (brix_loc_cache_shm_zone == NULL) {
        return NGX_ERROR;
    }

    brix_loc_cache_shm_zone->init = loc_cache_shm_init_zone;
    brix_loc_cache_shm_zone->data = (void *) 1;

    return NGX_OK;
}

int
brix_loc_cache_lookup(const char *path, char *host, size_t host_sz,
    uint16_t *port)
{
    brix_loc_table_t  *tbl;
    brix_loc_entry_t  *e;
    uint32_t           h;
    ngx_uint_t         i, idx;
    ngx_msec_t         now = ngx_current_msec;
    int                hit = 0;

    tbl = loc_table();
    if (tbl == NULL || path == NULL || path[0] == '\0'
        || ngx_strlen(path) >= BRIX_LOC_CACHE_PATH_MAX)
    {
        return 0;
    }

    h = loc_hash(path);

    ngx_shmtx_lock(&brix_loc_cache_mutex);

    for (i = 0; i < BRIX_LOC_CACHE_SLOTS; i++) {
        idx = (h + i) & (BRIX_LOC_CACHE_SLOTS - 1);
        e = &tbl->slots[idx];

        if (!e->in_use) {
            break;    /* probe chain ends at the first never-used slot */
        }
        if (brix_shm_slot_expired(now, e->expires)) {
            continue; /* stale — invisible, but keep probing past it */
        }
        if (e->path_hash == h && ngx_strcmp(e->path, path) == 0) {
            ngx_cpystrn((u_char *) host, (u_char *) e->host, host_sz);
            *port = e->port;
            hit = 1;
            break;
        }
    }

    ngx_shmtx_unlock(&brix_loc_cache_mutex);
    return hit;
}

void
brix_loc_cache_insert(const char *path, const char *host, uint16_t port)
{
    brix_loc_table_t  *tbl;
    brix_loc_entry_t  *e;
    uint32_t           h;
    ngx_uint_t         i, idx, victim;
    ngx_msec_t         now = ngx_current_msec;

    tbl = loc_table();
    if (tbl == NULL || path == NULL || host == NULL
        || ngx_strlen(path) >= BRIX_LOC_CACHE_PATH_MAX
        || ngx_strlen(host) >= sizeof(e->host))
    {
        return;
    }

    h = loc_hash(path);
    victim = BRIX_LOC_CACHE_SLOTS;    /* sentinel: none found yet */

    ngx_shmtx_lock(&brix_loc_cache_mutex);

    for (i = 0; i < BRIX_LOC_CACHE_SLOTS; i++) {
        idx = (h + i) & (BRIX_LOC_CACHE_SLOTS - 1);
        e = &tbl->slots[idx];

        if (e->in_use && !brix_shm_slot_expired(now, e->expires)
            && (e->path_hash != h || ngx_strcmp(e->path, path) != 0))
        {
            continue;    /* live entry for another path — keep probing */
        }

        /* Free, expired, or the same path: claim this slot. */
        victim = idx;
        break;
    }

    if (victim == BRIX_LOC_CACHE_SLOTS) {
        /* Every slot is live for other paths: overwrite the home slot —
         * bounded eviction (loc_cache.h contract). */
        victim = h & (BRIX_LOC_CACHE_SLOTS - 1);
    }

    e = &tbl->slots[victim];
    e->path_hash = h;
    ngx_cpystrn((u_char *) e->path, (u_char *) path, sizeof(e->path));
    ngx_cpystrn((u_char *) e->host, (u_char *) host, sizeof(e->host));
    e->port    = port;
    e->expires = now + BRIX_LOC_CACHE_TTL_MS;
    e->in_use  = 1;

    ngx_shmtx_unlock(&brix_loc_cache_mutex);
}
