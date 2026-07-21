/*
 * reqid_map.c — CMS↔engine request-id sidecar map (Phase-89 W2 / ADR-2b).
 *
 * See reqid_map.h for the contract.  Mirrors manager/loc_cache.c: zone via
 * ngx_shared_memory_add + brix_shm_table_alloc (mutex bound to the slab
 * pool's recoverable lock word, spin+yield — INVARIANT #10), fnv1a
 * open-addressing, lazy TTL expiry, bounded home-slot eviction.
 */

#include "reqid_map.h"
#include "core/ngx_brix_module.h"     /* ngx_stream_brix_module (zone tag) */
#include "core/fnv.h"                 /* BRIX_FNV1A32_* hash constants      */
#include "core/compat/shm_slots.h"

ngx_shm_zone_t *brix_cms_reqid_map_shm_zone;

static ngx_shmtx_t  brix_cms_reqid_map_mutex;

/* reqid_table — resolve the zone to the live table, or NULL when the zone has
 * not been allocated / is still at its (void *) 1 init sentinel. */
static brix_cms_reqid_table_t *
reqid_table(void)
{
    if (brix_cms_reqid_map_shm_zone == NULL
        || brix_cms_reqid_map_shm_zone->data == NULL
        || brix_cms_reqid_map_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (brix_cms_reqid_table_t *) brix_cms_reqid_map_shm_zone->data;
}

static uint32_t
reqid_hash(const char *key)
{
    uint32_t  h = BRIX_FNV1A32_OFFSET_BASIS;

    while (*key != '\0') {
        h ^= (uint32_t) (u_char) *key++;
        h *= BRIX_FNV1A32_PRIME;
    }
    return h;
}

static ngx_int_t
reqid_map_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    brix_cms_reqid_table_t  *tbl;
    ngx_flag_t               fresh;

    tbl = brix_shm_table_alloc(shm_zone, data,
                                 sizeof(brix_cms_reqid_table_t),
                                 &brix_cms_reqid_map_mutex, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    if (fresh) {
        ngx_memzero(tbl->slots, sizeof(tbl->slots));
    }

    return NGX_OK;
}

ngx_int_t
brix_cms_reqid_map_configure(ngx_conf_t *cf)
{
    ngx_str_t  zone_name = ngx_string("brix_cms_reqid_map");

    brix_cms_reqid_map_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                        brix_shm_zone_size(sizeof(brix_cms_reqid_table_t)),
                        &ngx_stream_brix_module);
    if (brix_cms_reqid_map_shm_zone == NULL) {
        return NGX_ERROR;
    }

    brix_cms_reqid_map_shm_zone->init = reqid_map_shm_init_zone;
    brix_cms_reqid_map_shm_zone->data = (void *) 1;

    return NGX_OK;
}

void
brix_cms_reqid_map_put(const char *cms_reqid, const char *engine_reqid,
    const char *notify, const char *prty)
{
    brix_cms_reqid_table_t  *tbl;
    brix_cms_reqid_entry_t  *e;
    uint32_t                 h;
    ngx_uint_t               i, idx, victim;
    ngx_msec_t               now = ngx_current_msec;

    tbl = reqid_table();
    if (tbl == NULL || cms_reqid == NULL || engine_reqid == NULL
        || cms_reqid[0] == '\0'
        || ngx_strlen(cms_reqid) >= BRIX_CMS_REQID_KEY_MAX
        || ngx_strlen(engine_reqid) >= BRIX_CMS_REQID_ENGINE_MAX)
    {
        return;
    }

    h = reqid_hash(cms_reqid);
    victim = BRIX_CMS_REQID_MAP_SLOTS;    /* sentinel: none found yet */

    ngx_shmtx_lock(&brix_cms_reqid_map_mutex);

    for (i = 0; i < BRIX_CMS_REQID_MAP_SLOTS; i++) {
        idx = (h + i) & (BRIX_CMS_REQID_MAP_SLOTS - 1);
        e = &tbl->slots[idx];

        if (e->in_use && !brix_shm_slot_expired(now, e->expires)
            && (e->key_hash != h || ngx_strcmp(e->cms_reqid, cms_reqid) != 0))
        {
            continue;    /* live entry for another reqid — keep probing */
        }

        victim = idx;    /* free, expired, or same key: claim */
        break;
    }

    if (victim == BRIX_CMS_REQID_MAP_SLOTS) {
        /* Every slot live for other keys: overwrite the home slot —
         * bounded eviction (reqid_map.h contract). */
        victim = h & (BRIX_CMS_REQID_MAP_SLOTS - 1);
    }

    e = &tbl->slots[victim];
    e->key_hash = h;
    ngx_cpystrn((u_char *) e->cms_reqid, (u_char *) cms_reqid,
                sizeof(e->cms_reqid));
    ngx_cpystrn((u_char *) e->engine_reqid, (u_char *) engine_reqid,
                sizeof(e->engine_reqid));
    ngx_cpystrn((u_char *) e->notify,
                (u_char *) (notify != NULL ? notify : ""),
                sizeof(e->notify));
    ngx_cpystrn((u_char *) e->prty,
                (u_char *) (prty != NULL ? prty : ""),
                sizeof(e->prty));
    e->expires = now + BRIX_CMS_REQID_MAP_TTL_MS;
    e->in_use  = 1;

    ngx_shmtx_unlock(&brix_cms_reqid_map_mutex);
}

int
brix_cms_reqid_map_take(const char *cms_reqid, char *engine_reqid_out,
    size_t engine_reqid_sz)
{
    brix_cms_reqid_table_t  *tbl;
    brix_cms_reqid_entry_t  *e;
    uint32_t                 h;
    ngx_uint_t               i, idx;
    ngx_msec_t               now = ngx_current_msec;
    int                      hit = 0;

    tbl = reqid_table();
    if (tbl == NULL || cms_reqid == NULL || cms_reqid[0] == '\0'
        || ngx_strlen(cms_reqid) >= BRIX_CMS_REQID_KEY_MAX)
    {
        return 0;
    }

    h = reqid_hash(cms_reqid);

    ngx_shmtx_lock(&brix_cms_reqid_map_mutex);

    for (i = 0; i < BRIX_CMS_REQID_MAP_SLOTS; i++) {
        idx = (h + i) & (BRIX_CMS_REQID_MAP_SLOTS - 1);
        e = &tbl->slots[idx];

        if (!e->in_use) {
            break;    /* probe chain ends at the first never-used slot */
        }
        if (brix_shm_slot_expired(now, e->expires)) {
            continue; /* stale — invisible, but keep probing past it */
        }
        if (e->key_hash == h && ngx_strcmp(e->cms_reqid, cms_reqid) == 0) {
            ngx_cpystrn((u_char *) engine_reqid_out,
                        (u_char *) e->engine_reqid, engine_reqid_sz);
            /* A prepdel consumes the mapping: expire the slot in place so
             * the probe chain over it stays intact. */
            e->expires = now;
            hit = 1;
            break;
        }
    }

    ngx_shmtx_unlock(&brix_cms_reqid_map_mutex);
    return hit;
}
