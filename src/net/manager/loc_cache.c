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

/* §2.6 — set-once (config time, before fork) TTL policy.  ttl covers positive
 * entries (brix_cms_fxhold; stock cms.fxhold defaults to 8h, BriX keeps the
 * legacy 30s unless configured); emptylife covers negative entries (0 = the
 * feature is off and negatives are never written). */
static ngx_msec_t  brix_loc_cache_ttl_ms       = BRIX_LOC_CACHE_TTL_MS;
static ngx_msec_t  brix_loc_cache_emptylife_ms = 0;

void
brix_loc_cache_set_ttl(ngx_msec_t ttl_ms)
{
    if (ttl_ms > 0) {
        brix_loc_cache_ttl_ms = ttl_ms;
    }
}

void
brix_loc_cache_set_emptylife(ngx_msec_t emptylife_ms)
{
    brix_loc_cache_emptylife_ms = emptylife_ms;
}

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

/*
 * brix_loc_cache_lookup2 — three-way probe (contract in loc_cache.h).
 *
 * WHAT: BRIX_LOC_HIT with host/port filled for a live positive entry,
 *       BRIX_LOC_NEG for a live negative ("no holder") entry, BRIX_LOC_MISS
 *       otherwise.
 * WHY:  The locate path treats the three outcomes differently: redirect,
 *       answer kXR_NotFound without re-probing the cluster, or fan out.
 * HOW:  Linear probe from the path's home slot; expired entries are invisible
 *       but probed past; the chain ends at the first never-used slot.  A
 *       negative entry is one with an empty host (§2.6).
 */
int
brix_loc_cache_lookup2(const char *path, char *host, size_t host_sz,
    uint16_t *port)
{
    brix_loc_table_t  *tbl;
    brix_loc_entry_t  *e;
    uint32_t           h;
    ngx_uint_t         i, idx;
    ngx_msec_t         now = ngx_current_msec;
    int                hit = BRIX_LOC_MISS;

    tbl = loc_table();
    if (tbl == NULL || path == NULL || path[0] == '\0'
        || ngx_strlen(path) >= BRIX_LOC_CACHE_PATH_MAX)
    {
        return BRIX_LOC_MISS;
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
            if (e->host[0] == '\0') {
                hit = BRIX_LOC_NEG;
            } else {
                ngx_cpystrn((u_char *) host, (u_char *) e->host, host_sz);
                *port = e->port;
                hit = BRIX_LOC_HIT;
            }
            break;
        }
    }

    ngx_shmtx_unlock(&brix_loc_cache_mutex);
    return hit;
}

int
brix_loc_cache_lookup(const char *path, char *host, size_t host_sz,
    uint16_t *port)
{
    return brix_loc_cache_lookup2(path, host, host_sz, port) == BRIX_LOC_HIT;
}

/*
 * loc_insert_core — shared claim-and-write for positive and negative entries.
 *
 * WHAT: Claims the path's slot (free, expired, or same-path; bounded eviction
 *       of the home slot when every probed slot is live for other paths) and
 *       writes the entry with the given host ("" = negative) and TTL.
 * WHY:  Positive and negative inserts differ only in payload and TTL; one
 *       core keeps the probe/eviction contract in a single place.
 * HOW:  Same probe loop the original insert used, then the field writes.
 */
static void
loc_insert_core(const char *path, const char *host, uint16_t port,
    ngx_msec_t ttl_ms)
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
    e->expires = now + ttl_ms;
    e->in_use  = 1;

    ngx_shmtx_unlock(&brix_loc_cache_mutex);
}

void
brix_loc_cache_insert(const char *path, const char *host, uint16_t port)
{
    if (host == NULL || host[0] == '\0') {
        return;   /* an empty host encodes a negative entry — refuse here */
    }
    loc_insert_core(path, host, port, brix_loc_cache_ttl_ms);
}

/* §2.6 — record "no node holds path"; no-op unless emptylife is configured. */
void
brix_loc_cache_insert_negative(const char *path)
{
    if (brix_loc_cache_emptylife_ms == 0) {
        return;
    }
    loc_insert_core(path, "", 0, brix_loc_cache_emptylife_ms);
}

/*
 * brix_loc_cache_invalidate — §2.7 kXR_refresh support.
 *
 * WHAT: Expires any cached entry (positive or negative) for path.
 * WHY:  A refresh locate must observe the cluster, not the cache; expiring
 *       (rather than clearing in_use) preserves the open-addressing probe
 *       chain for co-hashed survivors.
 * HOW:  Probe like lookup; on the match, backdate expires so every reader
 *       treats the slot as stale (claimable by the next insert).
 */
void
brix_loc_cache_invalidate(const char *path)
{
    brix_loc_table_t  *tbl;
    brix_loc_entry_t  *e;
    uint32_t           h;
    ngx_uint_t         i, idx;
    ngx_msec_t         now = ngx_current_msec;

    tbl = loc_table();
    if (tbl == NULL || path == NULL || path[0] == '\0'
        || ngx_strlen(path) >= BRIX_LOC_CACHE_PATH_MAX)
    {
        return;
    }

    h = loc_hash(path);

    ngx_shmtx_lock(&brix_loc_cache_mutex);

    for (i = 0; i < BRIX_LOC_CACHE_SLOTS; i++) {
        idx = (h + i) & (BRIX_LOC_CACHE_SLOTS - 1);
        e = &tbl->slots[idx];

        if (!e->in_use) {
            break;
        }
        if (e->path_hash == h && ngx_strcmp(e->path, path) == 0) {
            e->expires = now;    /* expired <=> expires <= now */
            break;
        }
    }

    ngx_shmtx_unlock(&brix_loc_cache_mutex);
}
