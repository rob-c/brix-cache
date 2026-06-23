/*
 * kv.c — generic cross-worker key/value store in nginx shared memory.
 *
 * The table is allocated FROM the zone's slab pool (via xrootd_shm_table_alloc)
 * and published through shm_zone->data — it does NOT overlay shm.addr, which
 * holds nginx's ngx_slab_pool_t header. That header must stay intact because
 * ngx_unlock_mutexes() (run on every child death) force-unlocks the slab mutex
 * at shm.addr; clobbering it SIGSEGVs the master. Layout of the slab block:
 *
 *   +----------------------+  table base (shm_zone->data)
 *   | xrootd_kv_header_t   |  (lock must be first — ngx_shmtx_create target)
 *   +----------------------+  offset sizeof(header)
 *   | entry[0]             |  stride = sizeof(entry) + key_max + val_max
 *   | entry[1]             |
 *   |  ...                 |
 *   | entry[capacity-1]    |
 *   +----------------------+
 *
 * capacity is the largest power of two that fits the configured zone size
 * (computed at configure time), so (hash & (capacity-1)) selects the home
 * bucket without a modulo. The requested zone is padded by
 * xrootd_shm_zone_size() to cover the slab-pool overhead.
 */
#include "ngx_xrootd_module.h"   /* full ngx core + stream (NGX_STREAM_MAIN_CONF) */
#include "shm/kv.h"
#include "../compat/shm_slots.h"
#include "../compat/alloc_guard.h"

/* The directive may appear in either module's main block; both tags are
 * resolved at link time into the single combined binary. */
extern ngx_module_t ngx_http_xrootd_webdav_module;

/* ------------------------------------------------------------------ */
/* On-disk (shared-memory) structures                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    ngx_shmtx_sh_t  lock;        /* spinlock — MUST be first */
    uint64_t        count;       /* live entries */
    uint64_t        hits;        /* cache hits */
    uint64_t        misses;      /* cache misses */
    uint64_t        evictions;   /* TTL-expiry evictions */
    uint32_t        capacity;    /* number of buckets (power of two) */
    uint32_t        key_max;     /* max key bytes per entry */
    uint32_t        val_max;     /* max value bytes per entry */
    uint32_t        pad;
} xrootd_kv_header_t;

typedef struct {
    uint64_t     hash;       /* FNV-1a 64-bit hash of the key */
    uint32_t     key_len;    /* 0 = slot free */
    uint32_t     val_len;
    ngx_msec_t   expires;    /* ngx_current_msec at expiry; 0 = never */
    /* u_char key[key_max]; u_char val[val_max]; follow immediately */
} xrootd_kv_entry_t;

/* ------------------------------------------------------------------ */
/* Module-level zone registry                                          */
/* ------------------------------------------------------------------ */

static xrootd_kv_t *xrootd_kv_zones[XROOTD_KV_MAX_ZONES];
static ngx_uint_t   xrootd_kv_nzones;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static uint64_t
xrootd_kv_hash(const void *key, size_t len)
{
    const uint8_t *p = key;
    uint64_t       h = 14695981039346656037ULL;   /* FNV offset basis */
    size_t         i;

    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;                     /* FNV prime */
    }
    return h;
}

static uint32_t
xrootd_kv_floor_pow2(size_t n)
{
    uint32_t p = 1;

    if (n == 0) {
        return 0;
    }
    while ((size_t) (p << 1) <= n && (p << 1) != 0) {
        p <<= 1;
    }
    return p;
}

static xrootd_kv_header_t *
xrootd_kv_hdr(xrootd_kv_t *kv)
{
    /*
     * The table (header + entry array) is slab-allocated and published via
     * shm_zone->data by xrootd_shm_table_alloc() — it does NOT sit at
     * shm.addr (that holds nginx's ngx_slab_pool_t header, which must stay
     * intact so ngx_unlock_mutexes() can force-unlock the slab mutex on child
     * death). Until init runs, zone->data still holds the (void*)1 pending
     * sentinel or the kv handle, so guard against a non-table pointer.
     */
    if (kv == NULL || kv->zone == NULL || kv->zone->data == NULL
        || kv->zone->data == kv || kv->zone->data == (void *) 1)
    {
        return NULL;
    }
    return (xrootd_kv_header_t *) kv->zone->data;
}

static xrootd_kv_entry_t *
xrootd_kv_slot(xrootd_kv_header_t *h, size_t stride, uint32_t i)
{
    return (xrootd_kv_entry_t *)
        ((u_char *) h + sizeof(xrootd_kv_header_t) + (size_t) i * stride);
}

/*
 * Backward-shift deletion (Knuth Algorithm R): empty the slot at `hole`, then
 * pull forward any following entries whose home bucket lets them fill the gap,
 * preserving the linear-probe invariant so no live entry becomes unreachable.
 */
static ngx_uint_t
xrootd_kv_should_shift(uint32_t home, uint32_t hole, uint32_t cur)
{
    /* Shift iff `home` is NOT in the cyclic interval (hole, cur]. */
    if (hole <= cur) {
        return !(home > hole && home <= cur);
    }
    return !(home > hole || home <= cur);
}

static void
xrootd_kv_remove_at(xrootd_kv_header_t *h, size_t stride, uint32_t mask,
    uint32_t hole)
{
    uint32_t cur = hole;

    for ( ;; ) {
        xrootd_kv_slot(h, stride, hole)->key_len = 0;

        for ( ;; ) {
            xrootd_kv_entry_t *e;
            uint32_t           home;

            cur = (cur + 1) & mask;
            e = xrootd_kv_slot(h, stride, cur);
            if (e->key_len == 0) {
                return;                  /* end of probe chain */
            }
            home = (uint32_t) (e->hash & mask);
            if (xrootd_kv_should_shift(home, hole, cur)) {
                break;                   /* this entry can fill the hole */
            }
        }

        ngx_memcpy(xrootd_kv_slot(h, stride, hole),
                   xrootd_kv_slot(h, stride, cur), stride);
        hole = cur;
    }
}

/* ------------------------------------------------------------------ */
/* Zone configuration / init                                           */
/* ------------------------------------------------------------------ */

static ngx_int_t
xrootd_kv_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_kv_t        *kv = shm_zone->data;        /* set by configure */
    xrootd_kv_header_t *h;
    ngx_flag_t          fresh;

    /*
     * Allocate the table FROM the slab pool (not over shm.addr), so nginx's
     * ngx_slab_pool_t header survives ngx_unlock_mutexes() on child death.
     * The helper handles fresh-alloc, reload (data != NULL), and re-attach
     * (shm.exists), publishes the table via shm_zone->data, and creates the
     * process-local mutex handle from the table's first member (the lock).
     */
    h = xrootd_shm_table_alloc(shm_zone, data, kv->table_bytes,
                               &kv->mutex, &fresh);
    if (h == NULL) {
        return NGX_ERROR;
    }

    if (fresh) {
        /* Brand-new table: initialise the layout fields. The helper already
         * zeroed the region and created the mutex, so live counters
         * (count/hits/misses/evictions) start at 0 and must NOT be reset on
         * reuse. */
        h->capacity = kv->capacity;
        h->key_max  = (uint32_t) kv->key_max;
        h->val_max  = (uint32_t) kv->val_max;
    }
    return NGX_OK;
}

ngx_int_t
xrootd_kv_configure(ngx_conf_t *cf, xrootd_kv_t *kv, ngx_str_t *name,
    size_t size, size_t key_max, size_t val_max, void *module)
{
    size_t  avail, stride, table_bytes, zone_size;
    uint32_t cap;

    if (xrootd_kv_nzones >= XROOTD_KV_MAX_ZONES) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "too many xrootd_kv zones (max %d)",
                           XROOTD_KV_MAX_ZONES);
        return NGX_ERROR;
    }
    if (size < XROOTD_KV_MIN_SIZE) {
        size = XROOTD_KV_MIN_SIZE;
    }

    /*
     * Derive the bucket count from the requested size exactly as before
     * (size buys capacity), then size the slab-backed table region from it.
     * The table now lives in slab memory, so the zone we actually request is
     * padded by xrootd_shm_zone_size() to cover the ngx_slab_pool_t header,
     * the page-management array, and slab rounding.
     */
    stride      = sizeof(xrootd_kv_entry_t) + key_max + val_max;
    avail       = size - sizeof(xrootd_kv_header_t);
    cap         = xrootd_kv_floor_pow2(avail / stride);
    if (cap < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_kv_zone \"%V\": size too small for one entry",
                           name);
        return NGX_ERROR;
    }
    table_bytes = sizeof(xrootd_kv_header_t) + (size_t) cap * stride;
    zone_size   = xrootd_shm_zone_size(table_bytes);

    kv->name        = *name;
    kv->size        = size;
    kv->key_max     = key_max;
    kv->val_max     = val_max;
    kv->capacity    = cap;
    kv->table_bytes = table_bytes;

    kv->zone = ngx_shared_memory_add(cf, name, zone_size, module);
    if (kv->zone == NULL) {
        return NGX_ERROR;
    }
    if (kv->zone->data != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate xrootd_kv_zone \"%V\"", name);
        return NGX_ERROR;
    }

    kv->zone->init = xrootd_kv_init_zone;
    kv->zone->data = kv;

    xrootd_kv_zones[xrootd_kv_nzones++] = kv;
    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* Lookup / insert / delete                                            */
/* ------------------------------------------------------------------ */

int
xrootd_kv_get(xrootd_kv_t *kv, const void *key, size_t key_len,
    void *out, size_t *out_len)
{
    xrootd_kv_header_t *h = xrootd_kv_hdr(kv);
    uint64_t            hash;
    size_t              stride;
    uint32_t            mask, maxprobe, idx, p;
    ngx_msec_t          now;
    int                 result = 0;

    if (h == NULL || key_len == 0 || key_len > kv->key_max) {
        return 0;
    }

    hash     = xrootd_kv_hash(key, key_len);
    stride   = sizeof(xrootd_kv_entry_t) + kv->key_max + kv->val_max;
    now      = ngx_current_msec;

    ngx_shmtx_lock(&kv->mutex);

    mask     = h->capacity - 1;
    maxprobe = h->capacity / 2;
    idx      = (uint32_t) (hash & mask);

    for (p = 0; p < maxprobe; p++) {
        xrootd_kv_entry_t *e = xrootd_kv_slot(h, stride, idx);

        if (e->key_len == 0) {
            break;                       /* probe chain ends — not found */
        }
        if (e->hash == hash && e->key_len == key_len
            && ngx_memcmp((u_char *) e + sizeof(*e), key, key_len) == 0)
        {
            if (e->expires != 0 && e->expires <= now) {
                xrootd_kv_remove_at(h, stride, mask, idx);
                if (h->count > 0) { h->count--; }
                h->evictions++;
                break;                   /* expired — treat as miss */
            }
            if (out != NULL && out_len != NULL) {
                size_t vl = e->val_len;
                if (vl > *out_len) { vl = *out_len; }
                ngx_memcpy(out, (u_char *) e + sizeof(*e) + kv->key_max, vl);
                *out_len = vl;
            }
            result = 1;
            break;
        }
        idx = (idx + 1) & mask;
    }

    if (result) { h->hits++; } else { h->misses++; }

    ngx_shmtx_unlock(&kv->mutex);
    return result;
}

ngx_int_t
xrootd_kv_set(xrootd_kv_t *kv, const void *key, size_t key_len,
    const void *val, size_t val_len, ngx_msec_t ttl_ms)
{
    xrootd_kv_header_t *h = xrootd_kv_hdr(kv);
    uint64_t            hash;
    size_t              stride;
    uint32_t            mask, maxprobe, idx, p;
    ngx_msec_t          now;
    ngx_int_t           rc = NGX_ERROR;

    if (h == NULL
        || key_len == 0 || key_len > kv->key_max
        || val_len > kv->val_max)
    {
        return NGX_ERROR;
    }

    hash   = xrootd_kv_hash(key, key_len);
    stride = sizeof(xrootd_kv_entry_t) + kv->key_max + kv->val_max;
    now    = ngx_current_msec;

    ngx_shmtx_lock(&kv->mutex);

    mask     = h->capacity - 1;
    maxprobe = h->capacity / 2;
    idx      = (uint32_t) (hash & mask);

    for (p = 0; p < maxprobe; p++) {
        xrootd_kv_entry_t *e = xrootd_kv_slot(h, stride, idx);

        if (e->key_len == 0) {
            /* New insert — enforce the 0.5 load-factor cap. */
            if (h->count >= h->capacity / 2) {
                break;
            }
            e->hash    = hash;
            e->key_len = (uint32_t) key_len;
            e->val_len = (uint32_t) val_len;
            e->expires = ttl_ms ? (now + ttl_ms) : 0;
            ngx_memcpy((u_char *) e + sizeof(*e), key, key_len);
            if (val_len) {
                ngx_memcpy((u_char *) e + sizeof(*e) + kv->key_max,
                           val, val_len);
            }
            h->count++;
            rc = NGX_OK;
            break;
        }
        if (e->hash == hash && e->key_len == key_len
            && ngx_memcmp((u_char *) e + sizeof(*e), key, key_len) == 0)
        {
            /* Overwrite existing key. */
            e->val_len = (uint32_t) val_len;
            e->expires = ttl_ms ? (now + ttl_ms) : 0;
            if (val_len) {
                ngx_memcpy((u_char *) e + sizeof(*e) + kv->key_max,
                           val, val_len);
            }
            rc = NGX_OK;
            break;
        }
        idx = (idx + 1) & mask;
    }

    ngx_shmtx_unlock(&kv->mutex);
    return rc;
}

void
xrootd_kv_delete(xrootd_kv_t *kv, const void *key, size_t key_len)
{
    xrootd_kv_header_t *h = xrootd_kv_hdr(kv);
    uint64_t            hash;
    size_t              stride;
    uint32_t            mask, maxprobe, idx, p;

    if (h == NULL || key_len == 0 || key_len > kv->key_max) {
        return;
    }

    hash   = xrootd_kv_hash(key, key_len);
    stride = sizeof(xrootd_kv_entry_t) + kv->key_max + kv->val_max;

    ngx_shmtx_lock(&kv->mutex);

    mask     = h->capacity - 1;
    maxprobe = h->capacity / 2;
    idx      = (uint32_t) (hash & mask);

    for (p = 0; p < maxprobe; p++) {
        xrootd_kv_entry_t *e = xrootd_kv_slot(h, stride, idx);

        if (e->key_len == 0) {
            break;
        }
        if (e->hash == hash && e->key_len == key_len
            && ngx_memcmp((u_char *) e + sizeof(*e), key, key_len) == 0)
        {
            xrootd_kv_remove_at(h, stride, mask, idx);
            if (h->count > 0) { h->count--; }
            break;
        }
        idx = (idx + 1) & mask;
    }

    ngx_shmtx_unlock(&kv->mutex);
}

void
xrootd_kv_stats(xrootd_kv_t *kv, xrootd_kv_stats_t *out)
{
    xrootd_kv_header_t *h = xrootd_kv_hdr(kv);

    ngx_memzero(out, sizeof(*out));
    if (h == NULL) {
        return;
    }

    ngx_shmtx_lock(&kv->mutex);
    out->hits      = h->hits;
    out->misses    = h->misses;
    out->evictions = h->evictions;
    out->count     = h->count;
    out->capacity  = h->capacity;
    ngx_shmtx_unlock(&kv->mutex);
}

/* ------------------------------------------------------------------ */
/* Zone registry                                                       */
/* ------------------------------------------------------------------ */

xrootd_kv_t *
xrootd_kv_find(const ngx_str_t *name)
{
    ngx_uint_t i;

    for (i = 0; i < xrootd_kv_nzones; i++) {
        if (xrootd_kv_zones[i]->name.len == name->len
            && ngx_strncmp(xrootd_kv_zones[i]->name.data,
                           name->data, name->len) == 0)
        {
            return xrootd_kv_zones[i];
        }
    }
    return NULL;
}

ngx_uint_t
xrootd_kv_zone_count(void)
{
    return xrootd_kv_nzones;
}

xrootd_kv_t *
xrootd_kv_zone_get(ngx_uint_t i)
{
    return (i < xrootd_kv_nzones) ? xrootd_kv_zones[i] : NULL;
}

/* ------------------------------------------------------------------ */
/* `xrootd_kv_zone <name> <size> key=<bytes> val=<bytes>;` directive    */
/* ------------------------------------------------------------------ */

char *
xrootd_kv_zone_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t   *value = cf->args->elts;
    ngx_str_t    name  = value[1];
    ssize_t      size;
    size_t       key_max = 0;
    size_t       val_max = 0;
    ngx_uint_t   i;
    xrootd_kv_t *kv;
    void        *module;

    size = ngx_parse_size(&value[2]);
    if (size == NGX_ERROR || size <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid xrootd_kv_zone size \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    for (i = 3; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "key=", 4) == 0) {
            key_max = ngx_atoi(value[i].data + 4, value[i].len - 4);
        } else if (ngx_strncmp(value[i].data, "val=", 4) == 0) {
            val_max = ngx_atoi(value[i].data + 4, value[i].len - 4);
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid xrootd_kv_zone parameter \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (key_max == 0 || key_max == (size_t) NGX_ERROR
        || val_max == 0 || val_max == (size_t) NGX_ERROR)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_kv_zone \"%V\" requires key=<bytes> and val=<bytes>",
            &name);
        return NGX_CONF_ERROR;
    }

    if (xrootd_kv_find(&name) != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate xrootd_kv_zone \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    XROOTD_PCALLOC_OR_RETURN(kv, cf->pool, sizeof(xrootd_kv_t), NGX_CONF_ERROR);

    module = (cf->cmd_type & NGX_STREAM_MAIN_CONF)
             ? (void *) &ngx_stream_xrootd_module
             : (void *) &ngx_http_xrootd_webdav_module;

    if (xrootd_kv_configure(cf, kv, &name, (size_t) size,
                            key_max, val_max, module) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
