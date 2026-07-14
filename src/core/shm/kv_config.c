/*
 * kv_config.c — configuration, registry, and zone initialisation for the
 * generic cross-worker key/value store (data-plane ops live in kv.c).
 *
 * WHAT: Owns everything that runs at configuration/init time rather than on the
 *       request hot path — the `brix_kv_zone` directive setter, the
 *       brix_kv_configure() geometry computation, the slab-backed zone init
 *       callback, and the process-wide zone registry (brix_kv_find /
 *       brix_kv_zone_count / brix_kv_zone_get).
 * WHY:  kv.c held both the request-time table operations (get/set/delete/stats)
 *       and this configuration/registry machinery, pushing it past the 500-line
 *       cap. The two planes are independent — they share only the private
 *       on-slab layout types (kv_internal.h) and no functions call across the
 *       split — so separating them keeps each file focused and under the cap.
 * HOW:  brix_kv_configure() derives the power-of-two bucket count from the
 *       requested size, sizes the slab-backed table, and registers the zone;
 *       brix_kv_init_zone() (the zone `init` callback) allocates the table from
 *       the slab pool via brix_shm_table_alloc() and initialises layout fields
 *       only on a fresh zone; the registry array records every configured zone
 *       so consumer directives and the Prometheus exporter can resolve them.
 */
#include "core/ngx_brix_module.h"   /* full ngx core + stream (NGX_STREAM_MAIN_CONF) */
#include "kv.h"
#include "kv_internal.h"
#include "core/compat/shm_slots.h"
#include "core/compat/alloc_guard.h"

/* The directive may appear in either module's main block; both tags are
 * resolved at link time into the single combined binary. */
extern ngx_module_t ngx_http_brix_webdav_module;


static brix_kv_t *brix_kv_zones[BRIX_KV_MAX_ZONES];
static ngx_uint_t   brix_kv_nzones;


/* ---- Largest power of two not exceeding n ----
 *
 * WHAT: Returns the greatest power of two that is <= n, or 0 when n is 0.
 *
 * WHY: The bucket count must be a power of two so the home bucket can be
 *      selected with (hash & (capacity-1)) instead of a modulo. Deriving it
 *      from the entry budget once, at configure time, keeps the hot path
 *      branch-free.
 *
 * HOW:
 *   1. Return 0 immediately for n == 0.
 *   2. Double a uint32 accumulator while it stays below 2^31 and the next
 *      doubling (widened to size_t before the shift, so it cannot wrap) still
 *      fits within n; the 2^31 gate preserves the historical cap.
 */
static uint32_t
brix_kv_floor_pow2(size_t n)
{
    uint32_t p = 1;

    if (n == 0) {
        return 0;
    }
    /* Widen BEFORE shifting so the doubling cannot wrap in uint32; the
     * p < 2^31 gate preserves the old wrap-guard's cap of 2^31. */
    while (p < 0x80000000u && ((size_t) p << 1) <= n) {
        p <<= 1;
    }
    return p;
}


/* ---- Zone init callback: allocate the table from the slab pool ----
 *
 * WHAT: nginx `init` callback for a brix_kv zone. Allocates (or re-attaches to)
 *       the slab-backed table, builds the process-local mutex handle, and on a
 *       fresh table initialises the immutable layout fields. Returns NGX_OK on
 *       success, NGX_ERROR when the slab allocation fails.
 *
 * WHY: The table MUST be allocated FROM the slab pool (not laid over shm.addr),
 *      so nginx's ngx_slab_pool_t header survives ngx_unlock_mutexes() on child
 *      death. Live counters (count/hits/misses/evictions) must persist across a
 *      reload/re-attach, so they are only reset on a genuinely fresh table.
 *
 * HOW:
 *   1. Delegate fresh-alloc / reload / re-attach and mutex creation to
 *      brix_shm_table_alloc(), which publishes the table via shm_zone->data.
 *   2. On failure return NGX_ERROR.
 *   3. When *fresh, set capacity/key_max/val_max from the config handle; leave
 *      the already-zeroed live counters untouched.
 */
static ngx_int_t
brix_kv_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    brix_kv_t        *kv = shm_zone->data;        /* set by configure */
    brix_kv_header_t *h;
    ngx_flag_t          fresh;

    /*
     * Allocate the table FROM the slab pool (not over shm.addr), so nginx's
     * ngx_slab_pool_t header survives ngx_unlock_mutexes() on child death.
     * The helper handles fresh-alloc, reload (data != NULL), and re-attach
     * (shm.exists), publishes the table via shm_zone->data, and creates the
     * process-local mutex handle from the table's first member (the lock).
     */
    h = brix_shm_table_alloc(shm_zone, data, kv->table_bytes,
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

/* ---- Register a brix_kv zone during configuration ----
 *
 * WHAT: Computes the zone geometry (bucket count, table byte size, padded zone
 *       size), fills the caller-allocated brix_kv_t handle, adds the shared
 *       memory zone, and records the zone in the registry. Returns NGX_OK, or
 *       NGX_ERROR on registry overflow, too-small size, or a duplicate zone.
 *
 * WHY: The bucket count is derived from the requested size exactly as before
 *      (size buys capacity), but the table now lives in slab memory, so the
 *      zone actually requested is padded by brix_shm_zone_size() to cover the
 *      ngx_slab_pool_t header, the page-management array, and slab rounding.
 *
 * HOW:
 *   1. Reject when the registry is full; clamp size up to BRIX_KV_MIN_SIZE.
 *   2. Derive stride, the entry budget, and the power-of-two capacity; reject
 *      when not even one entry fits.
 *   3. Compute table_bytes and the padded zone_size; populate the handle.
 *   4. ngx_shared_memory_add(); reject a duplicate (zone->data already set).
 *   5. Wire the init callback + handle, append to the registry, return NGX_OK.
 */
ngx_int_t
brix_kv_configure(ngx_conf_t *cf, brix_kv_t *kv, ngx_str_t *name,
    size_t size, size_t key_max, size_t val_max, void *module)
{
    size_t  avail, stride, table_bytes, zone_size;
    uint32_t cap;

    if (brix_kv_nzones >= BRIX_KV_MAX_ZONES) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "too many brix_kv zones (max %d)",
                           BRIX_KV_MAX_ZONES);
        return NGX_ERROR;
    }
    if (size < BRIX_KV_MIN_SIZE) {
        size = BRIX_KV_MIN_SIZE;
    }

    /*
     * Derive the bucket count from the requested size exactly as before
     * (size buys capacity), then size the slab-backed table region from it.
     * The table now lives in slab memory, so the zone we actually request is
     * padded by brix_shm_zone_size() to cover the ngx_slab_pool_t header,
     * the page-management array, and slab rounding.
     */
    stride      = sizeof(brix_kv_entry_t) + key_max + val_max;
    avail       = size - sizeof(brix_kv_header_t);
    cap         = brix_kv_floor_pow2(avail / stride);
    if (cap < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_kv_zone \"%V\": size too small for one entry",
                           name);
        return NGX_ERROR;
    }
    table_bytes = sizeof(brix_kv_header_t) + (size_t) cap * stride;
    zone_size   = brix_shm_zone_size(table_bytes);

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
                           "duplicate brix_kv_zone \"%V\"", name);
        return NGX_ERROR;
    }

    kv->zone->init = brix_kv_init_zone;
    kv->zone->data = kv;

    brix_kv_zones[brix_kv_nzones++] = kv;
    return NGX_OK;
}


/* ---- Resolve a configured zone by name ----
 *
 * WHAT: Returns the registered brix_kv_t whose name matches `name`, or NULL
 *       when no such zone exists.
 *
 * WHY: Consumer directives (token cache, auth cache, rate limiter) name a zone
 *      by string and must resolve it to the shared handle at configuration time.
 *
 * HOW: Linear scan of the registry comparing length then bytes; return the
 *      first match or NULL.
 */
brix_kv_t *
brix_kv_find(const ngx_str_t *name)
{
    ngx_uint_t i;

    for (i = 0; i < brix_kv_nzones; i++) {
        if (brix_kv_zones[i]->name.len == name->len
            && ngx_strncmp(brix_kv_zones[i]->name.data,
                           name->data, name->len) == 0)
        {
            return brix_kv_zones[i];
        }
    }
    return NULL;
}

/* ---- Number of registered zones ----
 *
 * WHAT: Returns the count of configured brix_kv zones.
 *
 * WHY: The Prometheus exporter iterates every zone to emit per-zone counters.
 *
 * HOW: Return the registry length.
 */
ngx_uint_t
brix_kv_zone_count(void)
{
    return brix_kv_nzones;
}

/* ---- Fetch a registered zone by index ----
 *
 * WHAT: Returns the i-th registered zone, or NULL when i is out of range.
 *
 * WHY: Pairs with brix_kv_zone_count() for a bounds-checked iteration over all
 *      zones without exposing the registry array.
 *
 * HOW: Return brix_kv_zones[i] when i is in range, else NULL.
 */
brix_kv_t *
brix_kv_zone_get(ngx_uint_t i)
{
    return (i < brix_kv_nzones) ? brix_kv_zones[i] : NULL;
}


/* ---- `brix_kv_zone` directive setter ----
 *
 * WHAT: Parses `brix_kv_zone <name> <size> key=<bytes> val=<bytes>` and
 *       registers the zone. Returns NGX_CONF_OK, or NGX_CONF_ERROR on an
 *       invalid size, unknown/missing key=/val= parameters, or a duplicate name.
 *
 * WHY: The directive is valid in both the http{} and stream{} main blocks; the
 *      owning module tag is selected from cf->cmd_type so the zone is attached
 *      to the correct nginx module for shared-memory lifecycle.
 *
 * HOW:
 *   1. Parse the size argument; reject non-positive sizes.
 *   2. Walk the remaining args collecting key=/val= byte maxima; reject unknown.
 *   3. Require both key_max and val_max to be present and valid.
 *   4. Reject a duplicate name; allocate the handle from cf->pool.
 *   5. Select the owning module by cf->cmd_type and call brix_kv_configure().
 */
char *
brix_kv_zone_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t   *value = cf->args->elts;
    ngx_str_t    name  = value[1];
    ssize_t      size;
    size_t       key_max = 0;
    size_t       val_max = 0;
    ngx_uint_t   i;
    brix_kv_t *kv;
    void        *module;

    size = ngx_parse_size(&value[2]);
    if (size == NGX_ERROR || size <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid brix_kv_zone size \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    for (i = 3; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "key=", 4) == 0) {
            key_max = ngx_atoi(value[i].data + 4, value[i].len - 4);
        } else if (ngx_strncmp(value[i].data, "val=", 4) == 0) {
            val_max = ngx_atoi(value[i].data + 4, value[i].len - 4);
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid brix_kv_zone parameter \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (key_max == 0 || key_max == (size_t) NGX_ERROR
        || val_max == 0 || val_max == (size_t) NGX_ERROR)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_kv_zone \"%V\" requires key=<bytes> and val=<bytes>",
            &name);
        return NGX_CONF_ERROR;
    }

    if (brix_kv_find(&name) != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate brix_kv_zone \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    BRIX_PCALLOC_OR_RETURN(kv, cf->pool, sizeof(brix_kv_t), NGX_CONF_ERROR);

    module = (cf->cmd_type & NGX_STREAM_MAIN_CONF)
             ? (void *) &ngx_stream_brix_module
             : (void *) &ngx_http_brix_webdav_module;

    if (brix_kv_configure(cf, kv, &name, (size_t) size,
                            key_max, val_max, module) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
