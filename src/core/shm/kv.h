/*
 * kv.h — generic cross-worker key/value store in nginx shared memory.
 *
 * An open-addressed (linear-probing) hash table laid out in a single shared
 * memory segment.  Used as the substrate for the JWT validation cache, the
 * auth-result cache, and the token-bucket rate limiter — each of which is just
 * a thin typed wrapper over an xrootd_kv_t zone.
 *
 * Design notes:
 *   - Keys and values are opaque byte buffers bounded by key_max / val_max,
 *     fixed at zone-configuration time.
 *   - FNV-1a 64-bit hash, linear probing with backward-shift deletion so the
 *     probe chains stay contiguous (no tombstones).
 *   - Load factor capped at 0.5: set() refuses to insert a *new* key once the
 *     live count reaches capacity/2, bounding worst-case probe distance.
 *   - Expiry is lazy: get() evicts an entry it finds expired and reports a
 *     miss.  No background sweeper.
 *   - One spinlock per zone; every op holds it for a single O(1) probe
 *     sequence with no I/O or allocation inside the critical section.
 */
#ifndef XROOTD_SHM_KV_H
#define XROOTD_SHM_KV_H

/* Lightweight — only nginx core types, so this header can be embedded in the
 * per-module config structs (types/config.h, webdav.h) without an include
 * cycle through ngx_xrootd_module.h.  Consumers needing stream/http symbols
 * include ngx_xrootd_module.h themselves. */
#include <ngx_config.h>
#include <ngx_core.h>

#define XROOTD_KV_MIN_SIZE   (64 * 1024)   /* smallest accepted zone size */
#define XROOTD_KV_MAX_ZONES  16            /* module-wide zone registry cap */

/*
 * Process-local handle to a shared zone.  Allocated from the configuration
 * pool by the xrootd_kv_zone directive and pointed at by consumer conf fields
 * (token_cache_kv, auth_cache_kv, rate-limit kv).  The shared table is
 * slab-allocated and published via kv->zone->data (NOT at shm.addr, which holds
 * nginx's slab-pool header); mutex is a per-process handle to the shared spinlock.
 */
typedef struct {
    ngx_str_t        name;      /* zone name — used for Prometheus labels */
    ngx_shm_zone_t  *zone;      /* nginx shared-memory zone */
    ngx_shmtx_t      mutex;     /* process-local handle to the shared lock */
    size_t           size;      /* configured zone size in bytes */
    size_t           key_max;   /* max key length per entry */
    size_t           val_max;   /* max value length per entry */
    uint32_t         capacity;  /* bucket count (power of two), computed at configure */
    size_t           table_bytes; /* header + capacity*stride, slab-allocated at init */
} xrootd_kv_t;

/* Snapshot of a zone's counters for Prometheus export. */
typedef struct {
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t count;
    uint32_t capacity;
} xrootd_kv_stats_t;

/*
 * xrootd_kv_configure() — register the SHM zone during configuration.
 * kv must be caller-allocated and persist for the process lifetime (allocate
 * from cf->pool).  name->data must likewise persist (cf args qualify).  size
 * is clamped up to XROOTD_KV_MIN_SIZE.  module is the owning nginx module tag
 * (&ngx_stream_xrootd_module or &ngx_http_xrootd_webdav_module).
 */
ngx_int_t xrootd_kv_configure(ngx_conf_t *cf, xrootd_kv_t *kv,
    ngx_str_t *name, size_t size, size_t key_max, size_t val_max,
    void *module);

/*
 * xrootd_kv_get() — look up a key.  Returns 1 on hit (out/out_len populated,
 * truncated to the smaller of val_len and *out_len), 0 on miss/expired.
 */
int xrootd_kv_get(xrootd_kv_t *kv, const void *key, size_t key_len,
    void *out, size_t *out_len);

/*
 * xrootd_kv_set() — insert or overwrite.  ttl_ms is milliseconds until expiry
 * (0 = no expiry).  Returns NGX_OK, or NGX_ERROR when the zone is full at the
 * 0.5 load-factor cap, the key/value exceed the configured maxima, or the
 * zone is not yet mapped.
 */
ngx_int_t xrootd_kv_set(xrootd_kv_t *kv, const void *key, size_t key_len,
    const void *val, size_t val_len, ngx_msec_t ttl_ms);

/* xrootd_kv_delete() — remove a key.  No-op if absent. */
void xrootd_kv_delete(xrootd_kv_t *kv, const void *key, size_t key_len);

/* xrootd_kv_stats() — snapshot hit/miss/eviction/count/capacity counters. */
void xrootd_kv_stats(xrootd_kv_t *kv, xrootd_kv_stats_t *out);

/*
 * Zone registry — every configured zone is recorded here so consumer
 * directives can resolve a zone by name (xrootd_kv_find) and the Prometheus
 * exporter can iterate all zones.
 */
xrootd_kv_t *xrootd_kv_find(const ngx_str_t *name);
ngx_uint_t   xrootd_kv_zone_count(void);
xrootd_kv_t *xrootd_kv_zone_get(ngx_uint_t i);

/*
 * xrootd_kv_zone_directive() — setter for the `xrootd_kv_zone` directive:
 *   xrootd_kv_zone <name> <size> key=<bytes> val=<bytes>;
 * Valid in http{} and stream{} main blocks.
 */
char *xrootd_kv_zone_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#endif /* XROOTD_SHM_KV_H */
