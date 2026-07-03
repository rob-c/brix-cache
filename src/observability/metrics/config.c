#include "core/config/config.h"
#include "core/compat/shm_slots.h"

/*
 * WHAT: Configure the Prometheus metrics shared-memory zone and assign per-listener slots.
 * WHY: All server blocks share a single atomic counters region so workers can increment
 *      counters lock-free via ngx_atomic_t fields. Each listener gets a deterministic slot
 *      number that becomes a stable Prometheus label source (low-cardinality invariant).
 * HOW: Add shared memory zone "brix_metrics" sized via brix_shm_zone_size() so the table
 *      can be slab-allocated without clobbering the slab-pool header; register the shm_init
 *      callback; iterate cmcf->servers to assign slots 0..N to enabled listeners. Returns
 *      NGX_OK or NGX_ERROR on allocation failure.
 */

/*
 * Create (or reuse) the module's metrics SHM zone. Idempotent per config
 * cycle: ngx_shared_memory_add returns the existing zone on a repeat call.
 * Split out of the stream postconfiguration (phase-68) so an HTTP-only
 * deployment — a standalone cvmfs:// cache node has no stream block — still
 * gets the counter table its /metrics endpoint exports.
 */
ngx_int_t
brix_metrics_ensure_zone(ngx_conf_t *cf)
{
    ngx_str_t  zone_name = ngx_string("brix_metrics");
    size_t     zone_size;

    zone_size = brix_shm_zone_size(sizeof(ngx_brix_metrics_t));
    ngx_brix_shm_zone = ngx_shared_memory_add(cf, &zone_name, zone_size,
                                                &ngx_stream_brix_module);
    if (ngx_brix_shm_zone == NULL) {
        return NGX_ERROR;
    }
    if (ngx_brix_shm_zone->init == NULL) {
        ngx_brix_shm_zone->init = ngx_brix_metrics_shm_init;
        ngx_brix_shm_zone->data = (void *) 1;
    }
    return NGX_OK;
}

ngx_int_t
brix_configure_metrics(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf)
{
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                     i;
    ngx_uint_t                     slot = 0;

    /*
     * One shared zone is used for all enabled server blocks. Each server is
     * assigned a small integer slot; live connections cache that slot and
     * update counters lock-free via atomics.
     */

    /*
     * Size the zone so the metrics table can be allocated FROM the slab pool
     * (brix_shm_table_alloc) without overwriting the ngx_slab_pool_t header.
     * Laying the table directly over shm.addr would clobber the slab mutex that
     * nginx's ngx_unlock_mutexes() force-unlocks on every child death, SIGSEGVing
     * the master. The helper accounts for the table bytes plus slab overhead.
     */
    if (brix_metrics_ensure_zone(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    cscfp = cmcf->servers.elts;

    /* Assign deterministic metrics slots to enabled listeners. */
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_brix_module);
        if (!xcf->common.enable || slot >= BRIX_METRICS_MAX_SERVERS) {
            continue;
        }

        /* Slot numbers become stable label sources for the HTTP metrics exporter. */
        xcf->metrics_slot = (ngx_int_t) slot++;
    }

    return NGX_OK;
}

/*
 * WHAT: Initialize (or reuse) the shared memory zone containing Prometheus counters.
 * WHY: nginx reloads preserve existing shared-memory mappings; without this logic every
 *      config reload would zero live counters, losing historical metrics data. Additionally
 *      the table MUST live in slab memory — not directly over shm.addr — so the
 *      ngx_slab_pool_t header that nginx's ngx_unlock_mutexes() relies on survives every
 *      child exit (otherwise the master SIGSEGVs whenever any worker dies).
 * HOW: Delegate the fresh-alloc / reload / re-attach lifecycle to brix_shm_table_alloc,
 *      which allocates the ngx_brix_metrics_t from the slab pool, zeroes it on a brand-new
 *      allocation, and publishes it via shm_zone->data. The metrics table is lock-less
 *      (atomic counters only) so NULL is passed for the mutex argument. There are no
 *      fresh-only field inits beyond the zeroing the helper already performs.
 */

/*
 * fnv1a64_file — FNV-1a 64-bit hash of a file's bytes (config fingerprint).
 *
 * Reads the file in fixed chunks so an arbitrarily large (included) config never
 * needs to be held whole in memory.  Returns 0 on any open/read failure — the
 * caller treats 0 as "fingerprint unavailable", never as a real digest.  Note
 * this fingerprints the top-level config file only; `include`d files are not
 * folded in (documented in reload-semantics.md), so config_generation, not the
 * hash, is the authoritative "a reload happened" signal.
 */
static uint64_t
fnv1a64_file(ngx_str_t *path, ngx_log_t *log)
{
    u_char     buf[4096];
    uint64_t   h = 0xcbf29ce484222325ULL;   /* FNV offset basis (64-bit) */
    ngx_fd_t   fd;
    ssize_t    n;
    size_t     i;

    if (path == NULL || path->len == 0) {
        return 0;
    }

    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "xrootd: cannot read config \"%V\" for version hash",
                      path);
        return 0;
    }

    for ( ;; ) {
        n = ngx_read_fd(fd, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        for (i = 0; i < (size_t) n; i++) {
            h ^= (uint64_t) buf[i];
            h *= 0x100000001b3ULL;           /* FNV prime (64-bit) */
        }
    }

    (void) ngx_close_file(fd);
    return h;
}


void
brix_config_version_publish(ngx_cycle_t *cycle)
{
    ngx_brix_metrics_t  *tbl;
    ngx_atomic_uint_t      gen;
    uint64_t               hash;

    /*
     * No metrics zone means no enabled stream server block — nothing to publish
     * and nothing to probe.  The zone's ->data is the slab-allocated table once
     * the master has mapped it (before this init_module hook runs).
     */
    if (ngx_brix_shm_zone == NULL || ngx_brix_shm_zone->data == NULL) {
        return;
    }
    tbl = ngx_brix_shm_zone->data;

    hash = fnv1a64_file(&cycle->conf_file, cycle->log);

    /*
     * init_module runs exactly once per config load in the master, so a plain
     * atomic increment counts loads precisely (the metrics zone re-attaches
     * across reload, so the previous value is preserved).  The hash is written
     * by this single master before any worker forks off the new cycle.
     */
    gen = ngx_atomic_fetch_add(&tbl->config_generation, 1) + 1;
    tbl->config_hash = hash;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "xrootd: config generation %ui live (pid %P, version %016xL)",
                  (ngx_uint_t) gen, ngx_pid, hash);
}


ngx_int_t
ngx_brix_metrics_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t             fresh;
    ngx_brix_metrics_t  *tbl;

    tbl = brix_shm_table_alloc(shm_zone, data,
                                 sizeof(ngx_brix_metrics_t), NULL, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    if (fresh) {
        /*
         * Brand-new allocation. The helper has already zeroed the table, which
         * is all the metrics counters require — every field starts at zero and
         * is updated lock-free via ngx_atomic_t. No additional field inits here.
         */
    }

    return NGX_OK;
}
