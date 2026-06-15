#include "../config/config.h"
#include "../compat/shm_slots.h"

/*
 * WHAT: Configure the Prometheus metrics shared-memory zone and assign per-listener slots.
 * WHY: All server blocks share a single atomic counters region so workers can increment
 *      counters lock-free via ngx_atomic_t fields. Each listener gets a deterministic slot
 *      number that becomes a stable Prometheus label source (low-cardinality invariant).
 * HOW: Add shared memory zone "xrootd_metrics" sized via xrootd_shm_zone_size() so the table
 *      can be slab-allocated without clobbering the slab-pool header; register the shm_init
 *      callback; iterate cmcf->servers to assign slots 0..N to enabled listeners. Returns
 *      NGX_OK or NGX_ERROR on allocation failure.
 */

ngx_int_t
xrootd_configure_metrics(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf)
{
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
    ngx_str_t                      zone_name = ngx_string("xrootd_metrics");
    size_t                         zone_size;
    ngx_uint_t                     i;
    ngx_uint_t                     slot = 0;

    /*
     * One shared zone is used for all enabled server blocks. Each server is
     * assigned a small integer slot; live connections cache that slot and
     * update counters lock-free via atomics.
     */

    /*
     * Size the zone so the metrics table can be allocated FROM the slab pool
     * (xrootd_shm_table_alloc) without overwriting the ngx_slab_pool_t header.
     * Laying the table directly over shm.addr would clobber the slab mutex that
     * nginx's ngx_unlock_mutexes() force-unlocks on every child death, SIGSEGVing
     * the master. The helper accounts for the table bytes plus slab overhead.
     */
    zone_size = xrootd_shm_zone_size(sizeof(ngx_xrootd_metrics_t));
    ngx_xrootd_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                  zone_size,
                                                  &ngx_stream_xrootd_module);
    if (ngx_xrootd_shm_zone == NULL) {
        return NGX_ERROR;
    }

    /* init() will either zero a new mapping or hand back an existing one. */
    ngx_xrootd_shm_zone->init = ngx_xrootd_metrics_shm_init;
    /* Non-NULL sentinel tells the init callback this is the first setup. */
    ngx_xrootd_shm_zone->data = (void *) 1;

    cscfp = cmcf->servers.elts;

    /* Assign deterministic metrics slots to enabled listeners. */
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);
        if (!xcf->common.enable || slot >= XROOTD_METRICS_MAX_SERVERS) {
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
 * HOW: Delegate the fresh-alloc / reload / re-attach lifecycle to xrootd_shm_table_alloc,
 *      which allocates the ngx_xrootd_metrics_t from the slab pool, zeroes it on a brand-new
 *      allocation, and publishes it via shm_zone->data. The metrics table is lock-less
 *      (atomic counters only) so NULL is passed for the mutex argument. There are no
 *      fresh-only field inits beyond the zeroing the helper already performs.
 */

ngx_int_t
ngx_xrootd_metrics_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t             fresh;
    ngx_xrootd_metrics_t  *tbl;

    tbl = xrootd_shm_table_alloc(shm_zone, data,
                                 sizeof(ngx_xrootd_metrics_t), NULL, &fresh);
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
