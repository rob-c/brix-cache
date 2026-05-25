#include "../config/config.h"

/*
 * WHAT: Configure the Prometheus metrics shared-memory zone and assign per-listener slots.
 * WHY: All server blocks share a single atomic counters region so workers can increment
 *      counters lock-free via ngx_atomic_t fields. Each listener gets a deterministic slot
 *      number that becomes a stable Prometheus label source (low-cardinality invariant).
 * HOW: Add shared memory zone "xrootd_metrics" with sizeof(ngx_xrootd_metrics_t)+one-page
 *      headroom; register the shm_init callback; iterate cmcf->servers to assign slots 0..N
 *      to enabled listeners. Returns NGX_OK or NGX_ERROR on allocation failure.
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

    /* Extra page headroom follows a common nginx shared-memory sizing pattern. */
    zone_size = sizeof(ngx_xrootd_metrics_t) + ngx_pagesize;
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
 *      config reload would zero live counters, losing historical metrics data. The `data`
 *      parameter is a sentinel (1 on first setup) that distinguishes fresh allocation from
 *      reuse-after-reload.
 * HOW: If `data` is non-NULL we're reusing an existing zone — return it as-is with NGX_OK.
 *      On first init, zero the freshly mapped region via ngx_memzero and cast its address
 *      to ngx_xrootd_metrics_t for typed access by request paths.
 */

ngx_int_t
ngx_xrootd_metrics_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_xrootd_metrics_t *shm;

    if (data) {
        /*
         * nginx is reusing an existing shared zone across a reload; preserve
         * live counters instead of wiping them on every config reload.
         */
        shm_zone->data = data;
        return NGX_OK;
    }

    /* First initialization: zero the freshly mapped shared memory region. */
    shm = (ngx_xrootd_metrics_t *) shm_zone->shm.addr;
    ngx_memzero(shm, sizeof(*shm));

    /* Save the typed pointer so request paths do not have to recast repeatedly. */
    shm_zone->data = shm;
    return NGX_OK;
}
