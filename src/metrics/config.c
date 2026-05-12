#include "../config/config.h"

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
        if (!xcf->enable || slot >= XROOTD_METRICS_MAX_SERVERS) {
            continue;
        }

        /* Slot numbers become stable label sources for the HTTP metrics exporter. */
        xcf->metrics_slot = (ngx_int_t) slot++;
    }

    return NGX_OK;
}

/*
 * ngx_xrootd_metrics_shm_init - shared memory zone init callback.
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
