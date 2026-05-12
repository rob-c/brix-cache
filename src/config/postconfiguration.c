#include "config.h"

ngx_int_t
ngx_stream_xrootd_postconfiguration(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
    ngx_uint_t                     i;

    cmcf  = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cscfp = cmcf->servers.elts;

    /*
     * Attempt to load libvomsapi.so.1 via dlopen. If the library is not
     * present we continue; config validation below rejects xrootd_require_vo
     * directives when VOMS is unavailable.
     */
    (void) xrootd_voms_init(cf->log);

    /*
     * First pass over enabled servers initializes local runtime resources and
     * auth state after inherited values have been merged.
     */
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);

        if (!xcf->enable) {
            continue;
        }

        if (xrootd_config_prepare_server(cf, xcf) != NGX_OK
            || xrootd_configure_gsi(cf, xcf) != NGX_OK
            || xrootd_configure_tls(cf, xcf) != NGX_OK
            || xrootd_configure_token_auth(cf, xcf) != NGX_OK
            || xrootd_configure_sss_auth(cf, xcf) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /*
     * Policy rules depend on finalized roots and on auth/VOMS availability, so
     * keep them after the auth setup pass.
     */
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);

        if (!xcf->enable) {
            continue;
        }

        if (xrootd_config_finalize_policy(cf, xcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (xrootd_configure_metrics(cf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xrootd_configure_session_registry(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    {
        /*
         * The server registry is a single shared-memory zone.  Walk all enabled
         * server blocks to find the largest configured capacity so operators can
         * set xrootd_registry_slots once on whichever block they prefer.
         * All enabled blocks have registry_slots >= 128 after merge.
         */
        ngx_uint_t registry_slots = 0;

        for (i = 0; i < cmcf->servers.nelts; i++) {
            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                       ngx_stream_xrootd_module);
            if (xcf->enable && xcf->registry_slots > registry_slots) {
                registry_slots = xcf->registry_slots;
            }
        }

        if (xrootd_srv_configure_registry(cf, registry_slots ? registry_slots : 128) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (xrootd_pending_configure(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xrootd_tpc_key_configure_registry(cf) != NGX_OK) {
        return NGX_ERROR;
    }

#if (NGX_THREADS)
    if (xrootd_configure_thread_pools(cf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}
