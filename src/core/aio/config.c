#include "core/config/config.h"


/*
 * xrootd_configure_thread_pools — resolve thread-pool names to concrete pool
 * objects for all XRootD-enabled stream server blocks.
 *
 * Called during postconfiguration.  Iterates every stream server block and, if
 * XRootD is enabled, looks up the configured pool name (or "default" if not
 * explicitly set) in the nginx thread-pool registry.
 *
 * If the pool is not found and cache is enabled, the configuration fails with
 * NGX_LOG_EMERG — cache I/O requires a thread pool.  Otherwise, a NGX_LOG_NOTICE
 * message is emitted and async I/O falls back to synchronous pread/pwrite.
 *
 * Returns NGX_OK on success, NGX_ERROR on missing required pool.
 */
ngx_int_t
xrootd_configure_thread_pools(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf)
{
    static ngx_str_t              default_pool_name = ngx_string("default");
    ngx_stream_core_srv_conf_t  **cscfp;
    ngx_stream_xrootd_srv_conf_t *xcf;
    ngx_uint_t                    i;

    cscfp = cmcf->servers.elts;

    /*
     * Resolve each enabled server's thread-pool name to the concrete pool
     * object created by nginx's top-level thread_pool config.
     */
    for (i = 0; i < cmcf->servers.nelts; i++) {
        ngx_str_t *pool_name;

        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);
        if (!xcf->common.enable) {
            continue;
        }

        /* Empty name means "use nginx's default thread pool". */
        pool_name = (xcf->common.thread_pool_name.len > 0)
                    ? &xcf->common.thread_pool_name
                    : &default_pool_name;

        xcf->common.thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
        if (xcf->common.thread_pool == NULL) {
            if (xcf->cache) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_cache requires a working thread pool "
                    "(configure xrootd_thread_pool or nginx's default "
                    "thread_pool)");
                return NGX_ERROR;
            }

            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd: thread pool \"%V\" not found - "
                "async file I/O disabled (add a thread_pool directive)",
                pool_name);
        } else {
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd: using thread pool \"%V\" for async file I/O",
                pool_name);
        }
    }

    return NGX_OK;
}

