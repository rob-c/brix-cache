/* mirror_common.c — see mirror_common.h for WHAT/WHY/HOW. */

#include "protocols/shared/mirror_common.h"

#include "core/config/config.h"                 /* brix_metrics_ensure_zone */
#include "observability/dashboard/dashboard.h"  /* brix_configure_dashboard */

#include <ngx_thread_pool.h>


ngx_int_t
brix_http_mirror_key_path(const char *root, const char *key, size_t key_len,
    char *path, size_t path_size)
{
    size_t  rn = (root[0] == '/' && root[1] == '\0') ? 0 : ngx_strlen(root);

    if (rn + key_len >= path_size) {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }
    if (rn > 0) {
        ngx_memcpy(path, root, rn);
    }
    ngx_memcpy(path + rn, key, key_len);
    path[rn + key_len] = '\0';

    return NGX_OK;
}


ngx_int_t
brix_http_mirror_postconf(ngx_conf_t *cf, ngx_uint_t ctx_index,
    brix_http_mirror_active_pt active, const char *directive)
{
    ngx_http_core_main_conf_t    *cmcf;
    ngx_http_core_srv_conf_t    **cscfp;
    ngx_http_brix_shared_conf_t  *common;
    static ngx_str_t              default_pool_name = ngx_string("default");
    ngx_str_t                    *pool_name;
    void                         *lcf;
    ngx_uint_t                    s;

    if (brix_metrics_ensure_zone(cf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_configure_dashboard(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    cmcf  = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;

        lcf = ctx->loc_conf[ctx_index];
        if (lcf == NULL || !active(lcf)) {
            continue;
        }

        /* Sound because the shared conf is every protocol's first member. */
        common = lcf;

        pool_name = (common->thread_pool_name.len > 0)
                    ? &common->thread_pool_name
                    : &default_pool_name;

        common->thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
        if (common->thread_pool == NULL) {
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "%s: thread pool \"%V\" not found - async cache fills "
                "disabled (add a thread_pool directive)", directive,
                pool_name);
        }
    }

    return NGX_OK;
}
