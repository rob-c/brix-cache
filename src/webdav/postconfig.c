/*
 * postconfig.c - content handler registration and HTTP SSL/thread setup.
 */

#include "webdav.h"

#include <ngx_http_ssl_module.h>

#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

ngx_int_t
ngx_http_xrootd_webdav_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_http_ssl_srv_conf_t    *sslcf;
    ngx_http_xrootd_webdav_loc_conf_t *wdcf;
    ngx_uint_t                  s;
    X509_VERIFY_PARAM          *param;

    if (webdav_auth_init_ssl_indices(cf->log) != NGX_OK) {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_xrootd_webdav_handler;

    cscfp = cmcf->servers.elts;
    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;

        wdcf = ctx->loc_conf[ngx_http_xrootd_webdav_module.ctx_index];
        if (wdcf == NULL || !wdcf->proxy_certs) {
            continue;
        }

        sslcf = ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        if (sslcf == NULL || sslcf->ssl.ctx == NULL) {
            continue;
        }

        param = SSL_CTX_get0_param(sslcf->ssl.ctx);
        if (param) {
            X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_ALLOW_PROXY_CERTS);
            ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                          "xrootd_webdav: enabled X509_V_FLAG_ALLOW_PROXY_CERTS"
                          " on SSL context for server %V",
                          &cscfp[s]->server_name);
        }
    }

    if (webdav_fd_table_init_ssl_index(cf->log) != NGX_OK) {
        return NGX_ERROR;
    }

#if (NGX_THREADS)
    {
        static ngx_str_t default_pool_name = ngx_string("default");

        for (s = 0; s < cmcf->servers.nelts; s++) {
            ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;
            ngx_str_t          *pool_name;

            wdcf = ctx->loc_conf[ngx_http_xrootd_webdav_module.ctx_index];
            if (wdcf == NULL || !wdcf->enable) {
                continue;
            }

            pool_name = (wdcf->thread_pool_name.len > 0)
                        ? &wdcf->thread_pool_name
                        : &default_pool_name;

            wdcf->thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
            if (wdcf->thread_pool == NULL) {
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                    "xrootd_webdav: thread pool \"%V\" not found - "
                    "async file I/O disabled (add a thread_pool directive)",
                    pool_name);
            } else {
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                    "xrootd_webdav: using thread pool \"%V\" for async file I/O",
                    pool_name);
            }
        }
    }
#endif

    return NGX_OK;
}
