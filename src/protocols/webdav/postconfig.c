/*
 * postconfig.c - content handler registration and HTTP SSL/thread setup.
 *
 * WHAT: Post-configuration lifecycle hook executed after nginx main configuration parsing — registers WebDAV content handler in NGX_HTTP_CONTENT_PHASE, enables GSI proxy certificate support on SSL contexts where proxy_certs=on, initializes SSL fd-cache index for connection reuse optimization, and allocates thread pool references for async file I/O operations (PUT/GET).
 *
 * WHY: nginx requires all modules to register their handlers during postconfiguration phase before accepting any traffic. WebDAV content handler must be registered in NGX_HTTP_CONTENT_PHASE so nginx can dispatch HTTP requests to ngx_http_xrootd_webdav_handler() after authentication completes. GSI/x509 proxy certificate authentication requires X509_V_FLAG_ALLOW_PROXY_CERTS flag on SSL context — without this flag, proxy certificates issued by CA intermediates are rejected as invalid (AGENTS.md INVARIANT: GSI auth uses proxy cert chains). Thread pool allocation enables async file I/O for blocking operations (PUT body write, GET range read) per AGENTS.md FAQ: "Async I/O? Event-loop only. No wait/sleep/read. Use ngx_thread_pool_run."
 *
 * HOW: Called once during nginx startup after all configuration directives parsed. First initializes SSL fd-cache index via webdav_auth_init_ssl_indices() for connection reuse optimization (already documented in fd_cache.c). Second, retrieves NGX_HTTP_CORE_MAIN_CONF and pushes ngx_http_xrootd_webdav_handler into content phase handler array — this is the entry point for all WebDAV HTTP requests after authentication routing. Third, iterates CMCF servers to find SSL contexts with proxy_certs=on flag, then sets X509_V_FLAG_ALLOW_PROXY_CERTS via SSL_CTX_get0_param + X509_VERIFY_PARAM_set_flags enabling GSI proxy cert chains. Fourth reinitializes fd-cache SSL index for connection tracking (per fd_cache.c). Finally iterates servers again under NGX_THREADS macro to locate thread pool via ngx_thread_pool_get() — uses wdcf->common.thread_pool_name if configured, otherwise defaults to "default" pool name defined in nginx.conf directive `thread_pool default threads=4 max_queue=65536`. Logs NOTICE-level message when pool not found (async I/O disabled) or successfully allocated.
 */

#include "webdav.h"
#include "tpc/common/registry.h"
#include "net/mirror/http_mirror.h"
#include "net/ratelimit/ratelimit.h"

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

    /* Access phase: auth, CORS, write guards, and token-scope checks. */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_xrootd_webdav_access_handler;

    /* Phase 21 Step C: OIDC introspection runs as a second access-phase
     * handler (after the main auth handler), so its subrequest suspend/resume
     * re-entry replays only the introspection check — not the whole auth gate. */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = webdav_introspect_access_handler;

    /* Phase 25: advanced rate limiting runs as a third access-phase handler
     * (after auth, so the identity is populated) and chains a body filter for
     * bandwidth accounting. */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = xrootd_rl_http_access_handler;

    /* Bandwidth is charged in the log phase from the known response size. */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = xrootd_rl_http_log_handler;

    /* Phase 24: traffic mirror.  The precontent handler does both jobs: on the
     * main request it fires the background shadow subrequests, and on each
     * mirror subrequest it takes the request over and proxies it to the shadow.
     * Doing the takeover in the precontent phase avoids any dependence on
     * content-phase handler ordering. */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = xrootd_http_mirror_precontent_handler;

    /* Content phase: native WebDAV method routing for all implemented methods. */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_xrootd_webdav_handler;

    /* Log phase: stamp the primary's final status for the divergence compare. */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = xrootd_http_mirror_log_handler;

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

    {
        static ngx_str_t default_pool_name = ngx_string("default");

        for (s = 0; s < cmcf->servers.nelts; s++) {
            ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;
            ngx_str_t          *pool_name;

            wdcf = ctx->loc_conf[ngx_http_xrootd_webdav_module.ctx_index];
            if (wdcf == NULL || !wdcf->common.enable) {
                continue;
            }

            pool_name = (wdcf->common.thread_pool_name.len > 0)
                        ? &wdcf->common.thread_pool_name
                        : &default_pool_name;

            wdcf->common.thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
            if (wdcf->common.thread_pool == NULL) {
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

    if (xrootd_tpc_registry_configure(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
