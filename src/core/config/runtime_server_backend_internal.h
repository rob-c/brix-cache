#ifndef BRIX_RUNTIME_SERVER_BACKEND_INTERNAL_H
#define BRIX_RUNTIME_SERVER_BACKEND_INTERNAL_H
/*
 * runtime_server_backend_internal.h — cross-file entry points for the
 * runtime_server_backend split (mechanical file-size cap). The default
 * write-staging machinery lives in runtime_server_backend_stage.c and the
 * cache-tier registration in runtime_server_backend_cache.c; only the three
 * entry points the top-level brix_tier_register_stores() orchestrator
 * (runtime_server_backend.c) invokes cross the file boundary and are therefore
 * non-static and declared here. Their sub-helpers stay file-local (static).
 *
 * Requires "config.h" (for ngx_conf_t + ngx_http_brix_shared_conf_t + ngx_int_t)
 * before inclusion.
 */

/* Provision the brix-managed default stage store for a whole-object remote
 * backend with no configured stage tier (runtime_server_backend_stage.c). */
void brix_tier_default_stage_store(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common);

/* Warn per stage/cache store that lives under a systemd PrivateTmp /tmp
 * (runtime_server_backend_stage.c). */
void brix_tier_warn_private_tmp(ngx_conf_t *cf,
    const ngx_http_brix_shared_conf_t *common);

/* Parse the cache_store URL and record its tier cfg + read-through policy on
 * the backend registry (runtime_server_backend_cache.c). */
ngx_int_t brix_tier_register_cache_store(ngx_conf_t *cf,
    ngx_http_brix_shared_conf_t *common);

/* Build the proxy-leg + redirector-leg outbound client SSL_CTXs with
 * fail-closed peer verification for a prepared server block
 * (runtime_server_tls.c). */
ngx_int_t brix_server_setup_tls(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf);

#endif /* BRIX_RUNTIME_SERVER_BACKEND_INTERNAL_H */
