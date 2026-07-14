/*
 * config_internal.h - cross-file declarations for the WebDAV config split.
 *
 * WHAT: declares the handful of config-lifecycle helpers that are DEFINED in one
 *   of config.c / config_merge.c / config_proxy.c but REFERENCED from another,
 *   after the mechanical file-size split of the former single config.c.
 * WHY: the split moved cohesive function clusters into sibling translation units;
 *   the merge entrypoint (config.c) still calls the base-merge/validate helpers
 *   (config_merge.c) and the proxy/mirror/token helpers (config_proxy.c), while
 *   those siblings call back into the cleanup/cors/summary helpers that stayed in
 *   config.c. These declarations keep every such reference linkable without
 *   duplicating any definition.
 */
#ifndef NGX_HTTP_BRIX_WEBDAV_CONFIG_INTERNAL_H_INCLUDED
#define NGX_HTTP_BRIX_WEBDAV_CONFIG_INTERNAL_H_INCLUDED

#include "webdav.h"

/* Defined in config.c, referenced by config_merge.c / config_proxy.c. */
void webdav_x509_store_cleanup(void *data);
ngx_int_t webdav_validate_cors_origins(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf);
ngx_uint_t webdav_summary_is_new(ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_loc_conf_t *prev);
void webdav_log_endpoint_summary(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf);

/* Defined in config_merge.c, referenced by config.c (merge entrypoint). */
char *webdav_merge_base_conf(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf);
char *webdav_validate_webdav_enabled(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf);

/* Defined in config_proxy.c, referenced by config.c (merge entrypoint). */
char *webdav_merge_auth_token_conf(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf);
char *webdav_merge_upstream_conf(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf);
char *webdav_merge_mirror_and_summary(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf);

#endif /* NGX_HTTP_BRIX_WEBDAV_CONFIG_INTERNAL_H_INCLUDED */
