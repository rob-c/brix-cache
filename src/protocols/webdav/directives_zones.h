/*
 * directives_zones.h — WebDAV shared-memory zone + packet-marking directives (kv/token/auth/revoke caches, rate-limit zones, SciTags pmark)
 * #included into ngx_http_brix_webdav_commands[] in webdav/module.c (compiler
 * concatenates; setters/enum tables stay visible). Not a standalone TU.
 */
#pragma once
    /* Phase 20: shared-memory KV zones, token cache, rate limiting */
    /* brix_kv_zone <name> <size> key=<bytes> val=<bytes>;  (http main) */
    { ngx_string("brix_kv_zone"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE,
      brix_kv_zone_directive,
      0,
      0,
      NULL },

    /* brix_token_cache zone=<name>; */
    { ngx_string("brix_token_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_token_cache_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, token_cache_kv),
      NULL },

    /* brix_rate_limit zone=<name> rate=<N>r/s burst=<N> [key=dn|ip]; */
    { ngx_string("brix_rate_limit"),
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      brix_rate_limit_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, rate_limit),
      NULL },

    /* Phase 21 Step C: OIDC token introspection (revocation) */
    /* Informational: the IdP /introspect endpoint URL (the actual request is
     * made by the operator-defined internal location). */
    { ngx_string("brix_webdav_token_introspect_url"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, introspect_url),
      NULL },

    /* Internal location URI that proxy_passes to the IdP; enables the check. */
    { ngx_string("brix_webdav_token_introspect_loc"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, introspect_loc),
      NULL },

    { ngx_string("brix_webdav_token_introspect_ttl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, introspect_ttl),
      NULL },

    { ngx_string("brix_webdav_token_introspect_fail_open"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, introspect_fail_open),
      NULL },

    /* brix_webdav_revoke_cache zone=<name>; */
    { ngx_string("brix_webdav_revoke_cache"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      webdav_conf_revoke_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#include "observability/pmark/directives.h"

    /* SciTags packet marking (src/pmark/) — see phase-34 doc */
    BRIX_PMARK_DIRECTIVES(NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET,
                          ngx_http_brix_webdav_loc_conf_t)
