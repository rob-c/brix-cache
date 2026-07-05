/*
 * directives_zones.inc — shared-memory zone directives (stream main-conf: brix_kv_zone, brix_token_cache, brix_auth_cache, brix_rate_limit_zone)
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
    /* Phase 20: shared-memory KV zones, caches, and rate limiting */
    /* brix_kv_zone <name> <size> key=<bytes> val=<bytes>;  (stream main) */
    { ngx_string("brix_kv_zone"),
      NGX_STREAM_MAIN_CONF | NGX_CONF_2MORE,
      brix_kv_zone_directive,
      0,
      0,
      NULL },

    /* brix_token_cache zone=<name>; */
    { ngx_string("brix_token_cache"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_token_cache_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, token_cache_kv),
      NULL },

    /* brix_auth_cache zone=<name> [ttl=<seconds>]; */
    { ngx_string("brix_auth_cache"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE12,
      brix_auth_cache_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, auth_cache),
      NULL },

    /* brix_rate_limit zone=<name> rate=<N>r/s burst=<N> [key=dn|ip]; */
    { ngx_string("brix_rate_limit"),
      NGX_STREAM_SRV_CONF | NGX_CONF_2MORE,
      brix_rate_limit_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, rate_limit),
      NULL },
