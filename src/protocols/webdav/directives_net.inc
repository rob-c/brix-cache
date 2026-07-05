/*
 * directives_net.inc — WebDAV clustering/traffic directives (legacy reverse-proxy stubs, WRITE-method mirroring, rate limiting)
 * #included into ngx_http_brix_webdav_commands[] in webdav/module.c (compiler
 * concatenates; setters/enum tables stay visible). Not a standalone TU.
 */
    /* ---- legacy WebDAV reverse-proxy directives DISABLED 2026-06-30 ----
     * (brix_webdav_proxy, _dynamic, _upstream, _max_fails, _fail_timeout,
     * _auth, _connect_timeout, _send_timeout, _read_timeout) are removed ahead of
     * deleting the unused WebDAV upstream-proxy implementation; a config using any
     * of them now fails with nginx "unknown directive". Handlers/runtime remain
     * temporarily, scheduled for removal. NOT affected: brix_webdav_proxy_certs
     * (GSI X.509 RFC-3820 proxy-cert acceptance — an AUTH directive, retained). */

    /* Phase 24: traffic mirroring (off by default) */    { ngx_string("brix_mirror_url"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_http_mirror_set_url,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_mirror_methods"),
      NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      brix_http_mirror_set_methods,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_mirror_sample"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.sample_pct),
      NULL },

    { ngx_string("brix_mirror_strip_auth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.strip_auth),
      NULL },

    /* Opt-in gate for mirroring WRITE methods (PUT/DELETE/MKCOL/MOVE/COPY) to the
     * shadow.  Off by default; the shadow MUST be an isolated namespace, never the
     * primary's backing store. */
    { ngx_string("brix_mirror_writes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.mirror_writes),
      NULL },

    { ngx_string("brix_mirror_log_diverge"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.log_diverge),
      NULL },

    { ngx_string("brix_mirror_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.timeout_ms),
      NULL },

    { ngx_string("brix_mirror_token"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, mirror.token),
      NULL },

    /* Phase 25: advanced rate limiting / traffic shaping */    { ngx_string("brix_rate_limit_zone"),     /* http main: zone=NAME:SIZE */
      NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
      brix_rl_zone_directive,
      0,
      0,
      NULL },

    { ngx_string("brix_rate_limit_rule"),     /* loc: request-rate rule */
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      brix_rl_rule_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, rl_rules),
      NULL },

    { ngx_string("brix_bandwidth_limit"),     /* loc: bandwidth rule */
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      brix_rl_bw_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, rl_rules),
      NULL },

    { ngx_string("brix_concurrency_limit"),   /* loc: per-principal in-flight cap (W7) */
      NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      brix_rl_conc_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, rl_rules),
      NULL },

    /* (legacy brix_webdav_proxy_*_timeout directives removed — see note above) */

