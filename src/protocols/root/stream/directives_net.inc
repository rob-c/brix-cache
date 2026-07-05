/*
 * directives_net.inc — clustering/proxy/traffic-shaping directives (redirect-collapse cache, traffic mirroring, rate limiting, dynamic upstream redirector)
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
    /* Phase 20: manager redirect-collapse cache capacity
     * (brix_redir_cache_slots). */
    { ngx_string("brix_redir_cache_slots"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, redir_cache_slots),
      NULL },

    /* Phase 22: active health checks (off by default) */    { ngx_string("brix_health_check"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, hc.enabled),
      NULL },

    { ngx_string("brix_health_check_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, hc.interval_ms),
      NULL },

    { ngx_string("brix_health_check_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, hc.timeout_ms),
      NULL },

    { ngx_string("brix_health_check_threshold"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, hc.threshold),
      NULL },

    { ngx_string("brix_health_check_blacklist"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, hc.blacklist_ms),
      NULL },

    { ngx_string("brix_health_check_type"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, hc.type),
      brix_hc_types },

    /* Phase 24: traffic mirroring (off by default) */    { ngx_string("brix_stream_mirror_url"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_stream_mirror_set_url,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_mirror_opcodes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_1MORE,
      brix_stream_mirror_set_opcodes,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_mirror_exclude_opcodes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_1MORE,
      brix_stream_mirror_set_exclude_opcodes,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_mirror_sample"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, mirror.sample_pct),
      NULL },

    { ngx_string("brix_mirror_strip_auth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, mirror.strip_auth),
      NULL },

    /* Opt-in gate for replaying WRITE/mutation opcodes to the shadow.  Off by
     * default; the shadow MUST be an isolated namespace (a separate server/root),
     * never the primary's backing store. */
    { ngx_string("brix_mirror_writes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, mirror.mirror_writes),
      NULL },

    { ngx_string("brix_mirror_log_diverge"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, mirror.log_diverge),
      NULL },

    { ngx_string("brix_mirror_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, mirror.timeout_ms),
      NULL },

    /* Phase 25: advanced rate limiting / traffic shaping */    { ngx_string("brix_rate_limit_zone"),     /* stream main: zone=NAME:SIZE */
      NGX_STREAM_MAIN_CONF | NGX_CONF_1MORE,
      brix_rl_zone_directive,
      0,
      0,
      NULL },

    { ngx_string("brix_rate_limit_rule"),     /* srv: request-rate rule */
      NGX_STREAM_SRV_CONF | NGX_CONF_2MORE,
      brix_rl_rule_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, rl_rules),
      NULL },

    { ngx_string("brix_bandwidth_limit"),     /* srv: bandwidth rule */
      NGX_STREAM_SRV_CONF | NGX_CONF_2MORE,
      brix_rl_bw_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, rl_rules),
      NULL },

    { ngx_string("brix_concurrency_limit"),   /* srv: W7 in-flight cap */
      NGX_STREAM_SRV_CONF | NGX_CONF_2MORE,
      brix_rl_conc_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, rl_rules),
      NULL },

    /* Dynamic upstream XRootD redirector (host:port to query for redirects). */
    { ngx_string("brix_upstream"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_upstream,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_upstream_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, upstream_tls),
      NULL },

    { ngx_string("brix_upstream_tls_ca"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, upstream_tls_ca),
      NULL },

    { ngx_string("brix_upstream_tls_name"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, upstream_tls_name),
      NULL },

    { ngx_string("brix_upstream_token_file"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, upstream_token_file),
      NULL },

    /* kXR_prepare / kXR_stage tape-backend dispatch hook */
    { ngx_string("brix_prepare_command"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, prepare_command),
      NULL },

    /* ---- legacy FRM directives (brix_frm*) DISABLED 2026-06-30 -------------
     * The Phase-35 FRM durable-tape-staging directive surface (brix_frm,
     * _queue_path, _max_inflight, _max_per_source, _stagecmd, _copycmd, _copymax,
     * _stage_ttl, _xfrhold, _stage_wait, _async_recall, _fail_backoff,
     * _fail_retries, _residency_cmd, _stage_dir, _force_scratch, _control_dir,
     * _copy_timeout, _migrate_copycmd, _purge_watermark, _purge_interval) is
     * removed ahead of deleting the now-unused FRM implementation. It is superseded
     * by the phase-64 tier/nearline backend (sd_frm). A config still using any of
     * these now fails with nginx "unknown directive". The frm.* conf fields,
     * handlers and runtime remain temporarily (no longer reachable from config) and
     * are scheduled for removal. */
