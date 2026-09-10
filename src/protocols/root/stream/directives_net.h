/*
 * directives_net.h — clustering/proxy/traffic-shaping directives (redirect-collapse cache, traffic mirroring, rate limiting, dynamic upstream redirector)
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
#pragma once
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

    /* Phase 24: traffic mirroring (off by default) */    { ngx_string("brix_mirror_url"),
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

    /* A-1: peer verification is mandatory by default — nginx -t refuses
     * brix_upstream_tls without a CA unless this is explicitly turned off. */
    { ngx_string("brix_upstream_tls_verify"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, upstream_ssl_verify),
      NULL },

    { ngx_string("brix_upstream_token_file"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, upstream_token_file),
      NULL },

    /* Phase 115 W2.4: GSI credential for the transparent-upstream connector.
     * Chosen when the upstream's login advert lists `gsi`; the key defaults
     * to the proxy PEM itself. */
    { ngx_string("brix_upstream_x509_proxy"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, upstream_x509_proxy),
      NULL },

    { ngx_string("brix_upstream_x509_key"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, upstream_x509_key),
      NULL },

    /* kXR_prepare / kXR_stage tape-backend dispatch hook */
    { ngx_string("brix_prepare_command"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, prepare_command),
      NULL },

    /* ---- FRM durable-tape-staging directives (brix_frm*) -------------------
     * The Phase-35 FRM directive surface, restored 2026-07-17. It populates the
     * embedded `frm` (brix_frm_conf_t) block, initialised in server_conf.c,
     * merged in server_conf_merge_security.c, and consumed by the stage-request
     * registry (brix_init_server_stage_registry, gated on frm.enable +
     * frm.control_dir). The knobs marked "accepted" are parsed for config
     * compatibility; the durable-queue/control-dir path drives the registry. */
    { ngx_string("brix_frm"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.enable),
      NULL },

    { ngx_string("brix_frm_queue_path"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.queue_path),
      NULL },

    { ngx_string("brix_frm_max_inflight"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.max_inflight),
      NULL },

    { ngx_string("brix_frm_stagecmd"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.stagecmd),
      NULL },
    { ngx_string("brix_frm_stagemsg"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.stagemsg),
      NULL },

    { ngx_string("brix_frm_copymax"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.copymax),
      NULL },

    { ngx_string("brix_frm_stage_ttl"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.stage_ttl),
      NULL },

    { ngx_string("brix_frm_stage_wait"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.stage_wait),
      NULL },

    { ngx_string("brix_frm_async_recall"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.async_recall),
      NULL },

    { ngx_string("brix_frm_fail_backoff"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.fail_backoff_ms),
      NULL },

    { ngx_string("brix_frm_fail_retries"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.fail_retries),
      NULL },

    { ngx_string("brix_frm_copy_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.copy_timeout),
      NULL },

    { ngx_string("brix_frm_control_dir"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.control_dir),
      NULL },

    /* two ratios (high low); custom setter validates low <= high and stores ppm */
    { ngx_string("brix_frm_purge_watermark"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
      brix_frm_set_purge_watermark,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm),
      NULL },

    { ngx_string("brix_frm_purge_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.purge_interval_ms),
      NULL },

    /* phase-115 W3.2: owned-bytes cap arm of the tape-buffer purge engine */
    { ngx_string("brix_frm_purge_max_bytes"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.purge_max_bytes),
      NULL },

    /* 2.0 F4: per-space purge rules + the external policy program.
     * brix_frm_purge_policy {*|<group>} <hi> <lo> [hold <time>] [polprog] */
    { ngx_string("brix_frm_purge_policy"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE3 | NGX_CONF_TAKE4 | NGX_CONF_TAKE5
          | NGX_CONF_TAKE6,
      brix_frm_set_purge_policy,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm),
      NULL },

    { ngx_string("brix_frm_purge_polprog"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, frm.purge_polprog),
      NULL },
