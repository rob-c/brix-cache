/*
 * http_directives_ops.h — SciTags pmark, named-credential/CA, traffic-mirror, rate-limit and tier
 * directive entries for the unified HTTP plane.  #included into the
 * brix_http_common_commands[] array in http_common.c so the family is
 * reviewable as one focused file instead of buried in a 770-line table
 * (same idiom as src/protocols/root/stream/directives_*.h).  Not a
 * standalone TU: textual array-member fragments that rely on the setters
 * and enum tables visible in http_common.c.
 */
#pragma once
    /* SciTags packet marking (src/observability/pmark/) — phase-101 W1: this
     * family used to be hand-copied into BOTH webdav and s3 command tables, so
     * first-module-wins made s3's copy dead code and SciTags on S3 a silent
     * no-op.  Registered ONCE here for the whole HTTP plane instead, at
     * BRIX_HTTP_ALL_CONF scope (a site-wide `brix_pmark on` at server{}/http{}
     * now works, matching the stream plane's Sm|Ss).  Generic slots rebase onto
     * the common conf; the four custom setters keep offset 0 and resolve the
     * target via pmark_conf(), which returns the shared preamble's pmark for any
     * struct that embeds it first.  Adopted into each protocol conf by
     * brix_shared_adopt_unified() below. */
    { ngx_string("brix_pmark"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.enable), NULL },
    { ngx_string("brix_pmark_firefly"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.firefly), NULL },
    { ngx_string("brix_pmark_flowlabel"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.flowlabel), NULL },
    { ngx_string("brix_pmark_scitag_cgi"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.scitag_cgi), NULL },
    { ngx_string("brix_pmark_firefly_origin"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.firefly_origin), NULL },
    { ngx_string("brix_pmark_http_plain"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.http_plain), NULL },
    { ngx_string("brix_pmark_echo"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.echo), NULL },
    { ngx_string("brix_pmark_appname"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.appname), NULL },
    { ngx_string("brix_pmark_defsfile"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.pmark.defsfile), NULL },
    { ngx_string("brix_pmark_domain"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, brix_pmark_set_domain,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_firefly_dest"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1, brix_pmark_set_firefly_dest,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_map_experiment"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE23, brix_pmark_set_map_experiment,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("brix_pmark_map_activity"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE3 | NGX_CONF_TAKE4,
      brix_pmark_set_map_activity,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },

    /* Shared-memory KV zones, token cache, rate limiting + traffic shaping
     * (phase-105 W1) — these bare names were registered by the WEBDAV module,
     * so first-module-wins accepted them in any http context while writing
     * webdav's conf: in an s3/cvmfs location they parsed cleanly and enforced
     * NOTHING (the 101-W1 pmark bug class, on a DoS-protection knob).
     * Registered ONCE here instead; the setters were already conf-agnostic
     * (raw cmd->offset arithmetic — core/shm/rate_limit.c, auth/token/
     * token_cache.c, core/shm/kv_config.c) and move unchanged.  The zone
     * declarations keep http-main scope; the per-location names upgrade to
     * BRIX_HTTP_ALL_CONF (site-wide `brix_rate_limit` at server{}/http{} is
     * the "simple first" spelling).  Enforcement: webdav access phase +
     * net/ratelimit engine; s3 gate + token cache wired in phase-105 W1
     * steps 3-4. */
    /* phase-105 W2 class-(ii) ownership relocations — bare cross-protocol
     * names that were registered by the webdav module. Mechanisms unchanged:
     * the credential registry is global (referent of brix_storage_credential,
     * which already lives here; the stream twin moved to stream_common in
     * 101-W3); the delegation endpoint is consumed by webdav's dispatch
     * (scope documented in directives.md); the client-CA store loads into
     * the SERVER SSL_CTX (already server-wide — hook stays in webdav
     * postconfig, reading the adopted preamble value). */
    { ngx_string("brix_credential"),       /* http main: named-credential block (§14) */
      NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
      brix_conf_credential_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("brix_delegation_endpoint"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.delegation_endpoint),
      NULL },
    { ngx_string("brix_client_ca_store"),  /* srv/loc: hashed dir for the front-leg
                                              client-verify store (stock
                                              ssl_client_certificate is file-only) */
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.client_ca_store),
      NULL },

    /* x509 verify source + chain depth (phase-105 W2/W3.5) — the auth-layer
     * trust material for GSI/VOMS cert auth (consumed by webdav today; scope
     * documented in directives.md) and the client proxy-chain depth cap, one
     * spelling with the stream plane. Plus the sender-side TCP congestion
     * alg, applied by the SHARED file-serve path for every HTTP download. */
    { ngx_string("brix_trusted_ca"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.trusted_ca),
      NULL },
    { ngx_string("brix_trusted_ca_dir"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.trusted_ca_dir),
      NULL },
    { ngx_string("brix_verify_depth"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.verify_depth),
      NULL },
    { ngx_string("brix_tcp_congestion"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.tcp_congestion),
      NULL },

    /* Traffic mirroring (phase-24 engine, src/net/mirror/) — phase-105 W2:
     * the 8 settings names were webdav-registered; the mirror phase handlers
     * are GLOBAL, so the settings belong to the plane, not one protocol.
     * The two custom setters resolve their target by cmd->offset (pmark
     * pattern), so they serve any conf embedding the preamble. */
    { ngx_string("brix_mirror_url"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1,
      brix_http_mirror_set_url,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.mirror),
      NULL },
    { ngx_string("brix_mirror_methods"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_1MORE,
      brix_http_mirror_set_methods,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.mirror),
      NULL },
    { ngx_string("brix_mirror_sample"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.mirror.sample_pct),
      NULL },
    { ngx_string("brix_mirror_strip_auth"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.mirror.strip_auth),
      NULL },
    { ngx_string("brix_mirror_writes"),    /* opt-in; shadow MUST be isolated */
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.mirror.mirror_writes),
      NULL },
    { ngx_string("brix_mirror_log_diverge"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.mirror.log_diverge),
      NULL },
    { ngx_string("brix_mirror_timeout"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.mirror.timeout_ms),
      NULL },
    { ngx_string("brix_mirror_token"),
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.mirror.token),
      NULL },

    { ngx_string("brix_max_delay"),        /* cap on advertised client wait (phase-105 W3) */
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.max_delay),
      NULL },
    { ngx_string("brix_kv_zone"),          /* http main: zone=name:size key= val= */
      NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE,
      brix_kv_zone_directive,
      0,
      0,
      NULL },
    { ngx_string("brix_token_cache"),      /* zone=<name> */
      BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1,
      brix_token_cache_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.token_cache_kv),
      NULL },
    { ngx_string("brix_rate_limit"),       /* zone= rate=<N>r/s burst=<N> [key=dn|ip] */
      BRIX_HTTP_ALL_CONF | NGX_CONF_2MORE,
      brix_rate_limit_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.rate_limit),
      NULL },
    { ngx_string("brix_rate_limit_zone"),  /* http main: zone=NAME:SIZE */
      NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
      brix_rl_zone_directive,
      0,
      0,
      NULL },
    { ngx_string("brix_rate_limit_rule"),  /* request-rate shaping rule */
      BRIX_HTTP_ALL_CONF | NGX_CONF_2MORE,
      brix_rl_rule_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.rl_rules),
      NULL },
    { ngx_string("brix_bandwidth_limit"),  /* bandwidth shaping rule */
      BRIX_HTTP_ALL_CONF | NGX_CONF_2MORE,
      brix_rl_bw_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.rl_rules),
      NULL },
    { ngx_string("brix_concurrency_limit"), /* per-principal in-flight cap */
      BRIX_HTTP_ALL_CONF | NGX_CONF_2MORE,
      brix_rl_conc_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.rl_rules),
      NULL },

    /* The tier directives: brix_cache_store, brix_cache_cold_store,
     * brix_stage, brix_stage_store, brix_stage_flush, brix_cache_max_object,
     * brix_cache_evict_at, brix_cache_evict_to, brix_cache_index_cache,
     * brix_cache_meta, brix_cache_slice_size, brix_cache_global_cas,
     * brix_cache_passthrough, brix_cache_passthrough_max, brix_cache_prefetch,
     * brix_cache_prefetch_window, brix_cache_only_if_cached. */
    BRIX_TIER_DIRECTIVES("brix_", ngx_http_brix_common_conf_t,
                         BRIX_HTTP_ALL_CONF, NGX_HTTP_LOC_CONF_OFFSET),

    /* Durable async backend-op queue (brix_backend_async[_batch|_wait]) — shared
     * with the root:// stream plane, adopted into each http protocol's `common`. */
    BRIX_BACKEND_ASYNC_DIRECTIVES("brix_", ngx_http_brix_common_conf_t,
                         BRIX_HTTP_ALL_CONF, NGX_HTTP_LOC_CONF_OFFSET),
