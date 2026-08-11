/*
 * shared_conf_merge.h — ngx_http_brix_shared_merge() and its per-family
 * helpers, moved out of shared_conf.h (phase-103: 747-line header split).
 * Not a standalone header: #included by shared_conf.h at the point the old
 * function sat, so every name it needs (the conf struct, the merge macros,
 * brix_shared_apply_read_only, brix_shared_credential_dir_ensure) is already
 * visible and every existing includer keeps working unchanged.
 *
 * The five helpers slice the old 280-line linear merge into its field
 * families; each lifts its statement block VERBATIM, in the original order,
 * so the merge semantics are byte-identical (phase-38 §8 bar).
 */
#pragma once

/* core runtime: enable/export root, write/security flags, logs, thread pool. */
static inline char *
brix_shared_merge_core(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *prev,
    ngx_http_brix_shared_conf_t *conf, const char *root_default)
{
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    /* root_default is a runtime const char* parameter, not a string literal;
     * ngx_conf_merge_str_value computes sizeof(default)-1, which yields the
     * pointer width (7 on 64-bit) rather than the actual string length — the
     * empty-string default used by s3/cvmfs became {len:7,data:""}, so the
     * pure-cache-node root.len==0 → "/" fallback never fired.  Hand-roll. */
    if (conf->root.data == NULL) {
        if (prev->root.data != NULL) {
            conf->root = prev->root;
        } else {
            conf->root.data = (u_char *) root_default;
            conf->root.len = ngx_strlen(root_default);
        }
    }
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_value(conf->verify_write, prev->verify_write, 0);
    ngx_conf_merge_value(conf->require_pgwrite, prev->require_pgwrite, 0);
    ngx_conf_merge_value(conf->data_substreams, prev->data_substreams, 1);
    ngx_conf_merge_value(conf->read_only, prev->read_only, 0);
    ngx_conf_merge_value(conf->compress, prev->compress, 0);
    ngx_conf_merge_value(conf->strict_security, prev->strict_security, 0);
    ngx_conf_merge_uint_value(conf->tls_require, prev->tls_require, 0);
    ngx_conf_merge_str_value(conf->access_log, prev->access_log, "");
    if (conf->access_log.len > 0
        && ngx_strcmp(conf->access_log.data, (u_char *) "off") != 0)
    {
        conf->access_log_file = ngx_conf_open_file(cf->cycle,
                                                   &conf->access_log);
        if (conf->access_log_file == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix: cannot register HTTP access log \"%V\"",
                &conf->access_log);
            return NGX_CONF_ERROR;
        }
    } else {
        conf->access_log_file = NULL;
    }
    ngx_conf_merge_value(conf->session_log, prev->session_log, 1);
    ngx_conf_merge_value(conf->ktls, prev->ktls, 0);   /* default OFF (phase-33 P5: opt-in, HW-offload-only) */
    /* Trusted cache-store surface: default OFF everywhere, so the reserved-name
     * 404 guard stays in force on every normal client location (default-deny). */
    ngx_conf_merge_value(conf->cache_store_endpoint,
                         prev->cache_store_endpoint, 0);
    ngx_conf_merge_value(conf->storage_staging, prev->storage_staging, 0);
    ngx_conf_merge_str_value(conf->thread_pool_name, prev->thread_pool_name, "");
    return NGX_CONF_OK;
}

/* backend storage: scheme string, credential store/delegation/STS family,
 * pblock sizing.  brix_shared_credential_dir_ensure runs here, exactly where
 * the old inline sequence ran it (right after the dir merge). */
static inline void
brix_shared_merge_backend(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *prev,
    ngx_http_brix_shared_conf_t *conf)
{
    ngx_conf_merge_str_value(conf->storage_backend, prev->storage_backend, "");
    ngx_conf_merge_str_value(conf->storage_credential, prev->storage_credential,
                             "");
    /* Defaults to a RAM-backed (tmpfs) store so delegated keys never touch
     * real disk; behaviour-neutral for non-delegated deployments because a
     * lookup miss with fallback=allow (the default) lands on the service
     * credential exactly like an unset dir. `""` opts out entirely. */
    ngx_conf_merge_str_value(conf->storage_credential_dir,
                             prev->storage_credential_dir,
                             BRIX_CREDENTIAL_DIR_DEFAULT);
    brix_shared_credential_dir_ensure(cf, &conf->storage_credential_dir);
    ngx_conf_merge_uint_value(conf->storage_credential_fallback,
                              prev->storage_credential_fallback, 0);
    ngx_conf_merge_str_value(conf->storage_credential_mint_ca_cert,
                             prev->storage_credential_mint_ca_cert, "");
    ngx_conf_merge_str_value(conf->storage_credential_mint_ca_key,
                             prev->storage_credential_mint_ca_key, "");
    ngx_conf_merge_sec_value(conf->storage_credential_mint_ttl,
                             prev->storage_credential_mint_ttl, 3600);
    ngx_conf_merge_uint_value(conf->backend_delegation,
                              prev->backend_delegation, 0);  /* SELECT */
    ngx_conf_merge_ptr_value(conf->backend_token_aud,
                             prev->backend_token_aud, NULL);
    ngx_conf_merge_str_value(conf->backend_tx_endpoint,
                             prev->backend_tx_endpoint, "");
    ngx_conf_merge_str_value(conf->backend_tx_client_id,
                             prev->backend_tx_client_id, "");
    ngx_conf_merge_str_value(conf->backend_tx_client_secret,
                             prev->backend_tx_client_secret, "");
    ngx_conf_merge_str_value(conf->backend_sts_endpoint,
                             prev->backend_sts_endpoint, "");
    ngx_conf_merge_str_value(conf->backend_sts_role,
                             prev->backend_sts_role, "");
    ngx_conf_merge_str_value(conf->backend_sts_access_key,
                             prev->backend_sts_access_key, "");
    ngx_conf_merge_str_value(conf->backend_sts_secret_key,
                             prev->backend_sts_secret_key, "");
    ngx_conf_merge_str_value(conf->backend_sts_region,
                             prev->backend_sts_region, "");
    ngx_conf_merge_value(conf->backend_sts_ttl, prev->backend_sts_ttl, 3600);
    ngx_conf_merge_uint_value(conf->backend_sts_flavor,
                              prev->backend_sts_flavor, 0);
    ngx_conf_merge_value(conf->backend_krb5_forwardable,
                         prev->backend_krb5_forwardable, 0);
    ngx_conf_merge_value(conf->backend_passthrough_persist,
                         prev->backend_passthrough_persist, 0);
    ngx_conf_merge_str_value(conf->backend_sss_keytab,
                             prev->backend_sss_keytab, "");
    ngx_conf_merge_size_value(conf->pblock_block_size, prev->pblock_block_size,
                              0);
}

/* phase-64 tier grammar + cache tuning + stage/async queue. */
static inline void
brix_shared_merge_tier(ngx_http_brix_shared_conf_t *prev,
    ngx_http_brix_shared_conf_t *conf)
{
    /* phase-64 tier grammar */
    ngx_conf_merge_str_value(conf->cache_store, prev->cache_store, "");
    ngx_conf_merge_str_value(conf->cache_root, prev->cache_root, "");  /* W8 */
    if (conf->cache_store_args == NULL) {
        conf->cache_store_args = prev->cache_store_args;
    }
    ngx_conf_merge_str_value(conf->cache_cold_store, prev->cache_cold_store, "");
    if (conf->cache_cold_store_args == NULL) {
        conf->cache_cold_store_args = prev->cache_cold_store_args;
    }
    if (conf->cache_peers == NULL) {
        conf->cache_peers = prev->cache_peers;
    }
    /* stage_enable keeps UNSET through the merge: brix_tier_register_stores
     * must tell "never configured" (may auto-provision the default gateway
     * stage store under /tmp/staging) apart from an explicit "brix_stage off"
     * opt-out. Its only reader tests == 1, so UNSET still means off. */
    ngx_conf_merge_value(conf->stage_enable, prev->stage_enable, NGX_CONF_UNSET);
    ngx_conf_merge_str_value(conf->stage_store, prev->stage_store, "");
    if (conf->stage_store_args == NULL) {
        conf->stage_store_args = prev->stage_store_args;
    }
    ngx_conf_merge_uint_value(conf->stage_flush_async, prev->stage_flush_async, 0);
    /* Durable async backend-op queue: default OFF (mutations run inline). When on,
     * batch defaults to 64 ops (min 1) and the time backstop to 200ms. */
    ngx_conf_merge_value(conf->backend_async, prev->backend_async, 0);
    ngx_conf_merge_uint_value(conf->backend_async_batch,
                              prev->backend_async_batch, 64);
    if (conf->backend_async_batch < 1) {
        conf->backend_async_batch = 1;
    }
    ngx_conf_merge_msec_value(conf->backend_async_wait,
                              prev->backend_async_wait, 200);
    ngx_conf_merge_off_value(conf->cache_max_object, prev->cache_max_object, 0);
    /* evict_at/evict_to stay UNSET through the merge (inherit-only): the
     * stream reaper merge must tell an explicit percent pair (which seeds the
     * watermark reaper) apart from the documented 90/80 defaults — those are
     * normalised into the tier policy at brix_tier_register_cache_store. */
    ngx_conf_merge_uint_value(conf->cache_evict_at, prev->cache_evict_at,
                              NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->cache_evict_to, prev->cache_evict_to,
                              NGX_CONF_UNSET_UINT);
    ngx_conf_merge_uint_value(conf->cache_meta_mode, prev->cache_meta_mode, 0);
    ngx_conf_merge_uint_value(conf->cache_batch_cinfo, prev->cache_batch_cinfo, 2);
    ngx_conf_merge_size_value(conf->cache_index_cache, prev->cache_index_cache, 0);
    ngx_conf_merge_size_value(conf->cache_slice_size, prev->cache_slice_size, 0);
    /* Background block prefetch (audit §4.1): jobs default OFF — speculative
     * origin reads are an explicit operator opt-in; window defaults to 8 MiB
     * (clamps each WILLNEED hint queued for background fill). */
    ngx_conf_merge_value(conf->cache_prefetch, prev->cache_prefetch, 0);
    ngx_conf_merge_size_value(conf->cache_prefetch_window,
                              prev->cache_prefetch_window, 8 * 1024 * 1024);
    /* 0 == BRIX_CACHE_VERIFY_OFF (fs/cache/verify.h; not included here — it
     * drags stream-typed cache internals into every HTTP module conf). */
    ngx_conf_merge_uint_value(conf->cache_verify_mode, prev->cache_verify_mode,
                              0);
    ngx_conf_merge_value(conf->cache_global_cas, prev->cache_global_cas, 0);
    ngx_conf_merge_value(conf->cache_passthrough, prev->cache_passthrough, 0);
    ngx_conf_merge_off_value(conf->cache_passthrough_max,
                             prev->cache_passthrough_max, 0);
    /* Off by default: a cache that refuses misses is a deliberate topology
     * choice (this node contributes only what it holds), never a default. */
    ngx_conf_merge_value(conf->cache_only_if_cached,
                         prev->cache_only_if_cached, 0);
    /* §4.3 pfc.uvkeep: 0 = off (a never-verified entry is trusted until its
     * normal TTL); a positive value bounds that trust window. */
    ngx_conf_merge_sec_value(conf->cache_uvkeep, prev->cache_uvkeep, 0);
}

/* authorization + x509 + token family (XrdAcc, ZIP, pwd, macaroon, CRL/
 * signing-policy, VOMS, token issuer/jwks + the [0,300] clock-skew clamp). */
static inline char *
brix_shared_merge_authx(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *prev,
    ngx_http_brix_shared_conf_t *conf)
{
    /* XrdAcc engine settings (phase-101 W2): merge the 11 settings fields +
     * apply defaults. The per-worker tables/timer tail is untouched. */
    brix_acc_http_merge_conf(&conf->acc, &prev->acc);

    /* ZIP member serving (phase-101 W4) — same defaults both planes had. */
    ngx_conf_merge_value(conf->zip_access, prev->zip_access, 0);
    ngx_conf_merge_size_value(conf->zip_cd_max_bytes, prev->zip_cd_max_bytes,
                              16 * 1024 * 1024);
    ngx_conf_merge_str_value(conf->pwd_file, prev->pwd_file, "");  /* W4 */
    ngx_conf_merge_value(conf->upload_resume, prev->upload_resume, 1);  /* W4: default ON */
    ngx_conf_merge_str_value(conf->token_macaroon_secret,               /* W4 */
                             prev->token_macaroon_secret, "");
    ngx_conf_merge_str_value(conf->token_macaroon_secret_old,
                             prev->token_macaroon_secret_old, "");
    ngx_conf_merge_str_value(conf->upload_stage_dir, prev->upload_stage_dir, "");  /* W4 */
    ngx_conf_merge_str_value(conf->crl, prev->crl, "");  /* W4 */
    ngx_conf_merge_uint_value(conf->signing_policy_mode, prev->signing_policy_mode,
                              BRIX_SP_MODE_ON);
    ngx_conf_merge_uint_value(conf->crl_mode, prev->crl_mode, BRIX_CRL_MODE_TRY);
    ngx_conf_merge_str_value(conf->vomsdir, prev->vomsdir, "");  /* W4 */
    ngx_conf_merge_str_value(conf->voms_cert_dir, prev->voms_cert_dir, "");  /* W4 */
    ngx_conf_merge_str_value(conf->token_jwks, prev->token_jwks, "");  /* W4 */
    ngx_conf_merge_str_value(conf->token_issuer, prev->token_issuer, "");
    ngx_conf_merge_str_value(conf->token_audience, prev->token_audience, "");
    ngx_conf_merge_str_value(conf->token_config, prev->token_config, "");  /* W4 */
    ngx_conf_merge_sec_value(conf->token_clock_skew, prev->token_clock_skew,
                             BRIX_TOKEN_CLOCK_SKEW_SECS);  /* unified 30 (stricter) */
    /* phase-105 W8: the [0,300] security clamp moved HERE from webdav's merge
     * so every HTTP protocol enforces it (s3 previously accepted any value).
     * sec_slot makes `5m` parse — the clamp is what keeps 300 the ceiling,
     * so it must reject loudly, never silently truncate. */
    if (conf->token_clock_skew < 0 || conf->token_clock_skew > 300) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_token_clock_skew is capped at 300s (security clamp against "
            "unit confusion); got %T", conf->token_clock_skew);
        return NGX_CONF_ERROR;
    }
    if (conf->vo_rules == NULL) {  /* W4: NULL-inherit, same as cache_store_args */
        conf->vo_rules = prev->vo_rules;
    }
    return NGX_CONF_OK;
}

/* network-facing tail: delegation endpoint, CA stores, congestion alg,
 * traffic mirror, token-cache/rate-limit/authdb/protbind engines, TPC SSRF
 * policy. */
static inline void
brix_shared_merge_net(ngx_http_brix_shared_conf_t *prev,
    ngx_http_brix_shared_conf_t *conf)
{
    /* phase-105 W3: HTTP maxdelay cap (0 = off — emit the protocol default). */
    ngx_conf_merge_sec_value(conf->max_delay, prev->max_delay, 0);
    /* phase-105 W2: delegation endpoint (default off) + front-leg client-CA
     * store dir (empty = stock ssl_client_certificate behavior alone). */
    ngx_conf_merge_value(conf->delegation_endpoint, prev->delegation_endpoint, 0);
    ngx_conf_merge_str_value(conf->client_ca_store, prev->client_ca_store, "");
    /* phase-105 W4.1: introspection quad (defaults preserved: ttl 30s,
     * fail_open ON — the pre-105 webdav values). */
    ngx_conf_merge_str_value(conf->introspect_url, prev->introspect_url, "");
    ngx_conf_merge_str_value(conf->introspect_loc, prev->introspect_loc, "");
    ngx_conf_merge_sec_value(conf->introspect_ttl, prev->introspect_ttl, 30);
    ngx_conf_merge_value(conf->introspect_fail_open,
                         prev->introspect_fail_open, 1);
    /* phase-105 W2/W3.5: auth-layer verify source + chain-depth cap +
     * sender-side congestion alg. verify_depth default 10 preserves the
     * historical HTTP default (stream keeps its own 0=unlimited). */
    ngx_conf_merge_str_value(conf->trusted_ca, prev->trusted_ca, "");
    ngx_conf_merge_str_value(conf->trusted_ca_dir, prev->trusted_ca_dir, "");
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 10);
    ngx_conf_merge_str_value(conf->tcp_congestion, prev->tcp_congestion, "");
    /* phase-105 W2: traffic-mirror settings (moved verbatim from webdav's
     * config_proxy.c so every HTTP protocol conf carries merged values;
     * targets inherit whole, enabled derives from them). */
    if (conf->mirror.targets == NULL) {
        conf->mirror.targets = prev->mirror.targets;
    }
    ngx_conf_merge_str_value(conf->mirror.token, prev->mirror.token, "");
    ngx_conf_merge_uint_value(conf->mirror.sample_pct,
                              prev->mirror.sample_pct, 100);
    ngx_conf_merge_uint_value(conf->mirror.method_mask,
                              prev->mirror.method_mask, BRIX_MIRROR_M_DEFAULT);
    ngx_conf_merge_value(conf->mirror.strip_auth,  prev->mirror.strip_auth,  1);
    ngx_conf_merge_value(conf->mirror.log_diverge, prev->mirror.log_diverge, 1);
    ngx_conf_merge_msec_value(conf->mirror.timeout_ms,
                              prev->mirror.timeout_ms, 5000);
    ngx_conf_merge_value(conf->mirror.mirror_writes,
                         prev->mirror.mirror_writes, 0);
    conf->mirror.enabled = (conf->mirror.targets != NULL
                            && conf->mirror.targets->nelts > 0) ? 1 : 0;
    /* phase-105 W1: token cache + rate limiting (were webdav-local; the
     * engine confs are location-scoped and inherit whole, exactly as the
     * old webdav merge did — plus rl_rules, which webdav never inherited
     * and now NULL-inherits like every other preamble rule array). */
    if (conf->token_cache_kv == NULL) {
        conf->token_cache_kv = prev->token_cache_kv;
    }
    if (conf->rate_limit.kv == NULL) {
        conf->rate_limit = prev->rate_limit;
    }
    if (conf->rl_rules == NULL) {
        conf->rl_rules = prev->rl_rules;
    }
    if (conf->authdb_rules == NULL) {  /* W5.2: NULL-inherit, like vo_rules */
        conf->authdb_rules = prev->authdb_rules;
    }
    if (conf->protbind == NULL) {  /* W4: protbind inherited whole (all-or-none) */
        conf->protbind = prev->protbind;
    }
    /* HTTP-TPC SSRF policy (phase-101 W4): deny local, allow private by default
     * (HEP federation nodes commonly sit on private networks; loopback stays
     * blocked). Source-host allowlist is opt-in and fail-closed when guarded. */
    ngx_conf_merge_value(conf->tpc_allow_local,   prev->tpc_allow_local,   0);
    ngx_conf_merge_value(conf->tpc_allow_private, prev->tpc_allow_private, 1);
    ngx_conf_merge_value(conf->tpc_source_guard,  prev->tpc_source_guard,  0);
    if (conf->tpc_source_allow == NULL) {  /* W4: NULL-inherit like protbind */
        conf->tpc_source_allow = prev->tpc_source_allow;
    }
    ngx_conf_merge_value(conf->tpc_require_source_size,
                         prev->tpc_require_source_size, 0);
    ngx_conf_merge_str_value(conf->tpc_verify_checksum,
                             prev->tpc_verify_checksum, "");  /* W4: "" = off */
}

/*
 * ngx_http_brix_shared_merge() — Merges shared preamble fields from parent to
 * child using standard nginx merge macros. Called at the top of each protocol's
 * merge_loc_conf function before protocol-specific merge logic runs.
 *
 * WHY: This is the SINGLE audit point for common.* config inheritance — every
 * HTTP protocol (WebDAV, S3, cvmfs) calls it instead of hand-merging the same
 * ~20 fields (which drifted per protocol and dropped the read-only enforcement
 * in cvmfs). Defaults: enable=0, allow_write=0, compress=0, ktls=0,
 * thread_pool_name="", storage_credential_dir=BRIX_CREDENTIAL_DIR_DEFAULT
 * (tmpfs store, ensured 0700 by brix_shared_credential_dir_ensure above),
 * tier grammar defaults as before.
 *
 * HOW: root_default parameterizes the one deliberate per-protocol difference
 * (WebDAV exports default to "/", S3/cvmfs to ""). Ends by applying the hard
 * read-only switch (see brix_shared_apply_read_only above) and merging pmark;
 * returns NGX_CONF_OK or NGX_CONF_ERROR (pmark merge failure).
 */
static inline char *
ngx_http_brix_shared_merge(ngx_conf_t *cf,
                             ngx_http_brix_shared_conf_t *prev,
                             ngx_http_brix_shared_conf_t *conf,
                             const char *root_default)
{
    char  *rc;

    rc = brix_shared_merge_core(cf, prev, conf, root_default);
    if (rc != NGX_CONF_OK) {
        return rc;
    }
    brix_shared_merge_backend(cf, prev, conf);
    brix_shared_merge_tier(prev, conf);

    /* Hard read-only: force allow_write off HERE so no protocol merge can
     * forget the enforcement (it must win before token-scope checks). */
    brix_shared_apply_read_only(conf, cf->log);

    rc = brix_shared_merge_authx(cf, prev, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }
    brix_shared_merge_net(prev, conf);

    return brix_pmark_conf_merge(cf, &prev->pmark, &conf->pmark);
}
