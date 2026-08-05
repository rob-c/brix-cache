/*
 * directives_core.inc — cvmfs core directives (scvmfs:// secure layer, manifest/negative TTL, quarantine, upstream allow/max, trace, per-protocol tier)
 * #included into ngx_http_brix_cvmfs_commands[] in cvmfs/module.c (compiler
 * concatenates; setters stay visible). Not a standalone TU.
 */
    /* ---- scvmfs:// (T22, EXPERIMENTAL) — the secure layer ON cvmfs ---- */

    { ngx_string("brix_scvmfs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, scvmfs),
      NULL },

    { ngx_string("brix_scvmfs_authz"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, scvmfs_authz),
      brix_scvmfs_authz_enum },

    { ngx_string("brix_scvmfs_token_issuers"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, scvmfs_token_issuers),
      NULL },

    { ngx_string("brix_scvmfs_x509_dn"),   /* EEC-DN allow-glob (x509 mode);
                                            * multi-occurrence, first match wins;
                                            * omit = accept any verified client */
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, scvmfs_x509_dn),
      NULL },

    { ngx_string("brix_scvmfs_vomsdir"),   /* per-VO LSC dir (voms mode)      */
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, scvmfs_vomsdir),
      NULL },

    { ngx_string("brix_scvmfs_voms_cert_dir"), /* VOMS signing-CA trust dir   */
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, scvmfs_voms_cert_dir),
      NULL },

    { ngx_string("brix_scvmfs_voms"),      /* VO-name allow-glob (voms mode);
                                            * multi-occurrence, any match wins;
                                            * omit = accept any carried VO      */
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, scvmfs_voms),
      NULL },

    /* ---- token-gated repos (phase-85 F3) ---- */

    { ngx_string("brix_cvmfs_repo_authz"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      cvmfs_conf_repo_authz,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, repo_authz),
      NULL },

    /* ---- virtual / composed repos (phase-87 G16) ---- */

    { ngx_string("brix_cvmfs_virtual_repo"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
      cvmfs_conf_virtual_repo,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, virtual_repos),
      NULL },

    /* ---- runtime provenance attestation (phase-87 G15) ---- */

    { ngx_string("brix_cvmfs_attest"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      cvmfs_conf_attest,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, attest_pkey),
      NULL },

    /* ---- per-VO/per-job QoS fill throttling (phase-85 F9) ---- */

    { ngx_string("brix_cvmfs_qos"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE3,
      cvmfs_conf_qos,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, qos),
      NULL },

    /* brix_cache_verify is owned by ngx_http_brix_common_module (same
     * off|cvmfs-cas enum); this protocol adopts it via brix_http_common_adopt(). */

    { ngx_string("brix_cvmfs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_brix_cvmfs_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.enable),
      NULL },

    /* Stratum-0 alias (phase-96 S13): names the published repo tree this
     * location serves (same effect as brix_export) and makes the intent
     * explicit — the merge refuses cache-fill upstream grammar in the same
     * block, and the gate answers /.cvmfs_master_replica so a real
     * Stratum-1 (cvmfs_server add-replica) recognizes a replication source. */
    { ngx_string("brix_cvmfs_stratum0_root"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.stratum0_root),
      NULL },

    { ngx_string("brix_cvmfs_manifest_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.manifest_ttl),
      NULL },

    { ngx_string("brix_cvmfs_negative_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.negative_ttl),
      NULL },

    { ngx_string("brix_cvmfs_offline_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.offline_ttl),
      NULL },

    { ngx_string("brix_cvmfs_quarantine_dir"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.quarantine_dir),
      NULL },

    { ngx_string("brix_cvmfs_verify_manifest"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.master_key),
      NULL },

    { ngx_string("brix_cvmfs_upstream_allow"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      cvmfs_conf_upstream_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.upstream_allow),
      NULL },

    { ngx_string("brix_cvmfs_upstream_max"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.upstream_max),
      NULL },

    { ngx_string("brix_cvmfs_trace"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.trace),
      NULL },

    /* ---- per-protocol tier directives over the shared preamble ----
     * brix_storage_backend, brix_cache_store and brix_thread_pool are owned by
     * ngx_http_brix_common_module; this protocol adopts them via
     * brix_http_common_adopt(). */
