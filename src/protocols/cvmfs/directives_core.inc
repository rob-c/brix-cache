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

    { ngx_string("brix_cache_verify"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, common.cache_verify_mode),
      brix_cvmfs_verify_enum },

    { ngx_string("brix_cvmfs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_brix_cvmfs_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.enable),
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

    { ngx_string("brix_cvmfs_quarantine_dir"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.quarantine_dir),
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

    /* ---- per-protocol tier directives over the shared preamble ---- */

    { ngx_string("brix_cvmfs_storage_backend"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, common.storage_backend),
      NULL },

    { ngx_string("brix_cvmfs_cache_store"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
      brix_conf_set_store_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, common.cache_store),
      (void *) offsetof(ngx_http_brix_cvmfs_loc_conf_t,
                        common.cache_store_args) },

    { ngx_string("brix_cvmfs_thread_pool"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, common.thread_pool_name),
      NULL },
