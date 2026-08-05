/*
 * directives_tpc.inc — WebDAV HTTP-TPC directives (SSRF policy, curl pull settings,
 *   stall bounds, marker/streams, credential-forward + OAuth2/OIDC delegation).
 * #included into ngx_http_brix_webdav_commands[] in webdav/module_commands.c
 * (compiler concatenates; setters/enum tables stay visible). Not a standalone TU.
 */
    { ngx_string("brix_webdav_tpc_allow_local"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_allow_local),
      NULL },

    { ngx_string("brix_webdav_tpc_allow_private"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_allow_private),
      NULL },

    /* Source-host NAMING allowlist (SSRF egress control), the WebDAV-plane
     * twin of the native brix_tpc_source_guard. Default off; when on, a COPY
     * may only pull from an allowlisted authority, enforced before curl dials
     * out (tpc_marker_start.c). */
    { ngx_string("brix_webdav_tpc_source_guard"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_source_guard),
      NULL },

    /* Hostnames (exact or leading-'.' domain suffix) a COPY may pull from.
     * Repeatable / space-separated — custom setter appends EVERY argument
     * (stock str_array keeps only the first, silently dropping the rest). */
    { ngx_string("brix_webdav_tpc_source_allow"),
      NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      webdav_conf_tpc_source_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_webdav_tpc_curl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_curl),
      NULL },

    { ngx_string("brix_webdav_tpc_cert"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cert),
      NULL },

    { ngx_string("brix_webdav_tpc_key"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_key),
      NULL },

    { ngx_string("brix_webdav_tpc_cadir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cadir),
      NULL },

    { ngx_string("brix_webdav_tpc_cafile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cafile),
      NULL },

    { ngx_string("brix_webdav_tpc_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_timeout),
      NULL },

    /* Phase 39 (WS4): HTTP-TPC low-speed stall abort (both 0 = off). */
    { ngx_string("brix_webdav_tpc_low_speed_bytes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_low_speed_bytes),
      NULL },

    { ngx_string("brix_webdav_tpc_low_speed_secs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_low_speed_secs),
      NULL },

    { ngx_string("brix_webdav_tpc_marker_interval"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_marker_interval),
      NULL },

    { ngx_string("brix_webdav_tpc_max_streams"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_max_streams),
      NULL },

    /* HTTP-TPC pull completion gate (see webdav_loc_conf.h). */
    { ngx_string("brix_webdav_tpc_require_source_size"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_require_source_size),
      NULL },

    { ngx_string("brix_webdav_tpc_verify_checksum"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      brix_webdav_conf_set_tpc_verify_digest,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_webdav_tpc_credential_forward"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_credential_forward),
      NULL },

    { ngx_string("brix_webdav_tpc_token_endpoint"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cred.token_endpoint),
      NULL },

    { ngx_string("brix_webdav_tpc_token_client_id"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cred.token_client_id),
      NULL },

    { ngx_string("brix_webdav_tpc_token_client_secret"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cred.token_client_secret),
      NULL },

    { ngx_string("brix_webdav_tpc_token_scope"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, tpc_cred.token_scope),
      NULL },
