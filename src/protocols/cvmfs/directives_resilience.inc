/*
 * directives_resilience.inc — cvmfs origin resilience directives (origin selection/geo-coords, upstream stall detection + force-through retry, server-side geo answering)
 * #included into ngx_http_brix_cvmfs_commands[] in cvmfs/module.c (compiler
 * concatenates; setters stay visible). Not a standalone TU.
 */
    { ngx_string("brix_cvmfs_origin_select"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.origin_select),
      brix_cvmfs_select_enum },

    { ngx_string("brix_cvmfs_origin_coords"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_http_brix_cvmfs_set_coords,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_cvmfs_here"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.here),
      NULL },

    { ngx_string("brix_cvmfs_client_hold"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.client_hold),
      NULL },

    { ngx_string("brix_cvmfs_fill_max_life"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.fill_max_life),
      NULL },

    { ngx_string("brix_cvmfs_rtt_interval"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.rtt_interval),
      NULL },

    /* ---- upstream stall detection + force-through retry (2026-07-03) ---- */

    { ngx_string("brix_cvmfs_origin_connect_timeout"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.origin_connect_timeout),
      NULL },

    { ngx_string("brix_cvmfs_origin_stall_timeout"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.origin_stall_timeout),
      NULL },

    { ngx_string("brix_cvmfs_origin_stall_bytes"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.origin_stall_bytes),
      NULL },

    { ngx_string("brix_cvmfs_origin_attempt_timeout"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.origin_attempt_timeout),
      NULL },

    { ngx_string("brix_cvmfs_shared_cache"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.shared_cache),
      NULL },

    { ngx_string("brix_cvmfs_unified_origin"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.unified_origin),
      NULL },

    { ngx_string("brix_cvmfs_origin_reuse_conn"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.origin_reuse_conn),
      NULL },

    { ngx_string("brix_cvmfs_fill_retry_policy"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.fill_retry_policy),
      brix_cvmfs_retry_policy_enum },

    /* ---- server-side geo answering (2026-07-03) ---- */

    { ngx_string("brix_cvmfs_geo_answer"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.geo_answer),
      brix_cvmfs_geo_answer_enum },

    { ngx_string("brix_cvmfs_geo_cache_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.geo_cache_ttl),
      NULL },

    { ngx_string("brix_cvmfs_geo_max_servers"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_cvmfs_loc_conf_t, cvmfs.geo_max_servers),
      NULL },
