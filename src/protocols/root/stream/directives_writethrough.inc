/*
 * directives_writethrough.inc — write-through cache directives (write-back mode, flush credential, never/always write-through path prefixes)
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
    /* write-through mode directives (mirrors XrdPfc configuration from
     * /tmp/xrootd-src/src/XrdPfc/README) ---- */

    { ngx_string("brix_write_through"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      brix_conf_set_wt_enable,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_wt_mode"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_wt_mode,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_wt_origin"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_wt_origin,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Names the brix_credential block (§14) the write-back flush authenticates to
     * the wt_origin with (ztn bearer); "" = anonymous. Composes C-3-token + C-5 for
     * an authenticated write-back round-trip. */
    { ngx_string("brix_wt_credential"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, wt.credential),
      NULL },

    /* Repeatable: path prefix that is NEVER write-through (deny list). */
    { ngx_string("brix_wt_deny_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_wt_deny_prefix,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Repeatable: path prefix that is ALWAYS write-through (allow list). */
    { ngx_string("brix_wt_allow_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_wt_allow_prefix,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

