/*
 * directives_writethrough.h — write-through cache directives (write-back mode, flush credential, never/always write-through path prefixes)
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
#pragma once
    /* POSC crash-orphan persistence policy (ofs.persist analog, §1.9). Distinct
     * from write-through: it governs the boot-time reaper of "<final>.xrd-tmp.*"
     * temps a crash stranded mid non-staged write. `auto` (default) reaps
     * dead-owner orphans; `manual`/`off` keep them for recovery; `hold <time>`
     * adds a grace period. Node-global (one reaper at worker-0 startup). */
    { ngx_string("brix_posc_persist"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1 | NGX_CONF_TAKE3,
      brix_conf_set_posc_persist,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* write-through mode directives (mirrors XrdPfc configuration from
     * /tmp/xrootd-src/src/XrdPfc/README) ---- */

    /* phase-105 W8 flag-setter audit: was the hand-rolled
     * brix_conf_set_wt_enable (a pure on/off parse + a NOTICE log) — the
     * stock flag slot is the HELPERS-rule spelling; wt.enable is an
     * NGX_CONF_UNSET-initialized ngx_flag_t, stock-compatible. */
    { ngx_string("brix_write_through"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, wt.enable),
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

