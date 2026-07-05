/*
 * directives_tier.inc — phase-64 composable tier-grammar (read-cache + write-stage) directives
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
    /* ---- phase-64 composable tier grammar (read-cache + write-stage tiers) ----
     * A cache/stage store URL composes an sd_cache / sd_stage decorator over the
     * storage backend (any driver). Shared X-macro (core/config/
     * tier_directives.h) — identical grammar to WebDAV and S3 by construction. */
    BRIX_TIER_DIRECTIVES("brix_", ngx_stream_brix_srv_conf_t,
                         NGX_STREAM_SRV_CONF, NGX_STREAM_SRV_CONF_OFFSET),

    /*
     * Per-request UNIX impersonation (phase 40).  These write to a process-global
     * settings block (at most one identity broker per nginx instance), so the
     * custom setters ignore the conf object; the conf field is present only to
     * satisfy nginx's setter-call convention and the offset carries an
     * BRIX_IMP_F_* selector for the multiplexed string/number setters.  Default
     * is `off` — nothing is spawned and no I/O is rerouted.
     */
    { ngx_string("brix_impersonation"),                 /* off | single | map */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_mode,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_impersonation_user"),            /* SINGLE: account */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      BRIX_IMP_F_SINGLE_USER,
      NULL },

    { ngx_string("brix_impersonation_socket"),          /* MAP: broker socket */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      BRIX_IMP_F_SOCKET,
      NULL },

    { ngx_string("brix_impersonation_export"),          /* MAP: confinement root */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      BRIX_IMP_F_EXPORT_ROOT,
      NULL },

    { ngx_string("brix_gridmap"),                       /* MAP: DN->user file */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      BRIX_IMP_F_GRIDMAP,
      NULL },

    { ngx_string("brix_idmap_default_user"),            /* MAP: squash account */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      BRIX_IMP_F_DEFAULT_USER,
      NULL },

    { ngx_string("brix_idmap_min_uid"),                 /* MAP: reserved floor */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_num,
      NGX_STREAM_SRV_CONF_OFFSET,
      BRIX_IMP_F_MIN_UID,
      NULL },

    { ngx_string("brix_idmap_cache_ttl"),               /* MAP: cache TTL secs */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_num,
      NGX_STREAM_SRV_CONF_OFFSET,
      BRIX_IMP_F_CACHE_TTL,
      NULL },

    { ngx_string("brix_impersonation_broker_user"),     /* MAP: non-root broker acct */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      BRIX_IMP_F_BROKER_USER,
      NULL },

    { ngx_string("brix_idmap_forbidden_users"),         /* deny-list target accounts */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      BRIX_IMP_F_FORBIDDEN_USERS,
      NULL },

    { ngx_string("brix_idmap_forbidden_groups"),        /* deny-list privileged groups */
      NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_imp_conf_str,
      NGX_STREAM_SRV_CONF_OFFSET,
      BRIX_IMP_F_FORBIDDEN_GROUPS,
      NULL },

