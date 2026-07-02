/*
 * server_conf.c — server-block config lifecycle: allocate, merge, enable.
 *
 * create_srv_conf() allocates one srv_conf per server block with every field at
 * an NGX_CONF_UNSET sentinel (or NULL), so the merge step can tell an omitted
 * directive from one explicitly set. merge_srv_conf() applies nginx parent→child
 * inheritance (ngx_conf_merge_* for scalars, xrootd_merge_arrays() for the
 * VO/group/manager-map rule sets), split into one helper per config area below.
 * enable() handles "xrootd on|off;", swapping in our session handler when on.
 */

#include "config.h"
#include "core/compat/af_policy.h"      /* XROOTD_AF_AUTO default for origin family */
#include "fs/cache/verify.h"          /* xrootd_cache_verify_mode_e default */
#include "net/ratelimit/ratelimit.h"   /* phase-59 W3a: throttle zone lookup */
#include "net/cms/cns.h"               /* §6 CNS mode enum */
#include "tpc/engine/key_registry.h"
#include "tpc/common/registry.h"   /* Phase 39 (WS5): registry reaper max-age */
#include "protocols/root/session/registry.h"   /* XROOTD_SESSION_REGISTRY_SLOTS default */
#include "net/manager/health_check.h" /* XROOTD_HC_TYPE_PING default */
#include "net/manager/registry.h"     /* Phase 39 (WS7): srv staleness setter */

/*
 * This function creates a new server-level configuration object for nginx.
 * It allocates memory and initializes every field to an "unset" or NULL state,
 * allowing the merge step later to distinguish between missing directives and
 * explicitly configured values.
 */
void *
ngx_stream_xrootd_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_xrootd_srv_conf_t *conf;

    /*
     * nginx allocates one per-server config object during parsing and then
     * merges parent/child scopes later. Start everything in an explicit
     * "unset" or NULL state so the merge step can tell whether a directive
     * was omitted or configured intentionally.
     */
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_xrootd_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * Scalar fields use nginx's UNSET sentinels when they participate in merge
     * logic; runtime-only objects start out NULL/invalid and are created later
     * during postconfiguration once parsing has finished.
     */
    conf->common.enable       = NGX_CONF_UNSET;
    conf->auth         = NGX_CONF_UNSET_UINT;
    conf->common.allow_write  = NGX_CONF_UNSET;
    conf->common.read_only    = NGX_CONF_UNSET;
    conf->common.pblock_block_size = NGX_CONF_UNSET_SIZE;
    conf->common.storage_instance  = NULL;
    /* common.storage_backend (ngx_str_t) left zeroed by pcalloc */
    /* phase-64 tier grammar scalars (str/array fields stay zeroed by pcalloc) */
    conf->common.stage_enable      = NGX_CONF_UNSET;
    conf->common.stage_flush_async = NGX_CONF_UNSET_UINT;
    conf->common.cache_max_object  = NGX_CONF_UNSET;
    conf->common.cache_evict_at    = NGX_CONF_UNSET_UINT;
    conf->common.cache_evict_to    = NGX_CONF_UNSET_UINT;
    conf->common.cache_meta_mode   = NGX_CONF_UNSET_UINT;
    conf->common.cache_batch_cinfo = NGX_CONF_UNSET_UINT;
    conf->common.cache_index_cache = NGX_CONF_UNSET_SIZE;
    conf->common.cache_slice_size  = NGX_CONF_UNSET_SIZE;

    /* XrdAcc engine (acc_tables / acc_timer / acc_nisdomain stay NULL/zero). */
    conf->acc_format      = NGX_CONF_UNSET_UINT;
    conf->acc_audit       = NGX_CONF_UNSET_UINT;
    conf->acc_refresh     = NGX_CONF_UNSET;
    conf->acc_gidlifetime = NGX_CONF_UNSET;
    conf->acc_pgo         = NGX_CONF_UNSET;
    conf->acc_resolve_hosts = NGX_CONF_UNSET;
    conf->acc_encoding    = NGX_CONF_UNSET;
    conf->csi_enable      = NGX_CONF_UNSET;
    conf->csi_fill        = NGX_CONF_UNSET;
    conf->csi_require     = NGX_CONF_UNSET;
    conf->csi_loose       = NGX_CONF_UNSET;
    conf->csi_trust_fs    = NGX_CONF_UNSET;
    conf->throttle_max_open_files  = NGX_CONF_UNSET_UINT;
    conf->throttle_max_active_conn = NGX_CONF_UNSET_UINT;
    xrootd_pmark_conf_init(&conf->common.pmark);  /* SciTags packet marking */
    conf->prepare_command.len  = 0;
    conf->prepare_command.data = NULL;
    xrootd_frm_conf_init(&conf->frm);   /* Phase 35: FRM tape staging */
    conf->crl_reload   = NGX_CONF_UNSET;
    conf->gsi_cert     = NULL;
    conf->gsi_key      = NULL;
    conf->gsi_store    = NULL;
    conf->gsi_cert_pem = NULL;
    conf->gsi_cert_pem_len = 0;
    conf->gsi_ca_hash  = 0;
    conf->gsi_signed_dh = NGX_CONF_UNSET_UINT;
    conf->gsi_max_inflight = NGX_CONF_UNSET;
    conf->vo_rules     = NULL;
    conf->group_rules  = NULL;
    conf->access_log_fd = NGX_INVALID_FILE;
    conf->metrics_slot = -1;
    conf->rootfd       = -1;
    conf->security_level = NGX_CONF_UNSET_UINT;
    conf->tls          = NGX_CONF_UNSET;
    conf->tls_ktls     = NGX_CONF_UNSET;
    conf->read_compress = NGX_CONF_UNSET;
    conf->write_compress = NGX_CONF_UNSET;
    conf->zip_access   = NGX_CONF_UNSET;
    conf->zip_cd_max_bytes = NGX_CONF_UNSET_SIZE;
    conf->zip_force_scratch = NGX_CONF_UNSET;
    conf->zip_stage_max_bytes = NGX_CONF_UNSET_SIZE;
    conf->tls_ctx      = NULL;
    conf->cache        = NGX_CONF_UNSET;
    conf->cache_origin_tls = NGX_CONF_UNSET;
    conf->cache_origin_family = NGX_CONF_UNSET_UINT;
    conf->cache_lock_timeout = NGX_CONF_UNSET;
    conf->cache_eviction_threshold = NGX_CONF_UNSET_UINT;
    conf->cache_max_file_size      = NGX_CONF_UNSET;
    conf->memory_budget            = NGX_CONF_UNSET;
    conf->readv_segment_size       = NGX_CONF_UNSET_SIZE;
    conf->io_uring                 = NGX_CONF_UNSET_UINT;
    conf->io_uring_queue_depth     = NGX_CONF_UNSET;
    conf->io_uring_admin           = NGX_CONF_UNSET;
    conf->io_uring_restrict        = NGX_CONF_UNSET;
    conf->cache_include_regex_set  = 0;
    conf->cache_dirty_max_age      = NGX_CONF_UNSET;
    conf->cache_high_watermark     = NGX_CONF_UNSET_UINT;
    conf->cache_low_watermark      = NGX_CONF_UNSET_UINT;
    conf->cache_reap_interval      = NGX_CONF_UNSET;
    conf->cache_deny_prefixes      = NULL;
    conf->cache_allow_prefixes     = NULL;
    conf->cache_wt_stage_block_size = NGX_CONF_UNSET_SIZE;
    conf->cache_wt_stage_high_watermark = NGX_CONF_UNSET_UINT;
    conf->cache_wt_stage_low_watermark  = NGX_CONF_UNSET_UINT;
    /* O_PATH rootfds: -1 until xrootd_cache_storage_init (pcalloc's 0 == stdin). */
    conf->cache_rootfd             = -1;
    conf->cache_state_rootfd       = -1;
    conf->cache_wt_stage_rootfd    = -1;
    conf->cache_wt_store_rootfd    = -1;
    /* cache_state_root left zeroed (ngx_str_t {0,NULL}) by pcalloc */
    conf->cache_verify             = NGX_CONF_UNSET_UINT;
    /* cache_verify_digest left zeroed (ngx_str_t {0,NULL}) by pcalloc */
    conf->cache_advertise          = NGX_CONF_UNSET;
    conf->cache_advertise_interval = NGX_CONF_UNSET_MSEC;
    conf->wt_enable                = NGX_CONF_UNSET;
    conf->wt_mode                  = XROOTD_WT_MODE_UNSET;
    conf->wt_origin_port           = 0;
    conf->wt_deny_prefixes         = NULL;
    conf->wt_allow_prefixes        = NULL;
    ngx_memzero(&conf->wt_decision, sizeof(conf->wt_decision));
    conf->manager_mode       = NGX_CONF_UNSET;
    conf->metadata_only      = NGX_CONF_UNSET;
    conf->supervisor         = NGX_CONF_UNSET;
    conf->virtual_redirector = NGX_CONF_UNSET;
    conf->collapse_redir     = NGX_CONF_UNSET;
    conf->collapse_redir_ttl = NGX_CONF_UNSET_MSEC;
    conf->recover_writes     = NGX_CONF_UNSET;
    conf->upload_resume      = NGX_CONF_UNSET;
    /* upload_stage_dir: ngx_str_t left zeroed by pcalloc (handled by merge_str). */
    conf->pipeline_depth = NGX_CONF_UNSET_UINT;
    conf->registry_slots = NGX_CONF_UNSET_UINT;
    conf->session_slots  = NGX_CONF_UNSET_UINT;
    conf->gsi_keypool_size = NGX_CONF_UNSET_UINT;
    conf->gsi_keypool_seed = NGX_CONF_UNSET_UINT;
    conf->redir_cache_slots = NGX_CONF_UNSET_UINT;
    conf->hc_enabled     = NGX_CONF_UNSET;
    conf->hc_interval_ms = NGX_CONF_UNSET_MSEC;
    conf->hc_timeout_ms  = NGX_CONF_UNSET_MSEC;
    conf->hc_threshold   = NGX_CONF_UNSET_UINT;
    conf->hc_blacklist_ms = NGX_CONF_UNSET_MSEC;
    conf->hc_type        = NGX_CONF_UNSET_UINT;

    /* Phase 24: traffic mirror (targets array NULL until a directive adds one). */
    conf->mirror.enabled     = NGX_CONF_UNSET;
    conf->mirror.targets     = NULL;
    conf->mirror.sample_pct  = NGX_CONF_UNSET_UINT;
    conf->mirror.method_mask = NGX_CONF_UNSET_UINT;
    conf->mirror.opcode_mask = NGX_CONF_UNSET_UINT;
    conf->mirror.opcode_exclude_mask = NGX_CONF_UNSET_UINT;
    conf->mirror.strip_auth  = NGX_CONF_UNSET;
    conf->mirror.log_diverge = NGX_CONF_UNSET;
    conf->mirror.timeout_ms  = NGX_CONF_UNSET_MSEC;
    conf->mirror.mirror_writes = NGX_CONF_UNSET;
    conf->proxy_enable              = NGX_CONF_UNSET;
    conf->proxy_port                = NGX_CONF_UNSET;
    conf->proxy_upstream_tls        = NGX_CONF_UNSET;
#if (NGX_SSL)
    conf->proxy_tls_ctx             = NULL;
#endif
    conf->proxy_auth                = NGX_CONF_UNSET_UINT;
    conf->proxy_login_user          = NGX_CONF_UNSET_UINT;
    conf->proxy_login_user_name[0]  = '\0';
    conf->proxy_audit_log_fd        = NGX_INVALID_FILE;
    conf->proxy_reconnect_attempts  = NGX_CONF_UNSET_UINT;
    conf->proxy_upstreams           = NULL;
    conf->proxy_connect_timeout     = NGX_CONF_UNSET_MSEC;
    conf->proxy_read_timeout        = NGX_CONF_UNSET_MSEC;
    conf->proxy_write_timeout       = NGX_CONF_UNSET_MSEC;
    conf->proxy_keepalive_interval  = NGX_CONF_UNSET_MSEC;
    conf->cms_locate_timeout = NGX_CONF_UNSET_MSEC;
    conf->cms_addr     = NULL;
    conf->http_handoff_addr = NULL;
    conf->relay_addr = NULL;
    conf->relay_guard_enable = NGX_CONF_UNSET;
    conf->upstream_addr = NULL;
    conf->cms_interval = NGX_CONF_UNSET;
    conf->cms_read_timeout     = NGX_CONF_UNSET_MSEC;
    conf->cms_send_timeout     = NGX_CONF_UNSET_MSEC;
    conf->cms_tcp_keepalive    = NGX_CONF_UNSET;
    conf->cms_tcp_user_timeout = NGX_CONF_UNSET_MSEC;
    conf->cms_initial_delay    = NGX_CONF_UNSET_MSEC;
    conf->cms_connect_retry    = NGX_CONF_UNSET_MSEC;
    conf->listen_port  = NGX_CONF_UNSET;
    conf->cms_ctx      = NULL;
    conf->ckscan_max_depth = NGX_CONF_UNSET_UINT;
    conf->ckscan_max_files = NGX_CONF_UNSET_UINT;
    conf->jwks_mtime                 = 0;
    conf->token_jwks_refresh_interval = NGX_CONF_UNSET_MSEC;
    conf->jwks_timer                  = NULL;
    conf->sss_lifetime      = NGX_CONF_UNSET;
    conf->sss_keys          = NULL;
    conf->krb5_ip_check     = NGX_CONF_UNSET;
#if (XROOTD_HAVE_KRB5)
    conf->krb5_context       = NULL;
    conf->krb5_keytab_obj    = NULL;
    conf->krb5_principal_obj = NULL;
#endif
    conf->unix_trust_remote = NGX_CONF_UNSET;
    conf->host_allow        = NGX_CONF_UNSET_PTR;
    conf->tpc_allow_local   = NGX_CONF_UNSET;
    conf->tpc_allow_private = NGX_CONF_UNSET;
    conf->ssi_enable        = NGX_CONF_UNSET;
    conf->ssi_cta_enable    = NGX_CONF_UNSET;
    conf->ssi_max_inflight  = NGX_CONF_UNSET_UINT;
    conf->ssi_request_max   = NGX_CONF_UNSET_SIZE;
    conf->ssi_response_max  = NGX_CONF_UNSET_SIZE;
    conf->ssi_cta_executor  = NGX_CONF_UNSET_UINT;
    conf->cns_mode          = NGX_CONF_UNSET_UINT;
    conf->tpc_key_ttl_ms    = NGX_CONF_UNSET_MSEC;
    conf->tpc_max_transfer_secs = NGX_CONF_UNSET_UINT;
    conf->tpc_outbound_tls  = NGX_CONF_UNSET;
    conf->tpc_delegate      = NGX_CONF_UNSET;
    conf->tpc_transfer_max_age  = NGX_CONF_UNSET;
    conf->tpc_outbound_bearer_file.len = 0;
    conf->tpc_outbound_bearer_file.data = NULL;
    conf->tpc_outbound_token_endpoint.len = 0;
    conf->tpc_outbound_token_endpoint.data = NULL;
    conf->tpc_outbound_client_id.len = 0;
    conf->tpc_outbound_client_id.data = NULL;
    conf->tpc_outbound_client_secret.len = 0;
    conf->tpc_outbound_client_secret.data = NULL;
    conf->tpc_outbound_scope.len = 0;
    conf->tpc_outbound_scope.data = NULL;

    conf->upstream_tls = NGX_CONF_UNSET;
#if (NGX_SSL)
    conf->upstream_tls_ctx = NULL;
#endif
    conf->upstream_tls_ca.len    = 0;
    conf->upstream_tls_ca.data   = NULL;
    conf->upstream_tls_name.len  = 0;
    conf->upstream_tls_name.data = NULL;
    conf->upstream_token_file.len  = 0;
    conf->upstream_token_file.data = NULL;

    conf->ocsp_enable     = NGX_CONF_UNSET;
    conf->ocsp_soft_fail  = NGX_CONF_UNSET;
    conf->ocsp_stapling   = NGX_CONF_UNSET;
    conf->ocsp_staple_data = NULL;
    conf->ocsp_staple_len  = 0;

    /* Phase 20 caches/limits: kv == NULL means the feature is disabled.  The
     * directive setters fill these in; merge inherits the parent block. */
    conf->token_cache_kv  = NULL;
    conf->auth_cache.kv   = NULL;
    conf->auth_cache.ttl_secs = 0;
    conf->rate_limit.kv   = NULL;
    conf->rate_limit.rate = 0;
    conf->rate_limit.burst = 0;
    conf->rate_limit.key_ip = 0;

    /* Phase 39: network-fault resilience (off by default). */
    conf->read_timeout      = NGX_CONF_UNSET_MSEC;
    conf->handshake_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_timeout      = NGX_CONF_UNSET_MSEC;
    conf->tcp_user_timeout  = NGX_CONF_UNSET_MSEC;
    conf->tcp_keepalive     = NGX_CONF_UNSET;
    conf->max_connections   = NGX_CONF_UNSET_UINT;
    conf->manager_stale_after = NGX_CONF_UNSET_MSEC;

    return conf;
}

/*
 * The merge below is split into one helper per configuration area. Each helper
 * is a verbatim slice of the original linear merge and is invoked in the SAME
 * order, so every cross-area derivation still sees its inputs already merged
 * (e.g. writethrough's origin/decision in merge_proxy_net depends on the cache
 * fields settled in merge_storage; CMS timeout derivation depends on
 * cms_interval). Helpers that can fail config validation return char*
 * (NGX_CONF_OK / NGX_CONF_ERROR); the rest return void.
 */

/* Identity & crypto: auth scheme + GSI/pwd, XrdAcc engine (+ native-authdb
 * validation), SciTags/FRM, X.509 material + CRL, access log, tokens + L1/L2
 * caches, sss/krb5/unix/host, security level, and TLS toggles. */
static char *
xrootd_merge_srv_security(ngx_conf_t *cf, ngx_stream_xrootd_srv_conf_t *conf,
    ngx_stream_xrootd_srv_conf_t *prev)
{
    /*
     * Standard nginx inheritance rules: values set on the current server
     * override the parent, otherwise we fall back to the parent or the hard
     * coded module default.
     */
    ngx_conf_merge_value(conf->common.enable,      prev->common.enable,      0);
    ngx_conf_merge_str_value(conf->common.root,    prev->common.root,        "/");
    ngx_conf_merge_uint_value(conf->auth,   prev->auth,        XROOTD_AUTH_NONE);
    ngx_conf_merge_uint_value(conf->gsi_signed_dh, prev->gsi_signed_dh,
                              XROOTD_GSI_SDH_OFF);
    ngx_conf_merge_value(conf->gsi_max_inflight, prev->gsi_max_inflight, 256);
    ngx_conf_merge_uint_value(conf->gsi_keypool_size, prev->gsi_keypool_size,
                              XROOTD_GSI_KEYPOOL_SIZE_DEFAULT);
    ngx_conf_merge_uint_value(conf->gsi_keypool_seed, prev->gsi_keypool_seed,
                              XROOTD_GSI_KEYPOOL_SEED_DEFAULT);
    ngx_conf_merge_str_value(conf->gsi_ciphers, prev->gsi_ciphers, "");
    ngx_conf_merge_str_value(conf->pwd_file, prev->pwd_file, "");
    ngx_conf_merge_value(conf->common.allow_write, prev->common.allow_write, 0);
    ngx_conf_merge_value(conf->common.read_only,    prev->common.read_only,    0);

    /* XrdAcc engine: default native, audit off, refresh off, 12h gid cache. */
    ngx_conf_merge_uint_value(conf->acc_format, prev->acc_format,
                              XROOTD_AUTHDB_FORMAT_NATIVE);
    ngx_conf_merge_uint_value(conf->acc_audit, prev->acc_audit,
                              XROOTD_AUTHDB_AUDIT_NONE);
    ngx_conf_merge_value(conf->acc_refresh, prev->acc_refresh, 0);
    ngx_conf_merge_value(conf->acc_gidlifetime, prev->acc_gidlifetime, 43200);
    ngx_conf_merge_value(conf->acc_pgo, prev->acc_pgo, 0);
    ngx_conf_merge_value(conf->acc_resolve_hosts, prev->acc_resolve_hosts, 0);
    ngx_conf_merge_value(conf->acc_encoding, prev->acc_encoding, 0);
    ngx_conf_merge_str_value(conf->acc_nisdomain, prev->acc_nisdomain, "");
    ngx_conf_merge_str_value(conf->acc_spacechar, prev->acc_spacechar, "");
    ngx_conf_merge_str_value(conf->acc_gidretran, prev->acc_gidretran, "");

    /*
     * The native authdb engine matches by DN/VO and so needs an authenticating
     * scheme; the xrdacc engine also authorizes anonymous `u *` rules, so it is
     * exempt.  Validated here, where both directives have settled.
     */
    if (conf->authdb.len > 0
        && conf->acc_format == XROOTD_AUTHDB_FORMAT_NATIVE
        && conf->auth != XROOTD_AUTH_GSI && conf->auth != XROOTD_AUTH_TOKEN
        && conf->auth != (XROOTD_AUTH_GSI | XROOTD_AUTH_TOKEN))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_authdb (native format) requires xrootd_auth gsi, token "
            "or both; use `xrootd_authdb_format xrdacc` for anonymous rules");
        return NGX_CONF_ERROR;
    }

    if (xrootd_pmark_conf_merge(cf, &prev->common.pmark, &conf->common.pmark)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_conf_merge_str_value(conf->prepare_command, prev->prepare_command, "");
    if (xrootd_frm_conf_merge(cf, &conf->frm, &prev->frm, &conf->prepare_command)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_conf_merge_str_value(conf->certificate,     prev->certificate,     "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_str_value(conf->trusted_ca,      prev->trusted_ca,      "");
    ngx_conf_merge_str_value(conf->vomsdir,         prev->vomsdir,         "");
    ngx_conf_merge_str_value(conf->voms_cert_dir,   prev->voms_cert_dir,   "");
    ngx_conf_merge_str_value(conf->crl,             prev->crl,             "");
    ngx_conf_merge_value(conf->crl_reload,    prev->crl_reload,      0);
    ngx_conf_merge_str_value(conf->access_log,      prev->access_log,      "");
    ngx_conf_merge_str_value(conf->token_jwks,      prev->token_jwks,      "");
    ngx_conf_merge_msec_value(conf->token_jwks_refresh_interval,
                              prev->token_jwks_refresh_interval,
                              NGX_CONF_UNSET_MSEC);
    ngx_conf_merge_str_value(conf->token_issuer,    prev->token_issuer,    "");
    ngx_conf_merge_str_value(conf->token_audience,  prev->token_audience,  "");
    ngx_conf_merge_str_value(conf->token_config,    prev->token_config,    "");
    ngx_conf_merge_ptr_value(conf->token_registry,  prev->token_registry,  NULL);
    ngx_conf_merge_str_value(conf->throttle_zone_name,
                             prev->throttle_zone_name, "");
    ngx_conf_merge_ptr_value(conf->throttle_zone, prev->throttle_zone, NULL);
    ngx_conf_merge_uint_value(conf->throttle_max_open_files,
                              prev->throttle_max_open_files, 0);
    ngx_conf_merge_uint_value(conf->throttle_max_active_conn,
                              prev->throttle_max_active_conn, 0);

    /* phase-59 W3a: resolve the named rate-limit zone the throttle keys its
     * per-user counters into (declared via xrootd_rate_limit_zone). */
    if (conf->throttle_zone == NULL && conf->throttle_zone_name.len > 0) {
        conf->throttle_zone = xrootd_rl_zone_get(&conf->throttle_zone_name);
        if (conf->throttle_zone == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_throttle_zone \"%V\" is not a declared "
                "xrootd_rate_limit_zone", &conf->throttle_zone_name);
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_value(conf->csi_enable,  prev->csi_enable,  1);
    ngx_conf_merge_str_value(conf->csi_prefix, prev->csi_prefix, "/.xrdt");
    ngx_conf_merge_value(conf->csi_fill,    prev->csi_fill,    1);
    ngx_conf_merge_value(conf->csi_require, prev->csi_require, 0);
    ngx_conf_merge_value(conf->csi_loose,   prev->csi_loose,   0);
    ngx_conf_merge_value(conf->csi_trust_fs, prev->csi_trust_fs, 0);
    ngx_conf_merge_str_value(conf->token_macaroon_secret,
                             prev->token_macaroon_secret,     "");
    ngx_conf_merge_str_value(conf->token_macaroon_secret_old,
                             prev->token_macaroon_secret_old, "");

    /* Phase 20 caches/limits: inherit the parent's whole config when this
     * block did not declare its own (kv still NULL). */
    if (conf->token_cache_kv == NULL) {
        conf->token_cache_kv = prev->token_cache_kv;
    }
    if (conf->auth_cache.kv == NULL) {
        conf->auth_cache = prev->auth_cache;
    }
    if (conf->rate_limit.kv == NULL) {
        conf->rate_limit = prev->rate_limit;
    }
    ngx_conf_merge_str_value(conf->sss_keytab,      prev->sss_keytab,      "");
    ngx_conf_merge_value(conf->sss_lifetime,        prev->sss_lifetime,    13);
    ngx_conf_merge_str_value(conf->krb5_principal,  prev->krb5_principal,  "");
    ngx_conf_merge_str_value(conf->krb5_keytab,     prev->krb5_keytab,     "");
    ngx_conf_merge_value(conf->krb5_ip_check,       prev->krb5_ip_check,   0);
    ngx_conf_merge_value(conf->unix_trust_remote,   prev->unix_trust_remote, 0);
    ngx_conf_merge_ptr_value(conf->host_allow,      prev->host_allow,      NULL);
    ngx_conf_merge_uint_value(conf->security_level, prev->security_level, 0);
    ngx_conf_merge_value(conf->tls,             prev->tls,             0);
    ngx_conf_merge_value(conf->tls_ktls,        prev->tls_ktls,        0);

    return NGX_CONF_OK;
}

/* Storage: read/write compression, ZIP access, the read-through cache (origin,
 * sizing, eviction, slice validation, include-regex inheritance), the memory
 * budget, readv segment sizing, and the io_uring backend. */
static char *
xrootd_merge_srv_storage(ngx_conf_t *cf, ngx_stream_xrootd_srv_conf_t *conf,
    ngx_stream_xrootd_srv_conf_t *prev)
{
    /* Storage backend selection (default POSIX) + pblock stripe size. */
    ngx_conf_merge_str_value(conf->common.storage_backend,
                             prev->common.storage_backend, "");
    ngx_conf_merge_size_value(conf->common.pblock_block_size,
                              prev->common.pblock_block_size, 0);

    /* phase-64 composable tier grammar */
    ngx_conf_merge_str_value(conf->common.cache_store, prev->common.cache_store,
                             "");
    if (conf->common.cache_store_args == NULL) {
        conf->common.cache_store_args = prev->common.cache_store_args;
    }
    ngx_conf_merge_value(conf->common.stage_enable, prev->common.stage_enable, 0);
    ngx_conf_merge_str_value(conf->common.stage_store, prev->common.stage_store,
                             "");
    if (conf->common.stage_store_args == NULL) {
        conf->common.stage_store_args = prev->common.stage_store_args;
    }
    ngx_conf_merge_uint_value(conf->common.stage_flush_async,
                              prev->common.stage_flush_async, 0);
    ngx_conf_merge_off_value(conf->common.cache_max_object,
                             prev->common.cache_max_object, 0);
    ngx_conf_merge_uint_value(conf->common.cache_evict_at,
                              prev->common.cache_evict_at, 90);
    ngx_conf_merge_uint_value(conf->common.cache_evict_to,
                              prev->common.cache_evict_to, 80);
    ngx_conf_merge_uint_value(conf->common.cache_meta_mode,
                              prev->common.cache_meta_mode, 0);
    ngx_conf_merge_uint_value(conf->common.cache_batch_cinfo,
                              prev->common.cache_batch_cinfo, 2);
    ngx_conf_merge_size_value(conf->common.cache_index_cache,
                              prev->common.cache_index_cache, 0);
    ngx_conf_merge_size_value(conf->common.cache_slice_size,
                              prev->common.cache_slice_size, 0);

    /* §6.5: the tier slice size must be 0 (off) or a positive multiple of the
     * 1 MiB cinfo block granule (so a partial fill never records a mis-aligned
     * block) — the same rule the legacy xrootd_cache_slice enforced. */
    if (conf->common.cache_slice_size != 0
        && (conf->common.cache_slice_size < (1024 * 1024)
            || (conf->common.cache_slice_size % (1024 * 1024)) != 0))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_slice_size must be a positive multiple of 1m");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->read_compress,   prev->read_compress,   0);
    ngx_conf_merge_value(conf->write_compress,  prev->write_compress,  0);
    ngx_conf_merge_value(conf->zip_access,      prev->zip_access,      0);
    ngx_conf_merge_size_value(conf->zip_cd_max_bytes, prev->zip_cd_max_bytes,
                              16 * 1024 * 1024);
    ngx_conf_merge_str_value(conf->zip_stage_dir, prev->zip_stage_dir, "");
    ngx_conf_merge_value(conf->zip_force_scratch, prev->zip_force_scratch, 0);
    ngx_conf_merge_size_value(conf->zip_stage_max_bytes,
                              prev->zip_stage_max_bytes, 512 * 1024 * 1024);
    ngx_conf_merge_value(conf->cache,           prev->cache,           0);
    ngx_conf_merge_str_value(conf->cache_root,  prev->cache_root,      "");
    ngx_conf_merge_str_value(conf->cache_state_root, prev->cache_state_root, "");
    ngx_conf_merge_str_value(conf->cache_wt_stage_root,
                             prev->cache_wt_stage_root, "");
    ngx_conf_merge_str_value(conf->cache_wt_stage_backend,
                             prev->cache_wt_stage_backend, "");
    ngx_conf_merge_size_value(conf->cache_wt_stage_block_size,
                              prev->cache_wt_stage_block_size, 0);

    /* Staging backpressure: default OFF (high == 0). When only HIGH is set, LOW
     * defaults 50000 ppm (5%) below it for hysteresis. The ordering invariant
     * (0 < low < high < 1e6) is enforced in runtime_server.c. */
    ngx_conf_merge_uint_value(conf->cache_wt_stage_high_watermark,
                              prev->cache_wt_stage_high_watermark, 0);
    ngx_conf_merge_uint_value(conf->cache_wt_stage_low_watermark,
                              prev->cache_wt_stage_low_watermark,
                              conf->cache_wt_stage_high_watermark > 50000
                                  ? conf->cache_wt_stage_high_watermark - 50000
                                  : conf->cache_wt_stage_high_watermark / 2);
    ngx_conf_merge_sec_value(conf->cache_dirty_max_age,
                             prev->cache_dirty_max_age, 604800);   /* 7 days */
    if (conf->cache_deny_prefixes == NULL) {
        conf->cache_deny_prefixes = prev->cache_deny_prefixes;
    }
    if (conf->cache_allow_prefixes == NULL) {
        conf->cache_allow_prefixes = prev->cache_allow_prefixes;
    }
    ngx_conf_merge_str_value(conf->cache_origin, prev->cache_origin,   "");
    ngx_conf_merge_value(conf->cache_origin_tls, prev->cache_origin_tls, 0);
    ngx_conf_merge_uint_value(conf->cache_origin_family,
                              prev->cache_origin_family, XROOTD_AF_AUTO);
    ngx_conf_merge_value(conf->cache_lock_timeout,
                         prev->cache_lock_timeout, 300);
    ngx_conf_merge_uint_value(conf->cache_eviction_threshold,
                              prev->cache_eviction_threshold, 900000);

    /* Watermark reaper: HIGH defaults to the on-fill eviction threshold so an
     * existing config keeps its bound; LOW defaults 50000 ppm (5%) below HIGH for
     * hysteresis; the timer runs every 60s by default. The ordering invariant
     * (0 < low < high < 1e6) is enforced in runtime_server.c. */
    ngx_conf_merge_uint_value(conf->cache_high_watermark,
                              prev->cache_high_watermark,
                              conf->cache_eviction_threshold);
    ngx_conf_merge_uint_value(conf->cache_low_watermark,
                              prev->cache_low_watermark,
                              conf->cache_high_watermark > 50000
                                  ? conf->cache_high_watermark - 50000
                                  : conf->cache_high_watermark / 2);
    ngx_conf_merge_sec_value(conf->cache_reap_interval,
                             prev->cache_reap_interval, 60);
    ngx_conf_merge_off_value(conf->cache_max_file_size,
                             prev->cache_max_file_size, 0);
    ngx_conf_merge_off_value(conf->memory_budget,
                             prev->memory_budget, 768 * 1024 * 1024);
    /* Default = stock XRootD maxReadv_ior = maxBuffsz(2 MiB) - sizeof(readahead_list). */
    ngx_conf_merge_size_value(conf->readv_segment_size,
                              prev->readv_segment_size,
                              (size_t) (2 * 1024 * 1024) - XROOTD_READV_SEGSIZE);

    /* Phase 44: optional io_uring backend.  Default mode AUTO (enable iff the
     * runtime probe passes, else silent thread-pool fallback); restrictions on;
     * admin endpoint off; panic-file unset. */
    ngx_conf_merge_uint_value(conf->io_uring,
                              prev->io_uring, XROOTD_IO_URING_AUTO);
    ngx_conf_merge_value(conf->io_uring_queue_depth,
                         prev->io_uring_queue_depth,
                         XROOTD_IO_URING_QUEUE_DEPTH);
    ngx_conf_merge_str_value(conf->io_uring_panic_file,
                             prev->io_uring_panic_file, "");
    ngx_conf_merge_value(conf->io_uring_admin, prev->io_uring_admin, 0);
    ngx_conf_merge_value(conf->io_uring_restrict, prev->io_uring_restrict, 1);


    /* Checksum-on-fill: default best-effort (verify when a digest is available,
     * fail-closed on mismatch). Operators opt down to off or up to require. */
    ngx_conf_merge_uint_value(conf->cache_verify, prev->cache_verify,
                              XROOTD_CACHE_VERIFY_BESTEFFORT);
    ngx_conf_merge_str_value(conf->cache_verify_digest,
                             prev->cache_verify_digest, "");

    /* Pelican cache advertisement (default off; interval clamped to the
     * federation minimum of 60s = MinFedTokenTickerRate). */
    ngx_conf_merge_value(conf->cache_advertise, prev->cache_advertise, 0);
    ngx_conf_merge_msec_value(conf->cache_advertise_interval,
                              prev->cache_advertise_interval, 60000);
    if (conf->cache_advertise_interval < 60000) {
        conf->cache_advertise_interval = 60000;
    }
    ngx_conf_merge_str_value(conf->cache_advertise_key,
                             prev->cache_advertise_key, "");
    ngx_conf_merge_str_value(conf->cache_data_url, prev->cache_data_url, "");
    ngx_conf_merge_str_value(conf->cache_web_url, prev->cache_web_url, "");
    ngx_conf_merge_str_value(conf->cache_sitename, prev->cache_sitename, "");
    ngx_conf_merge_str_value(conf->cache_issuer_url, prev->cache_issuer_url, "");
    if (conf->cache_advertise_ns == NULL) {
        conf->cache_advertise_ns = prev->cache_advertise_ns;
    }

    /* Inherit compiled regex from parent if the child didn't set one */
    if (!conf->cache_include_regex_set && prev->cache_include_regex_set) {
        conf->cache_include_regex_str = prev->cache_include_regex_str;
        conf->cache_include_regex     = prev->cache_include_regex;
        conf->cache_include_regex_set = 1;
    }

    return NGX_CONF_OK;
}

/* Third-party copy (TPC): local/private allowances, key TTL, transfer caps and
 * the abandoned-slot reaper age, and the outbound OAuth2/bearer credentials. */
static void
xrootd_merge_srv_tpc(ngx_stream_xrootd_srv_conf_t *conf,
    ngx_stream_xrootd_srv_conf_t *prev)
{
    ngx_conf_merge_value(conf->tpc_allow_local,   prev->tpc_allow_local,   0);
    ngx_conf_merge_value(conf->tpc_allow_private, prev->tpc_allow_private, 1);
    ngx_conf_merge_value(conf->ssi_enable,        prev->ssi_enable,        0);
    ngx_conf_merge_value(conf->ssi_cta_enable,    prev->ssi_cta_enable,    0);
    /* defaults mirror XROOTD_SSI_MAX_INFLIGHT (8) and the 1 MiB req/resp caps. */
    ngx_conf_merge_uint_value(conf->ssi_max_inflight, prev->ssi_max_inflight, 8);
    ngx_conf_merge_size_value(conf->ssi_request_max,  prev->ssi_request_max,  1u << 20);
    ngx_conf_merge_size_value(conf->ssi_response_max, prev->ssi_response_max, 1u << 20);
    ngx_conf_merge_str_value(conf->ssi_cta_journal,   prev->ssi_cta_journal,  "");
    ngx_conf_merge_uint_value(conf->ssi_cta_executor, prev->ssi_cta_executor, 0);
    ngx_conf_merge_uint_value(conf->cns_mode,     prev->cns_mode,          XROOTD_CNS_OFF);
    if (conf->cns_mode == XROOTD_CNS_COLLECT) {
        xrootd_cns_set_collect(1);   /* §6: this node maintains the CNS inventory */
    }
    ngx_conf_merge_value(conf->tpc_outbound_tls,  prev->tpc_outbound_tls,  0);
    ngx_conf_merge_value(conf->tpc_delegate,      prev->tpc_delegate,      0);
    ngx_conf_merge_msec_value(conf->tpc_key_ttl_ms, prev->tpc_key_ttl_ms,
                              XROOTD_TPC_KEY_TTL_MS);
    /* Phase 51 (B2): default native-TPC absolute wall-clock cap to a generous
     * 24h so a wedged transfer cannot pin a thread-pool worker forever; 0 still
     * means unlimited (back-compat).  Progress-based stall detection (the curl
     * low-speed bounds, webdav/tpc_config.c) is the primary guard — this is only
     * the absolute backstop, large enough never to clip a real transfer. */
    ngx_conf_merge_uint_value(conf->tpc_max_transfer_secs,
                              prev->tpc_max_transfer_secs, 86400);
    ngx_conf_merge_value(conf->tpc_transfer_max_age,
                         prev->tpc_transfer_max_age, 0);
    /* Phase 39 (WS5): publish the abandoned-slot reaper age to the shared TPC
     * registry (config-time, before fork).  Guarded so a 0-default block does not
     * disable a sibling block that enabled it. */
    if (conf->tpc_transfer_max_age > 0) {
        xrootd_tpc_registry_set_max_age((time_t) conf->tpc_transfer_max_age);
    }
    ngx_conf_merge_str_value(conf->tpc_outbound_bearer_file,
                             prev->tpc_outbound_bearer_file, "");
    ngx_conf_merge_str_value(conf->tpc_outbound_token_endpoint,
                             prev->tpc_outbound_token_endpoint, "");
    ngx_conf_merge_str_value(conf->tpc_outbound_client_id,
                             prev->tpc_outbound_client_id, "");
    ngx_conf_merge_str_value(conf->tpc_outbound_client_secret,
                             prev->tpc_outbound_client_secret, "");
    ngx_conf_merge_str_value(conf->tpc_outbound_scope,
                             prev->tpc_outbound_scope, "storage.read");
}

/* Cluster & sessions: manager/redirector mode, write recovery + staged uploads,
 * pipeline/registry/session sizing, active health checks, the traffic mirror,
 * the CMS client (+ resilience-timeout derivation), listen port, checksum-scan
 * limits, and the VO/group/manager-map rule arrays + redirector inheritance. */
static char *
xrootd_merge_srv_cluster(ngx_conf_t *cf, ngx_stream_xrootd_srv_conf_t *conf,
    ngx_stream_xrootd_srv_conf_t *prev)
{
    ngx_array_t *child_vo_rules;
    ngx_array_t *child_group_rules;

    ngx_conf_merge_value(conf->manager_mode,         prev->manager_mode,         0);
    ngx_conf_merge_value(conf->metadata_only,        prev->metadata_only,        0);
    ngx_conf_merge_value(conf->supervisor,           prev->supervisor,           0);
    ngx_conf_merge_value(conf->virtual_redirector,   prev->virtual_redirector,   0);
    ngx_conf_merge_value(conf->collapse_redir,       prev->collapse_redir,       0);
    ngx_conf_merge_msec_value(conf->collapse_redir_ttl, prev->collapse_redir_ttl, 30000);
    ngx_conf_merge_value(conf->recover_writes,       prev->recover_writes,       0);
    /* Uploads are staged + resumable by DEFAULT (atomic commit-on-close, resume
     * across a restart).  Set xrootd_upload_resume off to opt out. */
    ngx_conf_merge_value(conf->upload_resume,        prev->upload_resume,        1);
    ngx_conf_merge_str_value(conf->upload_stage_dir, prev->upload_stage_dir,     "");
    ngx_conf_merge_uint_value(conf->pipeline_depth,  prev->pipeline_depth,
                              XROOTD_PIPELINE_DEPTH_DEFAULT);
    /* Clamp the in-flight pipeline window to a sane range: >=1 (the recv loop and
     * ring arithmetic require a positive modulus) and <=MAX (bounds per-connection
     * out_ring/rd_pool memory). */
    if (conf->pipeline_depth < XROOTD_PIPELINE_DEPTH_MIN) {
        conf->pipeline_depth = XROOTD_PIPELINE_DEPTH_MIN;
    } else if (conf->pipeline_depth > XROOTD_PIPELINE_DEPTH_MAX) {
        conf->pipeline_depth = XROOTD_PIPELINE_DEPTH_MAX;
    }
    ngx_conf_merge_uint_value(conf->registry_slots,  prev->registry_slots,  128);
    ngx_conf_merge_uint_value(conf->session_slots,   prev->session_slots,
                              XROOTD_SESSION_REGISTRY_SLOTS);
    /* Left UNSET when unconfigured; postconfiguration treats UNSET as
     * "use the compile-time default" (XROOTD_REDIR_CACHE_SLOTS). */
    ngx_conf_merge_uint_value(conf->redir_cache_slots, prev->redir_cache_slots,
                              NGX_CONF_UNSET_UINT);

    /* Phase 22: active health checks — disabled by default (non-breaking). */
    ngx_conf_merge_value(conf->hc_enabled,       prev->hc_enabled,       0);
    ngx_conf_merge_msec_value(conf->hc_interval_ms,  prev->hc_interval_ms,  30000);
    ngx_conf_merge_msec_value(conf->hc_timeout_ms,   prev->hc_timeout_ms,    5000);
    ngx_conf_merge_uint_value(conf->hc_threshold,    prev->hc_threshold,        3);
    ngx_conf_merge_msec_value(conf->hc_blacklist_ms, prev->hc_blacklist_ms, 60000);
    ngx_conf_merge_uint_value(conf->hc_type, prev->hc_type, XROOTD_HC_TYPE_PING);

    /* Phase 24: traffic mirror — inherit parent targets if none set locally,
     * then derive `enabled` from the presence of at least one target. */
    if (conf->mirror.targets == NULL) {
        conf->mirror.targets = prev->mirror.targets;
    }
    ngx_conf_merge_uint_value(conf->mirror.sample_pct,  prev->mirror.sample_pct, 100);
    /* Default: mirror ALL ops; the operator de-selects with
     * xrootd_mirror_exclude_opcodes (or restricts with xrootd_mirror_opcodes). */
    ngx_conf_merge_uint_value(conf->mirror.opcode_mask, prev->mirror.opcode_mask,
                              XROOTD_MIRROR_OP_ALL);
    ngx_conf_merge_uint_value(conf->mirror.opcode_exclude_mask,
                              prev->mirror.opcode_exclude_mask, 0);
    ngx_conf_merge_uint_value(conf->mirror.method_mask, prev->mirror.method_mask,
                              XROOTD_MIRROR_M_DEFAULT);
    ngx_conf_merge_value(conf->mirror.strip_auth,  prev->mirror.strip_auth,  1);
    ngx_conf_merge_value(conf->mirror.log_diverge, prev->mirror.log_diverge, 1);
    ngx_conf_merge_msec_value(conf->mirror.timeout_ms, prev->mirror.timeout_ms, 5000);
    ngx_conf_merge_value(conf->mirror.mirror_writes,
                         prev->mirror.mirror_writes, 0);
    conf->mirror.enabled = (conf->mirror.targets != NULL
                            && conf->mirror.targets->nelts > 0) ? 1 : 0;

    ngx_conf_merge_msec_value(conf->cms_locate_timeout, prev->cms_locate_timeout,
                              5000);
    ngx_conf_merge_str_value(conf->cms_paths,       prev->cms_paths,       "");
    ngx_conf_merge_value(conf->cms_interval,        prev->cms_interval,    30);
    if (conf->cms_interval < 1) {
        /* 0 would arm a 0ms heartbeat timer AND zero the reconnect backoff
         * (connect.c) — both busy-loops. Floor the heartbeat at 1s. */
        conf->cms_interval = 1;
    }

    /*
     * Phase 50: CMS client resilience deadlines.  Resolve here (after
     * cms_interval is merged) so an unset directive auto-derives a generous
     * ON-by-default value from the heartbeat interval; an explicit 0 disables.
     *   - read timeout: max(3 x interval, 90s) — a healthy real cmsd pings well
     *     within its interval, so this never trips a conformant manager.
     *   - send timeout: 10s — bounds a manager that stops draining our writes.
     *   - tcp_user_timeout: defaults to the read-timeout as a kernel backstop.
     */
    if (conf->cms_read_timeout == NGX_CONF_UNSET_MSEC) {
        if (prev->cms_read_timeout != NGX_CONF_UNSET_MSEC) {
            conf->cms_read_timeout = prev->cms_read_timeout;
        } else {
            ngx_msec_t d = (ngx_msec_t) conf->cms_interval * 3 * 1000;
            conf->cms_read_timeout = (d > 90000) ? d : 90000;
        }
    }
    ngx_conf_merge_msec_value(conf->cms_send_timeout, prev->cms_send_timeout,
                              10000);
    ngx_conf_merge_value(conf->cms_tcp_keepalive, prev->cms_tcp_keepalive, 1);
    if (conf->cms_tcp_user_timeout == NGX_CONF_UNSET_MSEC) {
        conf->cms_tcp_user_timeout =
            (prev->cms_tcp_user_timeout != NGX_CONF_UNSET_MSEC)
                ? prev->cms_tcp_user_timeout
                : conf->cms_read_timeout;
    }

    /* Leave these UNSET through the merge so connect.c can pick the manager-locality
     * (loopback vs remote) profile default at worker start; an explicit directive
     * still wins and is inherited child<-parent. */
    ngx_conf_merge_msec_value(conf->cms_initial_delay, prev->cms_initial_delay,
                              NGX_CONF_UNSET_MSEC);
    ngx_conf_merge_msec_value(conf->cms_connect_retry, prev->cms_connect_retry,
                              NGX_CONF_UNSET_MSEC);

    ngx_conf_merge_value(conf->listen_port,         prev->listen_port,     XROOTD_DEFAULT_PORT);
    ngx_conf_merge_uint_value(conf->ckscan_max_depth,
                              prev->ckscan_max_depth, 32);
    ngx_conf_merge_uint_value(conf->ckscan_max_files,
                              prev->ckscan_max_files, 100000);

    if (conf->cms_addr == NULL && prev->cms_addr != NULL) {
        conf->cms_addr = prev->cms_addr;
        conf->cms_manager = prev->cms_manager;
    }

    if (conf->http_handoff_addr == NULL && prev->http_handoff_addr != NULL) {
        conf->http_handoff_addr = prev->http_handoff_addr;
        conf->http_handoff_name = prev->http_handoff_name;
    }

    if (conf->relay_addr == NULL && prev->relay_addr != NULL) {
        conf->relay_addr = prev->relay_addr;
        conf->relay_name = prev->relay_name;
    }

    child_vo_rules = conf->vo_rules;
    conf->vo_rules = xrootd_merge_arrays(cf, prev->vo_rules, child_vo_rules,
                                         sizeof(xrootd_vo_rule_t));
    if (conf->vo_rules == NULL && (prev->vo_rules != NULL || child_vo_rules != NULL)) {
        return NGX_CONF_ERROR;
    }

    child_group_rules = conf->group_rules;
    conf->group_rules = xrootd_merge_arrays(cf, prev->group_rules,
                                            child_group_rules,
                                            sizeof(xrootd_group_rule_t));
    if (conf->group_rules == NULL
        && (prev->group_rules != NULL || child_group_rules != NULL)) {
        return NGX_CONF_ERROR;
    }

    /* Merge manager_map entries (prefix -> backend mappings) */
    {
        ngx_array_t *child_manager_map = conf->manager_map;
        conf->manager_map = xrootd_merge_arrays(cf, prev->manager_map,
                                               child_manager_map,
                                               sizeof(xrootd_manager_map_t));
        if (conf->manager_map == NULL
            && (prev->manager_map != NULL || child_manager_map != NULL)) {
            return NGX_CONF_ERROR;
        }
    }

    /* Inherit upstream redirector from parent scope if not set locally */
    if (conf->upstream_host.len == 0 && prev->upstream_host.len > 0) {
        conf->upstream_host = prev->upstream_host;
        conf->upstream_port = prev->upstream_port;
        conf->upstream_addr = prev->upstream_addr;
    }

    return NGX_CONF_OK;
}

/* Upstream/proxy & network: upstream TLS + token, transparent proxy mode
 * (auth/login/timeouts/rewrite), the write-through origin + prefix rules +
 * decision struct, OCSP, the Phase-39 network-fault deadlines, and rate-limit
 * rule inheritance. */
static char *
xrootd_merge_srv_proxy_net(ngx_conf_t *cf, ngx_stream_xrootd_srv_conf_t *conf,
    ngx_stream_xrootd_srv_conf_t *prev)
{
    ngx_array_t *child_wt_deny_prefixes;
    ngx_array_t *child_wt_allow_prefixes;

    ngx_conf_merge_value(conf->upstream_tls,          prev->upstream_tls,          0);
    ngx_conf_merge_str_value(conf->upstream_tls_ca,   prev->upstream_tls_ca,   "");
    ngx_conf_merge_str_value(conf->upstream_tls_name, prev->upstream_tls_name, "");
    ngx_conf_merge_str_value(conf->upstream_token_file,
                             prev->upstream_token_file, "");

    ngx_conf_merge_value(conf->relay_guard_enable, prev->relay_guard_enable, 0);
    ngx_conf_merge_value(conf->proxy_enable,       prev->proxy_enable,       0);
    ngx_conf_merge_value(conf->proxy_port,         prev->proxy_port,         1094);
    ngx_conf_merge_value(conf->proxy_upstream_tls, prev->proxy_upstream_tls, 0);
    ngx_conf_merge_uint_value(conf->proxy_auth,    prev->proxy_auth,
                              XROOTD_PROXY_AUTH_ANONYMOUS);
    ngx_conf_merge_uint_value(conf->proxy_login_user, prev->proxy_login_user,
                              XROOTD_PROXY_LOGIN_ANONYMOUS);
    if (conf->proxy_login_user_name[0] == '\0'
        && prev->proxy_login_user_name[0] != '\0')
    {
        ngx_cpystrn((u_char *) conf->proxy_login_user_name,
                    (u_char *) prev->proxy_login_user_name,
                    sizeof(conf->proxy_login_user_name));
    }
    ngx_conf_merge_str_value(conf->proxy_audit_log,          prev->proxy_audit_log,          "");
    ngx_conf_merge_str_value(conf->proxy_upstream_tls_ca,    prev->proxy_upstream_tls_ca,    "");
    ngx_conf_merge_str_value(conf->proxy_upstream_tls_name,  prev->proxy_upstream_tls_name,  "");
    ngx_conf_merge_uint_value(conf->proxy_reconnect_attempts, prev->proxy_reconnect_attempts, 0);
    ngx_conf_merge_str_value(conf->proxy_path_strip, prev->proxy_path_strip, "");
    ngx_conf_merge_str_value(conf->proxy_path_add,   prev->proxy_path_add,   "");
    ngx_conf_merge_msec_value(conf->proxy_connect_timeout,    prev->proxy_connect_timeout,    10000);
    ngx_conf_merge_msec_value(conf->proxy_read_timeout,       prev->proxy_read_timeout,       60000);
    /* Phase 51 (B1): default the upstream write-stall deadline ON (60s) so a
     * slow/backpressured upstream that stops draining our writes can no longer
     * pin the client connection indefinitely.  0 still disables (back-compat). */
    ngx_conf_merge_msec_value(conf->proxy_write_timeout,      prev->proxy_write_timeout,      60000);
    ngx_conf_merge_msec_value(conf->proxy_keepalive_interval, prev->proxy_keepalive_interval, 15000);

    XROOTD_MERGE_PTR(conf, prev, proxy_upstreams);
    ngx_conf_merge_str_value(conf->proxy_host, prev->proxy_host, "");
    XROOTD_MERGE_HOSTPORT(conf, prev, cache_origin_host, cache_origin_port);

    ngx_conf_merge_value(conf->wt_enable, prev->wt_enable, 0);
    XROOTD_MERGE_ENUM(conf, prev, wt_mode, XROOTD_WT_MODE_UNSET, XROOTD_WT_MODE_SYNC);
    XROOTD_MERGE_HOSTPORT(conf, prev, wt_origin_host, wt_origin_port);
    if (conf->wt_origin_host.len == 0 && conf->cache_origin_host.len > 0) {
        conf->wt_origin_host = conf->cache_origin_host;
        conf->wt_origin_port = conf->cache_origin_port;
    }

    child_wt_deny_prefixes = conf->wt_deny_prefixes;
    conf->wt_deny_prefixes = xrootd_merge_arrays(cf, prev->wt_deny_prefixes,
                                                  child_wt_deny_prefixes,
                                                  sizeof(xrootd_wt_prefix_entry_t));
    if (conf->wt_deny_prefixes == NULL
        && (prev->wt_deny_prefixes != NULL || child_wt_deny_prefixes != NULL))
    {
        return NGX_CONF_ERROR;
    }

    child_wt_allow_prefixes = conf->wt_allow_prefixes;
    conf->wt_allow_prefixes = xrootd_merge_arrays(cf, prev->wt_allow_prefixes,
                                                   child_wt_allow_prefixes,
                                                   sizeof(xrootd_wt_prefix_entry_t));
    if (conf->wt_allow_prefixes == NULL
        && (prev->wt_allow_prefixes != NULL || child_wt_allow_prefixes != NULL))
    {
        return NGX_CONF_ERROR;
    }

    conf->wt_decision.fn = xrootd_wt_default_decide;
    conf->wt_decision.user_data = &conf->wt_decision;
    conf->wt_decision.deny_prefixes = conf->wt_deny_prefixes;
    conf->wt_decision.allow_prefixes = conf->wt_allow_prefixes;
    conf->wt_decision.max_write_through_bytes = conf->cache_max_file_size;
    conf->wt_decision.include_regex = conf->cache_include_regex;
    conf->wt_decision.include_regex_set = conf->cache_include_regex_set;

    ngx_conf_merge_value(conf->ocsp_enable,    prev->ocsp_enable,    0);
    ngx_conf_merge_value(conf->ocsp_soft_fail, prev->ocsp_soft_fail, 1);
    ngx_conf_merge_value(conf->ocsp_stapling,  prev->ocsp_stapling,  0);

    /* ocsp_staple_data/len are populated at init_process, not here */

    /* Phase 39: network-fault resilience — default OFF (0) = no behaviour change.
     * 0 means "disabled"; arm sites all guard on `> 0` (ngx_msec_t is unsigned). */
    ngx_conf_merge_msec_value(conf->read_timeout,      prev->read_timeout,      0);
    ngx_conf_merge_msec_value(conf->handshake_timeout, prev->handshake_timeout, 0);
    ngx_conf_merge_msec_value(conf->send_timeout,      prev->send_timeout,      0);
    ngx_conf_merge_msec_value(conf->tcp_user_timeout,  prev->tcp_user_timeout,  0);
    ngx_conf_merge_value(conf->tcp_keepalive,          prev->tcp_keepalive,     0);
    ngx_conf_merge_str_value(conf->tcp_congestion,     prev->tcp_congestion,    "");
    ngx_conf_merge_uint_value(conf->max_connections,   prev->max_connections,   0);
    ngx_conf_merge_msec_value(conf->manager_stale_after,
                              prev->manager_stale_after, 0);
    /* Phase 39 (WS7): publish the data-server staleness threshold to the shared
     * cluster registry (config-time, before fork).  Guarded so a 0-default block
     * does not disable a sibling that enabled it. */
    if (conf->manager_stale_after > 0) {
        xrootd_srv_set_stale_after(conf->manager_stale_after);
    }

    /* Phase 39 (WS9): a child server block with no advanced rate-limit rules of
     * its own inherits the parent's (the Phase-20 kv caches above already do;
     * the Phase-25 rl_rules array was previously never inherited). */
    if (conf->rl_rules == NULL) {
        conf->rl_rules = prev->rl_rules;
    }

    return NGX_CONF_OK;
}

/*
 * Standard nginx parent→child scope inheritance. Delegates to one helper per
 * configuration area (defined above), invoked in the original linear order so
 * cross-area derivations still observe their already-merged inputs. Any helper
 * returning NGX_CONF_ERROR aborts the merge (the error is already logged).
 */
char *
ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_xrootd_srv_conf_t *prev = parent;
    ngx_stream_xrootd_srv_conf_t *conf = child;

    if (xrootd_merge_srv_security(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (xrootd_merge_srv_storage(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    xrootd_merge_srv_tpc(conf, prev);
    if (xrootd_merge_srv_cluster(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (xrootd_merge_srv_proxy_net(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
 * ngx_stream_xrootd_enable - handler for the "xrootd on|off;" directive.
 */
char *
ngx_stream_xrootd_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_stream_core_srv_conf_t   *cscf;
    char                         *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    /* Explicit `xrootd off;` leaves the server block as a normal stream server. */
    if (!xcf->common.enable) {
        return NGX_CONF_OK;
    }

    /*
     * The stream core owns the accept loop; enabling the directive swaps in
     * our session handler for this server block.
     */
    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_xrootd_handler;

    return NGX_CONF_OK;
}
