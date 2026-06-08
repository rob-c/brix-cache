/* ------------------------------------------------------------------ */
/* Server Configuration — Allocation + Inheritance                     */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements server-level configuration lifecycle management during nginx parsing phase. It provides three functions: ngx_stream_xrootd_create_srv_conf() allocates and initializes a fresh srv_conf_t with all fields set to NGX_CONF_UNSET sentinels or NULL allowing the merge step to distinguish missing directives from explicitly configured values; ngx_stream_xrootd_merge_srv_conf() implements standard nginx parent→child scope inheritance using ngx_conf_merge_* macros for scalar fields and xrootd_merge_arrays() for array-based rule sets (VO rules, group rules, manager map entries); ngx_stream_xrootd_enable() handles the "xrootd on|off;" directive switching the server block handler from stream core default to xrootd session handler.
 *
 * WHY: Configuration lifecycle is critical for nginx modular deployment — each server block may have different auth mode (GSI/token/SSS), cache settings, or proxy configuration. The UNSET sentinel pattern ensures merge logic correctly handles cases where a child directive omits a value vs explicitly sets it to zero/null. Array merging enables hierarchical VO ACL rules and group inheritance policies to accumulate across nested server blocks without losing parent-level defaults. */

/* ------------------------------------------------------------------ */
/* Section: Configuration Allocation                                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: ngx_stream_xrootd_create_srv_conf() allocates a fresh srv_conf_t using ngx_pcalloc (zero-initialized pool allocation) and sets every field to either NGX_CONF_UNSET sentinel value or NULL depending on the field type. Scalar fields participate in merge logic use UNSET sentinels; runtime-only objects start out NULL/invalid and are created later during postconfiguration once parsing has finished. This ensures the merge step can distinguish between omitted directives (UNSET) and explicitly configured values.
 *
 * WHY: nginx allocates one config object per server block during parsing then merges parent/child scopes using ngx_conf_merge_* macros that only act on UNSET values. Without proper sentinel initialization, a child block omitting a directive would incorrectly inherit from parent or use default — the UNSET pattern ensures explicit inheritance semantics match user intent. Runtime objects (tls_ctx, cms_ctx) are NULL because they require SSL/crypto context creation during postconfig phase after parsing completes. */

/* ---- Function: ngx_stream_xrootd_create_srv_conf() ----
 *
 * WHAT: Allocates a fresh server-level configuration object using ngx_pcalloc (zero-initialized pool allocation), initializing every field to NGX_CONF_UNSET sentinel or NULL state allowing the merge step later to distinguish between missing directives and explicitly configured values. Scalar fields use UNSET sentinels for merge participation; runtime-only objects start out NULL/invalid created during postconfiguration once parsing has finished.
 *
 * WHY: nginx allocates one config object per server block during parsing then merges parent/child scopes using ngx_conf_merge_* macros that only act on UNSET values. Without proper sentinel initialization, a child block omitting a directive would incorrectly inherit from parent or use default — the UNSET pattern ensures explicit inheritance semantics match user intent. Runtime objects (tls_ctx, cms_ctx) are NULL because they require SSL/crypto context creation during postconfig phase after parsing completes.
 *
 * HOW: ngx_pcalloc allocation of sizeof(ngx_stream_xrootd_srv_conf_t) — zero-initialization via pcalloc — set every scalar field to NGX_CONF_UNSET/NGX_CONF_UNSET_UINT/NGX_CONF_UNSET_MSEC sentinel depending on type — set runtime objects (tls_ctx, cms_ctx, proxy_tls_ctx) to NULL — return conf pointer; NULL on allocation failure. */

/* ---- Function: ngx_stream_xrootd_merge_srv_conf() ----
 *
 * WHAT: Implements standard nginx parent→child scope inheritance for server-level configuration using ngx_conf_merge_* macros for scalar fields and xrootd_merge_arrays() for array-based rule sets (VO rules, group rules, manager map entries). Child values override parent; parent values used as fallback when child is UNSET/empty. Returns NGX_CONF_OK on success; NGX_CONF_ERROR on merge failure.
 *
 * WHY: nginx hierarchical configuration allows nested server blocks to inherit from parents while overriding specific directives — this merge function implements that inheritance chain ensuring child scope gets explicit values with sensible defaults from parent or module-level constants for completely omitted fields. Array merging enables VO ACL rules, group inheritance policies, and manager map entries to accumulate across nested server blocks without losing parent-level defaults.
 *
 * HOW: Three-phase merge → scalar field inheritance using ngx_conf_merge_* macros (value/str_value/uint_value/msec_value/off_value) with child override and parent fallback — array rule set merging using xrootd_merge_arrays() for vo_rules, group_rules, manager_map entries — runtime object inheritance (cms_addr, cms_manager, upstream_host/port, proxy_upstreams) — return NGX_CONF_OK; NGX_CONF_ERROR on any merge failure. */

/* ---- Function: ngx_stream_xrootd_enable() ----
 *
 * WHAT: Handles the "xrootd on|off;" directive — delegates flag parsing to ngx_conf_set_flag_slot then sets server block handler to ngx_stream_xrootd_handler when xrootd is enabled (on). When disabled (off) leaves server block as normal stream server without swapping in our session handler. Returns NGX_CONF_OK on success; NGX_CONF_ERROR on flag parsing failure.
 *
 * WHY: Enables selective XRootD protocol handling per server block — operators can mix nginx stream server functionality with xrootd proxy mode in the same configuration by enabling only specific server blocks. The handler swap is the critical mechanism that determines whether incoming TCP connections are processed as raw stream data or routed through XRootD session lifecycle (handshake → login → auth → read/write).
 *
 * HOW: Two-phase processing → delegate flag parsing to ngx_conf_set_flag_slot returning NGX_CONF_OK/NGX_CONF_ERROR — if enabled (on) retrieve stream core module srv_conf via ngx_stream_conf_get_module_srv_conf and swap handler to ngx_stream_xrootd_handler — return NGX_CONF_OK. */

#include "config.h"
#include "../tpc/key_registry.h"

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
    conf->prepare_command.len  = 0;
    conf->prepare_command.data = NULL;
    conf->crl_reload   = NGX_CONF_UNSET;
    conf->gsi_cert     = NULL;
    conf->gsi_key      = NULL;
    conf->gsi_store    = NULL;
    conf->gsi_cert_pem = NULL;
    conf->gsi_cert_pem_len = 0;
    conf->gsi_ca_hash  = 0;
    conf->vo_rules     = NULL;
    conf->group_rules  = NULL;
    conf->access_log_fd = NGX_INVALID_FILE;
    conf->metrics_slot = -1;
    conf->security_level = NGX_CONF_UNSET_UINT;
    conf->tls          = NGX_CONF_UNSET;
    conf->tls_ctx      = NULL;
    conf->cache        = NGX_CONF_UNSET;
    conf->cache_origin_tls = NGX_CONF_UNSET;
    conf->cache_lock_timeout = NGX_CONF_UNSET;
    conf->cache_eviction_threshold = NGX_CONF_UNSET_UINT;
    conf->cache_max_file_size      = NGX_CONF_UNSET;
    conf->cache_include_regex_set  = 0;
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
    conf->registry_slots = NGX_CONF_UNSET_UINT;
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
    conf->proxy_keepalive_interval  = NGX_CONF_UNSET_MSEC;
    conf->cms_locate_timeout = NGX_CONF_UNSET_MSEC;
    conf->cms_addr     = NULL;
    conf->upstream_addr = NULL;
    conf->cms_interval = NGX_CONF_UNSET;
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
    conf->tpc_allow_local   = NGX_CONF_UNSET;
    conf->tpc_allow_private = NGX_CONF_UNSET;
    conf->tpc_key_ttl_ms    = NGX_CONF_UNSET_MSEC;
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

    return conf;
}

char *
ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_xrootd_srv_conf_t *prev = parent;
    ngx_stream_xrootd_srv_conf_t *conf = child;
    ngx_array_t                  *child_vo_rules;
    ngx_array_t                  *child_group_rules;
    ngx_array_t                  *child_wt_deny_prefixes;
    ngx_array_t                  *child_wt_allow_prefixes;

    /*
     * Standard nginx inheritance rules: values set on the current server
     * override the parent, otherwise we fall back to the parent or the hard
     * coded module default.
     */
    ngx_conf_merge_value(conf->common.enable,      prev->common.enable,      0);
    ngx_conf_merge_str_value(conf->common.root,    prev->common.root,        "/");
    ngx_conf_merge_uint_value(conf->auth,   prev->auth,        XROOTD_AUTH_NONE);
    ngx_conf_merge_value(conf->common.allow_write, prev->common.allow_write, 0);
    ngx_conf_merge_str_value(conf->prepare_command, prev->prepare_command, "");
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
    ngx_conf_merge_str_value(conf->token_macaroon_secret,
                             prev->token_macaroon_secret,     "");
    ngx_conf_merge_str_value(conf->token_macaroon_secret_old,
                             prev->token_macaroon_secret_old, "");
    ngx_conf_merge_str_value(conf->sss_keytab,      prev->sss_keytab,      "");
    ngx_conf_merge_value(conf->sss_lifetime,        prev->sss_lifetime,    13);
    ngx_conf_merge_str_value(conf->krb5_principal,  prev->krb5_principal,  "");
    ngx_conf_merge_str_value(conf->krb5_keytab,     prev->krb5_keytab,     "");
    ngx_conf_merge_value(conf->krb5_ip_check,       prev->krb5_ip_check,   0);
    ngx_conf_merge_value(conf->unix_trust_remote,   prev->unix_trust_remote, 0);
    ngx_conf_merge_uint_value(conf->security_level, prev->security_level, 0);
    ngx_conf_merge_value(conf->tls,             prev->tls,             0);
    ngx_conf_merge_value(conf->cache,           prev->cache,           0);
    ngx_conf_merge_str_value(conf->cache_root,  prev->cache_root,      "");
    ngx_conf_merge_str_value(conf->cache_origin, prev->cache_origin,   "");
    ngx_conf_merge_value(conf->cache_origin_tls, prev->cache_origin_tls, 0);
    ngx_conf_merge_value(conf->cache_lock_timeout,
                         prev->cache_lock_timeout, 300);
    ngx_conf_merge_uint_value(conf->cache_eviction_threshold,
                              prev->cache_eviction_threshold, 900000);
    ngx_conf_merge_off_value(conf->cache_max_file_size,
                             prev->cache_max_file_size, 0);

    /* Inherit compiled regex from parent if the child didn't set one */
    if (!conf->cache_include_regex_set && prev->cache_include_regex_set) {
        conf->cache_include_regex_str = prev->cache_include_regex_str;
        conf->cache_include_regex     = prev->cache_include_regex;
        conf->cache_include_regex_set = 1;
    }

    ngx_conf_merge_value(conf->tpc_allow_local,   prev->tpc_allow_local,   0);
    ngx_conf_merge_value(conf->tpc_allow_private, prev->tpc_allow_private, 1);
    ngx_conf_merge_msec_value(conf->tpc_key_ttl_ms, prev->tpc_key_ttl_ms,
                              XROOTD_TPC_KEY_TTL_MS);
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

    ngx_conf_merge_value(conf->manager_mode,         prev->manager_mode,         0);
    ngx_conf_merge_value(conf->metadata_only,        prev->metadata_only,        0);
    ngx_conf_merge_value(conf->supervisor,           prev->supervisor,           0);
    ngx_conf_merge_value(conf->virtual_redirector,   prev->virtual_redirector,   0);
    ngx_conf_merge_value(conf->collapse_redir,       prev->collapse_redir,       0);
    ngx_conf_merge_msec_value(conf->collapse_redir_ttl, prev->collapse_redir_ttl, 30000);
    ngx_conf_merge_value(conf->recover_writes,       prev->recover_writes,       0);
    ngx_conf_merge_uint_value(conf->registry_slots,  prev->registry_slots,  128);
    ngx_conf_merge_msec_value(conf->cms_locate_timeout, prev->cms_locate_timeout,
                              5000);
    ngx_conf_merge_str_value(conf->cms_paths,       prev->cms_paths,       "");
    ngx_conf_merge_value(conf->cms_interval,        prev->cms_interval,    30);
    ngx_conf_merge_value(conf->listen_port,         prev->listen_port,     XROOTD_DEFAULT_PORT);
    ngx_conf_merge_uint_value(conf->ckscan_max_depth,
                              prev->ckscan_max_depth, 32);
    ngx_conf_merge_uint_value(conf->ckscan_max_files,
                              prev->ckscan_max_files, 100000);

    if (conf->cms_addr == NULL && prev->cms_addr != NULL) {
        conf->cms_addr = prev->cms_addr;
        conf->cms_manager = prev->cms_manager;
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

    ngx_conf_merge_value(conf->upstream_tls,          prev->upstream_tls,          0);
    ngx_conf_merge_str_value(conf->upstream_tls_ca,   prev->upstream_tls_ca,   "");
    ngx_conf_merge_str_value(conf->upstream_tls_name, prev->upstream_tls_name, "");
    ngx_conf_merge_str_value(conf->upstream_token_file,
                             prev->upstream_token_file, "");

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
    ngx_conf_merge_msec_value(conf->proxy_keepalive_interval, prev->proxy_keepalive_interval, 15000);

    if (conf->proxy_upstreams == NULL && prev->proxy_upstreams != NULL) {
        conf->proxy_upstreams = prev->proxy_upstreams;
    }

    if (conf->proxy_host.len == 0 && prev->proxy_host.len > 0) {
        conf->proxy_host = prev->proxy_host;
    }

    if (conf->cache_origin_host.len == 0 && prev->cache_origin_host.len > 0) {
        conf->cache_origin_host = prev->cache_origin_host;
        conf->cache_origin_port = prev->cache_origin_port;
    }

    ngx_conf_merge_value(conf->wt_enable, prev->wt_enable, 0);
    if (conf->wt_mode == XROOTD_WT_MODE_UNSET) {
        conf->wt_mode = (prev->wt_mode == XROOTD_WT_MODE_UNSET)
                        ? XROOTD_WT_MODE_SYNC
                        : prev->wt_mode;
    }

    if (conf->wt_origin_host.len == 0 && prev->wt_origin_host.len > 0) {
        conf->wt_origin_host = prev->wt_origin_host;
        conf->wt_origin_port = prev->wt_origin_port;
    }
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
