#include "config.h"
#include "../tpc/key_registry.h"

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
    conf->enable       = NGX_CONF_UNSET;
    conf->auth         = NGX_CONF_UNSET_UINT;
    conf->allow_write  = NGX_CONF_UNSET;
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
    conf->tls          = NGX_CONF_UNSET;
    conf->tls_ctx      = NULL;
    conf->cache        = NGX_CONF_UNSET;
    conf->cache_origin_tls = NGX_CONF_UNSET;
    conf->cache_lock_timeout = NGX_CONF_UNSET;
    conf->cache_eviction_threshold = NGX_CONF_UNSET_UINT;
    conf->cache_max_file_size      = NGX_CONF_UNSET;
    conf->cache_include_regex_set  = 0;
    conf->manager_mode = NGX_CONF_UNSET;
    conf->registry_slots = NGX_CONF_UNSET_UINT;
    conf->proxy_enable              = NGX_CONF_UNSET;
    conf->proxy_port                = NGX_CONF_UNSET;
    conf->proxy_upstream_tls        = NGX_CONF_UNSET;
#if (NGX_SSL)
    conf->proxy_tls_ctx             = NULL;
#endif
    conf->proxy_auth                = NGX_CONF_UNSET_UINT;
    conf->proxy_audit_log_fd        = NGX_INVALID_FILE;
    conf->proxy_reconnect_attempts  = NGX_CONF_UNSET_UINT;
    conf->proxy_upstreams           = NULL;
    conf->proxy_connect_timeout     = NGX_CONF_UNSET_MSEC;
    conf->proxy_read_timeout        = NGX_CONF_UNSET_MSEC;
    conf->cms_locate_timeout = NGX_CONF_UNSET_MSEC;
    conf->cms_addr     = NULL;
    conf->cms_interval = NGX_CONF_UNSET;
    conf->listen_port  = NGX_CONF_UNSET;
    conf->cms_ctx      = NULL;
    conf->sss_lifetime      = NGX_CONF_UNSET;
    conf->sss_keys          = NULL;
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

    return conf;
}

char *
ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_xrootd_srv_conf_t *prev = parent;
    ngx_stream_xrootd_srv_conf_t *conf = child;
    ngx_array_t                  *child_vo_rules;
    ngx_array_t                  *child_group_rules;

    /*
     * Standard nginx inheritance rules: values set on the current server
     * override the parent, otherwise we fall back to the parent or the hard
     * coded module default.
     */
    ngx_conf_merge_value(conf->enable,      prev->enable,      0);
    ngx_conf_merge_str_value(conf->root,    prev->root,        "/");
    ngx_conf_merge_uint_value(conf->auth,   prev->auth,        XROOTD_AUTH_NONE);
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_str_value(conf->certificate,     prev->certificate,     "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_str_value(conf->trusted_ca,      prev->trusted_ca,      "");
    ngx_conf_merge_str_value(conf->vomsdir,         prev->vomsdir,         "");
    ngx_conf_merge_str_value(conf->voms_cert_dir,   prev->voms_cert_dir,   "");
    ngx_conf_merge_str_value(conf->crl,             prev->crl,             "");
    ngx_conf_merge_value(conf->crl_reload,    prev->crl_reload,      0);
    ngx_conf_merge_str_value(conf->access_log,      prev->access_log,      "");
    ngx_conf_merge_str_value(conf->token_jwks,      prev->token_jwks,      "");
    ngx_conf_merge_str_value(conf->token_issuer,    prev->token_issuer,    "");
    ngx_conf_merge_str_value(conf->token_audience,  prev->token_audience,  "");
    ngx_conf_merge_str_value(conf->token_macaroon_secret,
                             prev->token_macaroon_secret,     "");
    ngx_conf_merge_str_value(conf->token_macaroon_secret_old,
                             prev->token_macaroon_secret_old, "");
    ngx_conf_merge_str_value(conf->sss_keytab,      prev->sss_keytab,      "");
    ngx_conf_merge_value(conf->sss_lifetime,        prev->sss_lifetime,    13);
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

    ngx_conf_merge_value(conf->manager_mode,         prev->manager_mode,    0);
    ngx_conf_merge_uint_value(conf->registry_slots,  prev->registry_slots,  128);
    ngx_conf_merge_msec_value(conf->cms_locate_timeout, prev->cms_locate_timeout,
                              5000);
    ngx_conf_merge_str_value(conf->cms_paths,       prev->cms_paths,       "");
    ngx_conf_merge_value(conf->cms_interval,        prev->cms_interval,    30);
    ngx_conf_merge_value(conf->listen_port,         prev->listen_port,     XROOTD_DEFAULT_PORT);

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
    }

    ngx_conf_merge_value(conf->proxy_enable,       prev->proxy_enable,       0);
    ngx_conf_merge_value(conf->proxy_port,         prev->proxy_port,         1094);
    ngx_conf_merge_value(conf->proxy_upstream_tls, prev->proxy_upstream_tls, 0);
    ngx_conf_merge_uint_value(conf->proxy_auth,    prev->proxy_auth,
                              XROOTD_PROXY_AUTH_ANONYMOUS);
    ngx_conf_merge_str_value(conf->proxy_audit_log,          prev->proxy_audit_log,          "");
    ngx_conf_merge_str_value(conf->proxy_upstream_tls_ca,    prev->proxy_upstream_tls_ca,    "");
    ngx_conf_merge_str_value(conf->proxy_upstream_tls_name,  prev->proxy_upstream_tls_name,  "");
    ngx_conf_merge_uint_value(conf->proxy_reconnect_attempts, prev->proxy_reconnect_attempts, 0);
    ngx_conf_merge_str_value(conf->proxy_path_strip, prev->proxy_path_strip, "");
    ngx_conf_merge_str_value(conf->proxy_path_add,   prev->proxy_path_add,   "");
    ngx_conf_merge_msec_value(conf->proxy_connect_timeout, prev->proxy_connect_timeout, 10000);
    ngx_conf_merge_msec_value(conf->proxy_read_timeout,    prev->proxy_read_timeout,    60000);

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
    if (!xcf->enable) {
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
