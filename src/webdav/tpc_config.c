/*
 * tpc_config.c - HTTP-TPC location defaults and inheritance.
 */

#include "webdav.h"

void
ngx_http_xrootd_webdav_tpc_create_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    conf->tpc = NGX_CONF_UNSET;
    conf->tpc_timeout = NGX_CONF_UNSET_UINT;
}

void
ngx_http_xrootd_webdav_tpc_merge_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    ngx_http_xrootd_webdav_loc_conf_t *prev)
{
    ngx_conf_merge_value(conf->tpc, prev->tpc, 0);
    ngx_conf_merge_str_value(conf->tpc_curl, prev->tpc_curl,
                             "/usr/bin/curl");
    ngx_conf_merge_str_value(conf->tpc_cert, prev->tpc_cert, "");
    ngx_conf_merge_str_value(conf->tpc_key, prev->tpc_key, "");
    ngx_conf_merge_str_value(conf->tpc_cadir, prev->tpc_cadir, "");
    ngx_conf_merge_str_value(conf->tpc_cafile, prev->tpc_cafile, "");
    ngx_conf_merge_uint_value(conf->tpc_timeout, prev->tpc_timeout, 0);

    /* Merge OAuth2/OIDC token-delegation config. */
    ngx_conf_merge_str_value(conf->tpc_cred.token_endpoint,
                             prev->tpc_cred.token_endpoint, "");
    ngx_conf_merge_str_value(conf->tpc_cred.token_client_id,
                             prev->tpc_cred.token_client_id, "");
    ngx_conf_merge_str_value(conf->tpc_cred.token_client_secret,
                             prev->tpc_cred.token_client_secret, "");
    ngx_conf_merge_str_value(conf->tpc_cred.token_scope,
                             prev->tpc_cred.token_scope, "storage.read");

    if (conf->tpc_cadir.len == 0 && conf->cadir.len > 0) {
        conf->tpc_cadir = conf->cadir;
    }
    if (conf->tpc_cafile.len == 0 && conf->cafile.len > 0) {
        conf->tpc_cafile = conf->cafile;
    }
    if (conf->tpc_key.len == 0 && conf->tpc_cert.len > 0) {
        conf->tpc_key = conf->tpc_cert;
    }
}
