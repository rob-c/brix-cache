/* File: tpc_config.c — HTTP-TPC location defaults and inheritance
 * WHAT: Configures HTTP third-party copy (TPC) settings for WebDAV locations. This file contains two lifecycle functions: create_loc_conf initializes TPC fields to NGX_CONF_UNSET sentinel values marking them as unset; merge_loc_conf inherits parent config values using ngx_conf_merge_* macros and applies smart defaults for curl path (/usr/bin/curl), timeout (0 = no limit), OAuth2/OIDC token delegation credentials (empty endpoint, storage.read default scope). Also implements cross-field inheritance: if TPC-specific cert/key paths are unset but general WebDAV cafile/cadir exist, copies those values to ensure TPC has certificate access even when not explicitly configured.
 *
 * WHY: HTTP-TPC requires curl as the transfer tool and TLS credentials for source authentication — these defaults must be inherited from parent/server configuration so individual locations can override only what they need. OAuth2/OIDC token delegation enables TPC to acquire temporary credentials for accessing remote endpoints without requiring client-side certificate exchange. The smart inheritance logic (cafile/cadir fallback, cert→key copy) reduces configuration burden by providing reasonable defaults when operators don't explicitly set every field. Thread safety: config setup runs once during nginx startup; no concurrent access after initialization. */

#include "webdav.h"

void
ngx_http_brix_webdav_tpc_create_loc_conf(
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    conf->tpc              = NGX_CONF_UNSET;
    conf->tpc_timeout      = NGX_CONF_UNSET_UINT;
    conf->tpc_low_speed_bytes = NGX_CONF_UNSET_UINT;
    conf->tpc_low_speed_secs  = NGX_CONF_UNSET_UINT;
    conf->tpc_allow_local   = NGX_CONF_UNSET;
    conf->tpc_allow_private = NGX_CONF_UNSET;
    conf->tpc_marker_interval = NGX_CONF_UNSET_UINT;
    conf->tpc_max_streams     = NGX_CONF_UNSET_UINT;
}

void
ngx_http_brix_webdav_tpc_merge_loc_conf(
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_loc_conf_t *prev)
{
    ngx_conf_merge_value(conf->tpc, prev->tpc, 0);
    /* SSRF policy: deny local, allow private by default (HEP federation nodes
     * commonly reside on private networks, but loopback must stay blocked). */
    ngx_conf_merge_value(conf->tpc_allow_local,   prev->tpc_allow_local,   0);
    ngx_conf_merge_value(conf->tpc_allow_private, prev->tpc_allow_private, 1);
    ngx_conf_merge_str_value(conf->tpc_curl, prev->tpc_curl,
                             "/usr/bin/curl");
    ngx_conf_merge_str_value(conf->tpc_cert, prev->tpc_cert, "");
    ngx_conf_merge_str_value(conf->tpc_key, prev->tpc_key, "");
    ngx_conf_merge_str_value(conf->tpc_cadir, prev->tpc_cadir, "");
    ngx_conf_merge_str_value(conf->tpc_cafile, prev->tpc_cafile, "");
    /* Phase 51 (B2): default the curl low-speed stall detector ON (abort a pull/
     * push that averages < 1KB/s for 60s) so a stalled remote cannot hold a
     * thread-pool worker indefinitely.  This measures lack of PROGRESS, not
     * duration, so a slow-but-advancing transfer is never clipped.  The absolute
     * total timeout stays opt-in (0 = unlimited) — operators who need a hard cap
     * set brix_webdav_tpc_timeout.  0 on either low-speed knob disables it. */
    ngx_conf_merge_uint_value(conf->tpc_timeout, prev->tpc_timeout, 0);
    ngx_conf_merge_uint_value(conf->tpc_low_speed_bytes,
                              prev->tpc_low_speed_bytes, 1024);
    ngx_conf_merge_uint_value(conf->tpc_low_speed_secs,
                              prev->tpc_low_speed_secs, 60);
    ngx_conf_merge_uint_value(conf->tpc_marker_interval,
                              prev->tpc_marker_interval, 0);
    ngx_conf_merge_uint_value(conf->tpc_max_streams, prev->tpc_max_streams, 1);

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
