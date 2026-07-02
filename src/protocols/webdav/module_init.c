/*
 * module_init.c - extracted concern
 * Phase-38 split of module.c; behavior-identical.
 */
#include "webdav_module_internal.h"


/*
 * Directive table for the WebDAV HTTP module.  Mechanical: each entry binds a
 * config keyword to a setter and (usually) a field offset in the location conf.
 * Most use stock nginx setters (set_flag/str/num/sec/msec_slot); the handful of
 * custom handlers above (CORS origin list, proxy auth/upstream, open_file_cache)
 * and the cross-module setters (mirror, rate-limit, KV, token-cache) appear
 * where they are grouped by feature.  Defaults/merge live in config.c.
 */


/* Preconfiguration: register the $xrootd_protocol variable. */
/*
 * Resolve $xrootd_protocol for the current request: "webdav", "s3", or "http".
 * Precedence is webdav > s3 > plain http, decided by which sibling module is
 * enabled in this request's location conf (WebDAV wins if both somehow apply).
 * Used in log_format / proxy decisions to label the served protocol.
 */
ngx_int_t
xrootd_http_protocol_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xrootd_webdav_loc_conf_t *wdcf;
    ngx_http_s3_loc_conf_t            *scf;
    const char                        *label;
    size_t                             len;

    (void) data;

    label = "http";
    len = sizeof("http") - 1;

    wdcf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (wdcf != NULL && wdcf->common.enable) {
        label = "webdav";
        len = sizeof("webdav") - 1;
    } else {
        scf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
        if (scf != NULL && scf->common.enable) {
            label = "s3";
            len = sizeof("s3") - 1;
        }
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) label;

    return NGX_OK;
}


ngx_int_t
xrootd_http_add_protocol_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var;
    ngx_str_t            name = ngx_string("xrootd_protocol");

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = xrootd_http_protocol_variable;
    var->data = 0;

    return NGX_OK;
}


ngx_int_t
ngx_http_xrootd_webdav_preconfiguration(ngx_conf_t *cf)
{
    return xrootd_http_add_protocol_variables(cf);
}


ngx_int_t
ngx_http_xrootd_webdav_init_process(ngx_cycle_t *cycle)
{
    (void) cycle;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    return NGX_OK;
}


void
ngx_http_xrootd_webdav_exit_process(ngx_cycle_t *cycle)
{
    (void) cycle;
    curl_global_cleanup();
}
