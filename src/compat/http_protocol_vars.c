/*
 * http_protocol_vars.c — shared nginx HTTP variables for protocol-tagged logs.
 */

#include "http_protocol_vars.h"
#include "../webdav/webdav.h"
#include "../s3/s3.h"

static ngx_int_t
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
    ngx_str_t           name = ngx_string("xrootd_protocol");

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = xrootd_http_protocol_variable;
    var->data = 0;

    return NGX_OK;
}
