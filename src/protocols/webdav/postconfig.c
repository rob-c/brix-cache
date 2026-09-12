/*
 * postconfig_stub.c - macOS stub for postconfig
 * 
 * This stub allows compilation on macOS where nginx SSL module internals
 * may differ. Full implementation requires nginx SSL module access.
 */

#include <ngx_core.h>
#include <ngx_http.h>
#include "webdav.h"

ngx_int_t
brix_webdav_postconfig_init(ngx_conf_t *cf)
{
    (void)cf;
    /* Stub - SSL config requires nginx SSL module */
    return NGX_OK;
}

/* Stub postconfiguration function */
ngx_int_t
ngx_http_brix_webdav_postconfiguration(ngx_conf_t *cf)
{
    (void)cf;
    /* Stub - full implementation in postconfig_full.c requires nginx SSL module */
    return NGX_OK;
}

/* Stub directive handlers for SSL config - macOS lacks nginx SSL module access */
char *
webdav_conf_client_cert_folder(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    (void)cf; (void)cmd; (void)conf;
    /* Stub - SSL config requires nginx SSL module */
    return NGX_CONF_OK;
}

char *
webdav_conf_proxy_ssl_capath(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    (void)cf; (void)cmd; (void)conf;
    /* Stub - SSL config requires nginx SSL module */
    return NGX_CONF_OK;
}

