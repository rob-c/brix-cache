/*
 * module_directives_cert_stub.c - macOS stub for cert directives
 * 
 * This stub allows compilation on macOS where nginx SSL module internals
 * may differ. Full implementation requires nginx SSL module access.
 */

/* Stub - no header needed */
#include <ngx_core.h>
#include <ngx_http.h>

char *
brix_webdav_cert_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    (void)cf; (void)cmd; (void)conf;
    /* Stub - cert handling requires nginx SSL module */
    return NGX_CONF_OK;
}

char *
brix_webdav_cert_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    (void)cf; (void)cmd; (void)conf;
    return NGX_CONF_OK;
}

char *
brix_webdav_cert_ca(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    (void)cf; (void)cmd; (void)conf;
    return NGX_CONF_OK;
}
