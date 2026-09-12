/*
 * postconfig_proxy_capath_stub.c - macOS stub
 */

#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t
brix_webdav_proxy_capath_init(ngx_conf_t *cf)
{
    (void)cf;
    /* Stub - SSL config requires nginx SSL module */
    return NGX_OK;
}
