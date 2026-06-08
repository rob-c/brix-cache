#ifndef XROOTD_HTTP_PROTOCOL_VARS_H
#define XROOTD_HTTP_PROTOCOL_VARS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t xrootd_http_add_protocol_variables(ngx_conf_t *cf);

#endif /* XROOTD_HTTP_PROTOCOL_VARS_H */
