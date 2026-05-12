#ifndef XROOTD_READ_LOCATE_H
#define XROOTD_READ_LOCATE_H

#include "../ngx_xrootd_module.h"

ngx_int_t xrootd_handle_locate(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif

