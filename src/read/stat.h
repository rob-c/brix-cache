#ifndef XROOTD_READ_STAT_H
#define XROOTD_READ_STAT_H

#include "../ngx_xrootd_module.h"

ngx_int_t xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);

#endif // XROOTD_READ_STAT_H
