#ifndef XROOTD_STATX_H
#define XROOTD_STATX_H

#include "../ngx_xrootd_module.h"

ngx_int_t xrootd_handle_statx(xrootd_ctx_t *ctx, ngx_connection_t *c,
                              ngx_stream_xrootd_srv_conf_t *conf);

#endif // XROOTD_STATX_H
