#ifndef XROOTD_READ_OPEN_H
#define XROOTD_READ_OPEN_H

#include "../ngx_xrootd_module.h"

ngx_int_t xrootd_handle_open(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_open_resolved_file(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf, const char *resolved, uint16_t options, uint16_t mode_bits, ngx_flag_t is_write);
ngx_int_t xrootd_open_cached_read(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf, const char *clean_path, uint16_t options, uint16_t mode_bits);

#endif // XROOTD_READ_OPEN_H
