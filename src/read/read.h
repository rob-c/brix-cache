#ifndef XROOTD_READ_H
#define XROOTD_READ_H

#include "../ngx_xrootd_module.h"


ngx_int_t xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_readv(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_pgread(xrootd_ctx_t *ctx, ngx_connection_t *c);
size_t xrootd_pgread_encode_pages(const u_char *src, size_t len, u_char *dst);

#endif // XROOTD_READ_H
