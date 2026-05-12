#ifndef XROOTD_QUERY_INTERNAL_H
#define XROOTD_QUERY_INTERNAL_H

#include "../ngx_xrootd_module.h"

uint32_t xrootd_query_adler32_fd(int fd, const char *path, ngx_log_t *log);
uint32_t xrootd_query_adler32_file(const ngx_str_t *root,
    const char *path, ngx_log_t *log);
ngx_flag_t xrootd_query_digest_fd(int fd, const char *path, const EVP_MD *md,
    unsigned char *out, unsigned int *outlen, ngx_log_t *log);
ngx_flag_t xrootd_query_digest_file(const ngx_str_t *root,
    const char *path, const EVP_MD *md,
    unsigned char *out, unsigned int *outlen, ngx_log_t *log);

ngx_int_t xrootd_query_cksum(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, ClientQueryRequest *req);
ngx_int_t xrootd_query_ckscan(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_space(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_fsinfo(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_config(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_stats(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_query_xattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_finfo(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_query_visa(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ClientQueryRequest *req);
ngx_int_t xrootd_query_opaque(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_query_opaquf(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_query_opaqug(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ClientQueryRequest *req);
ngx_int_t xrootd_query_prep_status(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif /* XROOTD_QUERY_INTERNAL_H */
