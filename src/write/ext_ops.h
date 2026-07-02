#ifndef XROOTD_WRITE_EXT_OPS_H
#define XROOTD_WRITE_EXT_OPS_H

/*
 * ext_ops.h — handlers for the nginx-xrootd vendor extension opcodes
 * (kXR_setattr / kXR_symlink / kXR_readlink / kXR_link).  Declared together and
 * included by both the write dispatcher (setattr/symlink/link) and the read
 * dispatcher (readlink), since readlink is a non-mutating op.
 */
#include "core/ngx_xrootd_module.h"

/* kXR_setattr — set times (utimens) and/or owner (chown) on a path. */
ngx_int_t xrootd_handle_setattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
/* kXR_symlink — create a symbolic link (target stored verbatim). */
ngx_int_t xrootd_handle_symlink(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
/* kXR_link — create a hard link. */
ngx_int_t xrootd_handle_link(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
/* kXR_readlink — read a symlink's target (read-side op). */
ngx_int_t xrootd_handle_readlink(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif /* XROOTD_WRITE_EXT_OPS_H */
