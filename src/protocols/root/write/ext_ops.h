#ifndef BRIX_WRITE_EXT_OPS_H
#define BRIX_WRITE_EXT_OPS_H

/*
 * ext_ops.h — handlers for the nginx-xrootd vendor extension opcodes
 * (kXR_setattr / kXR_symlink / kXR_readlink / kXR_link).  Declared together and
 * included by both the write dispatcher (setattr/symlink/link) and the read
 * dispatcher (readlink), since readlink is a non-mutating op.
 */
#include "core/ngx_brix_module.h"

/* kXR_setattr — set times (utimens) and/or owner (chown) on a path. */
ngx_int_t brix_handle_setattr(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);
/* kXR_symlink — create a symbolic link (target stored verbatim). */
ngx_int_t brix_handle_symlink(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);
/* kXR_link — create a hard link. */
ngx_int_t brix_handle_link(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);
/* kXR_readlink — read a symlink's target (read-side op). */
ngx_int_t brix_handle_readlink(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

#endif /* BRIX_WRITE_EXT_OPS_H */
