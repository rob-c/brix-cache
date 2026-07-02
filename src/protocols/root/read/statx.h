#ifndef XROOTD_STATX_H
#define XROOTD_STATX_H

#include "core/ngx_xrootd_module.h"

/*
 * xrootd_handle_statx — batched metadata query for multiple paths.
 *
 * Implements kXR_statx opcode. Accepts up to 256 null-terminated
 * paths in a single request, resolves each, stat(2)s it, and returns
 * inline inode/size/flags/mtime lines — reducing round-trips vs
 * individual kXR_stat calls.
 */
ngx_int_t xrootd_handle_statx(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif /* XROOTD_STATX_H */
