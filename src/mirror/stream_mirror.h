/*
 * stream_mirror.h — Phase 24 XRootD stream traffic mirror.
 *
 * Off by default.  When `xrootd_stream_mirror_url host:port` is configured on a
 * server block, a qualifying READ request (kXR_stat/locate/open/dirlist/statx,
 * per xrootd_mirror_opcodes) is replayed fire-and-forget to one or more shadow
 * XRootD servers AFTER the primary handler has already answered the client.
 * The shadow connection runs the same bootstrap as the health-check probe
 * (handshake -> protocol -> login), then sends the saved request frame, reads
 * the response status, discards the body, and compares the status against the
 * primary to detect divergence.  The client is never delayed and never sees the
 * shadow response.
 *
 * Memory: the mirror context is allocated from ngx_cycle->pool (not the client
 * connection pool) because the client connection may close before the shadow
 * exchange completes — see Phase 24 Step D.
 */
#ifndef XROOTD_MIRROR_STREAM_MIRROR_H
#define XROOTD_MIRROR_STREAM_MIRROR_H

#include "../ngx_xrootd_module.h"

/*
 * Fire a mirror replay for the just-dispatched read request, if mirroring is
 * enabled and this opcode/sample passes the filter.  No-op (zero hot-path cost
 * beyond one flag test) when conf->mirror.enabled == 0.  primary_rc is the
 * return code from the primary read-opcode dispatch, used for the best-effort
 * divergence comparison.
 */
void xrootd_stream_mirror_maybe(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, ngx_int_t primary_rc);

/* Directive setters (registered in src/stream/module.c). */
char *xrootd_stream_mirror_set_url(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_stream_mirror_set_opcodes(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *xrootd_stream_mirror_set_exclude_opcodes(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

#endif /* XROOTD_MIRROR_STREAM_MIRROR_H */
