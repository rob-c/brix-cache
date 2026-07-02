#ifndef XROOTD_UPSTREAM_H
#define XROOTD_UPSTREAM_H

#include "ngx_xrootd_module.h"

/*
 * Upstream redirector query subsystem.
 *
 * When xrootd_manager_mode is enabled and a kXR_locate or kXR_open finds a
 * server in the registry, the server does NOT redirect immediately.  Instead it
 * uses the upstream module to make a lightweight XRootD "locate" query to the
 * registered data server, confirming the file exists, then replies with the
 * data server address as a kXR_redirect response.
 *
 * State machine integration:
 *   xrootd_upstream_start() is called from the opcode handler.
 *   ctx->state = XRD_ST_UPSTREAM is set; the client-facing read event is disarmed.
 *   When the upstream response arrives, ctx->state is restored and the
 *   appropriate kXR_redirect or kXR_error response is sent to the client.
 *   xrootd_upstream_cleanup() is called from xrootd_on_disconnect() to release
 *   all upstream resources even if the upstream query is still in flight.
 */

/*
 * xrootd_upstream_start — initiate a TCP connection to the selected upstream
 * data server, post the locate query, and wait for the response.
 *
 * Returns NGX_OK (ctx->state = XRD_ST_UPSTREAM on success, error response
 * already queued on NGX_ERROR).
 */
ngx_int_t xrootd_upstream_start(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_upstream_cleanup — cancel the upstream query and release all
 * resources (TCP connection, pool allocations) associated with *up.
 *
 * Safe to call from the disconnect handler even if the upstream connection has
 * already closed.  *up is invalid after this call.
 */
void xrootd_upstream_cleanup(xrootd_upstream_t *up);

#endif /* XROOTD_UPSTREAM_H */

