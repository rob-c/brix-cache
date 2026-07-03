#ifndef BRIX_UPSTREAM_H
#define BRIX_UPSTREAM_H

#include "core/ngx_brix_module.h"

/*
 * Upstream redirector query subsystem.
 *
 * When brix_manager_mode is enabled and a kXR_locate or kXR_open finds a
 * server in the registry, the server does NOT redirect immediately.  Instead it
 * uses the upstream module to make a lightweight XRootD "locate" query to the
 * registered data server, confirming the file exists, then replies with the
 * data server address as a kXR_redirect response.
 *
 * State machine integration:
 *   brix_upstream_start() is called from the opcode handler.
 *   ctx->state = XRD_ST_UPSTREAM is set; the client-facing read event is disarmed.
 *   When the upstream response arrives, ctx->state is restored and the
 *   appropriate kXR_redirect or kXR_error response is sent to the client.
 *   brix_upstream_cleanup() is called from brix_on_disconnect() to release
 *   all upstream resources even if the upstream query is still in flight.
 */

/*
 * brix_upstream_start — initiate a TCP connection to the selected upstream
 * data server, post the locate query, and wait for the response.
 *
 * Returns NGX_OK (ctx->state = XRD_ST_UPSTREAM on success, error response
 * already queued on NGX_ERROR).
 */
ngx_int_t brix_upstream_start(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/*
 * brix_upstream_cleanup — cancel the upstream query and release all
 * resources (TCP connection, pool allocations) associated with *up.
 *
 * Safe to call from the disconnect handler even if the upstream connection has
 * already closed.  *up is invalid after this call.
 */
void brix_upstream_cleanup(brix_upstream_t *up);

#endif /* BRIX_UPSTREAM_H */

