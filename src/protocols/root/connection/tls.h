#ifndef BRIX_CONN_TLS_H
#define BRIX_CONN_TLS_H
#include "core/ngx_brix_module.h"
#include "observability/metrics/metrics.h"
#include "event_sched.h"

/*
 * brix_start_tls — initiate the TLS handshake on an existing TCP connection
 * after the kXR_haveTLS response has been fully flushed.
 *
 * Called from ngx_stream_brix_send() when ctx->tls_pending is set and the
 * write buffer has drained.  Sets ctx->state = XRD_ST_TLS_HANDSHAKE and calls
 * ngx_ssl_handshake() which re-arms both read and write events.
 *
 * Precondition: conf->ssl_ctx must be non-NULL (brix_configure_tls succeeded).
 * On handshake failure, nginx tears down the connection automatically.
 */
void brix_start_tls(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/*
 * brix_tls_handshake_done — nginx callback invoked when SSL_accept() completes.
 *
 * On success: clears ctx->tls_pending, resets ctx->state = XRD_ST_REQ_HEADER,
 * re-arms the read event and enters the recv loop.
 * On failure (c->ssl->handshaked == 0): closes the session.
 */
void brix_tls_handshake_done(ngx_connection_t *c);

#endif /* BRIX_CONN_TLS_H */
