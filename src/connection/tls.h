#ifndef XROOTD_CONN_TLS_H
#define XROOTD_CONN_TLS_H
#include "core/ngx_xrootd_module.h"
#include "observability/metrics/metrics.h"
#include "event_sched.h"

/*
 * xrootd_start_tls — initiate the TLS handshake on an existing TCP connection
 * after the kXR_haveTLS response has been fully flushed.
 *
 * Called from ngx_stream_xrootd_send() when ctx->tls_pending is set and the
 * write buffer has drained.  Sets ctx->state = XRD_ST_TLS_HANDSHAKE and calls
 * ngx_ssl_handshake() which re-arms both read and write events.
 *
 * Precondition: conf->ssl_ctx must be non-NULL (xrootd_configure_tls succeeded).
 * On handshake failure, nginx tears down the connection automatically.
 */
void xrootd_start_tls(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_tls_handshake_done — nginx callback invoked when SSL_accept() completes.
 *
 * On success: clears ctx->tls_pending, resets ctx->state = XRD_ST_REQ_HEADER,
 * re-arms the read event and enters the recv loop.
 * On failure (c->ssl->handshaked == 0): closes the session.
 */
void xrootd_tls_handshake_done(ngx_connection_t *c);

#endif /* XROOTD_CONN_TLS_H */
