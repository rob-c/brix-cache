/*
 * WHAT: This file implements in-protocol TLS upgrade for roots:// clients using the kXR_ableTLS/kXR_haveTLS handshake mechanism. Called by recv.c when ctx->tls_pending is set (after server sends kXR_haveTLS flag indicating TLS support) — drives the TLS upgrade lifecycle including SSL connection creation, handshake initiation, and callback completion handling. On success: transitions to encrypted transport; on failure: disconnects immediately with error log.
 *
 * WHY: In-protocol TLS upgrade enables secure transport for roots:// clients without requiring pre-established TLS at TCP level — server advertises kXR_haveTLS capability during login, then the client negotiates encryption over the existing socket. Security invariant: TLS creation must succeed before any further protocol communication (no cleartext fallback after kXR_haveTLS).
 *
 * HOW: Two functions drive the lifecycle — xrootd_start_tls() creates SSL from TCP socket via ngx_ssl_create_connection with NGX_SSL_BUFFER flag, sets c->ssl->handler to xrootd_tls_handshake_done(), then calls ngx_ssl_handshake(). If rc==NGX_AGIN returns (async pending), if rc==NGX_OK invokes xrootd_tls_handshake_done() immediately, else logs error and disconnects. xrootd_tls_handshake_done() checks c->ssl->handshaked flag — false: log cipher info, call xrootd_on_disconnect(), xrootd_close_all_files(), finalize with NGX_STREAM_INTERNAL_SERVER_ERROR; true: log cipher name via SSL_get_cipher(), reset ctx->tls_pending=0, set state=XRD_ST_REQ_HEADER, reset hdr_pos=0, restore c->read/write handlers to ngx_stream_xrootd_recv/ngx_stream_xrootd_send, call ngx_stream_xrootd_recv() to resume. Thread safety: single-owner per connection on nginx event thread — no locking required.
 */

/*
 * WHAT: xrootd_tls_handshake_done() is called by nginx's SSL layer when the TLS handshake either succeeds or fails — handles both success and failure paths with appropriate state transitions. On success path: resets ctx->tls_pending=0, transitions state from XRD_ST_TLS_HANDSHAKE back to XRD_ST_REQ_HEADER, re-arms recv loop via ngx_stream_xrootd_recv(). On failure path: logs error with cipher info (if available), calls xrootd_on_disconnect() and xrootd_close_all_files(), finalizes session with NGX_STREAM_INTERNAL_SERVER_ERROR.
 *
 * WHY: This callback is the critical bridge between SSL layer and XRootD protocol state machine — without proper handling, failed handshakes would leave ctx in XRD_ST_TLS_HANDSHAKE indefinitely causing connection stalls. Success path ensures clean transition back to normal request processing; failure path guarantees immediate cleanup of all resources before session finalization.
 *
 * HOW: Check c->ssl->handshaked flag — if false (failure): log error, disconnect, close files, finalize with NGX_STREAM_INTERNAL_SERVER_ERROR and return; if true (success): log cipher name, reset ctx->tls_pending=0, set state=XRD_ST_REQ_HEADER, reset hdr_pos=0, restore recv/send handlers, call ngx_stream_xrootd_recv() to resume request loop. Thread safety: single-owner per connection on nginx event thread — no locking required.
 */

#include "tls.h"
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_posted.h>
#include <ngx_stream.h>
#include <ngx_event_openssl.h>
#include <openssl/err.h>

void xrootd_tls_handshake_done(ngx_connection_t *c) {
    ngx_stream_session_t *s   = c->data;
    xrootd_ctx_t         *ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    if (!c->ssl->handshaked) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "xrootd: kXR_ableTLS handshake failed");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "xrootd: kXR_ableTLS TLS handshake complete (%s)", SSL_get_cipher(c->ssl->connection));
    ctx->tls_pending = 0;
    ctx->state       = XRD_ST_REQ_HEADER;
    ctx->hdr_pos     = 0;
    c->read->handler  = ngx_stream_xrootd_recv;
    c->write->handler = ngx_stream_xrootd_send;
    ngx_stream_xrootd_recv(c->read);
}

void
xrootd_start_tls(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_stream_session_t *s  = c->data;
    ngx_int_t             rc;
    /*
     * Phase 33: clear any stale entries left on the per-thread OpenSSL error
     * queue by earlier GSI/crypto work (the module never calls ERR_clear_error
     * elsewhere).  A dirty queue makes nginx's clean-close detection misreport a
     * benign close as "SSL_do_handshake() failed", inflating spurious
     * kXR_ableTLS/unknown-ca failures on this in-protocol TLS path.
     */
    ERR_clear_error();
    ctx->state = XRD_ST_TLS_HANDSHAKE;
    if (ngx_ssl_create_connection(conf->tls_ctx, c, NGX_SSL_BUFFER) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "xrootd: ngx_ssl_create_connection failed");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
    c->ssl->handler = xrootd_tls_handshake_done;
    rc = ngx_ssl_handshake(c);
    if (rc == NGX_AGAIN) {
        return;
    }
    if (rc == NGX_OK) {
        xrootd_tls_handshake_done(c);
        return;
    }
    ngx_log_error(NGX_LOG_ERR, c->log, 0, "xrootd: kXR_ableTLS ngx_ssl_handshake error");
    xrootd_on_disconnect(ctx, c);
    xrootd_close_all_files(ctx);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}
