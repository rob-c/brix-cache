#include "tls.h"
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_posted.h>
#include <ngx_stream.h>
#include <ngx_event_openssl.h>

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

void xrootd_start_tls(xrootd_ctx_t *ctx, ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf) {
    ngx_stream_session_t *s  = c->data;
    ngx_int_t             rc;
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
