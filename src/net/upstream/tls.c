/* upstream/tls.c — Outbound TLS upgrade for transparent proxy upstream redirector
 * WHAT: This file provides two functions for upgrading the upstream TCP connection to TLS after a remote XRootD server signals kXR_gotoTLS in its kXR_protocol response:

 *      1. xrootd_upstream_start_tls() — wraps up->conn in SSL, sets SNI hostname, starts TLS handshake
 *      2. xrootd_upstream_tls_handshake_done() — nginx ssl->handler callback that resends kXR_login over TLS once handshake completes

 * WHY: Transparent proxy mode requires the upstream connection to support TLS when backend servers demand it (kXR_gotoTLS). The client's kXR_login must be sent over the upgraded TLS channel, not cleartext TCP. This file handles the transition from raw TCP → SSL-wrapped connection → re-login over TLS.

 * HOW: start_tls() calls ngx_ssl_create_connection() with upstream TLS context → sets SNI (directive override wins, falls back to configured host) → assigns ssl->handler callback → calls ngx_ssl_handshake(). handshake_done() fires on completion: checks ctx validity and handshaked flag → restores normal event handlers → allocates fresh kXR_login frame via xrootd_upstream_build_login() → flushes over TLS connection → arms read event for login response.
 */

#include "upstream_internal.h"

#if (NGX_SSL)

static void xrootd_upstream_tls_handshake_done(ngx_connection_t *uconn);

/*

 * WHAT: xrootd_upstream_start_tls() wraps the upstream TCP connection in SSL and initiates the TLS handshake.

 * WHY: When backend XRootD server signals kXR_gotoTLS, the existing cleartext TCP connection must be upgraded to TLS before sending kXR_login. The SSL context comes from conf->upstream_tls_ctx; SNI is set from either an explicit override directive or the configured upstream host name.

 * HOW: Sets bs_phase = XRD_UP_BS_TLS → calls ngx_ssl_create_connection() with NGX_SSL_BUFFER | NGX_SSL_CLIENT flags → sets SNI via SSL_set_tlsext_host_name() (conf->upstream_tls_name wins if non-empty, falls back to conf->upstream_host) → assigns ssl->handler callback → calls ngx_ssl_handshake(). If handshake completes synchronously (unlikely), immediately fires xrootd_upstream_tls_handshake_done(). Returns NGX_OK on success, NGX_ERROR on SSL creation failure.
 */
ngx_int_t
xrootd_upstream_start_tls(xrootd_upstream_t *up,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_connection_t  *uconn = up->conn;
    const char        *sni;

    if (ngx_ssl_create_connection(conf->upstream_tls_ctx, uconn,
                                  NGX_SSL_BUFFER | NGX_SSL_CLIENT)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* SNI: explicit override directive wins; fall back to configured host. */
    sni = (conf->upstream_tls_name.len > 0)
          ? (const char *) conf->upstream_tls_name.data
          : (const char *) conf->upstream_host.data;
    SSL_set_tlsext_host_name(uconn->ssl->connection, sni);

    uconn->ssl->handler = xrootd_upstream_tls_handshake_done;
    up->bs_phase = XRD_UP_BS_TLS;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, up->client_conn->log, 0,
                   "xrootd: upstream starting TLS handshake (sni=%s)", sni);

    if (ngx_ssl_handshake(uconn) != NGX_AGAIN) {
        /* Completed synchronously (unlikely but handle it). */
        xrootd_upstream_tls_handshake_done(uconn);
    }

    return NGX_OK;
}

/*

 * WHAT: xrootd_upstream_tls_handshake_done() is the nginx ssl->handler callback that fires once the TLS handshake completes (success or failure). On success, restores normal event handlers, allocates a fresh kXR_login frame, and flushes it over the now-TLS connection.

 * WHY: The SSL handshake replaces the normal upstream read/write event handlers. After completion, those handlers must be restored so subsequent request/response traffic flows normally. A fresh kXR_login is needed because credentials sent over cleartext before TLS upgrade are no longer valid on the encrypted channel.

 * HOW: Checks ctx validity and destroyed flag → calls cleanup if invalid; checks uconn->ssl->handshaked → calls abort if failed. On success: (1) restores read handler to xrootd_upstream_read_handler, write handler to xrootd_upstream_write_handler, (2) allocates ClientLoginRequest from pool via ngx_palloc(), builds login frame via xrootd_upstream_build_login(), (3) sets wbuf/wbuf_len/wbuf_pos for flush → calls xrootd_upstream_flush(), (4) if partial write: arms write event; if fully written: arms read event to wait for login response. Sets bs_phase = XRD_UP_BS_LOGIN.
 */
static void
xrootd_upstream_tls_handshake_done(ngx_connection_t *uconn)
{
    xrootd_upstream_t   *up  = uconn->data;
    xrootd_ctx_t        *ctx = up->client_ctx;
    ClientLoginRequest  *req;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_upstream_cleanup(up);
        return;
    }

    if (!uconn->ssl->handshaked) {
        xrootd_upstream_abort(up, "upstream: TLS handshake failed");
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, up->client_conn->log, 0,
                   "xrootd: upstream TLS handshake done; resending kXR_login");

    /* Restore normal event handlers (TLS handshake replaces them). */
    uconn->read->handler  = xrootd_upstream_read_handler;
    uconn->write->handler = xrootd_upstream_write_handler;

    /* Build a fresh kXR_login for the TLS channel. */
    req = ngx_palloc(uconn->pool, sizeof(*req));
    if (req == NULL) {
        xrootd_upstream_abort(up, "upstream: TLS re-login OOM");
        return;
    }
    xrootd_upstream_build_login(req);

    up->wbuf      = (u_char *) req;
    up->wbuf_len  = sizeof(*req);
    up->wbuf_pos  = 0;
    up->bs_phase  = XRD_UP_BS_LOGIN;

    /* Reset response accumulator for the login response. */
    up->rhdr_pos      = 0;
    up->resp_dlen     = 0;
    up->resp_body     = NULL;
    up->resp_body_pos = 0;

    if (xrootd_upstream_flush(up) == NGX_ERROR) {
        xrootd_upstream_abort(up, "upstream: TLS re-login send failed");
        return;
    }

    if (up->wbuf_pos < up->wbuf_len) {
        /* Not all bytes written yet; write handler will finish and arm read. */
        if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
            xrootd_upstream_abort(up, "upstream: TLS write event arm failed");
        }
        return;
    }

    /* All sent; wait for login response. */
    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        xrootd_upstream_abort(up, "upstream: TLS read event arm failed");
    }
}

#endif /* NGX_SSL */
