#include "ftp_ev.h"

#include "protocols/gridftp/ftp_dc_sec.h"

/*
 * ftp_ev_tls.c — non-blocking PROT P data-channel TLS for the event engine.
 *
 * WHAT: brings a GSI-protected (DCAU A / PROT P) data connection up as a TLS
 * session under the event loop, then hands the encrypted socket to the transfer
 * pump.  The cert logic (present the delegated user credential, verify the peer
 * proxy chain, pin its DN to the control identity) is the shared ftp_dc_sec core;
 * this file only drives the *handshake* non-blocking.
 *
 * WHY: the sync engine blocks the worker inside SSL_accept()/SSL_connect().  Here
 * the handshake runs through nginx's own SSL connection layer (ngx_ssl_handshake),
 * which arms the data connection's read/write events on WANT_READ/WANT_WRITE and
 * calls back when the handshake settles — so the worker keeps serving other
 * sessions.  Once the handshake completes nginx swaps the connection's recv/send
 * vtable to ngx_ssl_recv/ngx_ssl_write, so the RETR/STOR/LIST pumps in
 * ftp_ev_xfer.c move TLS records with no change: c->send/c->recv already speak TLS.
 *
 * HOW: the handshake driver is factored into two reusable primitives —
 * brix_ftp_ev_tls_begin() (create pool + SSL + cred/policy, arm the handshake with
 * a caller-supplied completion handler) and brix_ftp_ev_tls_verify() (the
 * post-handshake identity gate).  The single data connection wraps them behind
 * brix_ftp_ev_dc_start_tls()/ev_dc_tls_done(); each MODE E child stream
 * (ftp_ev_mode_e.c) reuses the same primitives with its own completion handler, so
 * N parallel PROT P streams all handshake through one implementation.
 */


/* Assemble the shared data-channel security descriptor from this session. */
static void
ev_dc_sec_of(ftp_ev_t *fc, brix_ftp_dc_sec_t *sec)
{
    ngx_memzero(sec, sizeof(*sec));
    sec->log           = fc->c->log;
    sec->deleg_proxy   = fc->deleg_proxy;
    sec->ctrl_leaf_pem = fc->ctrl_leaf_pem;
    sec->ctrl_dn       = fc->ctrl_dn;
    sec->ca_store      = fc->conf->ca_store;
}


/* Post-handshake identity gate: confirm the handshake settled, then enforce the
 * GSI DN pin (peer proxy DN == control identity).  Reused by the single data
 * connection and every MODE E child stream. */
ngx_int_t
brix_ftp_ev_tls_verify(ftp_ev_t *fc, ngx_connection_t *c)
{
    brix_ftp_dc_sec_t sec;

    if (!c->ssl->handshaked) {
        ngx_log_error(NGX_LOG_ERR, fc->c->log, 0,
                      "brix: GridFTP(ev) PROT P data-channel handshake failed");
        return NGX_ERROR;
    }
    ev_dc_sec_of(fc, &sec);
    return brix_ftp_dc_gsi_check(&sec, c->ssl->connection);
}


/* Drive the data-channel TLS handshake non-blocking.  Gives the wrapped socket a
 * per-connection pool (nginx SSL allocates its state on c->pool; a wrapped fd has
 * none), creates the SSL from the gateway ctx, installs the delegated credential
 * and TLS/proxy policy, sets `done` as the ssl->handler, and starts the handshake.
 * The pool is returned via *poolp for the caller to release on teardown. */
ngx_int_t
brix_ftp_ev_tls_begin(ftp_ev_t *fc, ngx_connection_t *c, ngx_pool_t **poolp,
                      int tls_client, void (*done)(ngx_connection_t *))
{
    brix_ftp_dc_sec_t  sec;
    ngx_uint_t         flags;
    ngx_int_t          rc;

    if (fc->conf->tls_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, fc->c->log, 0,
                      "brix: GridFTP(ev) PROT P requested but no server TLS "
                      "context configured");
        return NGX_ERROR;
    }

    *poolp = ngx_create_pool(1024, fc->c->log);
    if (*poolp == NULL) {
        return NGX_ERROR;
    }
    c->pool = *poolp;

    /* The TLS role follows which side opened the socket: an active-mode connect
     * (we dialled out) is the TLS client; a passive accept (the peer dialled in,
     * incl. every MODE E child stream) is the TLS server. */
    flags = tls_client ? NGX_SSL_CLIENT : 0;

    if (ngx_ssl_create_connection(fc->conf->tls_ctx, c, flags) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, fc->c->log, 0,
                      "brix: GridFTP(ev) data-channel ngx_ssl_create_connection "
                      "failed");
        return NGX_ERROR;
    }

    ev_dc_sec_of(fc, &sec);
    if (brix_ftp_dc_load_deleg(&sec, c->ssl->connection) != NGX_OK) {
        return NGX_ERROR;
    }
    brix_ftp_dc_apply_policy(c->ssl->connection);

    c->ssl->handler = done;

    rc = ngx_ssl_handshake(c);
    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;                    /* ssl->handler fires on completion   */
    }
    if (rc == NGX_OK) {
        done(c);                             /* completed inline (loopback)        */
        return NGX_OK;
    }
    return NGX_ERROR;
}


/* nginx ssl->handler for the single data connection: enforce the GSI DN pin, then
 * start the transfer — or fail closed. */
static void
ev_dc_tls_done(ngx_connection_t *c)
{
    ftp_ev_dc_t *dc = c->data;

    if (brix_ftp_ev_tls_verify(dc->fc, c) != NGX_OK) {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }

    /* Handshake + identity confirmed; nginx has already repointed c->recv/c->send
     * at ngx_ssl_recv/ngx_ssl_write, so the pump moves TLS records transparently. */
    brix_ftp_ev_data_ready(dc);
}


void
brix_ftp_ev_dc_start_tls(ftp_ev_dc_t *dc)
{
    if (brix_ftp_ev_tls_begin(dc->fc, dc->dconn, &dc->dpool, dc->tls_client,
                              ev_dc_tls_done) == NGX_ERROR)
    {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
    }
}
