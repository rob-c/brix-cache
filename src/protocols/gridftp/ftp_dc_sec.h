#ifndef BRIX_GRIDFTP_DC_SEC_H
#define BRIX_GRIDFTP_DC_SEC_H

/*
 * gridftp/ftp_dc_sec.h — GridFTP data-channel GSI security core for the
 * event-driven (ev/) engine.
 *
 * WHAT: the cert/identity operations a GSI-protected (DCAU A / PROT P) data
 * channel needs — present the delegated user credential on the data SSL, apply
 * the data-channel TLS policy, and PKIX-verify the peer's proxy chain while
 * pinning its end-entity DN to the control-channel identity.
 *
 * WHY: GridFTP's protected data channel is a straight TLS session on the data
 * socket (client ClientHello, no globus token framing).  The event engine drives
 * ngx_ssl_handshake off the data connection's events; the cert/identity logic is
 * factored out here — independent of how the handshake is driven — so it is
 * written, reviewed, and fixed once as the data-channel security boundary.
 *
 * HOW: the caller creates the SSL (SSL_new / ngx_ssl_create_connection) and binds
 * the fd, then hands this module a brix_ftp_dc_sec_t view of the session's GSI
 * state.  brix_ftp_dc_load_deleg() installs the delegated proxy + chain + key;
 * brix_ftp_dc_apply_policy() sets the TLS 1.2 cap / abrupt-EOF tolerance / peer-
 * cert requirement; brix_ftp_dc_gsi_check() runs post-handshake to verify the
 * peer chain and pin its DN.  None of them touch the fd or drive the handshake.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

/* A read-only view of one session's control-channel GSI state, assembled by the
 * owning engine from its own per-connection context.  The strings are borrowed
 * (owned by the session), so this descriptor is safe to build on the stack. */
typedef struct {
    ngx_log_t   *log;
    ngx_str_t    deleg_proxy;     /* assembled "<proxy><chain><key>" PEM      */
    ngx_str_t    ctrl_leaf_pem;   /* client control-channel leaf cert PEM     */
    ngx_str_t    ctrl_dn;         /* control-channel verified subject DN      */
    X509_STORE  *ca_store;        /* trust roots for the peer proxy chain     */
} brix_ftp_dc_sec_t;

/* Present the delegated user credential (leaf proxy + issuer chain + private
 * key) as `ssl`'s certificate.  DCAU authenticates the data channel as the user
 * on both ends, so the server offers the proxy the client delegated on the
 * control channel — not the host cert.  Returns NGX_OK / NGX_ERROR. */
ngx_int_t brix_ftp_dc_load_deleg(const brix_ftp_dc_sec_t *sec, SSL *ssl);

/* Apply the data-channel TLS policy: cap at TLS 1.2, tolerate GridFTP's
 * close-without-close_notify EOF, and require a peer cert (the chain is checked
 * post-handshake in brix_ftp_dc_gsi_check, so the TLS-layer verify accepts any
 * presented cert).  Never fails. */
void      brix_ftp_dc_apply_policy(SSL *ssl);

/* Post-handshake gate for both the accept (passive) and connect (active) roles:
 * PKIX-verify the peer's RFC 3820 proxy chain against `sec->ca_store` and require
 * its end-entity DN to name the control-channel identity (exact, or extended by
 * trailing /CN= proxy components for a gsiftp<->gsiftp TPC leg).  This DN pin is
 * the data-channel security boundary.  Returns NGX_OK / NGX_ERROR. */
ngx_int_t brix_ftp_dc_gsi_check(const brix_ftp_dc_sec_t *sec, SSL *ssl);

#endif /* BRIX_GRIDFTP_DC_SEC_H */
