#ifndef BRIX_GSSAPI_GSI_MECH_H
#define BRIX_GSSAPI_GSI_MECH_H

/*
 * gsi_mech.h — server-side Globus GSI GSSAPI mechanism over a mem-BIO OpenSSL
 * TLS handshake (phase-82 §1.9 / §2.8).  Drives the RFC 2228 AUTH GSSAPI / ADAT
 * token exchange that gsiftp clients (globus-url-copy, gfal2) speak:
 *
 *   1. a TLS 1.2 handshake carried in base64 ADAT tokens (335 continue / 235
 *      done), the client presenting an RFC-3820 proxy as its certificate;
 *   2. the GSI credential-delegation sub-exchange layered over that channel as
 *      application-data: delegator sends 'D', we (acceptor) reply with a proxy
 *      certificate REQUEST, the delegator signs it, we assemble the delegated
 *      credential (brix_gsi_build_pxyreq / brix_gsi_assemble_proxy);
 *   3. post-auth confidentiality: control commands/replies are GSS-wrapped
 *      (SSL_write/SSL_read) as RFC 2228 MIC/CONF/ENC tokens.
 *
 * The engine is transport-agnostic: the caller base64-decodes each ADAT/MIC/ENC
 * argument and feeds the raw token in; the out token is raw bytes to base64 back
 * onto the wire.  TLS is pinned to 1.2 because the GSI ADAT state machine expects
 * the acceptor's final flight (ChangeCipherSpec+Finished) in the last token — the
 * TLS 1.3 flight shape breaks the 335/235 semantics.
 */

#include <ngx_core.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

typedef struct brix_gssapi_srv_s brix_gssapi_srv_t;

typedef enum {
    BRIX_GSS_CONTINUE = 0,   /* out holds the next token; reply 335, feed me more */
    BRIX_GSS_COMPLETE,       /* auth (+delegation) done; out may hold a final token */
    BRIX_GSS_FAILED
} brix_gss_status_e;

/*
 * brix_gssapi_srv_create — new acceptor bound to `ssl_ctx` (host cert/key +
 * client-cert request configured by the caller) and `ca_store` (trust roots for
 * post-handshake proxy-chain verification).  When accept_deleg is non-zero the
 * GSI 'D'→CSR→signed-proxy delegation round runs before completion.  Returns
 * NULL on allocation failure.  All OpenSSL objects are released via a pool
 * cleanup, so the engine needs no explicit free on the happy path
 * (brix_gssapi_srv_free is available for eager teardown).
 */
brix_gssapi_srv_t *brix_gssapi_srv_create(ngx_pool_t *pool, ngx_log_t *log,
    SSL_CTX *ssl_ctx, X509_STORE *ca_store, unsigned accept_deleg);

/*
 * brix_gssapi_srv_step — feed one decoded ADAT token (`in`/`in_len`) and get the
 * next outgoing token in `out` (pool-allocated; out->len may be 0).  Returns
 * BRIX_GSS_CONTINUE (send 335 ADAT=out), BRIX_GSS_COMPLETE (send 235 ADAT=out
 * and switch to the wrapped control channel) or BRIX_GSS_FAILED (send 535).
 */
brix_gss_status_e brix_gssapi_srv_step(brix_gssapi_srv_t *g,
    const u_char *in, size_t in_len, ngx_str_t *out);

/*
 * brix_gssapi_srv_peer — after COMPLETE, return the verified end-entity subject
 * DN (`dn_out`) and, when delegation ran, the assembled delegated credential PEM
 * (`proxy_pem_out`, empty otherwise).  Either out arg may be NULL.  Returns
 * NGX_OK when the peer chain verified, NGX_ERROR otherwise.
 */
ngx_int_t brix_gssapi_srv_peer(brix_gssapi_srv_t *g,
    ngx_str_t *dn_out, ngx_str_t *proxy_pem_out);

/*
 * brix_gssapi_srv_peer_cert_pem — after COMPLETE, return the client's leaf
 * certificate (the proxy it authenticated with) as PEM in `out` (pool-allocated).
 * This is the direct issuer of any delegated proxy and is NOT part of the
 * server-side SSL_get_peer_cert_chain(), so callers assembling a presentable
 * chain from the delegated credential need it separately.  NGX_OK / NGX_ERROR.
 */
ngx_int_t brix_gssapi_srv_peer_cert_pem(brix_gssapi_srv_t *g, ngx_str_t *out);

/*
 * brix_gssapi_wrap / _unwrap — post-auth confidentiality layer.  wrap encrypts
 * `in` into a protected token (SSL_write → drain); unwrap decrypts a received
 * token (feed → SSL_read) into plaintext.  `out` is pool-allocated.  NGX_OK/ERR.
 */
ngx_int_t brix_gssapi_wrap(brix_gssapi_srv_t *g,
    const u_char *in, size_t in_len, ngx_str_t *out);
ngx_int_t brix_gssapi_unwrap(brix_gssapi_srv_t *g,
    const u_char *in, size_t in_len, ngx_str_t *out);

void brix_gssapi_srv_free(brix_gssapi_srv_t *g);

#endif /* BRIX_GSSAPI_GSI_MECH_H */
