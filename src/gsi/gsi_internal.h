#ifndef XROOTD_GSI_INTERNAL_H
#define XROOTD_GSI_INTERNAL_H

#include "../ngx_xrootd_module.h"

/*
 * xrootd_gsi_send_cert — respond to a kXR_auth/kXGC_certreq message by
 * generating a Diffie-Hellman ephemeral key pair, encoding the public key as a
 * hex string, signing it with the server's RSA key, and sending the kXGC_cert
 * response.
 *
 * Sets ctx->gsi_dh_key on success; the key is freed after kXGC_cert arrives
 * and the shared secret is derived (signing_key = SHA-256(DH-shared)).
 *
 * Returns NGX_OK (response queued), NGX_ERROR on crypto or send failure.
 */
ngx_int_t xrootd_gsi_send_cert(xrootd_ctx_t *ctx, ngx_connection_t *c);

/*
 * xrootd_handle_token_auth — handle kXR_auth with protocol "ztn" (WLCG/SciToken).
 *
 * Extracts the bearer token from the payload, validates it via
 * xrootd_token_validate(), and sets ctx->auth_done = 1 on success.
 *
 * Returns NGX_OK (auth accepted or rejected with error response queued).
 */
ngx_int_t xrootd_handle_token_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/*
 * xrootd_handle_sss_auth — handle kXR_auth with protocol "sss" (Simple Shared
 * Secret).
 *
 * Decrypts the Blowfish-CFB64 token, verifies the CRC32 integrity check,
 * validates the timestamp (replay prevention), and optionally checks the source
 * IP.  Sets ctx->auth_done = 1 on success.
 *
 * Returns NGX_OK (auth accepted or rejected with error response queued).
 */
ngx_int_t xrootd_handle_sss_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif /* XROOTD_GSI_INTERNAL_H */
