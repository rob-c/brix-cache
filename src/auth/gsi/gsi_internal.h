#ifndef XROOTD_GSI_INTERNAL_H
#define XROOTD_GSI_INTERNAL_H

#include "core/ngx_xrootd_module.h"

/*---- GSI internal header — function declarations for credential authentication ----
 *
 * WHAT: Declares three authentication handlers dispatched from src/gsi/auth.c based on credtype field:
 *   - xrootd_gsi_send_cert() — GSI round 1 DH key generation response
 *   - xrootd_handle_token_auth() — WLCG/SciToken (ztn) JWT validation
 *   - xrootd_handle_sss_auth() — Simple Shared Secret (sss) Blowfish decryption */

/*---- Credential type routing function declarations ----
 *
 * WHY: Each credential type has its own handler with different cryptographic mechanisms:
 *   GSI = DH key exchange + AES encryption + X509 certificate parsing;
 *   Token = JWT validation against JWKS (RSA/ECDSA signature verification);
 *   SSS = Blowfish-CFB64 decryption + CRC32 integrity + timestamp replay prevention. */

/*---- GSI round 1 response function declaration ----
 *
 * WHAT: xrootd_gsi_send_cert() — respond to kXGC_certreq by generating ephemeral DH key pair (ffdhe2048),
 *       encoding public key as hex blob, signing client rtag with RSA PKCS1, assembling kXGS_cert wire response. */

/*---- GSI round 1 function postconditions ----
 *
 * WHY: Sets ctx->gsi_dh_key on success — this private DH key is used in round 2 (parse.c) for shared secret derivation via EVP_PKEY_derive().
 *      Key is freed after kXGC_cert arrives and signing_key = SHA-256(DH-shared) is computed. */

/*---- GSI round 1 function return values ----
 *
 * WHY: Returns NGX_OK (response queued successfully), NGX_ERROR on crypto or send failure — caller sends appropriate error response. */

/*---- GSI round 1 function declaration ----
 *
 * WHAT: Called from src/gsi/auth.c as part of kXGC_certreq handling after credential type verification. Returns ngx_int_t result. */

ngx_int_t xrootd_gsi_send_cert(xrootd_ctx_t *ctx, ngx_connection_t *c);

/*---- WLCG/SciToken JWT validation function declaration ----
 *
 * WHAT: xrootd_handle_token_auth() — handle kXR_auth with protocol "ztn" (WLCG/SciToken bearer token). */

/*---- Token authentication mechanism ----
 *
 * WHY: Extracts bearer token from payload, validates via xrootd_token_validate() against configured JWKS and issuer.
 *      Uses RSA/ECDSA signature verification to validate JWT claims — single-round authentication (no DH exchange needed). */

/*---- Token authentication postconditions ----
 *
 * WHY: Sets ctx->auth_done = 1 on success — enables subsequent authenticated operations like file access and TPC transfers. */

/*---- Token authentication function declaration ----
 *
 * WHAT: Called from src/gsi/auth.c as part of kXR_auth handling after credential type "ztn" verification. Returns NGX_OK result. */

ngx_int_t xrootd_handle_token_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/*---- SSS shared secret authentication function declaration ----
 *
 * WHAT: xrootd_handle_sss_auth() — handle kXR_auth with protocol "sss" (Simple Shared Secret for trusted environments). */

/*---- SSS authentication mechanism ----
 *
 * WHY: Decrypts Blowfish-CFB64 token, verifies CRC32 integrity check, validates timestamp (replay prevention), 
 *      optionally checks source IP. Used in trusted/controlled environments where pre-shared secrets are acceptable. */

/*---- SSS authentication postconditions ----
 *
 * WHY: Sets ctx->auth_done = 1 on success — enables subsequent authenticated operations like file access and TPC transfers. */

/*---- SSS authentication function declaration ----
 *
 * WHAT: Called from src/gsi/auth.c as part of kXR_auth handling after credential type "sss" verification. Returns NGX_OK result. */

ngx_int_t xrootd_handle_sss_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif /* XROOTD_GSI_INTERNAL_H */
