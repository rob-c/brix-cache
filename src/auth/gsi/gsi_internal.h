#ifndef BRIX_GSI_INTERNAL_H
#define BRIX_GSI_INTERNAL_H

#include "core/ngx_brix_module.h"

/*---- GSI internal header — function declarations for credential authentication ----
 *
 * WHAT: Declares three authentication handlers dispatched from src/gsi/auth.c based on credtype field:
 *   - brix_gsi_send_cert() — GSI round 1 DH key generation response
 *   - brix_handle_token_auth() — WLCG/SciToken (ztn) JWT validation
 *   - brix_handle_sss_auth() — Simple Shared Secret (sss) Blowfish decryption */

/*---- Credential type routing function declarations ----
 *
 * WHY: Each credential type has its own handler with different cryptographic mechanisms:
 *   GSI = DH key exchange + AES encryption + X509 certificate parsing;
 *   Token = JWT validation against JWKS (RSA/ECDSA signature verification);
 *   SSS = Blowfish-CFB64 decryption + CRC32 integrity + timestamp replay prevention. */

/*---- GSI round 1 response function declaration ----
 *
 * WHAT: brix_gsi_send_cert() — respond to kXGC_certreq by generating ephemeral DH key pair (ffdhe2048, BRIX_GSI_PROXY_KEY_BITS-bit),
 *       encoding public key as hex blob, signing client rtag with RSA PKCS1, assembling kXGS_cert wire response. */

/*---- GSI round 1 function postconditions ----
 *
 * WHY: Sets ctx->gsi.dh_key on success.
 *
 *   - Private DH key used in round 2 (parse.c) for shared secret derivation
 *   - Derivation via EVP_PKEY_derive()
 *   - Key freed after kXGC_cert arrives
 *   - Session cipher key (first key_len bytes of DH secret) persisted + armed
 */

/*---- GSI round 1 function return values ----
 *
 * WHY: Return values.
 *
 *   - NGX_OK: response queued successfully
 *   - NGX_ERROR: crypto or send failure (caller sends appropriate error response)
 */

/*---- GSI round 1 function declaration ----
 *
 * WHAT: Called from src/gsi/auth.c.
 *
 *   - Part of kXGC_certreq handling after credential type verification
 *   - Returns ngx_int_t result
 */

ngx_int_t brix_gsi_send_cert(brix_ctx_t *ctx, ngx_connection_t *c);

/*---- WLCG/SciToken JWT validation function declaration ----
 *
 * WHAT: brix_handle_token_auth() — handle kXR_auth with protocol "ztn" (WLCG/SciToken bearer token). */

/*---- Token authentication mechanism ----
 *
 * WHY: Extracts and validates bearer token.
 *
 *   - Validates via brix_token_validate() against configured JWKS and issuer
 *   - Uses RSA/ECDSA signature verification for JWT claims
 *   - Single-round authentication (no DH exchange needed)
 */

/*---- Token authentication postconditions ----
 *
 * WHY: Sets ctx->login.auth_done = 1 on success.
 *
 *   - Enables subsequent authenticated operations
 *   - File access and TPC transfers now permitted
 */

/*---- Token authentication function declaration ----
 *
 * WHAT: Called from src/gsi/auth.c.
 *
 *   - Part of kXR_auth handling after credential type "ztn" verification
 *   - Returns NGX_OK result
 */

ngx_int_t brix_handle_token_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/*---- SSS shared secret authentication function declaration ----
 *
 * WHAT: brix_handle_sss_auth() - handle kXR_auth with protocol "sss".
 *
 *   - Simple Shared Secret for trusted environments
 */

/*---- SSS authentication mechanism ----
 *
 * WHY: Decrypts and validates SSS token.
 *
 *   - Decrypts Blowfish-CFB64 token
 *   - Verifies CRC32 integrity check
 *   - Validates timestamp (replay prevention)
 *   - Optionally checks source IP
 *   - Used in trusted/controlled environments with pre-shared secrets
 */

/*---- SSS authentication postconditions ----
 *
 * WHY: Sets ctx->login.auth_done = 1 on success.
 *
 *   - Enables subsequent authenticated operations
 *   - File access and TPC transfers now permitted
 */

/*---- SSS authentication function declaration ----
 *
 * WHAT: Called from src/gsi/auth.c.
 *
 *   - Part of kXR_auth handling after credential type "sss" verification
 *   - Returns NGX_OK result
 */

ngx_int_t brix_handle_sss_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/*---- GSI kXR_auth split-file seam (auth.c <-> auth_cert.c) ----
 *
 * WHAT: brix_gsi_complete_auth() (defined in auth.c) finalizes a verified GSI
 *       login; gsi_auth_step_cert() (defined in auth_cert.c) runs GSI round 2
 *       (kXGC_cert). They call across the auth.c / auth_cert.c split, so both
 *       are declared here rather than kept file-static. */
ngx_int_t brix_gsi_complete_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);
ngx_int_t gsi_auth_step_cert(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

#endif /* BRIX_GSI_INTERNAL_H */
