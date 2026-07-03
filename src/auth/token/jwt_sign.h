#ifndef BRIX_TOKEN_JWT_SIGN_H
#define BRIX_TOKEN_JWT_SIGN_H

/*
 * jwt_sign.h — ES256 (ECDSA P-256 + SHA-256) JWT *minting*.
 *
 * WHAT: Produce a signed compact JWT ("<b64url header>.<b64url payload>.<b64url
 *       signature>") from a caller-supplied header/payload JSON and an EC P-256
 *       private key.
 * WHY:  The rest of the token layer only *verifies* JWTs (signature.c). The
 *       Pelican cache-registration path (src/cache/origin/pelican_register.c)
 *       must *create* a short-lived advertise token signed with the cache's own
 *       key so the federation Director can authenticate this node's periodic
 *       advertisements. This is the only minting path and is deliberately
 *       isolated from S3 SigV4 (INVARIANT 6) and from JWT *verification*.
 * HOW:  EVP_DigestSign with EVP_sha256() over "header.payload" yields a DER
 *       ECDSA signature; JWT requires the IEEE P1363 raw r||s form, so the DER
 *       is decoded (d2i_ECDSA_SIG) and each component fixed-width encoded to 32
 *       bytes — the exact inverse of brix_token_verify_es256(). All three
 *       segments are base64url-encoded (b64url_encode).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/evp.h>

/*
 * Load an EC (P-256) private key from a PEM file. Returns an EVP_PKEY the caller
 * must EVP_PKEY_free, or NULL on open/parse failure or if the key is not EC.
 */
EVP_PKEY *brix_jwt_load_ec_key(const char *pem_path);

/*
 * Mint an ES256 JWT into out[outsz]. header_json and payload_json are
 * NUL-terminated compact JSON objects (the caller sets "alg":"ES256","typ":"JWT"
 * in the header and any "kid"). Returns NGX_OK with a NUL-terminated token in
 * out, or NGX_ERROR on any crypto/encoding failure or if out is too small.
 * eckey must be an EC P-256 private key.
 */
ngx_int_t brix_jwt_sign_es256(EVP_PKEY *eckey, const char *header_json,
    const char *payload_json, char *out, size_t outsz);

#endif /* BRIX_TOKEN_JWT_SIGN_H */
