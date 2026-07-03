#ifndef BRIX_TOKEN_INTERNAL_H
#define BRIX_TOKEN_INTERNAL_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/evp.h>

#include "token.h"

/* WHAT: Internal token API — JWK→EVP_PKEY conversion for RSA and EC P-256 keys, RS256/ES256 signature verification.
* WHY: Provides the bridge between JWKS key material (n/e base64url values or x/y coordinates) and OpenSSL EVP_PKEY objects used by signature verification. RS256 uses direct EVP_DigestVerify chain; ES256 converts IEEE P1363 raw r||s format to DER-encoded ASN.1 via ECDSA_SIG before verification. Used exclusively by validate.c for JWT claim trust.
* HOW: rsa_pubkey_from_ne() decodes n/e base64url→BIGNUMs→OSSL_PARAM_BLD→EVP_PKEY fromdata; ec_pubkey_from_xy() validates 32-byte x/y coordinates→uncompressed point→group P-256→fromdata; verify_rs256() EVP_MD_CTX Init/Update/Final chain with SHA-256+RSA; verify_es256() sig_len==64 validate→BN_bin2bn r/s→ECDSA_SIG_set0→i2d_ECDSA_SIG DER→EVP chain. */


/* WHAT: Build RSA EVP_PKEY from JWK n/e base64url values.
* WHY: JWKS files contain RSA keys as base64url-encoded modulus (n) and exponent (e). This converts them to OpenSSL BIGNUMs then OSSL_PARAM_BLD→fromdata for use in EVP_DigestVerifyInit with SHA-256. Used by signature.c verify_rs256().
* HOW: Base64url-decode n/e → BN_bin2bn() into BIGNUM objects → OSSL_PARAM_BLD_create_params() → EVP_PKEY_fromdata() with EVP_KEYTYPE_RSA. Returns NULL on any allocation failure, caller frees via EVP_PKEY_free(). */
EVP_PKEY *brix_token_rsa_pubkey_from_ne(const char *n_b64,
    size_t n_b64_len, const char *e_b64, size_t e_b64_len, ngx_log_t *log);

/* WHAT: Build EC P-256 EVP_PKEY from JWK x/y base64url coordinates.
* WHY: JWKS files contain ECDSA keys as base64url-encoded x and y point coordinates. This validates 32-byte coordinates, creates uncompressed point, maps to group P-256, then converts to EVP_PKEY for use in EVP_DigestVerifyInit with SHA-256. Used by signature.c verify_es256().
* HOW: Base64url-decode x/y → validate each is exactly 32 bytes → EC_POINT_new() → EC_POINT_set_affine_coordinates_GFp() → group P-256 → OSSL_PARAM_BLD→EVP_PKEY_fromdata. Returns NULL on validation or allocation failure. */
EVP_PKEY *brix_token_ec_pubkey_from_xy(const char *x_b64,
    size_t x_b64_len, const char *y_b64, size_t y_b64_len, ngx_log_t *log);

/* WHAT: Verify RS256 (RSA + SHA-256) JWT signature using OpenSSL EVP_DigestVerify chain.
* WHY: RS256 is the primary algorithm for most JWKS providers. The three-step EVP verification chain (Init→Update→Final) provides constant-time comparison security against timing attacks. Used by validate.c to verify JWT payload integrity before trusting claims.
* HOW: EVP_MD_CTX_new() → EVP_DigestVerifyInit with SHA-256+RSA public key → EVP_DigestVerifyUpdate with signed_data (header+body concatenated) → EVP_DigestVerifyFinal with sig bytes. Returns 1 for valid, 0 for invalid or ctx allocation failure. */
int brix_token_verify_rs256(const u_char *signed_data, size_t signed_len,
    const u_char *sig, size_t sig_len, EVP_PKEY *pkey);

/* WHAT: Verify ES256 (ECDSA P-256 + SHA-256) JWT signature — converts IEEE P1363 raw r||s to DER ASN.1 via ECDSA_SIG before EVP verification.
* WHY: JWT ES256 signatures are 64-byte raw r||s format; OpenSSL expects DER-encoded ASN.1 for EC keys. This conversion enables consistent three-step EVP verification chain across both RS256 and ES256 algorithms. Used by validate.c for ECDSA-based JWKS providers.
* HOW: Validate sig_len==64 → BN_bin2bn(r 32 bytes) + BN_bin2bn(s 32 bytes) → ECDSA_SIG_new() + set0 transfers ownership → i2d_ECDSA_SIG produces DER output → same Init/Update/Final EVP chain as RS256 → OPENSSL_free(der). Returns 1 for valid, 0 for invalid or allocation failure. */
int brix_token_verify_es256(const u_char *signed_data, size_t signed_len,
    const u_char *sig_p1363, size_t sig_len, EVP_PKEY *pkey);

#endif /* BRIX_TOKEN_INTERNAL_H */
