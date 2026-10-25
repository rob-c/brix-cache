/* Public-key construction for JWKS entries (RSA and EC P-256).
 *
 * WHAT: Converts base64url-encoded JWK key parameters into OpenSSL EVP_PKEY objects.
 * RSA path: decode n/e from base64url → BIGNUMs → version-neutral key import;
 * EC P-256 path: decode x/y from base64url → uncompressed 65-byte point (0x04||x||y) →
 *   version-neutral P-256 key import.
 *
 * WHY: JWKS keys arrive as base64url-encoded n/e (RSA) or x/y (EC) strings in JSON.
 * The token layer needs OpenSSL EVP_PKEY handles to verify RS256 signatures via
 * brix_token_verify_signature(). These functions bridge JWK wire format → OpenSSL native.
 *
 * HOW: Both functions use b64url_decode() for base64url→binary conversion, then
 * auth/crypto/jwk_compat.h for native provider or 1.1.1 public-key construction.
 * All intermediate BIGNUMs are freed before return. */

#include "core/compat/log_event.h"
#include "token_internal.h"
#include "b64url.h"

#include <openssl/bn.h>
#include "auth/crypto/jwk_compat.h"
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */

/* WHAT: Construct OpenSSL RSA public key from base64url-encoded modulus (n) and
 * exponent (e). Returns EVP_PKEY on success, NULL on decode failure or BIGNUM/OSSL
 * construction error.
 * HOW: b64url_decode(n_b64→n_bin[512]) → BN_bin2bn → OSSL_PARAM_BLD_push_BN(N,e)
 *   → OSSL_PARAM_BLD_to_param → EVP_PKEY_CTX_new_from_name(RSA) + EVP_PKEY_fromdata;
 *   all intermediates freed before return. */
EVP_PKEY *
brix_token_rsa_pubkey_from_ne(const char *n_b64, size_t n_b64_len,
    const char *e_b64, size_t e_b64_len, ngx_log_t *log)
{
    u_char   n_bin[512], e_bin[16];
    ssize_t  n_len, e_len;
    BIGNUM  *bn_n, *bn_e;
    EVP_PKEY       *pkey;

    n_len = b64url_decode(n_b64, n_b64_len, n_bin, sizeof(n_bin));
    e_len = b64url_decode(e_b64, e_b64_len, e_bin, sizeof(e_bin));
    if (n_len <= 0 || e_len <= 0) {
        BRIX_LOG(NGX_LOG_ERR, log, 0,
                      "brix_token: JWKS: cannot decode RSA n/e");
        return NULL;
    }

    bn_n = BN_bin2bn(n_bin, (int) n_len, NULL);
    bn_e = BN_bin2bn(e_bin, (int) e_len, NULL);
    if (bn_n == NULL || bn_e == NULL) {
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    pkey = brix_crypto_rsa_public(bn_n, bn_e);
    BN_free(bn_n);
    BN_free(bn_e);

    return pkey;
}
/* WHAT: Construct OpenSSL EC P-256 public key from base64url-encoded x and y
 * coordinate values. Returns EVP_PKEY on success, NULL if decoded length != 32 bytes.
 * HOW: b64url_decode(x_b64→x_bin[32], y_b64→y_bin[32]) → validate each = 32 bytes;
 *   assemble uncompressed point (0x04||x||y in 65-byte buffer) → OSSL_PARAM_BLD with
 *   group P-256 + octet-string pub key → EVP_PKEY_CTX_new_from_name(EC) + EVP_PKEY_fromdata; */

EVP_PKEY *
brix_token_ec_pubkey_from_xy(const char *x_b64, size_t x_b64_len,
    const char *y_b64, size_t y_b64_len, ngx_log_t *log)
{
    u_char          x_bin[32], y_bin[32];
    ssize_t         x_len, y_len;
    u_char          pub_point[65];  /* 0x04 || x (32) || y (32) */

    x_len = b64url_decode(x_b64, x_b64_len, x_bin, sizeof(x_bin));
    y_len = b64url_decode(y_b64, y_b64_len, y_bin, sizeof(y_bin));
    if (x_len != 32 || y_len != 32) {
        BRIX_LOG(NGX_LOG_ERR, log, 0,
                      "brix_token: JWKS: EC P-256 x/y must each decode to 32 bytes");
        return NULL;
    }

    pub_point[0] = 0x04;  /* uncompressed point */
    ngx_memcpy(pub_point + 1,  x_bin, 32);
    ngx_memcpy(pub_point + 33, y_bin, 32);

    return brix_crypto_p256_public(pub_point, sizeof(pub_point));
}
