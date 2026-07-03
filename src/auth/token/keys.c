/* Public-key construction for JWKS entries (RSA and EC P-256).
 *
 * WHAT: Converts base64url-encoded JWK key parameters into OpenSSL EVP_PKEY objects.
 * RSA path: decode n/e from base64url → BIGNUMs → OSSL_PARAM_BLD → EVP_PKEY_fromdata(RSA);
 * EC P-256 path: decode x/y from base64url → uncompressed 65-byte point (0x04||x||y) →
 *   OSSL_PARAM_BLD with group name P-256 → EVP_PKEY_fromdata(EC).
 *
 * WHY: JWKS keys arrive as base64url-encoded n/e (RSA) or x/y (EC) strings in JSON.
 * The token layer needs OpenSSL EVP_PKEY handles to verify RS256 signatures via
 * brix_token_verify_signature(). These functions bridge JWK wire format → OpenSSL native.
 *
 * HOW: Both functions use b64url_decode() for base64url→binary conversion, then
 * OSSL_PARAM_BLD/OSSL_PARAM_BLD_to_param() to build key parameters, and
 * EVP_PKEY_CTX_new_from_name() + EVP_PKEY_fromdata() to construct the final handle.
 * All intermediate BIGNUMs/params/bld are freed before return. */

#include "token_internal.h"
#include "b64url.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

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
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM     *params;
    EVP_PKEY_CTX   *pctx;
    EVP_PKEY       *pkey;

    n_len = b64url_decode(n_b64, n_b64_len, n_bin, sizeof(n_bin));
    e_len = b64url_decode(e_b64, e_b64_len, e_bin, sizeof(e_bin));
    if (n_len <= 0 || e_len <= 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
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

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e);
    params = OSSL_PARAM_BLD_to_param(bld);

    pkey = NULL;
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pctx != NULL) {
        EVP_PKEY_fromdata_init(pctx);
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        EVP_PKEY_CTX_free(pctx);
    }

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
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
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM     *params;
    EVP_PKEY_CTX   *pctx;
    EVP_PKEY       *pkey;

    x_len = b64url_decode(x_b64, x_b64_len, x_bin, sizeof(x_bin));
    y_len = b64url_decode(y_b64, y_b64_len, y_bin, sizeof(y_bin));
    if (x_len != 32 || y_len != 32) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_token: JWKS: EC P-256 x/y must each decode to 32 bytes");
        return NULL;
    }

    pub_point[0] = 0x04;  /* uncompressed point */
    ngx_memcpy(pub_point + 1,  x_bin, 32);
    ngx_memcpy(pub_point + 33, y_bin, 32);

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        return NULL;
    }

    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                     pub_point, sizeof(pub_point));
    params = OSSL_PARAM_BLD_to_param(bld);

    pkey = NULL;
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (pctx != NULL) {
        EVP_PKEY_fromdata_init(pctx);
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        EVP_PKEY_CTX_free(pctx);
    }

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);

    return pkey;
}
