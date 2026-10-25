/*
 * jwk_compat.h — owned RSA/EC public keys from decoded JWK material.
 * WHAT: Version-select native key import without exposing provider objects.
 * WHY: JWT callers share one ownership and failure contract on 1.1.1 and 3+.
 * HOW: Preserve borrowed inputs; destroy partial objects before returning NULL.
 * Requires: key_compat.h and OpenSSL >= 1.1.1; no nginx declarations.
 */
#pragma once

#include "key_compat.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/* ---- Import a provider public key from a borrowed parameter builder ----
 * WHAT: Return an owned EVP_PKEY or NULL, leaving the builder with its caller.
 * WHY: RSA and EC imports must share complete cleanup on every provider error.
 * HOW: 1. Build parameters. 2. Import into the requested type. 3. Free temporaries.
 */
static inline EVP_PKEY *
brix_crypto_import_public(const char *type, OSSL_PARAM_BLD *builder)
{
    OSSL_PARAM *parameters = OSSL_PARAM_BLD_to_param(builder);
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    EVP_PKEY *key = NULL;

    if (parameters != NULL && context != NULL
        && EVP_PKEY_fromdata_init(context) == 1) {
        if (EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, parameters) != 1) {
            EVP_PKEY_free(key);
            key = NULL;
        }
    }
    EVP_PKEY_CTX_free(context);
    OSSL_PARAM_free(parameters);
    return key;
}
#endif

/* ---- Construct an RSA public key without consuming the input numbers ----
 * WHAT: Return an owned EVP_PKEY or NULL; modulus/exponent stay caller-owned.
 * WHY: RSA_set0_key consumes numbers but provider builders borrow them.
 * HOW: 1. Validate inputs. 2. Build with native ownership rules. 3. Clean up.
 */
static inline EVP_PKEY *
brix_crypto_rsa_public(const BIGNUM *modulus, const BIGNUM *exponent)
{
    EVP_PKEY *key = NULL;

    if (modulus == NULL || exponent == NULL) {
        return NULL;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();

    if (builder != NULL
        && OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_N, modulus) == 1
        && OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_E, exponent) == 1) {
        key = brix_crypto_import_public("RSA", builder);
    }
    OSSL_PARAM_BLD_free(builder);
#else
    RSA *rsa = RSA_new();
    BIGNUM *owned_n = BN_dup(modulus), *owned_e = BN_dup(exponent);

    if (rsa != NULL && owned_n != NULL && owned_e != NULL
        && RSA_set0_key(rsa, owned_n, owned_e, NULL) == 1) {
        owned_n = NULL;
        owned_e = NULL;
        key = EVP_PKEY_new();
        if (key != NULL && EVP_PKEY_set1_RSA(key, rsa) != 1) {
            EVP_PKEY_free(key);
            key = NULL;
        }
    }
    BN_free(owned_n);
    BN_free(owned_e);
    RSA_free(rsa);
#endif
    return key;
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/* ---- Import a legacy P-256 point with explicit curve validation ----
 * WHAT: Return an owned EVP_PKEY or NULL; the encoded point stays borrowed.
 * WHY: Low-level 1.1.1 setters must not accept off-curve JWT coordinates.
 * HOW: 1. Decode on P-256. 2. Validate. 3. Wrap with an independent reference.
 */
static inline EVP_PKEY *
brix_crypto_p256_legacy(const unsigned char *point, size_t length)
{
    EVP_PKEY *key = NULL;
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP *group = ec != NULL ? EC_KEY_get0_group(ec) : NULL;
    EC_POINT *decoded = group != NULL ? EC_POINT_new(group) : NULL;

    if (decoded != NULL && EC_POINT_oct2point(group, decoded, point, length, NULL) == 1
        && EC_KEY_set_public_key(ec, decoded) == 1 && EC_KEY_check_key(ec) == 1) {
        key = EVP_PKEY_new();
        if (key != NULL && EVP_PKEY_set1_EC_KEY(key, ec) != 1) {
            EVP_PKEY_free(key);
            key = NULL;
        }
    }
    EC_POINT_free(decoded);
    EC_KEY_free(ec);
    return key;
}
#endif

/* ---- Construct a P-256 public key from its uncompressed encoded point ----
 * WHAT: Return an owned public key or NULL for invalid input/native failure.
 * WHY: Both JWT implementations must reject malformed point encodings.
 * HOW: 1. Require 65-byte uncompressed encoding. 2. Import using the native API.
 */
static inline EVP_PKEY *
brix_crypto_p256_public(const unsigned char *point, size_t length)
{
    if (point == NULL || length != 65 || point[0] != 4) {
        return NULL;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY *key = NULL;
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();

    if (builder != NULL
        && OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME,
                                          "P-256", 0) == 1
        && OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY,
                                           point, length) == 1) {
        key = brix_crypto_import_public("EC", builder);
    }
    OSSL_PARAM_BLD_free(builder);
    return key;
#else
    return brix_crypto_p256_legacy(point, length);
#endif
}
