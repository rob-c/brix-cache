/*
 * key_compat.h — version-neutral OpenSSL public-key operations.
 * WHAT: Owns the small API differences shared by GSI, delegation and JWT.
 * WHY: OpenSSL 1.1.1 and provider-based releases must retain the same ownership
 *      and refusal contracts; callers must not manufacture OpenSSL API shims.
 * HOW: Select native implementations at compile time; return owned results.
 * Requires: OpenSSL >= 1.1.1; no nginx declarations.
 */
#pragma once

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error "BriX requires OpenSSL 1.1.1 or newer"
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

/* ---- Generate an RSA keypair through the common EVP interface ----
 * WHAT: Return an owned key or NULL, using the requested modulus size.
 * WHY: EVP_RSA_gen is a 3-only convenience API, not a protocol requirement.
 * HOW: Initialize RSA keygen, set its size, generate, and release temporaries.
 */
static inline EVP_PKEY *
brix_crypto_rsa_keygen(unsigned bits)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;

    if (bits <= 0x7fffffffU && context != NULL && EVP_PKEY_keygen_init(context) == 1
        && EVP_PKEY_CTX_set_rsa_keygen_bits(context, (int) bits) == 1) {
        if (EVP_PKEY_keygen(context, &key) != 1) {
            EVP_PKEY_free(key);
            key = NULL;
        }
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

/* ---- Set an RSA key-generation exponent without consuming the caller's BN ----
 * WHAT: Return 1 on success and 0 on failure, retaining input ownership.
 * WHY: OpenSSL 1.1.1's setter consumes its BN; the 3+ set1 setter copies it.
 * HOW: 1. Use set1 on 3+. 2. Otherwise duplicate and transfer on success only.
 */
static inline int
brix_crypto_rsa_keygen_exponent(EVP_PKEY_CTX *context, BIGNUM *exponent)
{
    if (context == NULL || exponent == NULL) {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return EVP_PKEY_CTX_set1_rsa_keygen_pubexp(context, exponent) > 0;
#else
    BIGNUM *copy = BN_dup(exponent);

    if (copy == NULL) {
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(context, copy) <= 0) {
        BN_free(copy);
        return 0;
    }
    return 1;
#endif
}

/* ---- Generate a P-256 private key using the common EVP keygen interface ----
 * WHAT: Return an owned keypair or NULL after any native key-generation error.
 * WHY: Credential minting must not depend on OpenSSL 3's convenience Q API.
 * HOW: 1. Select EC/P-256. 2. Generate. 3. Release context and partial output.
 */
static inline EVP_PKEY *
brix_crypto_p256_keygen(void)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *key = NULL;

    if (context != NULL && EVP_PKEY_keygen_init(context) == 1
        && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) == 1) {
        if (EVP_PKEY_keygen(context, &key) != 1) {
            EVP_PKEY_free(key);
            key = NULL;
        }
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

/* ---- Compare public keys without accepting unsupported comparisons ----
 * WHAT: Return 1 only for equal, non-NULL public keys; otherwise return 0.
 * WHY: Negative/unsupported comparison results must never authorize delegation.
 * HOW: 1. Reject NULL. 2. Require the version's comparison to return exactly 1.
 */
static inline int
brix_crypto_pkey_equal(EVP_PKEY *left, EVP_PKEY *right)
{
    if (left == NULL || right == NULL) {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return EVP_PKEY_eq(left, right) == 1;
#else
    return EVP_PKEY_cmp(left, right) == 1;
#endif
}

/* ---- Copy a DH public number into caller-owned storage ----
 * WHAT: Return 1 and an owned BIGNUM on success, otherwise 0 and NULL.
 * WHY: Provider getters allocate while 1.1.1 getters borrow; callers need one
 *      invariant so cleanup cannot free the source key's internal number.
 * HOW: 1. Clear output. 2. Fetch or duplicate the native public number.
 */
static inline int
brix_crypto_dh_public(EVP_PKEY *key, BIGNUM **public_number)
{
    if (public_number == NULL) {
        return 0;
    }
    *public_number = NULL;
    if (key == NULL || EVP_PKEY_base_id(key) != EVP_PKEY_DH) {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PUB_KEY, public_number);
#else
    const DH *dh = EVP_PKEY_get0_DH(key);
    const BIGNUM *borrowed = NULL;

    if (dh == NULL) {
        return 0;
    }
    DH_get0_key(dh, &borrowed, NULL);
    if (borrowed != NULL) {
        *public_number = BN_dup(borrowed);
    }
    return *public_number != NULL;
#endif
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/* ---- Copy DH parameters without dropping the subgroup order ----
 * WHAT: Return an owned parameter-only DH or NULL; input remains borrowed.
 * WHY: A PKCS#3 encode/decode copy can lose q; peer validation needs p/q/g.
 * HOW: 1. Duplicate each present number. 2. Transfer only on complete success.
 */
static inline DH *
brix_crypto_dh_copy_parameters(const DH *source)
{
    const BIGNUM *p = NULL, *q = NULL, *g = NULL;
    BIGNUM *owned_p, *owned_q, *owned_g;
    DH *copy;

    DH_get0_pqg(source, &p, &q, &g);
    if (p == NULL || g == NULL) {
        return NULL;
    }
    owned_p = BN_dup(p);
    owned_q = q != NULL ? BN_dup(q) : NULL;
    owned_g = BN_dup(g);
    copy = DH_new();
    if (owned_p == NULL || owned_g == NULL || (q != NULL && owned_q == NULL)
        || copy == NULL || DH_set0_pqg(copy, owned_p, owned_q, owned_g) != 1) {
        BN_free(owned_p);
        BN_free(owned_q);
        BN_free(owned_g);
        DH_free(copy);
        return NULL;
    }
    return copy;
}

/* ---- Wrap a legacy DH peer using owned parameter/public copies ----
 * WHAT: Return an owned key or NULL; both input handles remain borrowed.
 * WHY: Isolate the legacy set0/set1 ownership boundary from provider imports.
 * HOW: 1. Copy the group. 2. Transfer a public-number copy. 3. Wrap and free.
 */
static inline EVP_PKEY *
brix_crypto_dh_peer_legacy(EVP_PKEY *parameters, const BIGNUM *public_number)
{
    const DH *borrowed = EVP_PKEY_get0_DH(parameters);
    DH *copy = borrowed != NULL ? brix_crypto_dh_copy_parameters(borrowed) : NULL;
    BIGNUM *public_copy = BN_dup(public_number);
    EVP_PKEY *peer = NULL;

    if (copy != NULL && public_copy != NULL
        && DH_set0_key(copy, public_copy, NULL) == 1) {
        public_copy = NULL;
        peer = EVP_PKEY_new();
        if (peer != NULL && EVP_PKEY_set1_DH(peer, copy) != 1) {
            EVP_PKEY_free(peer);
            peer = NULL;
        }
    }
    BN_free(public_copy);
    DH_free(copy);
    return peer;
}
#endif

/* ---- Attach a peer's DH public number to the negotiated parameters ----
 * WHAT: Return an owned public-only EVP_PKEY or NULL, retaining both inputs.
 * WHY: GSI must derive using the peer's actual group, not silently substitute it.
 * HOW: 1. Copy parameter material. 2. Add the public number. 3. Wrap and clean up.
 */
static inline EVP_PKEY *
brix_crypto_dh_peer(EVP_PKEY *parameters, const BIGNUM *public_number)
{
    if (parameters == NULL || public_number == NULL
        || EVP_PKEY_base_id(parameters) != EVP_PKEY_DH) {
        return NULL;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY *peer = NULL;
    OSSL_PARAM *original = NULL, *addition = NULL, *merged = NULL;
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);

    if (builder != NULL && context != NULL
        && EVP_PKEY_todata(parameters, EVP_PKEY_KEY_PARAMETERS, &original) == 1
        && OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PUB_KEY, public_number) == 1
        && (addition = OSSL_PARAM_BLD_to_param(builder)) != NULL
        && (merged = OSSL_PARAM_merge(original, addition)) != NULL
        && EVP_PKEY_fromdata_init(context) == 1) {
        if (EVP_PKEY_fromdata(context, &peer, EVP_PKEY_PUBLIC_KEY, merged) != 1) {
            EVP_PKEY_free(peer);
            peer = NULL;
        }
    }
    EVP_PKEY_CTX_free(context);
    OSSL_PARAM_free(merged);
    OSSL_PARAM_free(addition);
    OSSL_PARAM_free(original);
    OSSL_PARAM_BLD_free(builder);
    return peer;
#else
    return brix_crypto_dh_peer_legacy(parameters, public_number);
#endif
}
