/*
 * gsi_dh.c - extracted concern
 * Phase-38 split of gsi_core.c; behavior-identical.
 */
#include "gsi_core_internal.h"
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */


EVP_PKEY *
brix_gsi_dh_keygen(void)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *k = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM    params[] = {
        OSSL_PARAM_utf8_string("group", "ffdhe2048", 0),
        OSSL_PARAM_END
    };

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_params(ctx, params) <= 0
        || EVP_PKEY_keygen(ctx, &k) <= 0) {
        brix_evp_pkey_ctx_free(ctx);
        return NULL;
    }
    brix_evp_pkey_ctx_free(ctx);
    return k;
#else
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) == 1
        && EVP_PKEY_CTX_set_dh_nid(ctx, NID_ffdhe2048) == 1
        && EVP_PKEY_keygen(ctx, &k) == 1) {
        brix_evp_pkey_ctx_free(ctx);
        return k;
    }
    brix_evp_pkey_ctx_free(ctx);
    brix_evp_pkey_free(k);
    return NULL;
#endif
}


BIGNUM *
brix_gsi_dh_pub_decode(const uint8_t *blob, size_t len)
{
    static const char b[] = "---BPUB---";
    static const char e[] = "---EPUB--";
    const uint8_t    *s = memmem(blob, len, b, sizeof(b) - 1);
    const uint8_t    *t = memmem(blob, len, e, sizeof(e) - 1);
    char             *hex;
    size_t            hl;
    BIGNUM           *bn = NULL;

    if (s == NULL || t == NULL || t <= s + (sizeof(b) - 1)) {
        return NULL;
    }
    s += sizeof(b) - 1;
    hl = (size_t) (t - s);
    hex = (char *) malloc(hl + 1);
    if (hex == NULL) {
        return NULL;
    }
    memcpy(hex, s, hl);
    hex[hl] = '\0';
    if (BN_hex2bn(&bn, hex) == 0) {
        free(hex);
        BN_free(bn);
        return NULL;
    }
    free(hex);
    return bn;
}


char *
brix_gsi_dh_pub_encode(EVP_PKEY *dh)
{
    BIGNUM *pub = NULL;
    char   *hex, *blob;
    size_t  n;

    if (!brix_crypto_dh_public(dh, &pub)) {
        return NULL;
    }
    hex = BN_bn2hex(pub);
    BN_free(pub);
    if (hex == NULL) {
        return NULL;
    }
    n = strlen(hex) + 32;
    blob = (char *) malloc(n);
    if (blob != NULL) {
        snprintf(blob, n, "---BPUB---%s---EPUB--", hex);
    }
    OPENSSL_free(hex);
    return blob;
}


EVP_PKEY *
brix_gsi_dh_build_peer(EVP_PKEY *mine, BIGNUM *peer_pub)
{
    return brix_crypto_dh_peer(mine, peer_pub);
}


uint8_t *
brix_gsi_dh_derive(EVP_PKEY *mine, EVP_PKEY *peer, size_t *slen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(mine, NULL);
    uint8_t      *secret = NULL;

    /* dh_pad=0 → unpadded big-endian secret (leading zeros stripped); both sides
     * must use the same so SHA256(secret) and the AES key match. */
    if (ctx == NULL
        || EVP_PKEY_derive_init(ctx) != 1
        || EVP_PKEY_CTX_set_dh_pad(ctx, 0) != 1
        || EVP_PKEY_derive_set_peer(ctx, peer) != 1
        || EVP_PKEY_derive(ctx, NULL, slen) != 1) {
        brix_evp_pkey_ctx_free(ctx);
        return NULL;
    }
    secret = (uint8_t *) malloc(*slen);
    if (secret == NULL || EVP_PKEY_derive(ctx, secret, slen) != 1) {
        free(secret);
        brix_evp_pkey_ctx_free(ctx);
        return NULL;
    }
    brix_evp_pkey_ctx_free(ctx);
    return secret;
}


/*                                                                       */
/* (EOS) and our server talks to stock clients.  Both ends use one FIXED */

/* The fixed DH parameters stock XrdSecgsi negotiates with. */

/* Load the fixed DH params as an EVP_PKEY (params only). */
EVP_PKEY *
gsi_fixed_dh_params(void)
{
    BIO      *bio = BIO_new_mem_buf(brix_gsi_dh_params_pem, -1);
    EVP_PKEY *p   = NULL;

    if (bio != NULL) {
        p = PEM_read_bio_Parameters(bio, NULL);
        BIO_free(bio);
    }
    return p;
}


/* Generate a DH keypair using the params held by `dhparams` (a params-or-public
 * EVP_PKEY).  NULL → the fixed 3072-bit params. */
EVP_PKEY *
gsi_dh_keygen_with(EVP_PKEY *dhparams)
{
    EVP_PKEY     *params = dhparams ? dhparams : gsi_fixed_dh_params();
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *key = NULL;

    if (params == NULL) {
        return NULL;
    }
    ctx = EVP_PKEY_CTX_new(params, NULL);
    if (ctx != NULL && EVP_PKEY_keygen_init(ctx) == 1) {
        EVP_PKEY_keygen(ctx, &key);
    }
    brix_evp_pkey_ctx_free(ctx);
    if (dhparams == NULL) {
        brix_evp_pkey_free(params);
    }
    return key;
}
