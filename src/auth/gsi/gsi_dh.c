/*
 * gsi_dh.c - extracted concern
 * Phase-38 split of gsi_core.c; behavior-identical.
 */
#include "gsi_core_internal.h"


EVP_PKEY *
brix_gsi_dh_keygen(void)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *k = NULL;
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
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return k;
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

    if (!EVP_PKEY_get_bn_param(dh, "pub", &pub)) {
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
    OSSL_PARAM     *mparams = NULL, *cparams = NULL, *merged = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    EVP_PKEY_CTX   *ctx = NULL;
    EVP_PKEY       *peer = NULL;

    if (EVP_PKEY_todata(mine, EVP_PKEY_KEY_PARAMETERS, &mparams) != 1) {
        return NULL;
    }
    bld = OSSL_PARAM_BLD_new();
    if (bld != NULL
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, peer_pub) == 1) {
        cparams = OSSL_PARAM_BLD_to_param(bld);
    }
    if (cparams != NULL) {
        merged = OSSL_PARAM_merge(mparams, cparams);
    }
    if (merged != NULL) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
        if (ctx != NULL && EVP_PKEY_fromdata_init(ctx) == 1) {
            if (EVP_PKEY_fromdata(ctx, &peer, EVP_PKEY_PUBLIC_KEY, merged) != 1) {
                peer = NULL;
            }
        }
    }

    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(merged);
    OSSL_PARAM_free(cparams);
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(mparams);
    return peer;
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
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    secret = (uint8_t *) malloc(*slen);
    if (secret == NULL || EVP_PKEY_derive(ctx, secret, slen) != 1) {
        free(secret);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return secret;
}


/*                                                                       */
/* (EOS) and our server talks to stock clients.  Both ends use one FIXED */

/* The fixed DH parameters, verbatim from XrdCryptosslCipher.cc. */

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
    EVP_PKEY_CTX_free(ctx);
    if (dhparams == NULL) {
        EVP_PKEY_free(params);
    }
    return key;
}
