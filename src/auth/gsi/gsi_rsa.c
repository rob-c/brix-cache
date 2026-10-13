/*
 * gsi_rsa.c - extracted concern
 * Phase-38 split of gsi_core.c; behavior-identical.
 */
#include "gsi_core_internal.h"
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */



int
brix_gsi_rand(uint8_t *out, size_t n)
{
    return RAND_bytes(out, (int) n) == 1;
}


/* ---- Generate one serialized-buffer-safe GSI random challenge tag ----
 *
 * WHAT: Fills out[8] with unbiased cryptographically random ASCII letters and
 *       digits. Returns 1 on success and 0 when the RNG fails.
 *
 * WHY: XrdSecgsi carries this challenge through its serialized-buffer parser;
 *      ':' is a field delimiter there and makes an otherwise valid handshake
 *      fail intermittently. Raw random bytes also include NUL. Alphanumeric
 *      bytes are opaque to that grammar while retaining 62 choices per byte.
 *
 * HOW: Draw bytes in batches, reject values >= 248 (the largest multiple of 62
 *      below 256), and map accepted bytes modulo the 62-character alphabet.
 */
int
brix_gsi_rand_tag(uint8_t out[8])
{
    static const uint8_t alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    uint8_t random[8];
    size_t  produced = 0;
    size_t  i;

    while (produced < sizeof(random)) {
        if (!brix_gsi_rand(random, sizeof(random))) {
            OPENSSL_cleanse(random, sizeof(random));
            return 0;
        }
        for (i = 0; i < sizeof(random) && produced < sizeof(random); i++) {
            if (random[i] < 248) {
                out[produced++] = alphabet[random[i] % 62];
            }
        }
    }
    OPENSSL_cleanse(random, sizeof(random));
    return 1;
}


/*
 * RSA private-key signature, byte-exact with XrdCryptosslRSA::EncryptPrivate:
 * EVP_PKEY_sign over the RAW input (no message digest) with RSA PKCS#1 v1.5
 * padding.  This is the GSI proof-of-possession op — the client signs the
 * server's random tag with the proxy private key (kXRS_signed_rtag); the server
 * recovers it with the public key.  `out` must hold >= EVP_PKEY_size(key) bytes.
 * Returns the signature length, or 0 on failure.  (Single-chunk: the rtag is far
 * smaller than the key modulus, so no chunking loop is needed.)
 */
size_t
brix_gsi_rsa_sign_raw(EVP_PKEY *key, const uint8_t *in, size_t inlen,
                        uint8_t *out)
{
    return brix_gsi_rsa_encrypt_private(key, in, inlen, out,
                                          (size_t) EVP_PKEY_size(key) + inlen);
}


/*
 * XrdCryptosslRSA::EncryptPrivate — RSA private-key "encrypt" (sign), chunked.
 * Input is split into <key_size - 11>-byte chunks; each is EVP_PKEY_sign'd with
 * PKCS#1 v1.5 into a key_size-byte output block.  Used to sign the DH cipher
 * blob (v>=DHsigned) and the rtag.  out must hold >= ceil(inlen/lcmax)*key_size.
 * Returns the total signature length, or 0.
 */
size_t
brix_gsi_rsa_encrypt_private(EVP_PKEY *key, const uint8_t *in, size_t inlen,
                               uint8_t *out, size_t outmax)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    size_t        ksz = (size_t) EVP_PKEY_size(key);
    size_t        lcmax = ksz > 11 ? ksz - 11 : 1;
    size_t        kk = 0, ke = 0;
    int           ok = 1;

    if (ctx == NULL || EVP_PKEY_sign_init(ctx) != 1
        || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
        brix_evp_pkey_ctx_free(ctx);
        return 0;
    }
    while (kk < inlen && ok) {
        size_t lc = (inlen - kk < lcmax) ? (inlen - kk) : lcmax;
        size_t lout = outmax - ke;
        if (EVP_PKEY_sign(ctx, out + ke, &lout, in + kk, lc) != 1) {
            ok = 0;
        } else {
            kk += lc;
            ke += lout;
        }
    }
    brix_evp_pkey_ctx_free(ctx);
    return ok ? ke : 0;
}


/*
 * XrdCryptosslRSA::DecryptPublic — RSA public-key "decrypt" (verify-recover),
 * chunked: each key_size-byte input block is EVP_PKEY_verify_recover'd (PKCS#1)
 * back to plaintext.  Recovers a DH cipher blob signed by the peer's cert key.
 * Returns the recovered length, or 0.
 */
size_t
brix_gsi_rsa_decrypt_public(EVP_PKEY *key, const uint8_t *in, size_t inlen,
                              uint8_t *out, size_t outmax)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    size_t        ksz = (size_t) EVP_PKEY_size(key);
    size_t        kk = 0, ke = 0;
    int           ok = 1;

    if (ctx == NULL || ksz == 0 || EVP_PKEY_verify_recover_init(ctx) != 1
        || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
        brix_evp_pkey_ctx_free(ctx);
        return 0;
    }
    while (kk + ksz <= inlen && ok) {
        size_t lout = outmax - ke;
        if (EVP_PKEY_verify_recover(ctx, out + ke, &lout, in + kk, ksz) != 1) {
            ok = 0;
        } else {
            kk += ksz;
            ke += lout;
        }
    }
    brix_evp_pkey_ctx_free(ctx);
    return ok ? ke : 0;
}
