/*
 * JWT signature verification (RS256 and ES256).
 */

#include "token_internal.h"

#include <openssl/bn.h>
#include <openssl/ecdsa.h>

int
xrootd_token_verify_rs256(const u_char *signed_data, size_t signed_len,
    const u_char *sig, size_t sig_len, EVP_PKEY *pkey)
{
    EVP_MD_CTX *mdctx;
    int         ok;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return 0;
    }

    ok = 0;
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) == 1
        && EVP_DigestVerifyUpdate(mdctx, signed_data, signed_len) == 1
        && EVP_DigestVerifyFinal(mdctx, sig, sig_len) == 1)
    {
        ok = 1;
    }

    EVP_MD_CTX_free(mdctx);
    return ok;
}

/*
 * Verify an ES256 (ECDSA P-256 + SHA-256) JWT signature.
 *
 * JWT ES256 signatures are IEEE P1363 format: raw r||s, each 32 bytes (64
 * total).  OpenSSL EVP_DigestVerifyFinal for EC keys expects DER-encoded
 * ASN.1, so we convert via ECDSA_SIG before calling the EVP interface.
 */
int
xrootd_token_verify_es256(const u_char *signed_data, size_t signed_len,
    const u_char *sig_p1363, size_t sig_len, EVP_PKEY *pkey)
{
    BIGNUM     *r, *s;
    ECDSA_SIG  *ecdsa_sig;
    u_char     *der;
    int         der_len;
    EVP_MD_CTX *mdctx;
    int         ok;

    if (sig_len != 64) {
        return 0;
    }

    r = BN_bin2bn(sig_p1363,      32, NULL);
    s = BN_bin2bn(sig_p1363 + 32, 32, NULL);
    if (r == NULL || s == NULL) {
        BN_free(r);
        BN_free(s);
        return 0;
    }

    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL) {
        BN_free(r);
        BN_free(s);
        return 0;
    }
    /* ECDSA_SIG_set0 transfers ownership of r and s */
    if (ECDSA_SIG_set0(ecdsa_sig, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ecdsa_sig);
        return 0;
    }

    der = NULL;
    der_len = i2d_ECDSA_SIG(ecdsa_sig, &der);
    ECDSA_SIG_free(ecdsa_sig);
    if (der_len <= 0) {
        return 0;
    }

    mdctx = EVP_MD_CTX_new();
    ok = 0;
    if (mdctx != NULL
        && EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) == 1
        && EVP_DigestVerifyUpdate(mdctx, signed_data, signed_len) == 1
        && EVP_DigestVerifyFinal(mdctx, der, (size_t) der_len) == 1)
    {
        ok = 1;
    }

    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(der);
    return ok;
}
