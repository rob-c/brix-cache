/*
 * WHAT: Verify JWT signatures for RS256 (RSA + SHA-256) and ES256 (ECDSA P-256 + SHA-256) algorithms. RS256 uses OpenSSL EVP_DigestVerify API directly; ES256 converts IEEE P1363 raw r||s format (64 bytes, each 32-byte component) to DER-encoded ASN.1 via ECDSA_SIG before calling EVP verification interface. Returns 1 for valid signature, 0 for invalid or allocation failure.
 */

/* WHY: JWT authentication requires cryptographic signature verification before trusting any claims extracted from the token payload. AGENTS.md INVARIANT #6 mandates "S3 SigV4 ≠ WLCG token — this function must not share logic with other authentication systems" — these functions are exclusively used by token validation path in src/token/validate.c and never shared with S3 auth handlers (src/s3/auth_sigv4_*.c). RS256 is the primary algorithm for most JWKS providers; ES256 support enables newer OIDC implementations using ECDSA keys. Three-step EVP verification chain (Init→Update→Final) provides constant-time comparison security against timing attacks. */

/* HOW: Two distinct verification paths. RS256 path (xrootd_token_verify_rs256): EVP_MD_CTX_new() → EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) with SHA-256 digest and RSA public key → EVP_DigestVerifyUpdate(mdctx, signed_data, signed_len) with JWT payload (header+body concatenated without separator) → EVP_DigestVerifyFinal(mdctx, sig, sig_len) with base64url-decoded signature bytes. Returns 0 on any step failure or ctx allocation failure. ES256 path (xrootd_token_verify_es256): validate sig_len==64 (P1363 format requires exactly 32+32 bytes) → BN_bin2bn() converts r and s components to BIGNUM objects → ECDSA_SIG_new() + ECDSA_SIG_set0() transfers ownership of r/s to signature struct → i2d_ECDSA_SIG() produces DER-encoded ASN.1 output → same three-step EVP verification chain as RS256 → OPENSSL_free(der) cleanup. Multiple allocation failure paths return 0 with appropriate BN/ECDSA_SIG cleanup. */

#include "token_internal.h"

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
