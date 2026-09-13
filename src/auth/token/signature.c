/*
 * WHAT: Verify JWT signatures for RS256 and ES256 algorithms.
 *
 *   - RS256: RSA + SHA-256, uses OpenSSL EVP_DigestVerify directly
 *   - ES256: ECDSA P-256 + SHA-256, converts IEEE P1363 -> DER ASN.1
 *     - P1363 format: raw r||s, BRIX_ES256_SIG_SIZE bytes (BRIX_ES256_SIG_COMPONENT each)
 *     - Converts via ECDSA_SIG before EVP verification
 *   - Returns: 1 = valid, 0 = invalid or allocation failure
 */

/* WHY: JWT auth requires crypto verification before trusting token claims.
 *
 *   - INVARIANT #6: S3 SigV4 != WLCG token (no shared logic with S3 auth)
 *   - Exclusive to token validation path (src/token/validate.c)
 *   - RS256: primary algorithm for most JWKS providers
 *   - ES256: enables newer OIDC implementations using ECDSA keys
 *   - Three-step EVP chain (Init->Update->Final) = constant-time security
 */

/* HOW: Two verification paths.
 *
 *   RS256 (brix_token_verify_rs256):
 *     - EVP_MD_CTX_new()
 *     - EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey)
 *     - EVP_DigestVerifyUpdate(mdctx, signed_data, signed_len)
 *     - EVP_DigestVerifyFinal(mdctx, sig, sig_len)
 *     - Returns 0 on any step failure or ctx allocation failure
 *
 *   ES256 (brix_token_verify_es256):
 *     - Validate sig_len == BRIX_ES256_SIG_SIZE (P1363 = 2 * BRIX_ES256_SIG_COMPONENT)
 *     - BN_bin2bn() converts r, s to BIGNUM objects
 *     - ECDSA_SIG_new() + ECDSA_SIG_set0() transfers r/s ownership
 *     - i2d_ECDSA_SIG() produces DER-encoded ASN.1
 *     - Same three-step EVP verification chain as RS256
 *     - OPENSSL_free(der) cleanup
 *     - Multiple allocation failure paths return 0 with BN/ECDSA_SIG cleanup
 */

#include "token_internal.h"
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */

int
brix_token_verify_rs256(const u_char *signed_data, size_t signed_len,
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

    brix_evp_md_ctx_free(mdctx);
    return ok;
}

/*
 * Verify an ES256 (ECDSA P-256 + SHA-256) JWT signature.
 *
 * JWT ES256 signatures are IEEE P1363 format: raw r||s, each
 * BRIX_ES256_SIG_COMPONENT bytes (BRIX_ES256_SIG_SIZE total). OpenSSL
 * EVP_DigestVerifyFinal for EC keys expects DER-encoded ASN.1, so we
 * convert via ECDSA_SIG before calling the EVP interface.
 */
int
brix_token_verify_es256(const u_char *signed_data, size_t signed_len,
    const u_char *sig_p1363, size_t sig_len, EVP_PKEY *pkey)
{
    BIGNUM     *r, *s;
    ECDSA_SIG  *ecdsa_sig;
    u_char     *der;
    int         der_len;
    EVP_MD_CTX *mdctx;
    int         ok;

    if (sig_len != BRIX_ES256_SIG_SIZE) {
        return 0;
    }

    r = BN_bin2bn(sig_p1363,      BRIX_ES256_SIG_COMPONENT, NULL);
    s = BN_bin2bn(sig_p1363 + BRIX_ES256_SIG_COMPONENT, BRIX_ES256_SIG_COMPONENT, NULL);
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

    brix_evp_md_ctx_free(mdctx);
    OPENSSL_free(der);
    return ok;
}
