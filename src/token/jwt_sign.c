/*
 * jwt_sign.c — ES256 JWT minting (see jwt_sign.h for the contract).
 *
 * The signature path is the exact inverse of xrootd_token_verify_es256()
 * (signature.c): sign with EVP_DigestSign to get a DER ECDSA signature, then
 * convert DER → IEEE P1363 raw r||s (32+32 bytes) as JWT requires. All buffers
 * are local; the only heap object is the DER signature, freed on every path.
 */

#include "jwt_sign.h"
#include "b64url.h"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <string.h>


EVP_PKEY *
xrootd_jwt_load_ec_key(const char *pem_path)
{
    BIO      *bio;
    EVP_PKEY *pkey;

    bio = BIO_new_file(pem_path, "r");
    if (bio == NULL) {
        return NULL;
    }
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        return NULL;
    }
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}


/* xrootd_jwt_der_to_p1363 — DER ECDSA sig → fixed 64-byte r||s * Returns 0 on success (raw[0..63] populated), -1 on failure. */
static int
xrootd_jwt_der_to_p1363(const unsigned char *der, size_t der_len,
    unsigned char raw[64])
{
    const unsigned char *p = der;
    ECDSA_SIG           *sig;
    const BIGNUM        *r, *s;

    sig = d2i_ECDSA_SIG(NULL, &p, (long) der_len);
    if (sig == NULL) {
        return -1;
    }
    ECDSA_SIG_get0(sig, &r, &s);

    /* BN_bn2binpad left-pads each component to exactly 32 bytes (P-256). */
    if (BN_bn2binpad(r, raw, 32) != 32 || BN_bn2binpad(s, raw + 32, 32) != 32) {
        ECDSA_SIG_free(sig);
        return -1;
    }
    ECDSA_SIG_free(sig);
    return 0;
}


ngx_int_t
xrootd_jwt_sign_es256(EVP_PKEY *eckey, const char *header_json,
    const char *payload_json, char *out, size_t outsz)
{
    EVP_MD_CTX    *mdctx;
    unsigned char *der = NULL;
    unsigned char  raw[64];
    char           signing_input[4096];
    char           sig_b64[128];
    size_t         der_len = 0;
    int            n, hlen, plen;

    /* signing input = b64url(header) "." b64url(payload) */
    hlen = (int) ngx_strlen(header_json);
    plen = (int) ngx_strlen(payload_json);

    /* Encode header. */
    b64url_encode(header_json, (size_t) hlen, signing_input, sizeof(signing_input));
    n = (int) ngx_strlen(signing_input);
    if (n <= 0 || (size_t) n + 1 >= sizeof(signing_input)) {
        return NGX_ERROR;
    }
    signing_input[n++] = '.';

    /* Encode payload directly after the dot. */
    b64url_encode(payload_json, (size_t) plen, signing_input + n,
                  sizeof(signing_input) - (size_t) n);
    if (ngx_strlen(signing_input + n) == 0) {
        return NGX_ERROR;
    }
    n = (int) ngx_strlen(signing_input);

    /* Sign "header.payload" → DER ECDSA signature. */
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return NGX_ERROR;
    }
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, eckey) != 1
        || EVP_DigestSign(mdctx, NULL, &der_len,
                          (const unsigned char *) signing_input, (size_t) n) != 1
        || der_len == 0)
    {
        EVP_MD_CTX_free(mdctx);
        return NGX_ERROR;
    }
    der = OPENSSL_malloc(der_len);
    if (der == NULL) {
        EVP_MD_CTX_free(mdctx);
        return NGX_ERROR;
    }
    if (EVP_DigestSign(mdctx, der, &der_len,
                       (const unsigned char *) signing_input, (size_t) n) != 1)
    {
        OPENSSL_free(der);
        EVP_MD_CTX_free(mdctx);
        return NGX_ERROR;
    }
    EVP_MD_CTX_free(mdctx);

    /* DER → raw r||s → base64url. */
    if (xrootd_jwt_der_to_p1363(der, der_len, raw) != 0) {
        OPENSSL_free(der);
        return NGX_ERROR;
    }
    OPENSSL_free(der);

    b64url_encode((const char *) raw, sizeof(raw), sig_b64, sizeof(sig_b64));
    if (ngx_strlen(sig_b64) == 0) {
        return NGX_ERROR;
    }

    /* out = signing_input "." signature */
    n = snprintf(out, outsz, "%s.%s", signing_input, sig_b64);
    if (n < 0 || (size_t) n >= outsz) {
        return NGX_ERROR;
    }
    return NGX_OK;
}
