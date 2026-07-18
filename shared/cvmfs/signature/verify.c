/* verify.c — CVMFS signature trust gate. See verify.h.
 *
 * CVMFS signs the *printed hash-line text* (the ASCII line after the "--\n"
 * marker) with RAW RSA-PKCS#1-v1.5 — i.e. RSA_private_encrypt of the hash text,
 * with NO SHA-1 DigestInfo. (Verified empirically against a real atlas.cern.ch
 * whitelist: RSA-public-recover of the signature yields the hash text verbatim.)
 * We verify with EVP_PKEY_verify + RSA_PKCS1_PADDING and no message digest, which
 * does that raw compare and also sidesteps the crypto-policy SHA-1 set_md gate.
 */
#include "cvmfs/signature/verify.h"
#include "cvmfs/object/object.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>

#include <string.h>

/* CVMFS signs the printed hash-line text, but with TWO schemes seen in the wild
 * (verified empirically against real atlas.cern.ch): the *manifest* is
 * RSA-PKCS#1-v1.5-SHA1 (a DigestInfo over SHA1(hash_text)); the *whitelist* is
 * RAW RSA-PKCS#1 (RSA_private_encrypt of the hash_text, no DigestInfo). We accept
 * EITHER. Both go through EVP_PKEY_verify with RSA_PKCS1_PADDING and no md, so we
 * never hit the policy-gated set_md path. */

static int rsa_verify_pkcs1(EVP_PKEY *pub, const unsigned char *tbs, size_t tbslen,
                            const unsigned char *sig, size_t slen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, NULL);
    if (ctx == NULL) return 0;
    int ok = EVP_PKEY_verify_init(ctx) == 1
          && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1
          && EVP_PKEY_verify(ctx, sig, slen, tbs, tbslen) == 1;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int rsa_pkcs1_verify_raw(EVP_PKEY *pub, const unsigned char *msg, size_t mlen,
                                const unsigned char *sig, size_t slen) {
    /* scheme A: raw PKCS#1 over the hash text (whitelist). */
    if (rsa_verify_pkcs1(pub, msg, mlen, sig, slen)) return 0;

    /* scheme B: PKCS#1 over the SHA-1 DigestInfo of the hash text (manifest). */
    static const unsigned char SHA1_DI_PREFIX[15] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
    unsigned char di[35], md[20];
    unsigned int  mdn = 0;
    EVP_MD_CTX   *c = EVP_MD_CTX_new();
    int ok = c != NULL
          && EVP_DigestInit_ex(c, EVP_sha1(), NULL) == 1
          && EVP_DigestUpdate(c, msg, mlen) == 1
          && EVP_DigestFinal_ex(c, md, &mdn) == 1 && mdn == 20;
    EVP_MD_CTX_free(c);
    if (!ok) return -1;
    memcpy(di, SHA1_DI_PREFIX, 15);
    memcpy(di + 15, md, 20);
    return rsa_verify_pkcs1(pub, di, sizeof(di), sig, slen) ? 0 : -1;
}

/* Bind the parsed body to the RSA-signed hash line. The hash line is CVMFS's own
 * printed digest of the body up to and including "--\n"; recomputing it and
 * comparing is what makes the signature cover the WHOLE artifact. Without it the
 * signature covers only the literal hash-line text, leaving every KV field and
 * fingerprint above "--" unauthenticated (an attacker keeps the hash-line +
 * signature and rewrites the body). Fail-closed: an unparsed/mismatched hash
 * line is treated as unbound. */
static int body_bound_to_hash(const unsigned char *body, size_t body_len,
                              const cvmfs_hash_t *signed_hash) {
    if (signed_hash->len == 0) return 0;
    /* Stock CVMFS hashes the body up to but EXCLUDING the "--\n" separator
     * (verified against live stratum-1 .cvmfspublished/.cvmfswhitelist); the
     * parsers record signed_body_len THROUGH the separator as the parse
     * offset, so strip it here. */
    if (body_len < 3) return 0;
    body_len -= 3;
    cvmfs_hash_t got;
    if (cvmfs_object_hash(signed_hash->algo, body, body_len, &got) != 0) return 0;
    return cvmfs_hash_eq(&got, signed_hash);
}

/* Parse an X.509 cert from PEM or, failing that, DER — real CVMFS cert objects
 * are DER, but our own fixtures and some tools emit PEM. */
static X509 *cert_from_pem(const unsigned char *pem, size_t len) {
    BIO *b = BIO_new_mem_buf(pem, (int) len);
    if (b == NULL) return NULL;
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    if (x == NULL) {
        const unsigned char *p = pem;
        x = d2i_X509(NULL, &p, (long) len);
    }
    return x;
}

int cvmfs_verify_manifest(const cvmfs_manifest_t *m, const unsigned char *cert_pem, size_t cert_len) {
    if (m->signed_hash_text == NULL || m->signed_hash_text_len == 0) return -1;

    X509 *x = cert_from_pem(cert_pem, cert_len);
    if (x == NULL) return -1;

    EVP_PKEY *pk = X509_get_pubkey(x);
    int rc = pk ? rsa_pkcs1_verify_raw(pk, m->signed_hash_text, m->signed_hash_text_len,
                                        m->signature, m->signature_len)
                : -1;
    EVP_PKEY_free(pk);
    X509_free(x);
    if (rc != 0) return rc;
    /* The signature is authentic — now bind it to the manifest body. */
    return body_bound_to_hash(m->signed_body, m->signed_body_len, &m->signed_hash) ? 0 : -1;
}

int cvmfs_cert_fingerprint(const unsigned char *cert_pem, size_t cert_len, char *out, size_t outlen) {
    X509 *x = cert_from_pem(cert_pem, cert_len);
    if (x == NULL) return -1;

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  mdn = 0;
    int           rc  = X509_digest(x, EVP_sha1(), md, &mdn);
    X509_free(x);
    if (rc != 1 || outlen < (size_t) mdn * 3) return -1;

    static const char hx[] = "0123456789ABCDEF";
    size_t o = 0;
    for (unsigned int i = 0; i < mdn; i++) {
        if (i) out[o++] = ':';
        out[o++] = hx[md[i] >> 4];
        out[o++] = hx[md[i] & 0xf];
    }
    out[o] = '\0';
    return 0;
}

int cvmfs_verify_whitelist(const cvmfs_whitelist_t *w, const unsigned char *master_pub_pem, size_t pub_len) {
    if (w->signed_hash_text == NULL || w->signed_hash_text_len == 0) return -1;

    /* `master_pub_pem` may concatenate several master public keys (CVMFS rotates
     * them, e.g. cern-it1/it4/it5); accept the whitelist if ANY of them verifies. */
    BIO *b = BIO_new_mem_buf(master_pub_pem, (int) pub_len);
    if (b == NULL) return -1;

    int       rc = -1;
    EVP_PKEY *pk;
    while ((pk = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL)) != NULL) {
        int ok = rsa_pkcs1_verify_raw(pk, w->signed_hash_text, w->signed_hash_text_len,
                                       w->signature, w->signature_len) == 0;
        EVP_PKEY_free(pk);
        if (ok) { rc = 0; break; }
    }
    BIO_free(b);
    if (rc != 0) return rc;
    /* Master signature is authentic — bind it to the whitelist body so the
     * fingerprint list (and expiry) cannot be edited under a valid signature.
     * This is what defeats the keyless substitute-cert forgery. */
    return body_bound_to_hash(w->signed_body, w->signed_body_len, &w->signed_hash) ? 0 : -1;
}
