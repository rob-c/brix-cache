/*
 * sign_unittest.c — standalone tests for the manifest/whitelist signers,
 * verified against the read-path oracle (manifest.c/whitelist.c/verify.c).
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_sign_ut \
 *       shared/cvmfs/signature/sign_unittest.c shared/cvmfs/signature/sign.c \
 *       shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
 *       shared/cvmfs/signature/verify.c shared/cvmfs/object/object.c \
 *       shared/cvmfs/grammar/hash.c -lcrypto -lz && /tmp/cvmfs_sign_ut
 * Exit 0 = all checks pass.
 */
#include "cvmfs/signature/sign.h"
#include "cvmfs/signature/manifest.h"
#include "cvmfs/signature/whitelist.h"
#include "cvmfs/signature/verify.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

/* PEM-encode a self-signed cert for `pk` into buf; returns length or -1. */
static int make_cert_pem(EVP_PKEY *pk, unsigned char *buf, size_t cap) {
    X509 *x = X509_new();
    X509_set_pubkey(x, pk);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_sign(x, pk, EVP_sha256());
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b, x);
    int n = BIO_read(b, buf, (int) cap);
    BIO_free(b);
    X509_free(x);
    return n;
}

static int make_pub_pem(EVP_PKEY *pk, unsigned char *buf, size_t cap) {
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(b, pk);
    int n = BIO_read(b, buf, (int) cap);
    BIO_free(b);
    return n;
}

static cvmfs_hash_t hash_of(const char *hex) {
    cvmfs_hash_t h;
    memset(&h, 0, sizeof(h));
    cvmfs_hash_parse(hex, strlen(hex), &h);
    return h;
}

static void test_load_key(EVP_PKEY *pk) {
    char path[128];
    snprintf(path, sizeof(path), "/tmp/cvmfs_sign_ut_key.%d.pem", getpid());
    FILE *f = fopen(path, "w");
    PEM_write_PrivateKey(f, pk, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    EVP_PKEY *back = cvmfs_sign_load_key(path);
    CHECK(back != NULL, "load_key reads a PEM private key");
    CHECK(back != NULL && EVP_PKEY_eq(back, pk) == 1, "load_key round-trips the key");
    EVP_PKEY_free(back);
    unlink(path);
    CHECK(cvmfs_sign_load_key(path) == NULL, "load_key on a missing file fails");
}

static void test_manifest(EVP_PKEY *certpk, const unsigned char *cert_pem, int cert_len,
                          EVP_PKEY *otherpk) {
    cvmfs_manifest_wr_t m;
    memset(&m, 0, sizeof(m));
    m.root_catalog = hash_of("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    m.certificate  = hash_of("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    m.history      = hash_of("cccccccccccccccccccccccccccccccccccccccc");
    m.reflog_checksum = hash_of("dddddddddddddddddddddddddddddddddddddddd");
    m.catalog_size = 4096;
    m.revision = 7;
    m.fqrn = "unit.brix.io";
    m.timestamp = 1750000000;
    m.ttl = 240;

    char body[1024];
    int blen = cvmfs_manifest_body(&m, body, sizeof(body));
    CHECK(blen > 0, "manifest body renders");
    CHECK(blen > 0 && strstr(body, "Hcccccccc") != NULL, "H line emitted when set");
    CHECK(blen > 0 && strstr(body, "Ydddddddd") != NULL, "Y line emitted when set");

    unsigned char art[4096];
    size_t alen = 0;
    CHECK(cvmfs_sign_artifact((unsigned char *) body, (size_t) blen, certpk,
                              1, art, sizeof(art), &alen) == 0, "manifest signs");

    cvmfs_manifest_t parsed;
    CHECK(cvmfs_manifest_parse(art, alen, &parsed) == 0, "signed manifest parses");
    CHECK(cvmfs_hash_eq(&parsed.root_catalog, &m.root_catalog), "parsed C matches");
    CHECK(cvmfs_hash_eq(&parsed.history, &m.history), "parsed H matches");
    CHECK(cvmfs_hash_eq(&parsed.reflog_checksum, &m.reflog_checksum), "parsed Y matches");
    CHECK(parsed.revision == 7 && parsed.ttl == 240
          && parsed.timestamp == 1750000000
          && strcmp(parsed.repo_name, "unit.brix.io") == 0, "parsed S/D/T/N match");
    CHECK(cvmfs_verify_manifest(&parsed, cert_pem, (size_t) cert_len) == 0,
          "verify.c accepts the signature");

    /* optional hashes omitted when unset */
    cvmfs_manifest_wr_t m2 = m;
    memset(&m2.history, 0, sizeof(m2.history));
    memset(&m2.reflog_checksum, 0, sizeof(m2.reflog_checksum));
    char body2[1024];
    int blen2 = cvmfs_manifest_body(&m2, body2, sizeof(body2));
    CHECK(blen2 > 0 && strchr(body2, 'H') == NULL && strchr(body2, 'Y') == NULL,
          "H/Y omitted when unset");

    /* errors */
    cvmfs_manifest_wr_t bad = m;
    memset(&bad.root_catalog, 0, sizeof(bad.root_catalog));
    char scratch[1024];
    CHECK(cvmfs_manifest_body(&bad, scratch, sizeof(scratch)) == -1,
          "missing root catalog refused");
    CHECK(cvmfs_manifest_body(&m, scratch, 16) == -1, "tiny buffer refused");
    char tiny[64];
    CHECK(cvmfs_sign_artifact((unsigned char *) body2, (size_t) blen2, certpk,
                              1, (unsigned char *) tiny, sizeof(tiny), &alen) == -1,
          "artifact overflow refused");
    CHECK(cvmfs_sign_artifact((unsigned char *) body2, (size_t) blen2, NULL,
                              1, art, sizeof(art), &alen) == -1, "NULL key refused");

    /* security-negative: tampered body must fail verification */
    unsigned char evil[4096];
    size_t elen = 0;
    cvmfs_sign_artifact((unsigned char *) body, (size_t) blen, certpk,
                        1, evil, sizeof(evil), &elen);
    evil[1] ^= 0x01;                                /* corrupt the C line */
    cvmfs_manifest_t tampered;
    CHECK(cvmfs_manifest_parse(evil, elen, &tampered) != 0
          || cvmfs_verify_manifest(&tampered, cert_pem, (size_t) cert_len) != 0,
          "tampered manifest rejected");

    /* security-negative: signed by the wrong key must fail */
    size_t wlen = 0;
    cvmfs_sign_artifact((unsigned char *) body, (size_t) blen, otherpk,
                        1, evil, sizeof(evil), &wlen);
    cvmfs_manifest_t wrongkey;
    CHECK(cvmfs_manifest_parse(evil, wlen, &wrongkey) == 0
          && cvmfs_verify_manifest(&wrongkey, cert_pem, (size_t) cert_len) != 0,
          "wrong-key manifest rejected");
}

static void test_whitelist(EVP_PKEY *master, const unsigned char *master_pub, int pub_len,
                           const unsigned char *cert_pem, int cert_len) {
    char fps[2][60];
    CHECK(cvmfs_cert_fingerprint(cert_pem, (size_t) cert_len,
                                 fps[0], sizeof(fps[0])) == 0, "cert fingerprint");
    snprintf(fps[1], sizeof(fps[1]), "%s", fps[0]);
    fps[1][0] = fps[1][0] == 'A' ? 'B' : 'A';       /* a second, distinct FP */

    char body[2048];
    int blen = cvmfs_whitelist_body("20260101000000", "20991231235959", "unit.brix.io",
                                    (const char (*)[60]) fps, 2, body, sizeof(body));
    CHECK(blen > 0, "whitelist body renders");

    unsigned char art[4096];
    size_t alen = 0;
    CHECK(cvmfs_sign_artifact((unsigned char *) body, (size_t) blen, master,
                              0, art, sizeof(art), &alen) == 0, "whitelist signs");

    cvmfs_whitelist_t parsed;
    CHECK(cvmfs_whitelist_parse(art, alen, &parsed) == 0, "signed whitelist parses");
    CHECK(parsed.n_fingerprints == 2 && cvmfs_whitelist_lists_fp(&parsed, fps[0]),
          "whitelist lists the cert fingerprint");
    CHECK(!cvmfs_whitelist_expired(&parsed, 1750000000), "whitelist not expired");
    CHECK(cvmfs_verify_whitelist(&parsed, master_pub, (size_t) pub_len) == 0,
          "verify.c accepts the whitelist signature");

    /* errors */
    CHECK(cvmfs_whitelist_body(NULL, "2099", "r", (const char (*)[60]) fps, 1,
                               body, sizeof(body)) == -1, "short expiry refused");
    CHECK(cvmfs_whitelist_body(NULL, "20991231235959", "r", (const char (*)[60]) fps, 0,
                               body, sizeof(body)) == -1, "zero fingerprints refused");

    /* security-negative: flipped fingerprint byte breaks the signature */
    unsigned char evil[4096];
    memcpy(evil, art, alen);
    evil[20] ^= 0x01;                                /* inside the body */
    cvmfs_whitelist_t tampered;
    CHECK(cvmfs_whitelist_parse(evil, alen, &tampered) != 0
          || cvmfs_verify_whitelist(&tampered, master_pub, (size_t) pub_len) != 0,
          "tampered whitelist rejected");
}

int main(void) {
    EVP_PKEY *certpk = EVP_RSA_gen(2048);
    EVP_PKEY *master = EVP_RSA_gen(2048);
    if (certpk == NULL || master == NULL) { fprintf(stderr, "keygen failed\n"); return 1; }

    unsigned char cert_pem[8192], master_pub[4096];
    int cert_len = make_cert_pem(certpk, cert_pem, sizeof(cert_pem));
    int pub_len  = make_pub_pem(master, master_pub, sizeof(master_pub));
    if (cert_len <= 0 || pub_len <= 0) { fprintf(stderr, "pem encode failed\n"); return 1; }

    test_load_key(certpk);
    test_manifest(certpk, cert_pem, cert_len, master);
    test_whitelist(master, master_pub, pub_len, cert_pem, cert_len);

    EVP_PKEY_free(certpk);
    EVP_PKEY_free(master);
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
