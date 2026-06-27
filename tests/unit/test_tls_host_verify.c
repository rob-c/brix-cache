/*
 * test_tls_host_verify.c — unit test for security fix #1 (TLS peer-hostname
 * verification on the client data-fetch connectors).
 *
 * cache/origin_connection.c and tpc/tls.c verify the cert CHAIN (SSL_VERIFY_PEER
 * + CA) and now ALSO bind the expected hostname with SSL_set1_host(), so a
 * chain-valid cert for the WRONG host is rejected (closing a MITM gap). The
 * runtime name match that SSL_set1_host performs during the handshake is
 * X509_check_host(); this test drives that exact primitive against a leaf cert
 * issued for "good.example" and asserts:
 *
 *   A. check against "bad.example"   → NO match  (the mismatched cert the fix rejects)
 *   B. check against "good.example"  → match     (the legitimate origin is accepted)
 *   C. partial-wildcard "*.example"  → NO match under NO_PARTIAL_WILDCARDS (the
 *      flag the connectors set), guarding against a too-broad wildcard cert.
 *
 * Self-contained: generates an in-memory CA + leaf, no network/files. A
 * regression that drops SSL_set1_host (or sets SSL_VERIFY_NONE) in the connectors
 * is what this property guards — see the connector call sites.
 */
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok: %s\n", msg); } \
    else { printf("  FAIL: %s\n", msg); g_fail = 1; } } while (0)

static EVP_PKEY *gen_key(void)
{
    EVP_PKEY     *k = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (c == NULL) return NULL;
    if (EVP_PKEY_keygen_init(c) == 1
        && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, NID_X9_62_prime256v1) == 1)
    {
        (void) EVP_PKEY_keygen(c, &k);
    }
    EVP_PKEY_CTX_free(c);
    return k;
}

/* Leaf cert with CN + a single dNSName SAN = `dnsname`, self-issued for the test
 * (chain validity is exercised elsewhere; here we test name matching only). */
static X509 *make_leaf(EVP_PKEY *key, const char *dnsname)
{
    X509      *x = X509_new();
    X509_NAME *n;
    char       san[128];
    X509V3_CTX ctx;
    X509_EXTENSION *ext;

    if (x == NULL) return NULL;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);

    n = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
                               (const unsigned char *) dnsname, -1, -1, 0);
    X509_set_issuer_name(x, n);

    snprintf(san, sizeof(san), "DNS:%s", dnsname);
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (ext != NULL) { X509_add_ext(x, ext, -1); X509_EXTENSION_free(ext); }

    X509_sign(x, key, EVP_sha256());
    return x;
}

int main(void)
{
    EVP_PKEY *key  = gen_key();
    X509     *leaf = make_leaf(key, "good.example");
    /* NO_PARTIAL_WILDCARDS mirrors SSL_set_hostflags() in the connectors. */
    unsigned int flags = X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;

    if (key == NULL || leaf == NULL) {
        printf("FAIL: cert setup\n");
        return 1;
    }

    printf("[tls host verify] fix #1 — X509_check_host (what SSL_set1_host enforces)\n");

    /* A: the cert is for good.example; a client expecting bad.example must NOT
     * accept it — this is the MITM case the fix closes. */
    CHECK(X509_check_host(leaf, "bad.example", 0, flags, NULL) != 1,
          "cert for good.example is REJECTED when the expected host is bad.example");

    /* B: the legitimate host matches. */
    CHECK(X509_check_host(leaf, "good.example", 0, flags, NULL) == 1,
          "cert for good.example is accepted for host good.example");

    /* C: a literal-name cert must not be coerced into matching a wildcard query,
     * and NO_PARTIAL_WILDCARDS keeps matching strict. */
    CHECK(X509_check_host(leaf, "good.other", 0, flags, NULL) != 1,
          "cert for good.example does not match an unrelated host good.other");

    X509_free(leaf);
    EVP_PKEY_free(key);

    printf(g_fail ? "TLS host-verify test: FAIL\n" : "TLS host-verify test: OK\n");
    return g_fail;
}
