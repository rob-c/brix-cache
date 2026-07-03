/* Standalone unit suite for the GSI proxy-delegation crypto (phase-57 §F6):
 *   brix_gsi_build_pxyreq   (request a proxy)
 *   brix_gsi_sign_pxyreq    (issue/sign a proxy from a request)
 *   brix_gsi_assemble_proxy (assemble the delegated credential)
 *
 * No nginx, no network, no stock interop — pure OpenSSL. Exercises every stage
 * plus the full create->sign->assemble round-trip, RFC-3820 chain verification
 * against a CA, two-level delegation (proxy-of-a-proxy + path length), and
 * negative cases (subject mismatch, key mismatch, garbage input, NULL args).
 *
 *   gcc -Wall -Wextra -I src src/gsi/proxy_req.c src/gsi/proxy_req_unittest.c \
 *       -lcrypto -o /tmp/pxr && /tmp/pxr
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

#include "proxy_req.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                                  \
        checks++;                                                              \
        if (!(cond)) { failures++; printf("  FAIL: %s\n", (msg)); }           \
        else { printf("  ok: %s\n", (msg)); }                                 \
    } while (0)

/* helpers */
static EVP_PKEY *genkey(void)
{
    EVP_PKEY     *k = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (c && EVP_PKEY_keygen_init(c) > 0
        && EVP_PKEY_CTX_set_rsa_keygen_bits(c, 2048) > 0) {
        EVP_PKEY_keygen(c, &k);
    }
    EVP_PKEY_CTX_free(c);
    return k;
}

static uint8_t *pem_of(X509 *x, size_t *len)
{
    BIO *b = BIO_new(BIO_s_mem());
    char *d;
    long  n;
    uint8_t *out;
    PEM_write_bio_X509(b, x);
    n = BIO_get_mem_data(b, &d);
    out = malloc((size_t) n + 1);
    memcpy(out, d, (size_t) n);
    out[n] = '\0';
    *len = (size_t) n;
    BIO_free(b);
    return out;
}

/* Make a cert (self-signed if ca==NULL, else signed by ca/cakey) with keyUsage,
 * and CA:TRUE if is_ca. Returns the X509 + sets *key. */
static X509 *mkcert(const char *cn, int is_ca, X509 *ca, EVP_PKEY *cakey,
                    EVP_PKEY **key)
{
    EVP_PKEY *k = genkey();
    X509     *x = X509_new();
    X509_NAME *n;
    X509_EXTENSION *e;

    *key = k;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), (long) (rand() % 1000000 + 2));
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, k);
    n = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n, "O", MBSTRING_ASC, (const unsigned char *) "T", -1, -1, 0);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *) cn, -1, -1, 0);
    X509_set_issuer_name(x, ca ? X509_get_subject_name(ca) : n);
    if (is_ca) {
        e = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
        if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); }
        e = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,keyCertSign,cRLSign");
        if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); }
    } else {
        e = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
                                "critical,digitalSignature,keyEncipherment");
        if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); }
    }
    X509_sign(x, ca ? cakey : k, EVP_sha256());
    return x;
}

/* Verify `leaf` chains to `ca` through the `inter` certs, allowing proxies. */
static int verify_proxy(X509 *leaf, X509 *ca, X509 **inter, int ninter)
{
    X509_STORE     *store = X509_STORE_new();
    STACK_OF(X509) *unt = sk_X509_new_null();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int             rc, i;

    X509_STORE_add_cert(store, ca);
    X509_STORE_set_flags(store, X509_V_FLAG_ALLOW_PROXY_CERTS);
    for (i = 0; i < ninter; i++) sk_X509_push(unt, inter[i]);
    X509_STORE_CTX_init(ctx, store, leaf, unt);
    rc = X509_verify_cert(ctx);
    if (rc != 1) {
        printf("    verify err: %s\n",
               X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }
    X509_STORE_CTX_free(ctx);
    sk_X509_free(unt);
    X509_STORE_free(store);
    return rc == 1;
}

static X509 *x509_from_pem(const uint8_t *pem, size_t len)
{
    BIO  *b = BIO_new_mem_buf(pem, (int) len);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    return x;
}

int main(void)
{
    char err[160];
    printf("GSI proxy-delegation crypto suite\n");

    /* fixtures: CA -> EEC */    EVP_PKEY *cakey = NULL, *eeckey = NULL;
    X509 *ca = mkcert("Test CA", 1, NULL, NULL, &cakey);
    X509 *eec = mkcert("User", 0, ca, cakey, &eeckey);
    size_t ca_len, eec_len;
    uint8_t *eec_pem = pem_of(eec, &eec_len);
    (void) pem_of; ca_len = 0; (void) ca_len;

    /* ============ 1. build_pxyreq ============ */
    printf("[build_pxyreq]\n");
    EVP_PKEY *reqkey = NULL;
    uint8_t  *reqder = NULL; size_t reqlen = 0;
    int rc = brix_gsi_build_pxyreq(eec_pem, eec_len, &reqkey, &reqder, &reqlen,
                                     err, sizeof(err));
    CHECK(rc == 0, "build_pxyreq succeeds");
    CHECK(reqkey && reqder && reqlen, "request outputs populated");
    const unsigned char *pp = reqder;
    X509_REQ *req = d2i_X509_REQ(NULL, &pp, (long) reqlen);
    CHECK(req != NULL, "request DER parses");
    CHECK(req && X509_REQ_verify(req, reqkey) == 1, "request self-signs");

    /* ============ 2. sign_pxyreq (issue) ============ */
    printf("[sign_pxyreq]\n");
    uint8_t *pxy_pem = NULL; size_t pxy_len = 0;
    rc = brix_gsi_sign_pxyreq(eec_pem, eec_len, eeckey, reqder, reqlen,
                                &pxy_pem, &pxy_len, err, sizeof(err));
    CHECK(rc == 0, "sign_pxyreq issues a proxy");
    if (rc) printf("    err: %s\n", err);
    X509 *pxy = pxy_pem ? x509_from_pem(pxy_pem, pxy_len) : NULL;
    CHECK(pxy != NULL, "issued proxy PEM parses");
    if (pxy) {
        CHECK(X509_NAME_cmp(X509_get_issuer_name(pxy),
                            X509_get_subject_name(eec)) == 0,
              "proxy issuer == EEC subject");
        CHECK(X509_verify(pxy, eeckey) == 1, "proxy signed by EEC key");
        EVP_PKEY *ppub = X509_get_pubkey(pxy);
        CHECK(ppub && EVP_PKEY_eq(ppub, reqkey) == 1, "proxy pubkey == request key");
        EVP_PKEY_free(ppub);
        int crit_pci = 0, i;
        for (i = 0; i < X509_get_ext_count(pxy); i++) {
            X509_EXTENSION *e = X509_get_ext(pxy, i);
            char o[128];
            OBJ_obj2txt(o, sizeof(o), X509_EXTENSION_get_object(e), 1);
            if (strcmp(o, "1.3.6.1.5.5.7.1.14") == 0)
                crit_pci = X509_EXTENSION_get_critical(e);
        }
        CHECK(crit_pci, "proxy has a critical proxyCertInfo");
        /* subject is the EEC subject + one extra CN RDN */
        CHECK(X509_NAME_entry_count(X509_get_subject_name(pxy))
              == X509_NAME_entry_count(X509_get_subject_name(eec)) + 1,
              "proxy subject = EEC + 1 RDN");
    }

    /* ============ 3. assemble_proxy ============ */
    printf("[assemble_proxy]\n");
    uint8_t *cred = NULL; size_t cred_len = 0;
    rc = brix_gsi_assemble_proxy(pxy_pem, pxy_len, reqkey, eec_pem, eec_len,
                                   &cred, &cred_len, err, sizeof(err));
    CHECK(rc == 0, "assemble_proxy succeeds with matching key");
    CHECK(cred && cred_len == pxy_len + eec_len, "credential = proxy + chain");
    /* count certs in the assembled credential */
    if (cred) {
        BIO *b = BIO_new_mem_buf(cred, (int) cred_len);
        int cnt = 0; X509 *t;
        while ((t = PEM_read_bio_X509(b, NULL, NULL, NULL))) { cnt++; X509_free(t); }
        BIO_free(b);
        CHECK(cnt == 2, "assembled credential holds 2 certs (proxy+EEC)");
    }

    /* key mismatch must fail */
    EVP_PKEY *wrong = genkey();
    uint8_t *bad = NULL; size_t badn = 0;
    rc = brix_gsi_assemble_proxy(pxy_pem, pxy_len, wrong, eec_pem, eec_len,
                                   &bad, &badn, err, sizeof(err));
    CHECK(rc == -1 && bad == NULL, "assemble rejects a mismatched key");
    EVP_PKEY_free(wrong);

    /* ============ 4. full RFC-3820 chain verification ============ */
    printf("[full chain verify]\n");
    {
        X509 *inter[1] = { eec };
        CHECK(verify_proxy(pxy, ca, inter, 1),
              "proxy -> EEC -> CA verifies (ALLOW_PROXY_CERTS)");
    }

    /* ============ 5. two-level delegation (proxy of a proxy) ============ */
    printf("[two-level delegation]\n");
    {
        EVP_PKEY *rk2 = NULL; uint8_t *rd2 = NULL; size_t rl2 = 0;
        int r = brix_gsi_build_pxyreq(pxy_pem, pxy_len, &rk2, &rd2, &rl2,
                                        err, sizeof(err));
        CHECK(r == 0, "build_pxyreq from a proxy (level 2)");
        uint8_t *pxy2_pem = NULL; size_t pxy2_len = 0;
        r = brix_gsi_sign_pxyreq(pxy_pem, pxy_len, reqkey, rd2, rl2,
                                   &pxy2_pem, &pxy2_len, err, sizeof(err));
        CHECK(r == 0, "sign level-2 request with the level-1 proxy");
        if (r) printf("    err: %s\n", err);
        X509 *pxy2 = pxy2_pem ? x509_from_pem(pxy2_pem, pxy2_len) : NULL;
        CHECK(pxy2 != NULL, "level-2 proxy parses");
        if (pxy2) {
            CHECK(X509_NAME_cmp(X509_get_issuer_name(pxy2),
                                X509_get_subject_name(pxy)) == 0,
                  "level-2 issuer == level-1 proxy subject");
            X509 *inter2[2] = { pxy, eec };
            CHECK(verify_proxy(pxy2, ca, inter2, 2),
                  "proxy2 -> proxy1 -> EEC -> CA verifies");
            X509_free(pxy2);
        }
        EVP_PKEY_free(rk2); free(rd2); free(pxy2_pem);
    }

    /* ============ 6. negatives ============ */
    printf("[negatives]\n");
    {
        /* request built from EEC, but signed by a DIFFERENT EEC → subject mismatch */
        EVP_PKEY *ek2 = NULL;
        X509 *eec2 = mkcert("Other", 0, ca, cakey, &ek2);
        size_t e2len; uint8_t *e2pem = pem_of(eec2, &e2len);
        uint8_t *op = NULL; size_t ol = 0;
        int r = brix_gsi_sign_pxyreq(e2pem, e2len, ek2, reqder, reqlen,
                                       &op, &ol, err, sizeof(err));
        CHECK(r == -1 && op == NULL, "sign rejects request whose subject != signer");

        /* garbage parent / request */
        EVP_PKEY *k = NULL; uint8_t *d = NULL; size_t l = 0;
        r = brix_gsi_build_pxyreq((const uint8_t *) "not a pem", 9, &k, &d, &l,
                                    err, sizeof(err));
        CHECK(r == -1, "build_pxyreq rejects garbage parent PEM");
        uint8_t bogus[8] = {1,2,3,4,5,6,7,8};
        uint8_t *op2 = NULL; size_t ol2 = 0;
        r = brix_gsi_sign_pxyreq(eec_pem, eec_len, eeckey, bogus, sizeof(bogus),
                                   &op2, &ol2, err, sizeof(err));
        CHECK(r == -1, "sign rejects garbage request DER");

        /* NULL args */
        r = brix_gsi_build_pxyreq(NULL, 0, &k, &d, &l, err, sizeof(err));
        CHECK(r == -1, "build_pxyreq rejects NULL parent");

        free(e2pem); EVP_PKEY_free(ek2); X509_free(eec2);
    }

    X509_REQ_free(req);
    X509_free(pxy); free(pxy_pem); free(cred);
    EVP_PKEY_free(reqkey); free(reqder);
    free(eec_pem); X509_free(eec); EVP_PKEY_free(eeckey);
    X509_free(ca); EVP_PKEY_free(cakey);

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
