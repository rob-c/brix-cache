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

/* Shared fixtures + cross-stage artifacts that flow between the numbered test
 * scenarios. main() owns one instance; each test_* stage reads what earlier
 * stages produced and populates its own outputs. Split, zero-initialised. */
typedef struct {
    const brix_gsi_err_t *esink;
    char                 *err;      /* esink's message buffer */

    /* fixtures */
    EVP_PKEY *cakey;
    EVP_PKEY *eeckey;
    X509     *ca;
    X509     *eec;
    uint8_t  *eec_pem;
    size_t    eec_len;

    /* stage-1 (build_pxyreq) outputs */
    EVP_PKEY *reqkey;
    uint8_t  *reqder;
    size_t    reqlen;
    X509_REQ *req;

    /* stage-2 (sign_pxyreq) outputs */
    uint8_t *pxy_pem;
    size_t   pxy_len;
    X509    *pxy;

    /* stage-3 (assemble_proxy) outputs */
    uint8_t *cred;
} suite_t;

/* WHAT: build the CA -> EEC fixture chain shared by every stage.
 * WHY:  all delegation scenarios start from a real end-entity credential.
 * HOW:  self-sign a CA, sign an EEC under it, and PEM-encode the EEC. */
static void suite_fixtures(suite_t *s)
{
    size_t ca_len;
    printf("GSI proxy-delegation crypto suite\n");
    /* fixtures: CA -> EEC */
    s->ca  = mkcert("Test CA", 1, NULL, NULL, &s->cakey);
    s->eec = mkcert("User", 0, s->ca, s->cakey, &s->eeckey);
    s->eec_pem = pem_of(s->eec, &s->eec_len);
    (void) pem_of; ca_len = 0; (void) ca_len;
}

/* WHAT: stage 1 — request a proxy from the EEC (brix_gsi_build_pxyreq).
 * WHY:  the request is the client half of RFC-3820 delegation.
 * HOW:  build the request, then confirm its DER parses and self-signs. */
static void test_build_pxyreq(suite_t *s)
{
    printf("[build_pxyreq]\n");
    const brix_gsi_blob_t eec_blob = { s->eec_pem, s->eec_len };
    brix_gsi_buf_t req_out = { NULL, 0 };
    int rc = brix_gsi_build_pxyreq(&eec_blob, &s->reqkey, &req_out, s->esink);
    s->reqder = req_out.data; s->reqlen = req_out.len;
    CHECK(rc == 0, "build_pxyreq succeeds");
    CHECK(s->reqkey && s->reqder && s->reqlen, "request outputs populated");
    const unsigned char *pp = s->reqder;
    s->req = d2i_X509_REQ(NULL, &pp, (long) s->reqlen);
    CHECK(s->req != NULL, "request DER parses");
    CHECK(s->req && X509_REQ_verify(s->req, s->reqkey) == 1, "request self-signs");
}

/* WHAT: stage 2 — issue/sign the proxy from the request (brix_gsi_sign_pxyreq).
 * WHY:  the issued proxy must chain to the EEC and carry a critical PCI.
 * HOW:  sign, parse the PEM, and check issuer/key/pubkey/PCI/subject shape. */
static void test_sign_pxyreq(suite_t *s)
{
    printf("[sign_pxyreq]\n");
    const brix_gsi_blob_t eec_blob = { s->eec_pem, s->eec_len };
    const brix_gsi_blob_t req_blob = { s->reqder, s->reqlen };
    brix_gsi_buf_t pxy_out = { NULL, 0 };
    int rc = brix_gsi_sign_pxyreq(&eec_blob, s->eeckey, &req_blob, &pxy_out,
                                  s->esink);
    s->pxy_pem = pxy_out.data; s->pxy_len = pxy_out.len;
    CHECK(rc == 0, "sign_pxyreq issues a proxy");
    if (rc) printf("    err: %s\n", s->err);
    s->pxy = s->pxy_pem ? x509_from_pem(s->pxy_pem, s->pxy_len) : NULL;
    CHECK(s->pxy != NULL, "issued proxy PEM parses");
    if (s->pxy) {
        CHECK(X509_NAME_cmp(X509_get_issuer_name(s->pxy),
                            X509_get_subject_name(s->eec)) == 0,
              "proxy issuer == EEC subject");
        CHECK(X509_verify(s->pxy, s->eeckey) == 1, "proxy signed by EEC key");
        EVP_PKEY *ppub = X509_get_pubkey(s->pxy);
        CHECK(ppub && EVP_PKEY_eq(ppub, s->reqkey) == 1, "proxy pubkey == request key");
        EVP_PKEY_free(ppub);
        int crit_pci = 0, i;
        for (i = 0; i < X509_get_ext_count(s->pxy); i++) {
            X509_EXTENSION *e = X509_get_ext(s->pxy, i);
            char o[128];
            OBJ_obj2txt(o, sizeof(o), X509_EXTENSION_get_object(e), 1);
            if (strcmp(o, "1.3.6.1.5.5.7.1.14") == 0)
                crit_pci = X509_EXTENSION_get_critical(e);
        }
        CHECK(crit_pci, "proxy has a critical proxyCertInfo");
        /* subject is the EEC subject + one extra CN RDN */
        CHECK(X509_NAME_entry_count(X509_get_subject_name(s->pxy))
              == X509_NAME_entry_count(X509_get_subject_name(s->eec)) + 1,
              "proxy subject = EEC + 1 RDN");
    }
}

/* WHAT: stage 3 — assemble the delegated credential (brix_gsi_assemble_proxy).
 * WHY:  the credential must be proxy||chain||key — a complete credential the
 *       holder can authenticate with — and reject a mismatched key.
 * HOW:  assemble with the matching key, count the certs, extract the embedded
 *       private key and match it to reqkey, then retry with a wrong key. */
static void test_assemble_proxy(suite_t *s)
{
    printf("[assemble_proxy]\n");
    size_t cred_len = 0;
    const brix_gsi_blob_t eec_blob = { s->eec_pem, s->eec_len };
    const brix_gsi_blob_t pxy_blob = { s->pxy_pem, s->pxy_len };
    brix_gsi_buf_t cred_out = { NULL, 0 };
    int rc = brix_gsi_assemble_proxy(&pxy_blob, s->reqkey, &eec_blob, &cred_out,
                                     s->esink);
    s->cred = cred_out.data; cred_len = cred_out.len;
    CHECK(rc == 0, "assemble_proxy succeeds with matching key");
    CHECK(s->cred && cred_len > s->pxy_len + s->eec_len,
          "credential = proxy + chain + key");
    /* count certs in the assembled credential (cert-reader must stop cleanly
     * at the trailing key block) */
    if (s->cred) {
        BIO *b = BIO_new_mem_buf(s->cred, (int) cred_len);
        int cnt = 0; X509 *t;
        while ((t = PEM_read_bio_X509(b, NULL, NULL, NULL))) { cnt++; X509_free(t); }
        BIO_free(b);
        CHECK(cnt == 2, "assembled credential holds 2 certs (proxy+EEC)");
    }
    /* the embedded private key must be present and be the request key */
    if (s->cred) {
        BIO *b = BIO_new_mem_buf(s->cred, (int) cred_len);
        EVP_PKEY *ck = b ? PEM_read_bio_PrivateKey(b, NULL, NULL, NULL) : NULL;
        CHECK(ck != NULL, "assembled credential holds a private key");
        CHECK(ck != NULL && EVP_PKEY_eq(ck, s->reqkey) == 1,
              "embedded private key == request key");
        EVP_PKEY_free(ck);
        BIO_free(b);
    }

    /* key mismatch must fail */
    EVP_PKEY *wrong = genkey();
    brix_gsi_buf_t bad_out = { NULL, 0 };
    rc = brix_gsi_assemble_proxy(&pxy_blob, wrong, &eec_blob, &bad_out, s->esink);
    CHECK(rc == -1 && bad_out.data == NULL, "assemble rejects a mismatched key");
    EVP_PKEY_free(wrong);
}

/* WHAT: stage 4 — verify proxy -> EEC -> CA under RFC-3820 rules.
 * WHY:  a well-formed proxy must validate with ALLOW_PROXY_CERTS.
 * HOW:  run verify_proxy with the EEC as the sole intermediate. */
static void test_full_chain_verify(suite_t *s)
{
    printf("[full chain verify]\n");
    X509 *inter[1] = { s->eec };
    CHECK(verify_proxy(s->pxy, s->ca, inter, 1),
          "proxy -> EEC -> CA verifies (ALLOW_PROXY_CERTS)");
}

/* WHAT: stage 5 — delegate a proxy of a proxy (two-level chain).
 * WHY:  nested delegation and path length must still verify to the CA.
 * HOW:  request+sign a level-2 proxy off level-1, check issuer and chain. */
static void test_two_level_delegation(suite_t *s)
{
    printf("[two-level delegation]\n");
    const brix_gsi_blob_t pxy_blob = { s->pxy_pem, s->pxy_len };
    EVP_PKEY *rk2 = NULL; uint8_t *rd2 = NULL; size_t rl2 = 0;
    brix_gsi_buf_t rd2_out = { NULL, 0 };
    int r = brix_gsi_build_pxyreq(&pxy_blob, &rk2, &rd2_out, s->esink);
    rd2 = rd2_out.data; rl2 = rd2_out.len;
    CHECK(r == 0, "build_pxyreq from a proxy (level 2)");
    uint8_t *pxy2_pem = NULL; size_t pxy2_len = 0;
    const brix_gsi_blob_t rd2_blob = { rd2, rl2 };
    brix_gsi_buf_t pxy2_out = { NULL, 0 };
    r = brix_gsi_sign_pxyreq(&pxy_blob, s->reqkey, &rd2_blob, &pxy2_out,
                             s->esink);
    pxy2_pem = pxy2_out.data; pxy2_len = pxy2_out.len;
    CHECK(r == 0, "sign level-2 request with the level-1 proxy");
    if (r) printf("    err: %s\n", s->err);
    X509 *pxy2 = pxy2_pem ? x509_from_pem(pxy2_pem, pxy2_len) : NULL;
    CHECK(pxy2 != NULL, "level-2 proxy parses");
    if (pxy2) {
        CHECK(X509_NAME_cmp(X509_get_issuer_name(pxy2),
                            X509_get_subject_name(s->pxy)) == 0,
              "level-2 issuer == level-1 proxy subject");
        X509 *inter2[2] = { s->pxy, s->eec };
        CHECK(verify_proxy(pxy2, s->ca, inter2, 2),
              "proxy2 -> proxy1 -> EEC -> CA verifies");
        X509_free(pxy2);
    }
    EVP_PKEY_free(rk2); free(rd2); free(pxy2_pem);
}

/* WHAT: stage 6 — negative cases (subject mismatch, garbage, NULL).
 * WHY:  the API must reject malformed or unauthorised delegation inputs.
 * HOW:  drive sign/build with a wrong signer, garbage blobs and NULL args. */
static void test_negatives(suite_t *s)
{
    printf("[negatives]\n");
    const brix_gsi_blob_t eec_blob = { s->eec_pem, s->eec_len };
    const brix_gsi_blob_t req_blob = { s->reqder, s->reqlen };

    /* request built from EEC, but signed by a DIFFERENT EEC -> subject mismatch */
    EVP_PKEY *ek2 = NULL;
    X509 *eec2 = mkcert("Other", 0, s->ca, s->cakey, &ek2);
    size_t e2len; uint8_t *e2pem = pem_of(eec2, &e2len);
    const brix_gsi_blob_t e2_blob = { e2pem, e2len };
    brix_gsi_buf_t op_out = { NULL, 0 };
    int r = brix_gsi_sign_pxyreq(&e2_blob, ek2, &req_blob, &op_out, s->esink);
    CHECK(r == -1 && op_out.data == NULL,
          "sign rejects request whose subject != signer");

    /* garbage parent / request */
    EVP_PKEY *k = NULL;
    const brix_gsi_blob_t garbage_blob = { (const uint8_t *) "not a pem", 9 };
    brix_gsi_buf_t d_out = { NULL, 0 };
    r = brix_gsi_build_pxyreq(&garbage_blob, &k, &d_out, s->esink);
    CHECK(r == -1, "build_pxyreq rejects garbage parent PEM");
    uint8_t bogus[8] = {1,2,3,4,5,6,7,8};
    const brix_gsi_blob_t bogus_blob = { bogus, sizeof(bogus) };
    brix_gsi_buf_t op2_out = { NULL, 0 };
    r = brix_gsi_sign_pxyreq(&eec_blob, s->eeckey, &bogus_blob, &op2_out,
                             s->esink);
    CHECK(r == -1, "sign rejects garbage request DER");

    /* NULL args */
    const brix_gsi_blob_t null_blob = { NULL, 0 };
    r = brix_gsi_build_pxyreq(&null_blob, &k, &d_out, s->esink);
    CHECK(r == -1, "build_pxyreq rejects NULL parent");

    free(e2pem); EVP_PKEY_free(ek2); X509_free(eec2);
}

/* WHAT: release every artifact allocated across the suite.
 * WHY:  keep the standalone run leak-clean for sanitiser builds.
 * HOW:  free fixtures and all per-stage outputs in reverse order. */
static void suite_teardown(suite_t *s)
{
    X509_REQ_free(s->req);
    X509_free(s->pxy); free(s->pxy_pem); free(s->cred);
    EVP_PKEY_free(s->reqkey); free(s->reqder);
    free(s->eec_pem); X509_free(s->eec); EVP_PKEY_free(s->eeckey);
    X509_free(s->ca); EVP_PKEY_free(s->cakey);
}

int main(void)
{
    char err[160];
    const brix_gsi_err_t esink = { err, sizeof(err) };
    suite_t s = { 0 };
    s.esink = &esink;
    s.err   = err;

    suite_fixtures(&s);
    test_build_pxyreq(&s);
    test_sign_pxyreq(&s);
    test_assemble_proxy(&s);
    test_full_chain_verify(&s);
    test_two_level_delegation(&s);
    test_negatives(&s);
    suite_teardown(&s);

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
