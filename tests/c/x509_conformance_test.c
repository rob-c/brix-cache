/*
 * x509_conformance_test.c — C-level WLCG x509 conformance (CHN/SP/CRL).
 *
 * Links the ngx-free trust cores against real forge fixtures and asserts the
 * enforcement DECISION logic and PKIX chain building.  Run via
 * tests/c/run_x509_conformance_tests.sh (forges fixtures, sets
 * BRIX_X509_FIXTURES).  Exit 0 = all checks pass.
 *
 * Scope split: this binary proves brix_sp_table_check / store attach / CRL
 * store flags / X509_verify_cert verdicts.  The proof that the production
 * verifier (brix_gsi_verify_chain, which is ngx-coupled) actually invokes this
 * logic on the wire is the pytest e2e layer.
 */
#include "auth/crypto/store_policy.h"

#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++; printf("  FAIL: %s\n", (msg)); } \
    else { printf("  ok: %s\n", (msg)); }                       \
} while (0)

static const char *FIX;

static char *
path_of(const char *scenario, const char *leaf)
{
    static char buf[4096];
    snprintf(buf, sizeof(buf), "%s/%s/%s", FIX, scenario, leaf);
    return buf;
}

/* Load the first PEM certificate from a file. */
static X509 *
load_first_cert(const char *path)
{
    FILE *fp = fopen(path, "r");
    X509 *c;
    if (fp == NULL) {
        return NULL;
    }
    c = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return c;
}

/* Load the Nth (0-based) PEM certificate from a multi-cert file. */
static X509 *
load_nth_cert(const char *path, int n)
{
    FILE *fp = fopen(path, "r");
    X509 *c = NULL;
    int   i;
    if (fp == NULL) {
        return NULL;
    }
    for (i = 0; i <= n; i++) {
        if (c != NULL) {
            X509_free(c);
        }
        c = PEM_read_X509(fp, NULL, NULL, NULL);
        if (c == NULL) {
            break;
        }
    }
    fclose(fp);
    return c;
}

/* --- signing_policy decision tests --------------------------------------- */

static void
test_signing_policy_decisions(void)
{
    printf("SP decisions (real certs):\n");

    /* sp_in_namespace: CA policy allows the test namespace — EEC inside */
    {
        brix_sp_table_t *t = brix_sp_table_build(path_of("sp_in_namespace", "ca"),
                                                 NULL, NULL);
        X509 *ca = load_first_cert(path_of("sp_in_namespace", "ca/ca.pem"));
        X509 *eec = load_first_cert(path_of("sp_in_namespace", "eec_in_ns.pem"));
        CHECK(t && ca && eec, "SP-C01 fixtures load (in_namespace)");
        CHECK(brix_sp_table_check(t, BRIX_SP_MODE_ON, ca, eec) == 1,
              "SP-C02 in-namespace subject allowed (ON)");
        CHECK(brix_sp_table_check(t, BRIX_SP_MODE_REQUIRE, ca, eec) == 1,
              "SP-C03 in-namespace subject allowed (REQUIRE)");
        brix_sp_table_free(t); X509_free(ca); X509_free(eec);
    }

    /* sp_out_of_namespace: EEC subject outside the CA's namespace. */
    {
        brix_sp_table_t *t = brix_sp_table_build(
            path_of("sp_out_of_namespace", "ca"), NULL, NULL);
        X509 *ca = load_first_cert(path_of("sp_out_of_namespace", "ca/ca.pem"));
        X509 *eec = load_first_cert(path_of("sp_out_of_namespace", "eec_out_ns.pem"));
        CHECK(brix_sp_table_check(t, BRIX_SP_MODE_ON, ca, eec) == 0,
              "SP-C04 out-of-namespace subject rejected (ON)");
        brix_sp_table_free(t); X509_free(ca); X509_free(eec);
    }

    /* sp_wrong_ca_block: policy file present but names a different CA. */
    {
        brix_sp_table_t *t = brix_sp_table_build(
            path_of("sp_wrong_ca_block", "ca"), NULL, NULL);
        X509 *ca = load_first_cert(path_of("sp_wrong_ca_block", "ca/ca.pem"));
        X509 *eec = load_first_cert(path_of("sp_wrong_ca_block", "eec_wrongblock.pem"));
        CHECK(brix_sp_table_check(t, BRIX_SP_MODE_ON, ca, eec) == 0,
              "SP-C05 wrong-CA policy file fails closed (ON)");
        brix_sp_table_free(t); X509_free(ca); X509_free(eec);
    }

    /* cad_md5_only has a CA but NO signing_policy file. */
    {
        brix_sp_table_t *t = brix_sp_table_build(path_of("cad_md5_only", "ca"),
                                                 NULL, NULL);
        X509 *ca = load_first_cert(path_of("cad_md5_only", "ca/ca.pem"));
        X509 *eec = load_first_cert(path_of("cad_md5_only", "eec.pem"));
        CHECK(brix_sp_table_check(t, BRIX_SP_MODE_ON, ca, eec) == 1,
              "SP-C06 no policy file present → allowed (ON)");
        CHECK(brix_sp_table_check(t, BRIX_SP_MODE_REQUIRE, ca, eec) == 0,
              "SP-C07 no policy file present → rejected (REQUIRE)");
        CHECK(brix_sp_table_check(t, BRIX_SP_MODE_OFF, ca, eec) == 1,
              "SP-C08 OFF always allows");
        brix_sp_table_free(t); X509_free(ca); X509_free(eec);
    }
}

/* --- store attach roundtrip ---------------------------------------------- */

static void
test_store_attach(void)
{
    printf("store attach:\n");
    X509_STORE     *store = X509_STORE_new();
    brix_sp_table_t *t = brix_sp_table_build(path_of("sp_in_namespace", "ca"),
                                             NULL, NULL);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    CHECK(brix_store_policy_attach(store, t, BRIX_SP_MODE_REQUIRE,
                                   BRIX_CRL_MODE_TRY) == 1,
          "SP-C09 attach table to store");
    X509_STORE_CTX_init(ctx, store, NULL, NULL);
    CHECK(brix_store_policy_mode(ctx) == BRIX_SP_MODE_REQUIRE,
          "SP-C10 mode round-trips via ex_data");
    CHECK(brix_store_crl_mode(ctx) == BRIX_CRL_MODE_TRY,
          "SP-C11 crl_mode round-trips via ex_data");
    CHECK(brix_store_policy_table(ctx) == t,
          "SP-C12 table pointer round-trips");

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);   /* frees the attached table via ex_data free cb */
}

/* --- shared store-config helper (SC) -------------------------------------- */

static void
test_store_configure(void)
{
    printf("store configure (shared helper):\n");
    X509_STORE *store = X509_STORE_new();
    /* require + no cadir (bundle) must fail. */
    CHECK(brix_store_configure(store, NULL, 0, 0,
              BRIX_SP_MODE_REQUIRE, BRIX_CRL_MODE_OFF, NULL, NULL) == -1,
          "SC-01 require+bundle rejected");
    X509_STORE_free(store);

    store = X509_STORE_new();
    X509_STORE_load_path(store, path_of("sp_in_namespace", "ca"));
    CHECK(brix_store_configure(store, path_of("sp_in_namespace", "ca"),
              X509_V_FLAG_ALLOW_PROXY_CERTS, 0,
              BRIX_SP_MODE_ON, BRIX_CRL_MODE_TRY, NULL, NULL) == 0,
          "SC-02 configure ok on a real CA dir");
    X509_STORE_free(store);
}

/* --- chain building (CHN) ------------------------------------------------- */

static int
verify_leaf(const char *scenario, const char *ca_pem, const char *cred,
            int leaf_idx)
{
    X509_STORE     *store = X509_STORE_new();
    X509           *ca = load_first_cert(path_of(scenario, ca_pem));
    X509           *leaf = load_nth_cert(path_of(scenario, cred), leaf_idx);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int             rv = -1;

    if (ca != NULL) {
        X509_STORE_add_cert(store, ca);
    }
    if (leaf != NULL) {
        X509_STORE_CTX_init(ctx, store, leaf, NULL);
        rv = X509_verify_cert(ctx);
    }

    X509_STORE_CTX_free(ctx);
    if (ca) X509_free(ca);
    if (leaf) X509_free(leaf);
    X509_STORE_free(store);
    return rv;
}

static void
test_chain_building(void)
{
    printf("CHN chain building:\n");
    /* cad_expired_ca: trust anchor is expired → verify must fail. */
    CHECK(verify_leaf("cad_expired_ca", "ca/ca.pem", "eec.pem", 0) != 1,
          "CHN-C01 expired trust anchor rejected");
    /* cad_md5_only: valid CA + EEC (leaf index 0) → verify succeeds. */
    CHECK(verify_leaf("cad_md5_only", "ca/ca.pem", "eec.pem", 0) == 1,
          "CHN-C02 valid EEC under valid CA accepted");
}

/* --- CRL store flags (CRL) ------------------------------------------------ */

/*
 * Mirror of the production crl_mode=TRY downgrade (pki_build.c): tolerate a CA
 * that simply has no CRL (the self-signed root here) while keeping the actual
 * revocation verdict fatal.  Without this, CRL_CHECK_ALL rejects even a
 * non-revoked leaf because the root has no CRL of its own.
 */
static int
crl_try_cb(int ok, X509_STORE_CTX *ctx)
{
    if (ok) {
        return 1;
    }
    return X509_STORE_CTX_get_error(ctx) == X509_V_ERR_UNABLE_TO_GET_CRL ? 1 : 0;
}

static void
test_crl_store(void)
{
    printf("CRL store:\n");
    /* A CRL that revokes an EEC: with CRL_CHECK the revoked leaf fails. */
    X509_STORE *store = X509_STORE_new();
    X509 *ca = load_first_cert(path_of("crl_revoked_eec", "ca/ca.pem"));
    X509 *good = load_nth_cert(path_of("crl_revoked_eec", "good.pem"), 0);
    X509 *bad = load_nth_cert(path_of("crl_revoked_eec", "revoked.pem"), 0);

    X509_STORE_add_cert(store, ca);
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    X509_STORE_set_verify_cb(store, crl_try_cb);   /* crl_mode=TRY parity */
    /* Load every CRL (.r0/.r1) from the CA dir. */
    X509_STORE_load_locations(store, NULL, path_of("crl_revoked_eec", "ca"));

    {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, good, NULL);
        CHECK(X509_verify_cert(ctx) == 1, "CRL-C01 non-revoked EEC accepted");
        X509_STORE_CTX_free(ctx);
    }
    {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, bad, NULL);
        CHECK(X509_verify_cert(ctx) != 1, "CRL-C02 revoked EEC rejected");
        X509_STORE_CTX_free(ctx);
    }

    if (ca) X509_free(ca);
    if (good) X509_free(good);
    if (bad) X509_free(bad);
    X509_STORE_free(store);
}

/* --- proxy classification + monotonicity (PX) ---------------------------- */

/* Load every PEM cert from a credential file into a leaf-first STACK. */
static STACK_OF(X509) *
load_chain(const char *path)
{
    FILE           *fp = fopen(path, "r");
    STACK_OF(X509) *sk = sk_X509_new_null();
    X509           *c;
    if (fp == NULL) {
        return sk;
    }
    while ((c = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(sk, c);
    }
    fclose(fp);
    return sk;
}

static void
test_proxy_monotonicity(void)
{
    printf("PX proxy monotonicity:\n");

    /* px_rfc3820_ok: proxy_full over EEC — no limited anywhere → ok. */
    {
        STACK_OF(X509) *sk = load_chain(path_of("px_rfc3820_ok", "proxy_full.pem"));
        CHECK(sk_X509_num(sk) >= 2, "PX-C01 rfc3820 chain loads");
        CHECK(brix_px_classify(sk_X509_value(sk, 0)) == BRIX_PX_FULL,
              "PX-C02 leaf classified FULL proxy");
        CHECK(brix_proxy_chain_ok(sk) == 1, "PX-C03 full-over-EEC is monotonic");
        sk_X509_pop_free(sk, X509_free);
    }

    /* px_limited_to_full: full proxy issued beneath a limited one → escalation. */
    {
        STACK_OF(X509) *sk = load_chain(path_of("px_limited_to_full", "escalated.pem"));
        int found_limited = 0, i;
        for (i = 0; i < sk_X509_num(sk); i++) {
            if (brix_px_classify(sk_X509_value(sk, i)) == BRIX_PX_LIMITED) {
                found_limited = 1;
            }
        }
        CHECK(found_limited, "PX-C04 limited proxy present in chain");
        CHECK(brix_proxy_chain_ok(sk) == 0,
              "PX-C05 full-beneath-limited rejected (RFC 3820 §3.8)");
        sk_X509_pop_free(sk, X509_free);
    }
}

int
main(void)
{
    FIX = getenv("BRIX_X509_FIXTURES");
    if (FIX == NULL) {
        fprintf(stderr, "BRIX_X509_FIXTURES not set\n");
        return 2;
    }

    test_signing_policy_decisions();
    test_store_attach();
    test_store_configure();
    test_chain_building();
    test_crl_store();
    test_proxy_monotonicity();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
