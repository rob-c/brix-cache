/*
 * gsi_eec_test.c — P80.11 regression: the EEC DN is the STABLE identity.
 *
 * WHAT: Drives the REAL brix_gsi_verify_chain() (gsi_verify.o + the shared
 *       x509 policy cores) against forged CA -> EEC -> proxy chains and asserts
 *       the End-Entity-Certificate normalization contract:
 *         success      — a valid proxy verifies; res.eec_buf == the EEC DN,
 *                        res.dn_buf == the proxy LEAF DN (they differ, so the
 *                        proxy /CN=<serial> really was present and stripped).
 *         keystone     — two proxies minted for the SAME EEC with DIFFERENT
 *                        serials produce DIFFERENT dn_buf but IDENTICAL eec_buf.
 *                        This is the whole point: re-minting a proxy must not
 *                        change the user's authorization identity.
 *         security-neg — a proxy whose EEC is signed by an UNTRUSTED CA fails
 *                        verification (NGX_ERROR) and res.eec_buf stays EMPTY:
 *                        no identity is ever derived from an unverified chain.
 *         edge         — a bare EEC (no proxy) verifies with eec_buf == dn_buf.
 *
 * WHY: The proxy leaf DN carries an RFC 3820 /CN=<serial> that changes on every
 *      voms-proxy-init; keying authz + per-user credential selection on it made
 *      the same human a different principal after each renewal (phase-80 6.1 /
 *      P80.11). This unit pins the fix at the C seam, independent of the wire
 *      fleet.
 *
 * HOW: Fixtures are forged by tests/x509forge.py into $BRIX_GSI_EEC_FIXTURES
 *      (see run_gsi_eec in tests/cmdscripts/c_auth_units.py). nginx's pool/log
 *      surface is stubbed — no nginx core objects are linked (same pattern as
 *      deleg_gate_test.c).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "auth/crypto/gsi_verify.h"

/* ---- nginx surface stubs (no nginx core objects are linked) --------------- */

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

u_char *
ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }
    while (--n && (*dst = *src) != '\0') {
        dst++;
        src++;
    }
    *dst = '\0';
    return dst;
}

/* ---- fixture helpers ------------------------------------------------------ */

static const char *g_dir;
static ngx_log_t   g_log;   /* log_level 0: ngx_log_error() bodies are skipped */

static X509 *
load_cert(const char *name)
{
    char  path[1024];
    FILE *fp;
    X509 *cert;

    (void) snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "gsi_eec: cannot open %s\n", path);
        return NULL;
    }
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (cert == NULL) {
        fprintf(stderr, "gsi_eec: cannot parse cert %s\n", path);
    }
    return cert;
}

/* Verify `proxy_file` (leaf) with `eec` as the sole untrusted intermediate,
 * trusting only `ca`. Returns the brix_gsi_verify_chain rc and fills *res. */
static ngx_int_t
verify_proxy(const char *proxy_file, X509 *eec, X509 *ca,
             brix_gsi_verify_result_t *res)
{
    X509_STORE     *store    = X509_STORE_new();
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    X509           *proxy    = load_cert(proxy_file);
    ngx_int_t       rc;

    assert(store != NULL && untrusted != NULL && proxy != NULL);
    assert(X509_STORE_add_cert(store, ca) == 1);
    if (eec != NULL) {
        assert(sk_X509_push(untrusted, eec) > 0);
    }

    rc = brix_gsi_verify_chain(&g_log, store, proxy, untrusted, 0, res, 0);

    X509_free(proxy);
    sk_X509_free(untrusted);          /* borrowed eec ref not owned here */
    X509_STORE_free(store);
    return rc;
}

int
main(int argc, char **argv)
{
    brix_gsi_verify_result_t res_a, res_b, res_eec, res_rogue;
    X509                    *ca, *eec, *rogue_ca, *rogue_eec;
    int                      failures = 0;

    g_dir = (argc > 1) ? argv[1] : getenv("BRIX_GSI_EEC_FIXTURES");
    if (g_dir == NULL) {
        fprintf(stderr, "gsi_eec: no fixture dir (argv[1] / BRIX_GSI_EEC_FIXTURES)\n");
        return 2;
    }

    ca        = load_cert("ca.pem");
    eec       = load_cert("eec.pem");
    rogue_ca  = load_cert("rogue_ca.pem");
    rogue_eec = load_cert("rogue_eec.pem");
    assert(ca && eec && rogue_ca && rogue_eec);

    /* (1) success — proxy A verifies; EEC stripped from the leaf DN. */
    assert(verify_proxy("proxy_a.pem", eec, ca, &res_a) == NGX_OK);
    if (strstr(res_a.dn_buf, "CN=alice") == NULL) {
        fprintf(stderr, "FAIL success: dn_buf=%s lacks EEC CN\n", res_a.dn_buf);
        failures++;
    }
    if (strcmp(res_a.dn_buf, res_a.eec_buf) == 0) {
        fprintf(stderr, "FAIL success: dn_buf == eec_buf (proxy CN not stripped): %s\n",
                res_a.eec_buf);
        failures++;
    }
    if (strstr(res_a.eec_buf, "CN=100001") != NULL) {
        fprintf(stderr, "FAIL success: eec_buf still carries proxy serial: %s\n",
                res_a.eec_buf);
        failures++;
    }

    /* (2) keystone — a second serial for the SAME EEC: different proxy leaf DN,
     *     IDENTICAL EEC identity. */
    assert(verify_proxy("proxy_b.pem", eec, ca, &res_b) == NGX_OK);
    if (strcmp(res_a.dn_buf, res_b.dn_buf) == 0) {
        fprintf(stderr, "FAIL keystone: two serials share a leaf DN (%s) — "
                "fixture not distinct\n", res_a.dn_buf);
        failures++;
    }
    if (strcmp(res_a.eec_buf, res_b.eec_buf) != 0) {
        fprintf(stderr, "FAIL keystone: EEC identity drifted across serials: "
                "%s != %s\n", res_a.eec_buf, res_b.eec_buf);
        failures++;
    }

    /* (3) edge — a bare EEC (no proxy) verifies with eec_buf == dn_buf. */
    assert(verify_proxy("eec.pem", NULL, ca, &res_eec) == NGX_OK);
    if (strcmp(res_eec.dn_buf, res_eec.eec_buf) != 0) {
        fprintf(stderr, "FAIL edge: bare EEC eec_buf != dn_buf: %s != %s\n",
                res_eec.dn_buf, res_eec.eec_buf);
        failures++;
    }

    /* (4) security-neg — proxy under an UNTRUSTED CA must fail closed and leak
     *     NO identity (eec_buf empty). */
    memset(&res_rogue, 0xAA, sizeof(res_rogue));   /* poison: prove it is zeroed */
    if (verify_proxy("rogue_proxy.pem", rogue_eec, ca, &res_rogue) != NGX_ERROR) {
        fprintf(stderr, "FAIL security-neg: untrusted chain was accepted\n");
        failures++;
    }
    if (res_rogue.eec_buf[0] != '\0') {
        fprintf(stderr, "FAIL security-neg: eec_buf populated from unverified "
                "chain: %s\n", res_rogue.eec_buf);
        failures++;
    }

    X509_free(ca);
    X509_free(eec);
    X509_free(rogue_ca);
    X509_free(rogue_eec);

    if (failures == 0) {
        printf("gsi_eec: OK (success + keystone + edge + security-neg)\n");
        return 0;
    }
    fprintf(stderr, "gsi_eec: %d assertion(s) failed\n", failures);
    return 1;
}
