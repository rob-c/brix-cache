/*
 * gsi_verify_depth_test.c — §5.10 (parity-fix wave 17): brix_gsi_verify_chain
 * honours the caller's chain-depth cap (the xrd.tlsca `verdepth` analog wired to
 * `brix_gsi_verify_depth`).
 *
 * WHAT: Drives the REAL brix_gsi_verify_chain() against a DEEP forged chain
 *       (trust CA -> intermediate CA #1 -> intermediate CA #2 -> EEC -> proxy)
 *       at three depth caps and asserts:
 *         success       — depth 0 (unlimited): the chain verifies (NGX_OK), so
 *                         the deep chain is otherwise sound.
 *         enforcement   — depth 1: X509_STORE_CTX_set_depth(1) rejects it
 *                         (NGX_ERROR) — the two intermediate CAs exceed the cap.
 *         security-neg  — depth 20 (generous): the SAME chain verifies again,
 *                         proving depth 1's rejection was specifically the cap
 *                         and a correctly-sized cap never breaks a valid chain.
 *
 * WHY: brix_gsi_verify_depth caps the accepted client proxy/cert chain depth at
 *      root:// GSI login; before wave 17 the caller passed 0 (unlimited). This
 *      unit pins the enforcement at the C seam, independent of a GSI handshake.
 *
 * HOW: Fixtures forged by tests/x509forge.py into $BRIX_GSI_VERDEPTH_FIXTURES
 *      (see run_gsi_verdepth in tests/cmdscripts/c_auth_units_part2.py). nginx's
 *      pool/log surface is stubbed — no nginx core objects are linked (same
 *      pattern as gsi_eec_test.c / deleg_gate_test.c).
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
        fprintf(stderr, "gsi_verdepth: cannot open %s\n", path);
        return NULL;
    }
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (cert == NULL) {
        fprintf(stderr, "gsi_verdepth: cannot parse cert %s\n", path);
    }
    return cert;
}

/* Verify the proxy leaf against `ca`, presenting `inter[0..n)` as untrusted
 * intermediates, with the given chain-depth cap. Returns the verify rc. */
static ngx_int_t
verify_at_depth(X509 *proxy, X509 **inter, int n, X509 *ca,
                ngx_uint_t depth)
{
    X509_STORE               *store     = X509_STORE_new();
    STACK_OF(X509)           *untrusted = sk_X509_new_null();
    brix_gsi_verify_result_t  res;
    ngx_int_t                 rc;
    int                       i;

    assert(store != NULL && untrusted != NULL);
    assert(X509_STORE_add_cert(store, ca) == 1);
    for (i = 0; i < n; i++) {
        assert(sk_X509_push(untrusted, inter[i]) > 0);
    }

    rc = brix_gsi_verify_chain(&g_log, store, proxy, untrusted, depth, &res, 0);

    sk_X509_free(untrusted);       /* borrowed intermediate refs not owned here */
    X509_STORE_free(store);
    return rc;
}

int
main(int argc, char **argv)
{
    X509 *ca, *intca1, *intca2, *eec, *proxy;
    X509 *inter[3];
    int   failures = 0;

    g_dir = (argc > 1) ? argv[1] : getenv("BRIX_GSI_VERDEPTH_FIXTURES");
    if (g_dir == NULL) {
        fprintf(stderr, "gsi_verdepth: no fixture dir "
                        "(argv[1] / BRIX_GSI_VERDEPTH_FIXTURES)\n");
        return 2;
    }

    ca     = load_cert("ca.pem");
    intca1 = load_cert("intca1.pem");
    intca2 = load_cert("intca2.pem");
    eec    = load_cert("eec.pem");
    proxy  = load_cert("proxy.pem");
    assert(ca && intca1 && intca2 && eec && proxy);

    inter[0] = eec;       /* nearest the leaf */
    inter[1] = intca2;
    inter[2] = intca1;    /* nearest the trust anchor */

    /* (1) success — no cap (0 = unlimited): the deep chain is sound. */
    if (verify_at_depth(proxy, inter, 3, ca, 0) != NGX_OK) {
        fprintf(stderr, "FAIL success: deep chain rejected with no depth cap\n");
        failures++;
    }

    /* (2) enforcement — depth 1 rejects a chain with two intermediate CAs. */
    if (verify_at_depth(proxy, inter, 3, ca, 1) != NGX_ERROR) {
        fprintf(stderr, "FAIL enforcement: depth cap 1 accepted a chain with "
                        "two intermediate CAs\n");
        failures++;
    }

    /* (3) security-neg — a generous cap (20) verifies the SAME chain, proving
     *     the depth-1 rejection was the cap, not a broken chain. */
    if (verify_at_depth(proxy, inter, 3, ca, 20) != NGX_OK) {
        fprintf(stderr, "FAIL boundary: a generous depth cap (20) rejected a "
                        "valid chain\n");
        failures++;
    }

    X509_free(ca);
    X509_free(intca1);
    X509_free(intca2);
    X509_free(eec);
    X509_free(proxy);

    if (failures == 0) {
        printf("gsi_verdepth: OK (unlimited-accept + cap1-reject + cap20-accept)\n");
        return 0;
    }
    fprintf(stderr, "gsi_verdepth: %d assertion(s) failed\n", failures);
    return 1;
}
