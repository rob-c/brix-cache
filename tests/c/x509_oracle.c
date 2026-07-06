/*
 * x509_oracle.c — replay the clause manifest through the real trust cores.
 *
 * For every c-oracle/davs case in manifest.tsv the oracle builds an X509_STORE
 * the way brix_build_ca_store does (load the shared CA dir + CRLs, then
 * brix_store_configure), verifies the credential, applies the same post-verify
 * signing_policy + proxy-monotonicity walk gsi_verify.c uses, and asserts the
 * verdict equals the manifest's expected value.  This exercises the ACTUAL
 * production decision logic (signing_policy.c, store_policy.c) at scale without
 * nginx; the wire fleet proves brix_gsi_verify_chain invokes the same cores.
 *
 * Run via tests/c/run_x509_oracle.sh.  Optional argv[1] = id-prefix filter.
 * Exit 0 iff every replayed case matches; nonzero on any mismatch.
 */
#include "auth/crypto/store_policy.h"

#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *FIX;

/* -- group config (mirror of x509forge.GROUPS) ---------------------------- */

typedef struct {
    const char    *name;
    brix_sp_mode_t sp_mode;
    int            crl_mode;
    int            use_bundle;   /* cafile instead of cadir */
} group_cfg_t;

static const group_cfg_t GROUPS[] = {
    { "sp_on_crl_off",      BRIX_SP_MODE_ON,      BRIX_CRL_MODE_OFF,     0 },
    { "sp_off_crl_off",     BRIX_SP_MODE_OFF,     BRIX_CRL_MODE_OFF,     0 },
    { "sp_require_crl_off", BRIX_SP_MODE_REQUIRE, BRIX_CRL_MODE_OFF,     0 },
    { "sp_on_crl_try",      BRIX_SP_MODE_ON,      BRIX_CRL_MODE_TRY,     0 },
    { "sp_on_crl_require",  BRIX_SP_MODE_ON,      BRIX_CRL_MODE_REQUIRE, 0 },
    { "sp_off_crl_try",     BRIX_SP_MODE_OFF,     BRIX_CRL_MODE_TRY,     0 },
    { "bundle",             BRIX_SP_MODE_OFF,     BRIX_CRL_MODE_OFF,     1 },
};

static const group_cfg_t *
group_of(const char *name)
{
    for (size_t i = 0; i < sizeof(GROUPS) / sizeof(GROUPS[0]); i++) {
        if (strcmp(GROUPS[i].name, name) == 0) {
            return &GROUPS[i];
        }
    }
    return NULL;
}

/* -- helpers -------------------------------------------------------------- */

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

/* Eager-load every .r0/.r1 CRL from the CA dir (mirrors pki_load_crls). */
static int
load_crls(X509_STORE *store, const char *cadir)
{
    DIR           *dir = opendir(cadir);
    struct dirent *ent;
    int            count = 0;
    if (dir == NULL) {
        return 0;
    }
    while ((ent = readdir(dir)) != NULL) {
        size_t n = strlen(ent->d_name);
        if (n > 3 && ent->d_name[n - 3] == '.' && ent->d_name[n - 2] == 'r'
            && ent->d_name[n - 1] >= '0' && ent->d_name[n - 1] <= '9')
        {
            char path[4096];
            snprintf(path, sizeof(path), "%s/%s", cadir, ent->d_name);
            FILE *fp = fopen(path, "r");
            X509_CRL *crl;
            if (fp == NULL) {
                continue;
            }
            while ((crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL)) != NULL) {
                if (X509_STORE_add_crl(store, crl)) {
                    count++;
                }
                X509_CRL_free(crl);
            }
            fclose(fp);
        }
    }
    closedir(dir);
    return count;
}

/* Post-verify signing_policy walk (mirror of gsi_verify.c). */
static int
signing_policy_ok(X509_STORE_CTX *ctx)
{
    brix_sp_table_t *table = brix_store_policy_table(ctx);
    brix_sp_mode_t   mode  = brix_store_policy_mode(ctx);
    STACK_OF(X509)  *chain;
    int              n, i;

    if (mode == BRIX_SP_MODE_OFF) {
        return 1;
    }
    chain = X509_STORE_CTX_get0_chain(ctx);
    if (chain == NULL) {
        return 1;
    }
    n = sk_X509_num(chain);
    for (i = 0; i + 1 < n; i++) {
        X509 *subject = sk_X509_value(chain, i);
        X509 *issuer  = sk_X509_value(chain, i + 1);
        if (X509_get_extension_flags(subject) & EXFLAG_PROXY) {
            continue;
        }
        if (!brix_sp_table_check(table, mode, issuer, subject)) {
            return 0;
        }
    }
    return 1;
}

/* Every cert in the verified chain must pass the per-cert conformance policy. */
static int
chain_policy_ok(STACK_OF(X509) *chain)
{
    int i, n = chain ? sk_X509_num(chain) : 0;
    for (i = 0; i < n; i++) {
        if (brix_cert_policy_violation(sk_X509_value(chain, i))) {
            return 0;
        }
    }
    return 1;
}

/* Full verdict for one case: build store, verify, post-checks.  davs cases use
 * webdav flags (no proxy certs); c-oracle cases use GSI flags (allow proxy),
 * so the oracle matches each surface's production configuration. */
static int
verdict_accept(const group_cfg_t *g, const char *cred_path, const char *surface)
{
    char cadir[4096], bundle[4096];
    snprintf(cadir, sizeof(cadir), "%s/shared/ca", FIX);
    snprintf(bundle, sizeof(bundle), "%s/shared/bundle.pem", FIX);

    X509_STORE     *store = X509_STORE_new();
    unsigned long   flags = (strcmp(surface, "davs") == 0)
                            ? 0UL : X509_V_FLAG_ALLOW_PROXY_CERTS;
    int             crl_count = 0;
    STACK_OF(X509) *chain;
    X509_STORE_CTX *ctx;
    int             ok, accept;

    if (g->use_bundle) {
        X509_STORE_load_file(store, bundle);
    } else {
        X509_STORE_load_path(store, cadir);
        if (g->crl_mode != BRIX_CRL_MODE_OFF) {
            crl_count = load_crls(store, cadir);
        }
    }

    if (brix_store_configure(store, g->use_bundle ? NULL : cadir, flags,
            crl_count, g->sp_mode, g->crl_mode, NULL, NULL) != 0) {
        X509_STORE_free(store);
        return -1;   /* config error (e.g. require+bundle) → treated as reject */
    }

    chain = load_chain(cred_path);
    if (sk_X509_num(chain) == 0) {
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_free(store);
        return 0;
    }

    ctx = X509_STORE_CTX_new();
    {
        X509           *leaf = sk_X509_value(chain, 0);
        STACK_OF(X509) *untrusted = sk_X509_new_null();
        STACK_OF(X509) *vchain;
        int             i;
        for (i = 1; i < sk_X509_num(chain); i++) {
            sk_X509_push(untrusted, sk_X509_value(chain, i));
        }
        X509_STORE_CTX_init(ctx, store, leaf, untrusted);
        X509_STORE_CTX_set_depth(ctx, 10);
        /* davs = webdav over TLS: nginx's ssl_verify_client applies the OpenSSL
         * SSL_CLIENT purpose at the TLS layer before brix ever sees the cert.
         * Replicate that here so the oracle matches the wire exactly. */
        if (strcmp(surface, "davs") == 0) {
            X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_CLIENT);
        }
        ok = X509_verify_cert(ctx);
        vchain = X509_STORE_CTX_get0_chain(ctx);
        accept = ok
                 && signing_policy_ok(ctx)
                 && brix_proxy_chain_ok(vchain)
                 && brix_proxy_pci_ok(vchain)
                 && chain_policy_ok(vchain);
        sk_X509_free(untrusted);
    }

    X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_free(store);
    return accept ? 1 : 0;
}

int
main(int argc, char **argv)
{
    const char *filter = (argc > 1 && argv[1][0]) ? argv[1] : NULL;
    char        tsv[4096];
    FILE       *fp;
    char        line[8192];
    int         checks = 0, failures = 0;

    FIX = getenv("BRIX_X509_FIXTURES");
    if (FIX == NULL) {
        fprintf(stderr, "BRIX_X509_FIXTURES not set\n");
        return 2;
    }
    snprintf(tsv, sizeof(tsv), "%s/manifest.tsv", FIX);
    fp = fopen(tsv, "r");
    if (fp == NULL) {
        fprintf(stderr, "cannot open %s\n", tsv);
        return 2;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *id = strtok(line, "\t");
        char *cred = strtok(NULL, "\t");
        char *expected = strtok(NULL, "\t");
        char *surface = strtok(NULL, "\t");
        char *group = strtok(NULL, "\t\n");
        if (!id || !cred || !expected || !surface || !group) {
            continue;
        }
        if (strcmp(surface, "config") == 0) {
            continue;   /* nginx -t cases are not oracle-verifiable */
        }
        if (filter && strncmp(id, filter, strlen(filter)) != 0) {
            continue;
        }
        const group_cfg_t *g = group_of(group);
        if (g == NULL) {
            printf("  FAIL: %s unknown group %s\n", id, group);
            failures++; checks++;
            continue;
        }
        char credpath[4096];
        snprintf(credpath, sizeof(credpath), "%s/creds/%s", FIX, cred);

        int v = verdict_accept(g, credpath, surface);
        int want_accept = (strcmp(expected, "accept") == 0);
        int got_accept = (v == 1);
        checks++;
        if (got_accept != want_accept) {
            failures++;
            printf("  FAIL: %s expected %s got %s (group %s)\n",
                   id, expected, got_accept ? "accept" : "reject", group);
        }
    }
    fclose(fp);

    printf("\n%d oracle checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
