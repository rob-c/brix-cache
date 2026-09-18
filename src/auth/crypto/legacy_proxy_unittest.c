/*
 * legacy_proxy_unittest.c — unit suite for the GT2 (pre-RFC 3820) proxy shape
 * classifier and the limited-proxy chain rule over legacy proxies.
 *
 *   cc -std=c11 -D_GNU_SOURCE -DBRIX_PLATFORM_HOST=<host> -Wall -Wextra -Werror \
 *      -I src -I shared src/auth/crypto/legacy_proxy_unittest.c \
 *      src/auth/crypto/store_policy_conformance.c -lcrypto -o /tmp/lpx && /tmp/lpx
 *
 * Exit 0 and "all checks passed" = every pin holds. Certificates are minted
 * in memory with throwaway keys: only the SHAPE is under test here (the chain
 * signature and trust are the verifier's business and are pinned end to end
 * by tests/test_gsi_legacy_proxy.py).
 */

#include "auth/crypto/store_policy.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); g_fail++; } \
} while (0)

static EVP_PKEY *
throwaway_key(void)
{
    static EVP_PKEY *key;

    if (key == NULL) {
        key = EVP_RSA_gen(2048);
    }
    return key;
}

/* A certificate with `subject`, issued by `issuer_name`, optionally carrying
 * proxyCertInfo (RFC 3820) with the given policy OID. */
static X509 *
make_cert(X509_NAME *subject, X509_NAME *issuer_name, const char *pci_policy_oid)
{
    X509 *cert = X509_new();

    X509_set_version(cert, 2);
    X509_set_subject_name(cert, subject);
    X509_set_issuer_name(cert, issuer_name);
    X509_gmtime_adj(X509_getm_notBefore(cert), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_set_pubkey(cert, throwaway_key());
    if (pci_policy_oid != NULL) {
        PROXY_CERT_INFO_EXTENSION *pci = PROXY_CERT_INFO_EXTENSION_new();

        pci->proxyPolicy->policyLanguage = OBJ_txt2obj(pci_policy_oid, 1);
        X509_add1_ext_i2d(cert, NID_proxyCertInfo, pci, 1, 0);
        PROXY_CERT_INFO_EXTENSION_free(pci);
    }
    X509_sign(cert, throwaway_key(), EVP_sha256());
    return cert;
}

static X509_NAME *
name_of(const char *dc, const char *cn)
{
    X509_NAME *n = X509_NAME_new();

    X509_NAME_add_entry_by_txt(n, "DC", MBSTRING_ASC, (const unsigned char *) dc, -1, -1, 0);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *) cn, -1, -1, 0);
    return n;
}

/* `parent` + one CN. */
static X509_NAME *
child_name(const X509_NAME *parent, const char *cn)
{
    X509_NAME *n = X509_NAME_dup(parent);

    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *) cn, -1, -1, 0);
    return n;
}

#define RFC_IMPERSONATION "1.3.6.1.5.5.7.21.1"
#define RFC_LIMITED       "1.3.6.1.4.1.3536.1.1.1.9"

static void
test_shapes(void)
{
    X509_NAME *eec = name_of("test", "Alice");
    X509_NAME *ca = name_of("test", "Test CA");
    X509_NAME *full = child_name(eec, "proxy");
    X509_NAME *limited = child_name(eec, "limited proxy");
    X509_NAME *numeric = child_name(eec, "12345678");
    X509_NAME *other = child_name(eec, "something");
    X509_NAME *twodeep = child_name(full, "proxy");
    X509 *c;

    c = make_cert(eec, ca, NULL);
    CHECK(brix_gt2_proxy_kind(c) == BRIX_PX_NONE);          /* an EEC */
    X509_free(c);
    c = make_cert(full, eec, NULL);
    CHECK(brix_gt2_proxy_kind(c) == BRIX_PX_FULL);
    X509_free(c);
    c = make_cert(limited, eec, NULL);
    CHECK(brix_gt2_proxy_kind(c) == BRIX_PX_LIMITED);
    X509_free(c);
    c = make_cert(numeric, eec, NULL);
    CHECK(brix_gt2_proxy_kind(c) == BRIX_PX_FULL);
    X509_free(c);
    c = make_cert(other, eec, NULL);
    CHECK(brix_gt2_proxy_kind(c) == BRIX_PX_NONE);          /* not a proxy CN */
    X509_free(c);
    c = make_cert(twodeep, eec, NULL);
    CHECK(brix_gt2_proxy_kind(c) == BRIX_PX_NONE);          /* two CNs added */
    X509_free(c);
    c = make_cert(full, ca, NULL);
    CHECK(brix_gt2_proxy_kind(c) == BRIX_PX_NONE);          /* issuer is not the prefix */
    X509_free(c);
    /* an RFC 3820 proxy is never a GT2 proxy, whatever its CN */
    c = make_cert(full, eec, RFC_IMPERSONATION);
    CHECK(brix_gt2_proxy_kind(c) == BRIX_PX_NONE);
    CHECK(brix_px_classify(c) == BRIX_PX_FULL);
    X509_free(c);
    c = make_cert(numeric, eec, RFC_LIMITED);
    CHECK(brix_gt2_proxy_kind(c) == BRIX_PX_NONE);
    CHECK(brix_px_classify(c) == BRIX_PX_LIMITED);
    X509_free(c);

    X509_NAME_free(eec); X509_NAME_free(ca); X509_NAME_free(full);
    X509_NAME_free(limited); X509_NAME_free(numeric); X509_NAME_free(other);
    X509_NAME_free(twodeep);
}

/* Once the verifier marks a GT2 proxy, the classifier reports its kind and
 * the limited-monotonicity rule applies across GT2 and RFC proxies. */
static void
test_marked_chain_rules(void)
{
    X509_NAME *eec = name_of("test", "Bob");
    X509_NAME *ca = name_of("test", "Test CA");
    X509_NAME *lim = child_name(eec, "limited proxy");
    X509_NAME *full_below = child_name(lim, "proxy");
    X509 *root = make_cert(ca, ca, NULL);
    X509 *user = make_cert(eec, ca, NULL);
    X509 *limited = make_cert(lim, eec, NULL);
    X509 *full = make_cert(full_below, lim, RFC_IMPERSONATION);
    STACK_OF(X509) *chain = sk_X509_new_null();

    CHECK(brix_px_classify(limited) == BRIX_PX_LIMITED);    /* by shape, before marking */
    (void) X509_get_extension_flags(limited);
    X509_set_proxy_flag(limited);
    CHECK(brix_px_classify(limited) == BRIX_PX_LIMITED);    /* and after the verifier marks it */
    CHECK(X509_get_extension_flags(limited) & EXFLAG_PROXY);

    /* leaf..root order as X509_STORE_CTX_get0_chain hands it */
    sk_X509_push(chain, full);
    sk_X509_push(chain, limited);
    sk_X509_push(chain, user);
    sk_X509_push(chain, root);
    CHECK(!brix_proxy_chain_ok(chain));   /* RFC full beneath GT2 limited: escalation */
    sk_X509_delete(chain, 0);
    CHECK(brix_proxy_chain_ok(chain));    /* GT2 limited leaf alone is fine */

    sk_X509_free(chain);
    X509_free(full); X509_free(limited); X509_free(user); X509_free(root);
    X509_NAME_free(eec); X509_NAME_free(ca); X509_NAME_free(lim); X509_NAME_free(full_below);
}

int
main(void)
{
    test_shapes();
    test_marked_chain_rules();
    if (g_fail) {
        printf("%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
