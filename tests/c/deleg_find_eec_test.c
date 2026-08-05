/* Unit test for delegation_find_eec() — the shared end-entity-certificate scan
 * over a verified proxy chain (src/protocols/webdav/delegation.c).
 *
 * This is the primitive the $brix_delegated_cred EEC recovery relies on
 * (Finding 1 of docs/09-developer-guide/gsi-delegation-xrdhttp-fullmatrix.md):
 * delegated_cred_find_eec() in module_init.c now calls THIS function on both the
 * peer chain (SSL_get_peer_cert_chain) and, as a fallback, the verification-time
 * chain (SSL_get0_verified_chain). RFC 3820 proxies chain leaf -> parent
 * proxies -> EEC -> CA, so the EEC is the FIRST non-proxy entry; the scan must
 * skip every proxy and never hand a proxy cert back as if it were the EEC (which
 * would derive the wrong storage-credential key and delegate the wrong identity).
 *
 * Links the REAL delegation.o + the x509 policy sources (brix_px_classify);
 * delegation.o's nginx/upload-handler surface is name-stubbed below (this unit
 * only calls delegation_find_eec, which touches none of it). Fixtures (forged
 * via tests/x509forge.py) come from $BRIX_DELEG_FIND_EEC_FIXTURES:
 *   ca.pem     — CA
 *   eec.pem    — CA-signed end-entity cert (BRIX_PX_NONE)
 *   proxy.pem  — RFC 3820 proxy off the EEC (BRIX_PX_FULL)
 *   proxy2.pem — a second proxy off the EEC (distinct serial)
 *
 * Ritual: success (EEC found among proxies) + error (NULL/empty chain -> NULL)
 * + security-negative (all-proxy chain -> NULL, a proxy is NEVER returned).
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "auth/crypto/store_policy.h"   /* brix_px_classify, BRIX_PX_NONE */

/* delegation_find_eec is declared in delegation_internal.h, which drags the
 * webdav/nginx headers; this unit needs only the one prototype. */
X509 *delegation_find_eec(STACK_OF(X509) *chain);

/* ---- delegation.o link-satisfying stubs ----------------------------------
 * delegation.o also holds the T8 upload handler, which references the symbols
 * below. delegation_find_eec() calls NONE of them, so name-only stubs resolve
 * the link; they are never invoked at run time. No nginx headers are included,
 * so these definitions cannot collide with a real prototype. */
void brix_gsi_verify_chain(void) {}
void brix_http_body_read_all(void) {}
void brix_sanitize_log_string(void) {}
void brix_sd_ucred_key(void) {}
void webdav_metrics_finalize_request(void) {}
void ngx_http_output_filter(void) {}
void ngx_http_send_header(void) {}
void ngx_log_error_core(void) {}
void ngx_pcalloc(void) {}
void ngx_pnalloc(void) {}
void ngx_snprintf(void) {}
char ngx_http_brix_webdav_module;   /* data symbol, never read */

/* ---- helpers -------------------------------------------------------------- */

static X509 *
load_cert(const char *dir, const char *name)
{
    char   path[1024];
    FILE  *f;
    X509  *x;

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "rb");
    assert(f != NULL);
    x = PEM_read_X509(f, NULL, NULL, NULL);
    assert(x != NULL);
    fclose(f);
    return x;
}

/* Build a borrowed-reference stack from the given certs (NULL-terminated). The
 * stack owns no references — callers still free the certs individually. */
static STACK_OF(X509) *
mkchain(X509 *first, ...)
{
    STACK_OF(X509) *sk = sk_X509_new_null();
    va_list         ap;
    X509           *c;

    assert(sk != NULL);
    if (first != NULL) {
        assert(sk_X509_push(sk, first) > 0);
        va_start(ap, first);
        while ((c = va_arg(ap, X509 *)) != NULL) {
            assert(sk_X509_push(sk, c) > 0);
        }
        va_end(ap);
    }
    return sk;
}

int
main(void)
{
    const char     *dir = getenv("BRIX_DELEG_FIND_EEC_FIXTURES");
    X509           *eec, *proxy, *proxy2, *ca;
    STACK_OF(X509) *chain;

    assert(dir != NULL && "BRIX_DELEG_FIND_EEC_FIXTURES must point at the forge dir");

    ca     = load_cert(dir, "ca.pem");
    eec    = load_cert(dir, "eec.pem");
    proxy  = load_cert(dir, "proxy.pem");
    proxy2 = load_cert(dir, "proxy2.pem");

    /* Precondition on the fixtures: the classifier agrees with our labels, or
     * every case below would be vacuous. */
    assert(brix_px_classify(eec) == BRIX_PX_NONE);
    assert(brix_px_classify(ca) == BRIX_PX_NONE);
    assert(brix_px_classify(proxy) != BRIX_PX_NONE);
    assert(brix_px_classify(proxy2) != BRIX_PX_NONE);

    /* 1. SUCCESS (server peer-chain view: the leaf proxy is excluded, so the
     *    EEC is element 0). First non-proxy -> the EEC. */
    chain = mkchain(eec, ca, NULL);
    assert(delegation_find_eec(chain) == eec);
    sk_X509_free(chain);

    /* 2. SUCCESS (RFC 3820 ordering the fix cares about: a proxy PRECEDES the
     *    EEC). The scan must skip the proxy and return the EEC — proving it
     *    matches by kind, not by position, so it works on the verified chain
     *    OpenSSL rebuilds (leaf-proxy -> EEC -> CA). */
    chain = mkchain(proxy, eec, ca, NULL);
    {
        X509 *got = delegation_find_eec(chain);
        assert(got == eec);
        assert(got != proxy);
    }
    sk_X509_free(chain);

    /* 3. ERROR: no chain / empty chain -> NULL (sk_X509_num(NULL) == -1, so the
     *    loop is skipped). Fail-closed, never a crash. */
    assert(delegation_find_eec(NULL) == NULL);
    chain = mkchain(NULL);
    assert(delegation_find_eec(chain) == NULL);
    sk_X509_free(chain);

    /* 4. SECURITY-NEG: an all-proxy chain (no EEC recoverable) -> NULL. A proxy
     *    is NEVER returned in the EEC's place. Were it, module_init.c would key
     *    the delegated credential off a proxy DN (…/CN=<serial>) instead of the
     *    stable EEC DN — resolving the wrong file or a different user. Both a
     *    single proxy and a multi-proxy stack must fail closed. */
    chain = mkchain(proxy, NULL);
    assert(delegation_find_eec(chain) == NULL);
    sk_X509_free(chain);

    chain = mkchain(proxy, proxy2, NULL);
    assert(delegation_find_eec(chain) == NULL);
    sk_X509_free(chain);

    X509_free(ca);
    X509_free(eec);
    X509_free(proxy);
    X509_free(proxy2);
    printf("deleg_find_eec_test: all checks passed\n");
    return 0;
}
