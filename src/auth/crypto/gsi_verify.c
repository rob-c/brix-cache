/*
 * gsi_verify.c — shared x.509 proxy chain verification core.
 *
 * Both the XRootD stream (GSI kXR_auth) and WebDAV (DAVS client certificate)
 * authentication paths perform identical X509_STORE_CTX setup and chain
 * verification.  Centralising here means any bug fix or security improvement
 * (flag addition, depth handling, error logging) automatically covers all
 * callers.
 *
 * WHAT: Wraps OpenSSL X509_STORE_CTX lifecycle — allocate, initialise with
 *       leaf + untrusted chain + CA store, set ALLOW_PROXY_CERTS flag,
 *       optionally set depth, call X509_verify_cert, extract leaf subject DN.
 *
 * WHY: The stream and WebDAV paths previously duplicated this ~25-line block
 *      verbatim.  A single defect (wrong flag, missing depth, wrong error
 *      logging) would affect only one path, causing inconsistent security
 *      behaviour between the two protocols.
 *
 * HOW: See brix_gsi_verify_chain() below.  The caller retains ownership of
 *      all passed-in objects; none are freed here.
 */

#include "gsi_verify.h"

#include "auth/crypto/store_policy.h"
#include "core/compat/log_diag.h"

#include <openssl/x509v3.h>   /* EXFLAG_PROXY, X509_get_extension_flags */

#include <string.h>

/*
 * WHAT: enforce limited-proxy monotonicity over the verified chain.
 * WHY:  RFC 3820 §3.8 — a limited proxy must not be used to issue a full
 *       (unrestricted) proxy; doing so escalates privilege.
 * HOW:  Delegate to the ngx-free brix_proxy_chain_ok() so the pure logic is
 *       unit-testable; log and map its verdict to NGX_OK/NGX_ERROR here.
 */
static ngx_int_t
brix_gsi_enforce_proxy_monotonicity(X509_STORE_CTX *vctx, ngx_log_t *log)
{
    if (!brix_proxy_chain_ok(X509_STORE_CTX_get0_chain(vctx))) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "brix: GSI proxy chain rejected: a full proxy is issued beneath a "
            "limited proxy (RFC 3820 delegation escalation)");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: enforce Globus signing_policy over a verified chain.
 * WHY:  PKIX validation proves each cert was signed by its issuer, but the
 *       WLCG trust model additionally requires a CA sign only within its
 *       delegated namespace.  A trusted CA that signs outside its namespace
 *       passes X509_verify_cert yet must be rejected here.
 * HOW:  Walk the ordered chain leaf..root.  For each non-proxy subject, ask
 *       the store's attached policy table whether its issuer (the next cert)
 *       is permitted to sign it.  Proxy subjects are exempt — their issuer is
 *       the EEC/parent proxy, never a trust anchor.  Returns NGX_OK when every
 *       link is permitted, NGX_ERROR (logged) on the first violation.
 */
static ngx_int_t
brix_gsi_enforce_signing_policy(X509_STORE_CTX *vctx, ngx_log_t *log)
{
    brix_sp_table_t *table = brix_store_policy_table(vctx);
    brix_sp_mode_t   mode  = brix_store_policy_mode(vctx);
    STACK_OF(X509)  *chain;
    int              n, i;

    if (mode == BRIX_SP_MODE_OFF) {
        return NGX_OK;
    }

    chain = X509_STORE_CTX_get0_chain(vctx);   /* borrowed; do not free */
    if (chain == NULL) {
        return NGX_OK;
    }

    n = sk_X509_num(chain);
    for (i = 0; i + 1 < n; i++) {
        X509 *subject = sk_X509_value(chain, i);
        X509 *issuer  = sk_X509_value(chain, i + 1);

        if (X509_get_extension_flags(subject) & EXFLAG_PROXY) {
            continue;   /* proxy: issuer is the EEC, not a trust anchor */
        }

        if (!brix_sp_table_check(table, mode, issuer, subject)) {
            char subj_dn[1024];
            char ca_dn[1024];

            brix_x509_oneline(X509_get_subject_name(subject),
                              subj_dn, sizeof(subj_dn));
            brix_x509_oneline(X509_get_subject_name(issuer),
                              ca_dn, sizeof(ca_dn));
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "brix: GSI signing_policy: CA \"%s\" may not sign subject "
                "\"%s\" (namespace violation or missing policy)",
                ca_dn, subj_dn);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: hold every cert in the verified chain to the per-cert conformance
 *       policy, reject invalid proxyCertInfo, and (client_purpose) reject a
 *       leaf that is not usable for client authentication.
 * HOW:  delegate to the ngx-free brix_cert_policy_violation / brix_proxy_pci_ok
 *       / brix_leaf_purpose_violation; log and map to NGX_OK/NGX_ERROR.
 */
static ngx_int_t
brix_gsi_enforce_cert_policy(X509_STORE_CTX *vctx, X509 *leaf, ngx_log_t *log,
                             int client_purpose)
{
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(vctx);
    int             n, i;

    n = chain ? sk_X509_num(chain) : 0;
    for (i = 0; i < n; i++) {
        if (brix_cert_policy_violation(sk_X509_value(chain, i))) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "brix: GSI cert rejected: weak key/algorithm, malformed serial, "
                "or invalid DN in the chain (RFC 5280 / IGTF profile)");
            return NGX_ERROR;
        }
    }
    if (!brix_proxy_pci_ok(chain)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "brix: GSI proxy rejected: proxyCertInfo not critical or unknown "
            "policy language (RFC 3820 §3.1/§3.2)");
        return NGX_ERROR;
    }
    if (client_purpose && brix_leaf_purpose_violation(leaf)) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "brix: client cert rejected: extendedKeyUsage lacks clientAuth or "
            "keyUsage lacks digitalSignature (RFC 5280 §4.2.1.12/§4.2.1.3)");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: Verify an x.509 proxy certificate chain against a CA trust store.
 *
 * HOW (step by step):
 *   1. Allocate a fresh X509_STORE_CTX (never reuse across requests).
 *   2. Initialise it: store = CA trust store, subject = leaf, untrusted = intermediates.
 *   3. Set X509_V_FLAG_ALLOW_PROXY_CERTS so proxy certificates (RFC 3820) in
 *      the chain are accepted — required for WLCG proxy credentials.
 *   4. Optionally set chain depth via X509_STORE_CTX_set_depth when the
 *      caller has a configured limit (verify_depth > 0).
 *   5. Call X509_verify_cert(); on failure extract the error code, log it, and
 *      return NGX_ERROR.
 *   6. On success extract the subject DN from the leaf via X509_NAME_oneline,
 *      copy to res->dn_buf (truncating safely if oversized), free the
 *      OpenSSL-allocated string, and return NGX_OK.
 */
ngx_int_t
brix_gsi_verify_chain(ngx_log_t *log, X509_STORE *store,
    X509 *leaf, STACK_OF(X509) *untrusted,
    ngx_uint_t verify_depth,
    brix_gsi_verify_result_t *res,
    int client_purpose)
{
    X509_STORE_CTX *vctx;
    char           *dn_str;
    int             ok;

    ngx_memzero(res, sizeof(*res));

    vctx = X509_STORE_CTX_new();
    if (vctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix: GSI: X509_STORE_CTX_new() failed");
        return NGX_ERROR;
    }

    if (!X509_STORE_CTX_init(vctx, store, leaf, untrusted)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix: GSI: X509_STORE_CTX_init() failed");
        X509_STORE_CTX_free(vctx);
        return NGX_ERROR;
    }

    /* RFC 3820 proxy chains are accepted only on the GSI path; the WebDAV/TLS
     * client-cert path (client_purpose) does not accept proxies. */
    if (!client_purpose) {
        X509_STORE_CTX_set_flags(vctx, X509_V_FLAG_ALLOW_PROXY_CERTS);
    }

    if (verify_depth > 0) {
        X509_STORE_CTX_set_depth(vctx, (int) verify_depth);
    }

    ok = X509_verify_cert(vctx);
    if (!ok) {
        int         verr     = X509_STORE_CTX_get_error(vctx);
        const char *verr_str = X509_verify_cert_error_string(verr);

        BRIX_DIAG_WARN(log, 0,
            "brix: GSI client cert rejected: %s",
            "the client proxy/cert is expired, or its issuing CA is not in "
            "this server's trust store",
            "if \"expired\": the user must renew their proxy "
            "(voms-proxy-init / grid-proxy-init). If \"unable to get local "
            "issuer certificate\": add the issuing CA to the trust store and "
            "reload",
            verr_str);
        X509_STORE_CTX_free(vctx);
        return NGX_ERROR;
    }

    if (brix_gsi_enforce_signing_policy(vctx, log) != NGX_OK
        || brix_gsi_enforce_proxy_monotonicity(vctx, log) != NGX_OK
        || brix_gsi_enforce_cert_policy(vctx, leaf, log, client_purpose)
           != NGX_OK)
    {
        X509_STORE_CTX_free(vctx);
        return NGX_ERROR;
    }

    X509_STORE_CTX_free(vctx);

    dn_str = X509_NAME_oneline(X509_get_subject_name(leaf), NULL, 0);
    if (dn_str != NULL) {
        ngx_cpystrn((u_char *) res->dn_buf, (u_char *) dn_str,
                    sizeof(res->dn_buf));
        OPENSSL_free(dn_str);
    }

    return NGX_OK;
}
