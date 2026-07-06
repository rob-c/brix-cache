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
 * Proxy classification for RFC 3820 monotonicity.  A LIMITED proxy (legacy
 * "CN=limited proxy" or the Globus limited-policy OID) restricts delegation:
 * once one appears, every proxy nearer the leaf must also be limited, and a
 * legacy proxy may never sit beneath an RFC 3820 proxy.
 */
typedef enum { BRIX_PX_NONE, BRIX_PX_FULL, BRIX_PX_LIMITED } brix_px_kind_t;

/* Globus limited-proxy policy language OID: 1.3.6.1.4.1.3536.1.1.1.9. */
static const char *BRIX_PX_LIMITED_OID = "1.3.6.1.4.1.3536.1.1.1.9";

/*
 * WHAT: classify a certificate as non-proxy, full proxy, or limited proxy.
 * HOW:  OpenSSL flags RFC 3820 proxies (EXFLAG_PROXY); read the PROXY_CERT_INFO
 *       policy language OID to tell limited from full.  Fall back to the legacy
 *       Globus convention of a trailing "CN=limited proxy"/"CN=proxy" RDN when
 *       no proxyCertInfo is present.
 */
static brix_px_kind_t
brix_px_classify(X509 *cert)
{
    PROXY_CERT_INFO_EXTENSION *pci;
    brix_px_kind_t             kind = BRIX_PX_NONE;

    if (X509_get_extension_flags(cert) & EXFLAG_PROXY) {
        kind = BRIX_PX_FULL;
        pci = X509_get_ext_d2i(cert, NID_proxyCertInfo, NULL, NULL);
        if (pci != NULL) {
            char oid[128];
            int  n = OBJ_obj2txt(oid, sizeof(oid),
                                 pci->proxyPolicy->policyLanguage, 1);
            if (n > 0 && strcmp(oid, BRIX_PX_LIMITED_OID) == 0) {
                kind = BRIX_PX_LIMITED;
            }
            PROXY_CERT_INFO_EXTENSION_free(pci);
        }
        return kind;
    }

    /* Legacy Globus proxy: last RDN is CN=proxy or CN=limited proxy. */
    {
        X509_NAME *nm = X509_get_subject_name(cert);
        int        last = X509_NAME_entry_count(nm) - 1;
        if (last >= 0) {
            X509_NAME_ENTRY *e = X509_NAME_get_entry(nm, last);
            ASN1_STRING     *v = X509_NAME_ENTRY_get_data(e);
            const unsigned char *s = ASN1_STRING_get0_data(v);
            int len = ASN1_STRING_length(v);
            if (len == (int) sizeof("limited proxy") - 1
                && ngx_strncasecmp((u_char *) s,
                       (u_char *) "limited proxy", len) == 0)
            {
                return BRIX_PX_LIMITED;
            }
            if (len == (int) sizeof("proxy") - 1
                && ngx_strncasecmp((u_char *) s, (u_char *) "proxy", len) == 0)
            {
                return BRIX_PX_FULL;
            }
        }
    }
    return BRIX_PX_NONE;
}

/*
 * WHAT: enforce limited-proxy monotonicity over the verified chain.
 * WHY:  RFC 3820 §3.8 — a limited proxy must not be used to issue a full
 *       (unrestricted) proxy; doing so escalates privilege.
 * HOW:  Walk root..leaf tracking whether a limited proxy has been seen at a
 *       higher (more-authoritative) position.  A FULL proxy seen after a
 *       LIMITED one is an escalation → reject.
 */
static ngx_int_t
brix_gsi_enforce_proxy_monotonicity(X509_STORE_CTX *vctx, ngx_log_t *log)
{
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(vctx);
    int             n, i;
    int             seen_limited = 0;

    if (chain == NULL) {
        return NGX_OK;
    }

    n = sk_X509_num(chain);
    for (i = n - 1; i >= 0; i--) {   /* root .. leaf */
        brix_px_kind_t kind = brix_px_classify(sk_X509_value(chain, i));

        if (kind == BRIX_PX_LIMITED) {
            seen_limited = 1;
        } else if (kind == BRIX_PX_FULL && seen_limited) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "brix: GSI proxy chain rejected: a full proxy is issued "
                "beneath a limited proxy (RFC 3820 delegation escalation)");
            return NGX_ERROR;
        }
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
    brix_gsi_verify_result_t *res)
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

    X509_STORE_CTX_set_flags(vctx, X509_V_FLAG_ALLOW_PROXY_CERTS);

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
        || brix_gsi_enforce_proxy_monotonicity(vctx, log) != NGX_OK)
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
