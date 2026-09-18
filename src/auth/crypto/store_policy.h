/*
 * store_policy.h — signing_policy table + X509_STORE ex_data binding.
 *
 * WHAT: Builds a per-CA-directory table of parsed signing_policy files and
 *       attaches it (with the operator's whole brix_trust_policy_t — signing
 *       policy, CRL mode, CRL scope, verification-log level) to an X509_STORE,
 *       so the shared verifier and every store-rebuild path inherit
 *       enforcement from a single place.
 * WHY:  The verifier (brix_gsi_verify_chain) must decide "may this CA sign
 *       this subject?" without threading extra parameters through every
 *       caller.  Binding the table to the store lets the decision travel with
 *       the trust material — including the stream CRL-reload rebuild and the
 *       WebDAV build-once path, which do not share a config object.
 * HOW:  ngx-free at its core (uses signing_policy.h + libc); the OpenSSL glue
 *       lives here.  Logging is via a caller-supplied callback so no ngx
 *       symbol is required.  The store owns the attached table and frees it.
 */
#ifndef BRIX_CRYPTO_STORE_POLICY_H
#define BRIX_CRYPTO_STORE_POLICY_H

#include "auth/crypto/signing_policy.h"

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* CRL strictness, carried on the store alongside the signing_policy mode. */
#define BRIX_CRL_MODE_OFF     0   /* never set CRL verify flags */
#define BRIX_CRL_MODE_TRY     1   /* check where a CRL exists; missing = ok */
#define BRIX_CRL_MODE_REQUIRE 2   /* missing/expired/unverifiable CRL = reject */

/*
 * CRL SCOPE — how far up the chain the revocation check reaches.  This is
 * XRootD's `xrd.tlsca ... crlcheck all|last` residual.
 *
 *   ALL  (default)  every certificate in the chain must be covered by a CRL
 *                   its issuer published, and none of them may be listed on it.
 *   LAST            only the CREDENTIAL'S OWN end-entity certificate is held to
 *                   that; a revocation verdict on an issuer ABOVE it (a missing,
 *                   stale or unverifiable CA CRL — or a revoked intermediate) is
 *                   tolerated.
 *
 * IT IS NOT IMPLEMENTED BY DROPPING X509_V_FLAG_CRL_CHECK_ALL, and that is a
 * security property, not an implementation detail.  OpenSSL's plain CRL_CHECK
 * checks depth 0 only, AND OpenSSL skips proxy certificates when it walks for
 * revocation — so on a GSI proxy chain (proxy at depth 0, the EEC at depth 1)
 * plain CRL_CHECK checks NOTHING AT ALL.  Measured on OpenSSL 3.0.18 with
 * `openssl verify -allow_proxy_certs`: `-crl_check` accepts a proxy whose EEC
 * the CA has revoked; `-crl_check_all` refuses it at depth 1.  A `last` built
 * on the flag would therefore have been indistinguishable from `off` for every
 * grid login — a revoked user would only have to wrap their credential in a
 * proxy.
 *
 * So brix keeps CRL_CHECK|CRL_CHECK_ALL armed under BOTH values and narrows
 * the scope in the verify callback instead: under LAST a revocation-class
 * verdict counts only at the end-entity depth (the shallowest NON-proxy
 * certificate in the chain), and is tolerated at every other depth.  A revoked
 * end-entity certificate is therefore refused under BOTH values, which is the
 * invariant this knob is not allowed to break.  What LAST actually buys is the
 * deployment whose upstream CAs publish no usable CRL for their own issuers.
 * Non-revocation verdicts (expiry, signature, untrusted issuer) are untouched
 * at every depth under both values.
 */
#define BRIX_CRL_SCOPE_ALL   0    /* every certificate in the chain (default) */
#define BRIX_CRL_SCOPE_LAST  1    /* the end-entity certificate only */

/*
 * VERIFICATION LOG — the `xrd.tlsca ... verifylog` residual.  OFF is silent
 * (brix's historical behaviour: only the module's own one-line rejection).
 * FAILURE adds, on a rejected chain, the depth at which OpenSSL stopped and
 * the subject DN of the certificate that failed.  ALL additionally records the
 * subject DN of every certificate in an ACCEPTED chain.
 *
 * DNs ONLY.  The log never emits key material, a PEM body, or any certificate
 * bytes — an operator diagnosing "which CA did this chain actually come
 * through?" needs names, and the error log is not a place to widen what an
 * attacker who can read it learns (see the security negative in
 * tests/test_release20_tlsca_residuals.py).
 */
#define BRIX_TLS_VERIFY_LOG_OFF     0
#define BRIX_TLS_VERIFY_LOG_FAILURE 1
#define BRIX_TLS_VERIFY_LOG_ALL     2

typedef struct brix_sp_table_s brix_sp_table_t;

/*
 * WHAT: the complete trust-enforcement policy that travels with an X509_STORE.
 * WHY:  the store is built in one place (config parse, or a CRL-reload timer)
 *       and consulted in another (a verify callback, brix_gsi_verify_chain)
 *       that has no config object.  Passing the four knobs as one value keeps
 *       the store builders' signatures stable as knobs are added, and — more
 *       importantly — makes it impossible to add a knob that reaches
 *       brix_store_configure but never reaches the ex_data the verifier reads.
 * HOW:  initialise with BRIX_TRUST_POLICY_INIT (everything off / widest scope)
 *       and set the fields the caller actually configures.
 */
/* Legacy (pre-RFC 3820, "GT2") proxy acceptance: a proxy whose subject is its
 * issuer plus one CN (proxy / limited proxy / a number) and that carries no
 * proxyCertInfo.  OpenSSL recognises only RFC 3820 proxies on its own; the
 * verifier marks GT2 proxies with X509_set_proxy_flag() so the same chain
 * rules apply to them. */
#define BRIX_LEGACY_PROXY_OFF       0   /* refuse GT2 proxies (RFC 3820 only) */
#define BRIX_LEGACY_PROXY_ON        1   /* accept full and limited GT2 proxies */
#define BRIX_LEGACY_PROXY_FULL_ONLY 2   /* accept full GT2, refuse "limited proxy" */

typedef struct {
    brix_sp_mode_t  sp_mode;      /* BRIX_SP_MODE_*        */
    int             crl_mode;     /* BRIX_CRL_MODE_*       */
    int             crl_scope;    /* BRIX_CRL_SCOPE_*      */
    int             verify_log;   /* BRIX_TLS_VERIFY_LOG_* */
    int             legacy_proxy; /* BRIX_LEGACY_PROXY_*   */
} brix_trust_policy_t;

#define BRIX_TRUST_POLICY_INIT                                                \
    { BRIX_SP_MODE_OFF, BRIX_CRL_MODE_OFF, BRIX_CRL_SCOPE_ALL,                \
      BRIX_TLS_VERIFY_LOG_OFF, BRIX_LEGACY_PROXY_OFF }

/* Logging callback: level is one of the BRIX_SP_LOG_* values below. */
#define BRIX_SP_LOG_WARN  1
#define BRIX_SP_LOG_INFO  2
typedef void (*brix_sp_log_fn)(void *log, int level, const char *msg);

/*
 * Scan cadir for <hash>.signing_policy files and compile them into a table.
 * A NULL cadir yields an empty (never-present) table.  A file that fails to
 * parse is recorded as a poisoned entry (its CA is rejected at check time)
 * and reported once via log_fn.  Caller owns the result unless it is handed
 * to brix_store_policy_attach() (which takes ownership).
 */
brix_sp_table_t *brix_sp_table_build(const char *cadir,
                                     void *log, brix_sp_log_fn log_fn);

void brix_sp_table_free(brix_sp_table_t *t);

/*
 * Decide whether ca may sign subject under mode.
 *   OFF     → always 1.
 *   ON      → 1 if no policy file is present for ca; else enforce.
 *   REQUIRE → a granting policy file must be present and allow the subject.
 * A present-but-malformed or wrong-CA file fails closed (returns 0) in ON and
 * REQUIRE.  Returns 1 to allow, 0 to deny.
 */
int brix_sp_table_check(const brix_sp_table_t *t, brix_sp_mode_t mode,
                        X509 *ca, X509 *subject);

/*
 * Attach table + modes to a store.  The store takes ownership of table and
 * frees it when the store is freed.  Returns 1 on success, 0 on failure
 * (in which case the caller retains ownership of table).
 */
int brix_store_policy_attach(X509_STORE *store, brix_sp_table_t *table,
                             const brix_trust_policy_t *pol);

/*
 * WHAT: apply the full production trust-store configuration to a store that has
 *       already had its CA certs and CRLs loaded — extra_flags, the proxy
 *       check_issued override (only when X509_V_FLAG_ALLOW_PROXY_CERTS is set),
 *       crl_mode-gated CRL flags + the TRY-mode UNABLE_TO_GET_CRL downgrade, and
 *       the signing_policy table build+attach.
 * WHY:  centralising the flag/callback/policy setup means the production path
 *       (pki_build.c) and the C conformance oracle configure a store
 *       identically — the oracle tests the real decision logic, not a copy.
 * HOW:  ngx-free; logging via the caller-supplied log_fn.  Returns 0 on
 *       success, -1 on the require+bundle configuration error (cadir NULL with
 *       BRIX_SP_MODE_REQUIRE).  On -1 the caller frees the store.
 */
int brix_store_configure(X509_STORE *store, const char *cadir,
                         unsigned long extra_flags, int crl_count,
                         const brix_trust_policy_t *pol,
                         void *log, brix_sp_log_fn log_fn);

/* Fetch what was attached, resolved from a verification context's store. */
brix_sp_table_t *brix_store_policy_table(X509_STORE_CTX *ctx);
brix_sp_mode_t   brix_store_policy_mode(X509_STORE_CTX *ctx);
int              brix_store_crl_mode(X509_STORE_CTX *ctx);
int              brix_store_crl_scope(X509_STORE_CTX *ctx);
int              brix_store_verify_log(X509_STORE_CTX *ctx);
/* The BRIX_LEGACY_PROXY_* mode attached to a store (OFF when none). */
int              brix_store_legacy_proxy(X509_STORE *store);

/*
 * Shared DN canonicaliser — OpenSSL oneline slash form into buf.  Used on
 * BOTH the policy side and the cert side so escaping can never diverge.
 * Returns buf (NUL-terminated), or an empty string on failure.
 */
char *brix_x509_oneline(X509_NAME *name, char *buf, size_t buflen);

/*
 * RFC 3820 proxy classification + delegation monotonicity (ngx-free).
 *   NONE    — not a proxy
 *   FULL    — RFC 3820 impersonation/independent proxy, or legacy CN=proxy
 *   LIMITED — Globus limited-policy OID, or legacy CN=limited proxy
 */
typedef enum { BRIX_PX_NONE, BRIX_PX_FULL, BRIX_PX_LIMITED } brix_px_kind_t;

brix_px_kind_t brix_px_classify(X509 *cert);

/* The GT2 (pre-RFC 3820) proxy shape of `cert`: BRIX_PX_FULL for a subject
 * that is the issuer plus "CN=proxy" or a numeric CN, BRIX_PX_LIMITED for
 * "CN=limited proxy", BRIX_PX_NONE otherwise or when proxyCertInfo is present
 * (an RFC proxy, classified by brix_px_classify). Shape only: the signature
 * and the issuer's identity are the verifier's business. */
brix_px_kind_t brix_gt2_proxy_kind(X509 *cert);

/*
 * Per-certificate WLCG/IGTF conformance policy applied to every cert in a
 * verified chain: minimum key strength (RSA >= 2048, EC >= 256), no weak
 * signature algorithm (MD5/SHA-1), a well-formed serial number (positive,
 * <= 20 octets, RFC 5280 §4.1.2.2), and no embedded control/NUL bytes in the
 * subject/issuer DN (RFC 5280 §4.1.2.6).  Returns 1 when the cert violates
 * policy, 0 when it is clean.  Proxy certificates are exempt from the serial
 * ceiling (grid proxies routinely use large timestamp-derived serials).
 */
int brix_cert_policy_violation(X509 *cert);

/*
 * Leaf end-entity purpose check for client authentication: if the leaf carries
 * an extendedKeyUsage it must include clientAuth or anyExtendedKeyUsage
 * (RFC 5280 §4.2.1.12; absent EKU = any purpose = ok), and if it carries a
 * keyUsage it must assert digitalSignature (§4.2.1.3).  Returns 1 on violation,
 * 0 when the leaf is usable as a client credential.  Applied only to the leaf,
 * and only on the WebDAV/TLS client-cert path (not to GSI proxy leaves).
 */
int brix_leaf_purpose_violation(X509 *leaf);

/*
 * Reject a proxy chain that carries an invalid proxyCertInfo: a proxy-shaped
 * cert (subject = issuer + one CN) whose proxyCertInfo is non-critical, absent
 * where required, or uses an unrecognised policy-language OID.  Returns 1 if
 * the chain is acceptable, 0 on an invalid-proxy violation.
 */
int brix_proxy_pci_ok(STACK_OF(X509) *chain);

/*
 * Enforce that no full proxy is issued beneath a limited proxy (RFC 3820 §3.8).
 * chain is the verified chain leaf..root (as X509_STORE_CTX_get0_chain yields).
 * Returns 1 when the delegation is monotonic, 0 on an escalation.
 */
int brix_proxy_chain_ok(STACK_OF(X509) *chain);

#endif /* BRIX_CRYPTO_STORE_POLICY_H */
