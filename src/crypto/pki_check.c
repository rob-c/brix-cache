#include "pki_check.h"

#include <ngx_config.h>
#include <ngx_core.h>

#include "core/compat/log_diag.h"

#include <openssl/pem.h>
#include <openssl/evp.h>

/*
 * CRL issuer matching and signature checks shared by stream and WebDAV
 * startup consistency checks.
 */

#ifndef HAVE_X509_CRL_GET0_ISSUER
# if defined(X509_CRL_get0_issuer)
#  define HAVE_X509_CRL_GET0_ISSUER 1
# else
#  define HAVE_X509_CRL_GET0_ISSUER 0
# endif
#endif

#if HAVE_X509_CRL_GET0_ISSUER
# define CRL_GET_ISSUER(crl) X509_CRL_get0_issuer((crl))
#else
# define CRL_GET_ISSUER(crl) X509_CRL_get_issuer((crl))
#endif

/*
 *
 * WHAT: Converts an X509_NAME structure to a human-readable string via X509_NAME_oneline — produces the standard OpenSSL DN format used for CA/CRL issuer identification in error logs. Returns caller-owned malloc'd string that must be freed with OPENSSL_free.
 *
 * WHY: PKI verification functions need to log issuer DNs when CRL/CA mismatches occur; without converting the binary X509_NAME structure to readable text, operators can't determine which certificate in their trust store is causing the issue.
 *
 * HOW: Calls X509_NAME_oneline(name, NULL, 0) which returns a malloc'd string in standard DN format. Caller retains ownership and must free via OPENSSL_free.
 */

static char *
xrootd_pki_name_to_str(const X509_NAME *name)
{
    return X509_NAME_oneline(name, NULL, 0);
}

/*
 *
 * WHAT: Logs a structured PKI error message containing the X509_NAME as readable text — combines log_prefix, descriptive message, and DN string into a single ngx_log_error call. Frees the OpenSSL-allocated name string after logging.
 *
 * WHY: CRL/CA mismatch errors need to identify which issuer or CA was problematic; without converting the binary X509_NAME structure to readable text, operators can't determine which certificate in their trust store is causing the issue.
 *
 * HOW: Calls xrootd_pki_name_to_str() to convert name → string, logs with format "%s: PKI check: %s %s" using log_prefix + message + name_text (or "<unknown>" if conversion failed), frees name_text via OPENSSL_free.
 */

static void
xrootd_pki_log_name_error(ngx_log_t *log, const char *log_prefix,
    const char *message, const X509_NAME *name)
{
    char *name_text;

    name_text = xrootd_pki_name_to_str(name);
    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "%s: PKI check: %s %s",
                  log_prefix, message, name_text ? name_text : "<unknown>");

    if (name_text != NULL) {
        OPENSSL_free(name_text);
    }
}

/*
 *
 * WHAT: Compares the issuer DN of a CRL against the subject DN of a CA certificate — returns 1 if they match, 0 otherwise. Uses HAVE_X509_CRL_GET0_ISSUER compile-time macro to select between modern X509_CRL_get0_issuer (const pointer) and legacy X509_CRL_get_issuer (malloc'd pointer).
 *
 * WHY: CRL issuer matching is the first step of cross-signature verification; DN comparison selects candidate CA, then signature check proves the CRL was actually signed by that CA's private key. Without this helper, each caller would duplicate the issuer/subject extraction + comparison logic.
 *
 * HOW: Extracts crl_issuer via CRL_GET_ISSUER macro (conditional on OpenSSL version), extracts ca_subject via X509_get_subject_name, compares with X509_NAME_cmp — returns 1 if zero difference.
 */

static ngx_flag_t
xrootd_pki_crl_matches_ca(X509_CRL *crl, X509 *ca_cert)
{
    X509_NAME *crl_issuer;
    X509_NAME *ca_subject;

    crl_issuer = CRL_GET_ISSUER(crl);
    ca_subject = X509_get_subject_name(ca_cert);

    return X509_NAME_cmp(crl_issuer, ca_subject) == 0;
}

/*
 *
 * WHAT: Verifies that a CRL's digital signature was produced by the specified issuer CA's public key — returns 1 if valid, 0 on failure with structured error log. Extracts public key from CA cert, calls X509_CRL_verify, frees key.
 *
 * WHY: DN matching alone is insufficient to prove a CRL belongs to a CA; a different CA could have the same subject DN in misconfigured setups. The signature check proves cryptographic ownership — the CRL was actually signed by that CA's private key, not just nominally issued by it.
 *
 * HOW: Extracts issuer_subject and issuer_public_key from issuer_ca cert; if pubkey extraction fails, logs "CA has no public key" error; calls X509_CRL_verify(crl, issuer_public_key); frees pubkey via EVP_PKEY_free; on failure logs CRL signature verification error with issuer DN.
 */

static ngx_flag_t
xrootd_pki_crl_signature_valid(ngx_log_t *log, X509_CRL *crl,
    X509 *issuer_ca, const char *log_prefix)
{
    EVP_PKEY  *issuer_public_key;
    X509_NAME *issuer_subject;
    int        verify_ok;

    issuer_subject = X509_get_subject_name(issuer_ca);
    issuer_public_key = X509_get_pubkey(issuer_ca);
    if (issuer_public_key == NULL) {
        xrootd_pki_log_name_error(log, log_prefix,
                                  "CA has no public key",
                                  issuer_subject);
        return 0;
    }

    /*
     * Matching issuer DN selects the candidate CA; the signature check proves
     * the CRL was actually issued by that CA key.
     */
    verify_ok = X509_CRL_verify(crl, issuer_public_key);
    EVP_PKEY_free(issuer_public_key);

    if (verify_ok != 1) {
        xrootd_pki_log_name_error(log, log_prefix,
                                  "CRL signature verification failed for CRL issuer",
                                  issuer_subject);
        return 0;
    }

    return 1;
}

/*
 * xrootd_pki_verify_crls — at startup, check that every loaded CRL has a
 * matching CA certificate and a valid signature.
 *
 * This is a configuration-time consistency check, not an online revocation
 * check.  Its purpose is to catch mismatched ca_dir / crl_dir settings before
 * the server accepts any connections.
 *
 * Issuer matching: the CRL's issuer DN is compared with each CA's subject DN.
 * DN matching selects the candidate CA; the signature check then proves the
 * CRL was actually signed by that CA's private key.
 *
 * Errors are logged but do not cause the function to return NGX_ERROR — the
 * server starts even with a broken CRL so that a CA update doesn't take the
 * whole service down.  Operators should monitor the error log.
 *
 * Returns: always NGX_OK (errors are non-fatal, logged only).
 */
ngx_int_t
xrootd_pki_verify_crls(ngx_log_t *log, STACK_OF(X509) *ca_certs,
    STACK_OF(X509_CRL) *crls, const char *log_prefix)
{
    int crl_count;
    int ca_count;
    int crl_index;

    crl_count = sk_X509_CRL_num(crls);
    ca_count = sk_X509_num(ca_certs);

    for (crl_index = 0; crl_index < crl_count; crl_index++) {
        X509_CRL  *crl;
        X509_NAME *crl_issuer;
        ngx_flag_t issuer_found;
        int        ca_index;

        crl = sk_X509_CRL_value(crls, crl_index);
        crl_issuer = CRL_GET_ISSUER(crl);
        issuer_found = 0;

        for (ca_index = 0; ca_index < ca_count; ca_index++) {
            X509 *candidate_ca;

            candidate_ca = sk_X509_value(ca_certs, ca_index);
            if (xrootd_pki_crl_matches_ca(crl, candidate_ca)) {
                issuer_found = 1;
                (void) xrootd_pki_crl_signature_valid(log, crl,
                                                       candidate_ca,
                                                       log_prefix);
                break;
            }
        }

        if (!issuer_found) {
            xrootd_pki_log_name_error(log, log_prefix,
                                      "no matching CA found for CRL issuer",
                                      crl_issuer);
        }
    }

    return NGX_OK;
}

/*
 * xrootd_pki_check_paths — load CAs and CRLs from disk and verify
 * cross-signatures.  Called during nginx configuration phase.
 *
 * If ca_path or crl_path is NULL the corresponding check is skipped
 * gracefully.  The function always returns NGX_OK; problems are logged
 * as warnings.
 */
ngx_int_t
xrootd_pki_check_paths(ngx_log_t *log, const char *ca_path,
    const char *crl_path, const char *log_prefix)
{
    STACK_OF(X509)     *ca_certs;
    STACK_OF(X509_CRL) *crls;

    if (ca_path == NULL) {
        return NGX_OK;
    }

    ca_certs = xrootd_pki_load_certs_from_path(ca_path, log);
    if (ca_certs == NULL) {
        XROOTD_DIAG_WARN(log, 0,
            "%s: no CA certificates loaded from \"%s\"",
            "directory has no readable *.pem CA certs, or wrong path",
            "point the CA setting at your grid trust store "
            "(usually /etc/grid-security/certificates); until then ALL "
            "GSI/x509 client authentication will be rejected",
            log_prefix, ca_path);
        return NGX_OK;
    }

    if (crl_path == NULL) {
        sk_X509_pop_free(ca_certs, X509_free);
        return NGX_OK;
    }

    crls = xrootd_pki_load_crls_from_path(crl_path, log);
    if (crls == NULL) {
        XROOTD_DIAG_WARN(log, 0,
            "%s: no CRLs loaded from \"%s\"",
            "CRL directory is empty, stale, or wrong path",
            "run fetch-crl (or your CRL refresh cron) to populate it; "
            "until then REVOKED certificates are still ACCEPTED",
            log_prefix, crl_path);
        sk_X509_pop_free(ca_certs, X509_free);
        return NGX_OK;
    }

    (void) xrootd_pki_verify_crls(log, ca_certs, crls, log_prefix);

    sk_X509_pop_free(ca_certs, X509_free);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);

    return NGX_OK;
}

int
xrootd_check_pki_and_crl(const char *ca_dir, const char *crl_dir, ngx_log_t *log)
{
    (void) xrootd_pki_check_paths(log, ca_dir, crl_dir, "xrootd");

    return 0;
}
