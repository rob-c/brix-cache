#ifndef CRYPTO_PKI_CHECK_H
#define CRYPTO_PKI_CHECK_H

#include <openssl/x509.h>

#ifdef UNIT_TEST
typedef void XROOTD_LOG_T;
typedef int XROOTD_PKI_STATUS_T;
#else
#include <ngx_core.h>
typedef ngx_log_t XROOTD_LOG_T;
typedef ngx_int_t XROOTD_PKI_STATUS_T;
#endif

/*
 * Startup PKI consistency helpers.
 *
 * These checks are intentionally diagnostic: they log malformed CA/CRL setups
 * but do not fail nginx configuration parsing.  Production deployments often
 * receive CA bundles and CRLs from external grid-security packaging, so a
 * warning is more useful than taking the service down at reload time.
 */
/*
 * xrootd_pki_load_certs_from_path — load all PEM-format CA certificates
 * from a directory into an STACK_OF(X509).
 *
 * @path: filesystem directory containing .pem certificate files.
 * @log:  nginx log context for error reporting.
 *
 * Returns a freshly allocated STACK_OF(X509) on success, NULL on failure
 * (logged as warning). The caller owns the returned stack and must free it
 * with sk_X509_pop_free(stack, X509_free).
 */
STACK_OF(X509) *xrootd_pki_load_certs_from_path(const char *path,
    XROOTD_LOG_T *log);
/*
 * xrootd_pki_load_crls_from_path — load all PEM-format CRLs from a
 * directory into an STACK_OF(X509_CRL).
 *
 * @path: filesystem directory containing .pem CRL files.
 * @log:  nginx log context for error reporting.
 *
 * Returns a freshly allocated STACK_OF(X509_CRL) on success, NULL on failure
 * (logged as warning). The caller owns the returned stack and must free it
 * with sk_X509_CRL_pop_free(stack, X509_CRL_free).
 */
STACK_OF(X509_CRL) *xrootd_pki_load_crls_from_path(const char *path,
    XROOTD_LOG_T *log);
/*
 * xrootd_pki_verify_crls — verify that every loaded CRL has a matching
 * CA certificate and a valid cryptographic signature.
 *
 * @log:       nginx log context.
 * @ca_certs:  STACK_OF(X509) of trusted CA certificates.
 * @crls:      STACK_OF(X509_CRL) of loaded CRLs to verify.
 * @log_prefix: string prefix for error log messages.
 *
 * Two-phase verification per CRL:
 *   1. DN matching — the CRL's issuer DN is compared against each CA
 *      subject DN to select a candidate CA.
 *   2. Signature check — X509_CRL_verify confirms the CRL was signed by
 *      that CA's private key, preventing forgery.
 *
 * Returns always NGX_OK (errors are non-fatal, logged only). The caller
 * should monitor the error log for mismatches or signature failures.
 */
XROOTD_PKI_STATUS_T xrootd_pki_verify_crls(XROOTD_LOG_T *log,
    STACK_OF(X509) *ca_certs, STACK_OF(X509_CRL) *crls,
    const char *log_prefix);
/*
 * xrootd_pki_check_paths — load CA certificates and CRLs from disk
 * directories during nginx configuration phase, then verify cross-signatures.
 *
 * @log:       nginx log context.
 * @ca_path:   filesystem directory of CA certificates (NULL = skip).
 * @crl_path:  filesystem directory of CRLs (NULL = skip).
 * @log_prefix: string prefix for error log messages.
 *
 * Gracefully skips checks when either path is NULL. Always returns NGX_OK;
 * problems are logged as warnings only so the server starts even with
 * broken CA/CRL configuration rather than taking full outage.
 */
XROOTD_PKI_STATUS_T xrootd_pki_check_paths(XROOTD_LOG_T *log,
    const char *ca_path, const char *crl_path, const char *log_prefix);

/*
 * xrootd_check_pki_and_crl — simple wrapper for stream/WebDAV modules
 * to call the full PKI path loading + CRL consistency check.
 *
 * @ca_dir:  filesystem directory of CA certificates.
 * @crl_dir: filesystem directory of CRLs.
 * @log:     nginx log context.
 *
 * Delegates directly to xrootd_pki_check_paths() with hardcoded
 * log_prefix "xrootd". Returns 0 as success indicator.
 */
int xrootd_check_pki_and_crl(const char *ca_dir, const char *crl_dir,
    XROOTD_LOG_T *log);

#endif /* CRYPTO_PKI_CHECK_H */
