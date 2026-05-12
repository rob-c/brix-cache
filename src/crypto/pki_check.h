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
STACK_OF(X509) *xrootd_pki_load_certs_from_path(const char *path,
    XROOTD_LOG_T *log);
STACK_OF(X509_CRL) *xrootd_pki_load_crls_from_path(const char *path,
    XROOTD_LOG_T *log);
XROOTD_PKI_STATUS_T xrootd_pki_verify_crls(XROOTD_LOG_T *log,
    STACK_OF(X509) *ca_certs, STACK_OF(X509_CRL) *crls,
    const char *log_prefix);
XROOTD_PKI_STATUS_T xrootd_pki_check_paths(XROOTD_LOG_T *log,
    const char *ca_path, const char *crl_path, const char *log_prefix);

int xrootd_check_pki_and_crl(const char *ca_dir, const char *crl_dir,
    XROOTD_LOG_T *log);

#endif /* CRYPTO_PKI_CHECK_H */
