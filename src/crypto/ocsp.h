#ifndef XROOTD_CRYPTO_OCSP_H
#define XROOTD_CRYPTO_OCSP_H

/*
 * OCSP client: check certificate revocation status and staple OCSP responses.
 *
 * Two services are provided:
 *
 *   xrootd_ocsp_check_cert() — query the OCSP responder URL embedded in a
 *     client certificate and verify its revocation status.  Used in the GSI
 *     authentication path after X.509 chain verification.
 *
 *   xrootd_ocsp_staple_fetch() — fetch an OCSP response for the server's own
 *     certificate and cache it for TLS stapling (RFC 6066 / RFC 6961).
 *
 * Both functions are synchronous (blocking OpenSSL BIO) which is acceptable
 * because they execute on the auth path that already performs blocking crypto.
 */

#include "ngx_xrootd_module.h"
#include <openssl/x509.h>

/*
 * xrootd_ocsp_check_cert — query the OCSP responder for leaf's status.
 *
 * @log:       nginx log context
 * @leaf:      the client certificate to check (must not be NULL)
 * @issuer:    the issuer certificate (may be NULL for single-cert chains)
 * @soft_fail: if 1, treat network errors / unknown status as pass (return 0);
 *             if 0, treat any non-GOOD status as failure (return -1).
 *             A REVOKED status always returns -1 regardless of soft_fail.
 *
 * Returns 0 if the certificate is GOOD (or soft_fail allows the status),
 *         -1 if the certificate is REVOKED or the check definitively fails.
 */
int xrootd_ocsp_check_cert(ngx_log_t *log, X509 *leaf, X509 *issuer,
    int soft_fail);

/*
 * xrootd_ocsp_staple_fetch — fetch and cache an OCSP staple for the server
 * certificate.
 *
 * Queries the OCSP responder URL embedded in xcf->gsi_cert and stores the
 * raw DER-encoded OCSP response in xcf->ocsp_staple_data / ocsp_staple_len.
 * Memory is allocated with ngx_alloc() and must be freed by the caller when
 * the configuration is destroyed.
 *
 * Returns NGX_OK on success, NGX_ERROR on failure.
 */
ngx_int_t xrootd_ocsp_staple_fetch(ngx_log_t *log,
    ngx_stream_xrootd_srv_conf_t *xcf);

#endif /* XROOTD_CRYPTO_OCSP_H */
