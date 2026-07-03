/*
 * gsi_verify.h — shared x.509 proxy chain verification API.
 *
 * Both the XRootD stream layer (gsi/auth.c, GSI kXR_auth) and the
 * WebDAV layer (webdav/auth_cert.c, DAVS client certificates) perform
 * identical X509_STORE_CTX setup and chain verification.  This header
 * declares the unified entry point so the logic lives in one file.
 */

#ifndef BRIX_CRYPTO_GSI_VERIFY_H
#define BRIX_CRYPTO_GSI_VERIFY_H

#include <ngx_core.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/*
 * brix_gsi_verify_result_t — output populated by brix_gsi_verify_chain().
 *
 * dn_buf holds the NUL-terminated subject Distinguished Name extracted
 * from the verified leaf certificate (via X509_NAME_oneline).  It is
 * populated only when the function returns NGX_OK; left as an empty
 * string on failure.
 */
typedef struct {
    char dn_buf[1024];
} brix_gsi_verify_result_t;

/*
 * brix_gsi_verify_chain — verify an x.509 proxy certificate chain.
 *
 * Parameters
 *   log          — nginx log; error messages are written here on failure
 *   store        — pre-loaded X509_STORE of trusted CA certificates
 *   leaf         — end-entity / leaf certificate (not NULL)
 *   untrusted    — STACK_OF(X509) of intermediate certs, or NULL if none
 *   verify_depth — maximum proxy chain depth (0 = use OpenSSL default)
 *   res          — caller-allocated output; res->dn_buf set on NGX_OK
 *
 * Returns NGX_OK when the chain is valid; res->dn_buf is then
 * NUL-terminated and holds the subject DN of the verified leaf.
 * Returns NGX_ERROR on any failure (already logged); res is zeroed.
 *
 * Ownership: the function does NOT take ownership of leaf, untrusted,
 * or store.  All resources remain the caller's responsibility.
 */
ngx_int_t brix_gsi_verify_chain(ngx_log_t         *log,
                                   X509_STORE        *store,
                                   X509              *leaf,
                                   STACK_OF(X509)    *untrusted,
                                   ngx_uint_t         verify_depth,
                                   brix_gsi_verify_result_t *res);

#endif /* BRIX_CRYPTO_GSI_VERIFY_H */
