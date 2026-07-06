/*
 * pki_build.h — shared X509_STORE construction for CA/CRL verification.
 *
 * Consumed by both the XRootD stream module (GSI auth, src/gsi/config.c) and
 * the WebDAV HTTP module (x509 cert auth, src/webdav/auth_store.c).
 */

#ifndef CRYPTO_PKI_BUILD_H
#define CRYPTO_PKI_BUILD_H

#include <ngx_core.h>
#include <openssl/x509.h>

#include "auth/crypto/signing_policy.h"   /* brix_sp_mode_t */
#include "auth/crypto/store_policy.h"     /* BRIX_CRL_MODE_* for callers */

/*
 * brix_build_ca_store — build an X509_STORE for CA/CRL-based certificate
 * verification.
 *
 * @log:           nginx log context.
 * @cadir:         directory of CA certificates; NULL to skip.
 * @cafile:        single CA bundle file; NULL to skip.
 *                 If both cadir and cafile are NULL, system default paths are
 *                 loaded via X509_STORE_set_default_paths().
 * @crl_path:      CRL file or directory path; NULL to disable revocation
 *                 checking.  When non-NULL the path must be stat()-able;
 *                 failure is fatal (returns NULL).
 * @extra_flags:   additional X509_V_FLAG_* flags applied to the store before
 *                 CA loading (e.g. X509_V_FLAG_ALLOW_PROXY_CERTS for GSI
 *                 proxy certificate chains).  Pass 0 for no extra flags.
 * @crl_count_out: if non-NULL, receives the total count of CRLs loaded.
 * @sp_mode:       signing_policy enforcement mode (BRIX_SP_MODE_*).  When a
 *                 cadir is given its <hash>.signing_policy files are compiled
 *                 and attached to the store.  BRIX_SP_MODE_REQUIRE with only a
 *                 cafile (no directory to search) is a configuration error and
 *                 returns NULL.
 * @crl_mode:      CRL strictness (BRIX_CRL_MODE_*).  Gates whether CRL verify
 *                 flags are set and whether a missing CRL is tolerated (TRY)
 *                 or fatal (REQUIRE).
 *
 * Returns a new X509_STORE on success, NULL on failure.  On failure the store
 * has been freed and no cleanup is required by the caller.
 */
X509_STORE *brix_build_ca_store(ngx_log_t *log,
    const char *cadir,
    const char *cafile,
    const char *crl_path,
    unsigned long extra_flags,
    int *crl_count_out,
    brix_sp_mode_t sp_mode,
    int crl_mode);

#endif /* CRYPTO_PKI_BUILD_H */
