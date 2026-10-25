/* Native trust-store loader spelling across OpenSSL 1.1.1 and 3+.
 * Requires: OpenSSL >= 1.1.1; callers retain all store/path ownership.
 */
#pragma once
#include <openssl/x509_vfy.h>

/* ---- Load an explicit CA directory without adding implicit trust locations ----
 * WHAT: Return the native 1/0 result for the supplied directory.
 * WHY: Legacy load_locations must not widen trust by selecting defaults.
 * HOW: 1. Select the version's directory API. 2. Pass only the supplied path.
 */
static inline int
brix_crypto_store_load_path(X509_STORE *store, const char *directory)
{
    if (store == NULL || directory == NULL || directory[0] == '\0') {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return X509_STORE_load_path(store, directory);
#else
    return X509_STORE_load_locations(store, NULL, directory);
#endif
}

/* ---- Load an explicit CA bundle without adding implicit trust locations ----
 * WHAT: Return the native 1/0 result for the supplied bundle.
 * WHY: Backend selection must not change the configured trust boundary.
 * HOW: 1. Select the version's bundle API. 2. Pass only the supplied file.
 */
static inline int
brix_crypto_store_load_file(X509_STORE *store, const char *file)
{
    if (store == NULL || file == NULL || file[0] == '\0') {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return X509_STORE_load_file(store, file);
#else
    return X509_STORE_load_locations(store, file, NULL);
#endif
}
