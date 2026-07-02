/*
 * openssl_auto.h — scope-based automatic cleanup for OpenSSL objects.
 *
 * WHAT: typed `__attribute__((cleanup))` handlers + the XRD_AUTO(type) macro,
 *       so an OpenSSL handle declared with XRD_AUTO is freed automatically when
 *       it goes out of scope — on EVERY return path, with no manual free.
 *
 *           XRD_AUTO(EVP_CIPHER_CTX) *ctx = EVP_CIPHER_CTX_new();
 *           if (ctx == NULL)        return NULL;   // freed (NULL-safe)
 *           if (bad)                return NULL;   // freed
 *           ...                                    // freed on normal return too
 *
 * WHY: this module forbids `goto`, so the classic single-exit cleanup ladder is
 *      replaced by early-return — which means the SAME free has to be repeated at
 *      every exit (gsi_cipher.c freed one EVP_CIPHER_CTX at six different returns;
 *      parse_x509.c freed EVP_PKEY at eight). Each new early-return is a chance to
 *      forget one and leak. A scope-cleanup handler collapses all of them to a
 *      single declaration AND makes the free structurally unforgettable: the
 *      compiler emits it on every path, including ones added later. This turns the
 *      no-goto rule from a liability into an advantage over goto-cleanup.
 *
 * HOW: each XRD_OSSL_AUTO_DEFINE(type, freefn) emits a static-inline handler that
 *      takes the address of the variable and frees the pointed-to object if
 *      non-NULL (all the OpenSSL *_free functions below already tolerate NULL, but
 *      the guard keeps the intent explicit and the contract local). The handler is
 *      `static inline`, so there is no new translation unit and no ./configure
 *      change — include the header and declare with XRD_AUTO.
 *
 * OWNERSHIP: XRD_AUTO is for objects OWNED by the current scope. If a function
 *      RETURNS the handle (transfers ownership to the caller), do NOT use XRD_AUTO
 *      on it — keep it a plain pointer, or null it out before the return so the
 *      handler becomes a no-op. The malloc'd payload buffers that these functions
 *      return are the textbook example and stay manually managed.
 */
#ifndef XROOTD_COMPAT_OPENSSL_AUTO_H
#define XROOTD_COMPAT_OPENSSL_AUTO_H

#include <openssl/evp.h>
#include <openssl/x509.h>

/* Define a cleanup handler `xrd_ossl_cleanup_<type>` for an OpenSSL pointer type
 * whose single-argument destructor is `freefn`. */
#define XRD_OSSL_AUTO_DEFINE(type, freefn)              \
    static inline void xrd_ossl_cleanup_##type(type **p) \
    {                                                    \
        if (*p != NULL) {                                \
            freefn(*p);                                  \
        }                                                \
    }

XRD_OSSL_AUTO_DEFINE(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)
XRD_OSSL_AUTO_DEFINE(EVP_MD_CTX,     EVP_MD_CTX_free)
XRD_OSSL_AUTO_DEFINE(EVP_PKEY,       EVP_PKEY_free)
XRD_OSSL_AUTO_DEFINE(EVP_PKEY_CTX,   EVP_PKEY_CTX_free)
XRD_OSSL_AUTO_DEFINE(X509,           X509_free)

/* Declare a scope-owned OpenSSL handle that is freed automatically on every exit:
 *     XRD_AUTO(EVP_CIPHER_CTX) *ctx = EVP_CIPHER_CTX_new();
 */
#define XRD_AUTO(type) __attribute__((cleanup(xrd_ossl_cleanup_##type))) type

#endif /* XROOTD_COMPAT_OPENSSL_AUTO_H */
