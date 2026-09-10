/*
 * cred_load.h — load an outbound X.509 credential (PEM chain + private key).
 *
 * The server acts as a GSI *client* on three paths — the cache-fill origin
 * (src/fs/cache/origin_auth_gsi.c), the TPC destination (src/tpc/gsi/) and the
 * transparent upstream redirector (src/net/upstream/auth_gsi.c).  Each needs
 * the same two reads of operator-configured files: the proxy certificate chain
 * as one PEM blob, and the private key.  One loader keeps the O_NOFOLLOW
 * hardening and the "certs only, re-serialised" contract in a single place.
 */

#ifndef BRIX_GSI_CRED_LOAD_H
#define BRIX_GSI_CRED_LOAD_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

/* Every CERTIFICATE block of the PEM file at `path`, re-serialised as one
 * contiguous PEM blob (certs only — a key in the same file is dropped).  The
 * path is operator-configured (trusted like the server's own cert/key) and is
 * opened O_NOFOLLOW so a planted symlink cannot redirect it.  malloc'd, *outlen
 * set; NULL when the file is unreadable or holds no certificate.  Mirrors
 * client/lib/sec/sec_gsi.c load_proxy_pem. */
uint8_t *brix_gsi_cred_load_pem(const char *path, size_t *outlen);

/* The first PRIVATE KEY block of the PEM file at `path` (a proxy PEM carries
 * the key beside its chain; a plain host credential keeps it in its own file).
 * O_NOFOLLOW as above.  NULL when unreadable or keyless; caller frees. */
EVP_PKEY *brix_gsi_cred_load_key(const char *path);

#endif /* BRIX_GSI_CRED_LOAD_H */
