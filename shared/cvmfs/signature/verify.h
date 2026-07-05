/* verify.h — CVMFS signature trust gate (OpenSSL).
 *
 * WHAT: verify the manifest RSA signature against its X.509 cert, compute the
 *       cert fingerprint (to check whitelist membership), and verify the
 *       whitelist against the repo master public key.
 * WHY:  this is the whole read-path trust chain.
 * HOW:  CVMFS signs the SHA-1 digest of the signed body with RSA; we use
 *       EVP_DigestVerify with EVP_sha1().
 *
 * Full chain (enforced by the caller / SP-F mount path):
 *   whitelist sig valid vs master key
 *     → whitelist not expired
 *       → manifest cert fingerprint ∈ whitelist
 *         → manifest sig valid vs cert.
 * Any break = reject.
 */
#ifndef BRIX_CVMFS_VERIFY_H
#define BRIX_CVMFS_VERIFY_H

#include <stddef.h>
#include "cvmfs/signature/manifest.h"
#include "cvmfs/signature/whitelist.h"

/* 0 if the manifest signature verifies against the PEM cert, negative otherwise. */
int cvmfs_verify_manifest(const cvmfs_manifest_t *m, const unsigned char *cert_pem, size_t cert_len);

/* Write the cert SHA-1 fingerprint as uppercase "AA:BB:...". 0 on success. */
int cvmfs_cert_fingerprint(const unsigned char *cert_pem, size_t cert_len, char *out, size_t outlen);

/* 0 if the whitelist signature verifies against the master public key (PEM). */
int cvmfs_verify_whitelist(const cvmfs_whitelist_t *w, const unsigned char *master_pub_pem, size_t pub_len);

#endif /* BRIX_CVMFS_VERIFY_H */
