/* whitelist.h — parse a CVMFS .cvmfswhitelist (pure C).
 *
 * WHAT: expiry timestamp + the set of trusted certificate fingerprints, plus the
 *       signed body / RSA signature (verified against the repo master key).
 * WHY:  the whitelist is the trust anchor that authorizes the manifest's signing
 *       certificate.
 * HOW:  first line is the 14-digit UTC expiry (YYYYMMDDhhmmss); each fingerprint
 *       line matches AA:BB:...; body ends at "--\n". No allocation.
 */
#ifndef BRIX_CVMFS_WHITELIST_H
#define BRIX_CVMFS_WHITELIST_H

#include <stddef.h>

typedef struct {
    long                 expiry_utc;             /* epoch seconds */
    char                 fingerprints[16][60];   /* "AA:BB:...", NUL-term */
    size_t               n_fingerprints;
    const unsigned char *signed_body;      size_t signed_body_len;
    const unsigned char *signed_hash_text; size_t signed_hash_text_len; /* RSA-signed */
    const unsigned char *signature;        size_t signature_len;
} cvmfs_whitelist_t;

/* Parse `buf`/`len`. Returns 0 and fills *out, or -1 on malformed input. */
int cvmfs_whitelist_parse(const unsigned char *buf, size_t len, cvmfs_whitelist_t *out);

/* 1 if `fp_hex` ("AA:BB:...") is in the whitelist (case-insensitive). */
int cvmfs_whitelist_lists_fp(const cvmfs_whitelist_t *w, const char *fp_hex);

/* 1 if `now_utc` is past the whitelist expiry. */
int cvmfs_whitelist_expired(const cvmfs_whitelist_t *w, long now_utc);

#endif /* BRIX_CVMFS_WHITELIST_H */
