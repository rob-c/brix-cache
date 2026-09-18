/*
 * sha_crypt.h — SHA-256/SHA-512 crypt ("$5$" / "$6$") password hashing.
 *
 * WHAT: A self-contained implementation of the SHA-crypt scheme (Drepper,
 *       2008; the "$5$rounds=N$salt$hash" / "$6$…" htpasswd/shadow format)
 *       on top of OpenSSL's EVP digests.
 * WHY:  glibc's crypt(3) speaks it, but Darwin's (and other BSD-derived
 *       libcs') crypt(3) only knows DES and "$1$": a users file written with
 *       `openssl passwd -6` on Linux could not log in to the dashboard on a
 *       macOS host.  The verifier tries the platform crypt(3) first and only
 *       falls back here when it cannot handle the hash's method.
 * HOW:  brix_sha_crypt() derives the full hash string for `key` under the
 *       method / rounds / salt parsed from `setting` (a stored hash doubles as
 *       the setting, exactly like crypt(3)); the caller compares the strings.
 */
#ifndef BRIX_DASHBOARD_SHA_CRYPT_H
#define BRIX_DASHBOARD_SHA_CRYPT_H

#include <stddef.h>

/* Longest "$6$rounds=999999999$<16-byte salt>$<86-char hash>" plus NUL. */
#define BRIX_SHA_CRYPT_MAX 128

/* Whether `setting` names a method this implementation handles ($5$ / $6$). */
int brix_sha_crypt_handles(const char *setting);

/* Compute the crypt string for key/setting into out[outsz].
 * Returns 0 on success, -1 on a malformed setting or too-small buffer. */
int brix_sha_crypt(const char *key, const char *setting, char *out, size_t outsz);

#endif /* BRIX_DASHBOARD_SHA_CRYPT_H */
