/*
 * pwd.h — XRootD `pwd` (XrdSecpwd) password-auth constants + password-file API.
 *
 * WHAT: Shared declarations for the Phase 52 WS-B password protocol: the XrdSecpwd
 *       step codes and pwdStatus_t fields used on the wire, plus the password-file
 *       lookup/verify helpers (src/pwd/pwdfile.c).
 * WHY:  pwd is XRootD's legacy password scheme.  It is opt-in, TLS-gated, and the
 *       password never touches disk in cleartext — brix_pwd_file stores only a
 *       PBKDF2-HMAC-SHA1 salted hash (the exact KDF stock XrdSecpwd uses).
 * HOW:  The handshake (src/pwd/auth.c) drives a 2-round DH-bootstrapped exchange;
 *       round 2 decrypts the client credential and verifies it via the helpers
 *       declared here against the configured brix_pwd_file.
 *
 * Wire reference: docs/refactor/phase-52-pwd-wire-spec.md and the source at
 * /tmp/xrootd-src/src/XrdSecpwd/XrdSecProtocolpwd.{cc,hh}.
 */
#ifndef BRIX_PWD_H
#define BRIX_PWD_H

#include <ngx_core.h>
#include <stddef.h>
#include <stdint.h>

/* ---- XrdSecpwd step codes (XrdSecProtocolpwd.hh:125-147) ---- */
#define kXPC_normal      1000   /* client: standard credential packet      */
#define kXPC_creds       1003   /* client: (additional) credentials packet */
#define kXPS_credsreq    2001   /* server: please send credentials         */
#define kXPS_none           0   /* server: done                            */

/* XrdSecpwdVERSION (XrdSecProtocolpwd.hh:56). */
#define BRIX_PWD_VERSION  10100

/* pwdStatus_t ctype (XrdSecProtocolpwd.hh:100-112) — only the normal flow. */
#define kpCT_normal         0

/* pwdStatus_t options bit (XrdSecProtocolpwd.cc:148) — client has a tty/autolog;
 * mandatory or a stock server aborts a multi-round continuation. */
#define kOptsClntTty   0x0080

/* KDF parameters — must match stock XrdSecpwd (XrdCryptosslAux.cc:78-110). */
#define BRIX_PWD_KDF_ITERS   10000
#define BRIX_PWD_HASH_LEN       24
#define BRIX_PWD_MAX_SALT       64

/* The DH session cipher for the encrypted credential (our flow keys aes-128-cbc
 * with a zero IV — the same primitive as the GSI unsigned-DH path). */
#define BRIX_PWD_SESSION_KEYLEN 16

/*
 * Look up `user` in the brix_pwd_file at `path` and, on a match, return the
 * stored salt and PBKDF2 hash.  Lines are "user:salthex:hashhex[:vo1,vo2]"
 * (see docs/refactor/phase-52-pwd-wire-spec.md); '#'/blank lines are ignored.
 * The optional 4th field is a comma-separated VO/group list copied into `vos`
 * (set to "" for the legacy 3-field form; pass NULL/0 to skip).  An entry whose
 * VO list does not fit `voscap` is rejected — group membership must never be
 * silently truncated.  Returns NGX_OK (salt+hash+vos filled) or NGX_DECLINED
 * (no such user, parse error, or unreadable file).  All buffers caller-provided;
 * saltlen,hashlen are set out.
 */
ngx_int_t brix_pwd_file_lookup(const char *path, const char *user,
    uint8_t *salt, size_t *saltlen, uint8_t *hash, size_t *hashlen,
    char *vos, size_t voscap);

/*
 * Verify a plaintext password against a stored (salt, hash) pair using
 * PBKDF2-HMAC-SHA1 with BRIX_PWD_KDF_ITERS iterations.  Constant-time compare.
 * Returns 1 on match, 0 otherwise.
 */
int brix_pwd_verify(const uint8_t *password, size_t plen,
    const uint8_t *salt, size_t saltlen,
    const uint8_t *hash, size_t hashlen);

#endif /* BRIX_PWD_H */
