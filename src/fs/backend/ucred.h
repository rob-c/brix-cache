/*
 * ucred.h — per-user backend credential selection helper (phase-1 + phase-2 T2).
 *
 * WHAT: Declares the brix_sd_ucred_t result descriptor and the four public
 *       functions that map an authenticated brix_identity_t to a candidate
 *       credential file on disk — an x509 proxy PEM (checked for expiry), a
 *       WLCG bearer token (read verbatim, no expiry check here — the origin
 *       enforces the token's own exp claim), an S3 access-key/secret-key/
 *       region triple (phase-3 T3) for backends that authenticate via SigV4,
 *       or a CephX keyring file (per-user Ceph/RADOS auth, the ceph-peruser
 *       item) for backends that authenticate via librados.
 *
 * WHY:  Storage backends (e.g. remote root://, WebDAV, S3, Ceph/RADOS)
 *       require a per-user credential when acting on behalf of an
 *       authenticated principal.  Credential delegation capture is
 *       unreliable (clients may refuse); the sysadmin pre-provisions
 *       credentials under a shared directory keyed by a fs-safe principal
 *       stem or a short SHA-256 hash.  This helper encapsulates the
 *       key-derivation and expiry-check logic so callers never reimplement
 *       the search or validation.
 *
 * HOW:  brix_sd_ucred_principal() extracts the canonical principal string
 *       from brix_identity_t (DN preferred over subject).
 *       brix_sd_ucred_key() derives a filesystem-safe filename stem:
 *         - verbatim if [A-Za-z0-9@._][A-Za-z0-9@._-]{0,63} (S3/JWT subs);
 *         - "x5h-" + first 32 lowercase hex chars of SHA256 otherwise (DNs).
 *       brix_sd_ucred_select() tries literal then hash candidates:
 *         1. <dir>/<key>.pem (x509 proxy, expiry-checked);
 *         2. <dir>/<key>.token (bearer token, no expiry check);
 *         3. <dir>/<key>.s3 (SigV4 access-key/secret-key/region triple);
 *         4. <dir>/<key>.keyring (CephX keyring: user id + keyring path).
 *       x509 wins when multiple files exist; bearer wins over s3; s3 wins
 *       over ceph; an expired .pem is a hard DECLINED and does NOT silently
 *       fall through to a .token/.s3/.keyring file for the SAME key.
 *       brix_sd_ucred_resolve() looks up a specific key directly (flush path).
 *
 * `.s3` FILE FORMAT (phase-3 T3): exactly 3 lines, LF- or CRLF-terminated,
 * mode 0600 recommended:
 *     line 1: access key id   (required, non-empty)
 *     line 2: secret key      (required, non-empty)
 *     line 3: region          (optional; defaults to "us-east-1" when the
 *                               file has only 2 lines or line 3 is empty)
 * A file missing ak or sk (empty line 1 or 2, or fewer than 2 non-empty
 * lines) is treated as malformed and the .s3 candidate is DECLINED — it is
 * NOT a parse error surfaced to the caller, exactly like an unparseable .pem.
 * The secret key is sensitive: callers MUST NOT log brix_sd_ucred_t.s3_sk.
 *
 * `.keyring` FILE FORMAT (ceph-peruser item): a standard CephX keyring file,
 * e.g.:
 *     [client.bob]
 *         key = AQBv...==
 * Only the FIRST `[client.NAME]` section header is parsed (the caller does
 * not need the key material itself — librados reads the keyring file
 * directly via rados_conf_set(cluster,"keyring",path)).  The BARE id
 * ("bob", not "client.bob") is stored in out->ceph_user — sd_ceph_user_id()
 * (sd_ceph.c) re-adds the "client." prefix before rados_create(), matching
 * the export-level `user` config convention.  A keyring with no
 * `[client.X]` section header is malformed and the .keyring candidate is
 * DECLINED — it is NOT a parse error surfaced to the caller, exactly like an
 * unparseable .pem.  The keyring PATH (not its contents) is stored in
 * out->ceph_keyring; callers MUST NOT log its contents (it contains the
 * CephX secret key).
 */
#ifndef BRIX_FS_BACKEND_UCRED_H
#define BRIX_FS_BACKEND_UCRED_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "core/types/identity.h"

/* Maximum length of a derived filename key (including NUL). */
#define BRIX_UCRED_KEY_MAX    128

/* Maximum path length for a credential file (including NUL). */
#define BRIX_UCRED_PATH_MAX   1024

/* Maximum length of a principal string (including NUL). */
#define BRIX_UCRED_PRINC_MAX  512

/* Maximum length of a bearer token stored inline (including NUL).
 * WLCG tokens can be a few KB; 4096 covers realistic payloads. */
#define BRIX_UCRED_BEARER_MAX 4096

/* Maximum lengths for the S3 credential triple (including NUL). Sized to
 * match sd_s3_file's ak/sk/region fields (sd_s3_internal.h) so a value that
 * fits here always fits the eventual per-open copy. */
#define BRIX_UCRED_S3_AK_MAX     128
#define BRIX_UCRED_S3_SK_MAX     256
#define BRIX_UCRED_S3_REGION_MAX 64

/* Maximum path length for a CephX keyring file (including NUL); reuses the
 * generic path bound. Maximum length of the bare CephX user id parsed from
 * the keyring's "[client.NAME]" section header (including NUL). */
#define BRIX_UCRED_CEPH_KEYRING_MAX BRIX_UCRED_PATH_MAX
#define BRIX_UCRED_CEPH_USER_MAX    128

/*
 * Result descriptor filled by brix_sd_ucred_select() and
 * brix_sd_ucred_resolve().  All fields are NUL-terminated C strings stored
 * inline — no heap allocation, safe to pass between worker-thread and
 * event-loop (no nginx pool dependency).
 *
 * Exactly one credential kind is populated per successful select:
 * is_bearer=0/is_s3=0/is_ceph=0 → x509 (path has the PEM path, all other
 * kind-specific fields empty);
 * is_bearer=1 → bearer token (bearer has the token text, path has the
 * .token file path for logging, s3_ak/s3_sk/ceph_keyring/ceph_user empty);
 * is_s3=1 → S3 SigV4 triple (s3_ak/s3_sk/s3_region populated, path has the
 * .s3 file path for logging, bearer/ceph_keyring/ceph_user empty);
 * is_ceph=1 → CephX keyring (ceph_keyring has the keyring PATH, ceph_user
 * has the parsed bare user id, path has the .keyring file path for logging,
 * bearer/s3_* empty).  The four kinds are mutually exclusive for a given
 * key — x509 wins when multiple files exist, bearer wins over s3, s3 wins
 * over ceph (see brix_sd_ucred_resolve).
 */
typedef struct {
    char     principal[BRIX_UCRED_PRINC_MAX]; /* canonical principal string       */
    char     key[BRIX_UCRED_KEY_MAX];         /* derived filename stem             */
    char     path[BRIX_UCRED_PATH_MAX];       /* absolute path (.pem/.token/.s3/   */
                                               /* .keyring)                         */
    char     bearer[BRIX_UCRED_BEARER_MAX];   /* bearer token text (is_bearer=1)   */
    char     s3_ak[BRIX_UCRED_S3_AK_MAX];         /* S3 access key id (is_s3=1)    */
    char     s3_sk[BRIX_UCRED_S3_SK_MAX];         /* S3 secret key (is_s3=1; never */
                                                   /* log this field)               */
    char     s3_region[BRIX_UCRED_S3_REGION_MAX]; /* S3 region (is_s3=1)           */
    char     ceph_keyring[BRIX_UCRED_CEPH_KEYRING_MAX]; /* keyring PATH (is_ceph=1;
                                               * librados reads the file itself;
                                               * never log its contents)           */
    char     ceph_user[BRIX_UCRED_CEPH_USER_MAX]; /* bare CephX user id, e.g.      */
                                                   /* "bob" from "[client.bob]"     */
                                                   /* (is_ceph=1)                   */
    int      expired;                          /* 1 if .pem existed but past        */
                                               /* notAfter (at least one candidate) */
    unsigned is_bearer:1;                      /* 1 when bearer[] is populated      */
    unsigned is_s3:1;                          /* 1 when s3_ak/s3_sk populated      */
    unsigned is_ceph:1;                        /* 1 when ceph_keyring/ceph_user set */
} brix_sd_ucred_t;

/*
 * brix_sd_ucred_principal — extract the canonical principal from an identity.
 *
 * WHAT: Copies id->dn (if non-empty) else id->subject into buf as a
 *       NUL-terminated C string.  Returns NGX_ERROR if the identity is
 *       unauthenticated, both fields are empty, or the chosen field does not
 *       fit within cap bytes (including the NUL).
 *
 * WHY:  DN is the richer, more stable identifier for GSI/SSS principals;
 *       JWT sub / S3 access key is used only when no DN is present.
 *
 * HOW:  1. Reject unauthenticated or both-empty.
 *       2. Pick dn when dn.len > 0, else subject.
 *       3. memcpy + explicit NUL (ngx_str_t is not NUL-terminated).
 */
ngx_int_t brix_sd_ucred_principal(const brix_identity_t *id,
    char *buf, size_t cap);

/*
 * brix_sd_ucred_key — derive a filesystem-safe credential filename stem.
 *
 * WHAT: If principal matches [A-Za-z0-9@._][A-Za-z0-9@._-]{0,63} the key
 *       is the principal verbatim.  Otherwise the key is
 *       "x5h-" + the first 32 lowercase hex digits of SHA256(principal)
 *       (i.e. the first 16 bytes of the digest encoded as hex).
 *       Returns NGX_ERROR on empty principal or if the key would overflow cap.
 *
 * WHY:  Human-manageable filenames for token subjects and S3 access keys;
 *       DNs (which contain '/') always fall through to the hash form so
 *       they never corrupt a directory hierarchy.
 *
 * HOW:  1. Classify via ucred_principal_fs_safe (static helper in .c).
 *       2. Literal path: snprintf verbatim.
 *       3. Hash path: SHA256 via OpenSSL, snprintf 16-byte hex prefix.
 */
ngx_int_t brix_sd_ucred_key(const char *principal, char *key, size_t cap);

/*
 * brix_sd_ucred_resolve — look up a credential file by its exact key.
 *
 * WHAT: Tries <dir>/<key>.pem (x509 expiry-checked); if absent, <dir>/<key>.token
 *       (bearer, read verbatim); if that is also absent, <dir>/<key>.s3
 *       (SigV4 ak/sk/region triple, phase-3 T3); if that is also absent,
 *       <dir>/<key>.keyring (CephX keyring, ceph-peruser item).  Returns
 *       NGX_OK (valid — out->is_bearer / out->is_s3 / out->is_ceph distinguish
 *       the four kinds), NGX_DECLINED (all absent / .pem expired / .s3 or
 *       .keyring malformed — out->expired set on PEM expiry), or NGX_ERROR
 *       (path overflow).
 *
 * WHY:  Used by flush/write paths that already know the key (e.g. fetched
 *       from the open-time select result) and need a fresh expiry check.
 *       An expired .pem is a hard DECLINED — neither .token, .s3, nor
 *       .keyring is tried as a fallback.  x509 wins when multiple files
 *       exist; bearer wins over s3; s3 wins over ceph.
 *
 * HOW:  1. snprintf .pem path; overflow → NGX_ERROR.
 *       2. ucred_check_pem (internal): NGX_OK → return; absent → try .token;
 *          expired-or-error → return DECLINED (no further fallback).
 *       3. ucred_read_token: NGX_OK → set is_bearer=1, fill bearer, return OK;
 *          absent → try .s3; ucred_read_s3: NGX_OK → set is_s3=1, fill
 *          s3_ak/s3_sk/s3_region, return OK; absent → try .keyring;
 *          ucred_read_keyring: NGX_OK → set is_ceph=1, fill ceph_keyring/
 *          ceph_user, return OK; else → return DECLINED.
 *       4. On x509 NGX_OK fill out->path/key/is_bearer=0/is_s3=0/is_ceph=0; on
 *          bearer NGX_OK fill out->path/bearer/is_bearer=1; on s3 NGX_OK fill
 *          out->path/s3_ak/s3_sk/s3_region/is_s3=1; on ceph NGX_OK fill
 *          out->path/ceph_keyring/ceph_user/is_ceph=1; out->principal
 *          untouched.
 */
ngx_int_t brix_sd_ucred_resolve(const char *dir, const char *key,
    brix_sd_ucred_t *out);

/*
 * brix_sd_ucred_select — map an identity to its best available credential.
 *
 * WHAT: Zeroes *out, derives principal into out->principal, then tries:
 *         1. literal-key candidate <dir>/<principal>.{pem,token,s3,keyring}
 *            (only if fs-safe);
 *         2. hash-key candidate <dir>/x5h-<hex>.{pem,token,s3,keyring} (always).
 *       Within each candidate, .pem is tried before .token before .s3 before
 *       .keyring: x509 wins when multiple exist, bearer wins over s3, s3
 *       wins over ceph.  An expired .pem is a hard DECLINED — neither
 *       .token, .s3, nor .keyring for the SAME key is tried as a silent
 *       fallback.  The first candidate whose credential is valid wins
 *       (NGX_OK).  When no candidate wins, returns NGX_DECLINED with out->key
 *       set to the hash-form key (so callers can log the filename the
 *       administrator must provision) and out->expired OR'd across both
 *       candidates.
 *
 * WHY:  A single entry point for all per-user credential lookups; caller
 *       need not know about key derivation or credential-kind selection.
 *
 * HOW:  1. Zero *out; derive principal.
 *       2. Build candidate list (up to 2 entries).
 *       3. brix_sd_ucred_resolve each in order; first NGX_OK → return.
 *       4. On all-DECLINED: set out->key to hash key, return NGX_DECLINED.
 */
ngx_int_t brix_sd_ucred_select(const char *dir, const brix_identity_t *id,
    brix_sd_ucred_t *out);

/*
 * brix_sd_ucred_wipe — cleanse the secret-bearing fields of a resolved
 * credential once the caller has finished with it.
 *
 * WHAT: OPENSSL_cleanse()s the fields that carry live secret material —
 *       bearer[], s3_sk[], ceph_keyring[] — so the token/secret does not
 *       linger on the worker stack or heap after consumption.  Non-secret
 *       fields (principal, key, path, s3_ak, s3_region, ceph_user) and the
 *       kind flags are left intact for post-use logging; NULL is a no-op.
 *
 * WHY:  Defense-in-depth (T4): minimize secret residency so a later
 *       stack/heap info-leak or a core dump cannot read back a credential
 *       that should have been erased on use.  Pairs with the reader-side
 *       cleanse in ucred_read_token/_s3/_keyring.
 *
 * HOW:  Cleanse each secret field unconditionally (the field is zero-length
 *       when its kind is not populated, so cleansing is harmless).
 */
void brix_sd_ucred_wipe(brix_sd_ucred_t *cred);

#endif /* BRIX_FS_BACKEND_UCRED_H */
