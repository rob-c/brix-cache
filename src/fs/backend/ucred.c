/*
 * ucred.c — per-user backend-credential selection (phase-1 x509 + phase-2
 * bearer/.token + phase-3 T3 S3/.s3 + ceph-peruser .keyring). See ucred.h.
 *
 * WHAT: Implements the four public functions declared in ucred.h: principal
 *       extraction, filesystem-safe key derivation, single-key resolve, and
 *       identity-to-credential selection with expiry checking.  The
 *       credential-file format parsers (PEM/token/S3/keyring readers) live in
 *       ucred_parse.c and are reached via ucred_internal.h.
 *
 * WHY:  Backends acting on behalf of authenticated users need a per-user
 *       credential (x509 proxy, bearer token, S3 SigV4 triple, or CephX
 *       keyring).  Centralising the key-derivation and validation logic
 *       here prevents every backend from reimplementing (and diverging on)
 *       the search and validation semantics.
 *
 * HOW:  Static pure helpers (charset classifier) keep side effects at the
 *       edges.  All four public functions are small and single-purpose; none
 *       allocates heap memory.  The file-format parsers are called through the
 *       ucred_internal.h prototypes.
 */
#include "ucred.h"
#include "ucred_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* ---- Is `principal` usable verbatim as a credential filename stem? ----
 * WHAT: 1 iff principal matches [A-Za-z0-9@._][A-Za-z0-9@._-]{0,63}.
 * WHY:  Human-manageable filenames for token subs / S3 access keys; DNs
 *       (which contain '/') always fall through to the hash form.
 * HOW:  1. reject empty/oversized/leading '-'/leading '.'; 2. scan charset.
 *       Leading '.' is rejected for path-traversal / dotfile safety: "." and
 *       ".." would otherwise reach brix_sd_ucred_resolve as valid literals and
 *       produce paths like <dir>/../.pem — reads outside the credential dir. */
/* ---- Is one character allowed in a verbatim credential filename stem? ----
 * WHAT: 1 iff `c` is in [A-Za-z0-9@._-].
 * WHY:  Splitting the per-character charset test out of the scan loop keeps
 *       ucred_principal_fs_safe's cyclomatic complexity within the gate; the
 *       compound OR expression is the sole source of that function's branching.
 * HOW:  Range tests for the alnum classes plus the four literal specials. */
static int
ucred_fs_safe_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '@' || c == '.'
        || c == '_' || c == '-';
}

static int
ucred_principal_fs_safe(const char *principal)
{
    size_t i, len = strlen(principal);

    if (len == 0 || len > 64 || principal[0] == '-' || principal[0] == '.') {
        return 0;
    }
    for (i = 0; i < len; i++) {
        if (!ucred_fs_safe_char(principal[i])) {
            return 0;
        }
    }
    return 1;
}

/*
 * brix_sd_ucred_principal — extract canonical principal string from identity.
 *
 * WHAT: Copies id->dn (if non-empty) else id->subject into buf as a
 *       NUL-terminated C string.
 * WHY:  DN is the richer identifier; subject (JWT sub / S3 key) is the
 *       fallback when no DN is present.
 * HOW:  Reject unauthenticated / both-empty / overflow; memcpy + NUL.
 */
ngx_int_t
brix_sd_ucred_principal(const brix_identity_t *id, char *buf, size_t cap)
{
    ngx_str_t src;

    if (id == NULL || !id->is_authenticated) {
        return NGX_ERROR;
    }
    if (id->dn.len > 0) {
        src = id->dn;
    } else if (id->subject.len > 0) {
        src = id->subject;
    } else {
        return NGX_ERROR;
    }
    if (src.len >= cap) {
        return NGX_ERROR;
    }
    memcpy(buf, src.data, src.len);
    buf[src.len] = '\0';
    return NGX_OK;
}

/*
 * brix_sd_ucred_key — derive a filesystem-safe filename stem from a principal.
 *
 * WHAT: Literal verbatim when fs-safe; "x5h-" + first 32 hex chars of
 *       SHA256(principal) otherwise.
 * WHY:  DNs contain '/' and other shell-hostile chars; the hash form gives
 *       a stable, collision-resistant, admin-provisionable name.
 * HOW:  Classify; literal snprintf or SHA256 + hex-encode first 16 bytes.
 */
ngx_int_t
brix_sd_ucred_key(const char *principal, char *key, size_t cap)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int           n;

    if (principal == NULL || principal[0] == '\0') {
        return NGX_ERROR;
    }
    if (ucred_principal_fs_safe(principal)) {
        n = snprintf(key, cap, "%s", principal);
        if (n < 0 || (size_t) n >= cap) {
            return NGX_ERROR;
        }
        return NGX_OK;
    }
    SHA256((const unsigned char *) principal, strlen(principal), digest);
    n = snprintf(key, cap,
        "x5h-%02x%02x%02x%02x%02x%02x%02x%02x"
            "%02x%02x%02x%02x%02x%02x%02x%02x",
        digest[0],  digest[1],  digest[2],  digest[3],
        digest[4],  digest[5],  digest[6],  digest[7],
        digest[8],  digest[9],  digest[10], digest[11],
        digest[12], digest[13], digest[14], digest[15]);
    if (n < 0 || (size_t) n >= cap) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * brix_sd_ucred_resolve — look up a credential file by its exact key.
 *
 * WHAT: Tries <dir>/<key>.pem (x509, expiry-checked) then, only when the .pem
 *       is ABSENT, <dir>/<key>.token (bearer, no expiry check).  Fills *out on
 *       success (is_bearer=0 for x509, is_bearer=1 for bearer).
 * WHY:  Flush/write paths already know the key and need a fresh expiry check
 *       without re-running principal derivation.  An expired .pem is a hard
 *       DECLINED — the .token file is NOT tried as a fallback (the operator
 *       must fix the proxy; silent promotion to bearer would change identity).
 * HOW:  1. snprintf .pem path; overflow → NGX_ERROR.
 *       2. ucred_check_pem: NGX_OK → x509 path, return OK.
 *          expired (expired=1) → set out->expired, return DECLINED immediately.
 *          absent (expired=0) → fall through to .token probe.
 *       3. ucred_read_token on .token path: NGX_OK → bearer path, return OK;
 *          else → return DECLINED.
 */
ngx_int_t
brix_sd_ucred_resolve(const char *dir, const char *key, brix_sd_ucred_t *out)
{
    char      pem_path[BRIX_UCRED_PATH_MAX];
    char      tok_path[BRIX_UCRED_PATH_MAX];
    char      s3_path[BRIX_UCRED_PATH_MAX];
    char      keyring_path[BRIX_UCRED_PATH_MAX];
    int       n, expired;
    ngx_int_t pem_rc;

    n = snprintf(pem_path, sizeof(pem_path), "%s/%s.pem", dir, key);
    if (n < 0 || (size_t) n >= sizeof(pem_path)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    pem_rc = ucred_check_pem(pem_path, &expired);
    if (pem_rc == NGX_OK) {
        snprintf(out->path, sizeof(out->path), "%s", pem_path);
        snprintf(out->key,  sizeof(out->key),  "%s", key);
        out->expired   = 0;
        out->is_bearer = 0;
        out->is_s3     = 0;
        out->is_ceph   = 0;
        out->bearer[0] = '\0';
        return NGX_OK;
    }

    /* Hard stop on an expired .pem: never fall through to .token or .s3.
     * The operator must renew the proxy; silently promoting to bearer/s3
     * would change the presented identity without the admin's intent. */
    if (expired) {
        out->expired = 1;
        return NGX_DECLINED;
    }

    /* .pem is absent (not expired) — probe the .token file. */
    n = snprintf(tok_path, sizeof(tok_path), "%s/%s.token", dir, key);
    if (n < 0 || (size_t) n >= sizeof(tok_path)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (ucred_read_token(tok_path, out->bearer, sizeof(out->bearer)) == NGX_OK) {
        snprintf(out->path, sizeof(out->path), "%s", tok_path);
        snprintf(out->key,  sizeof(out->key),  "%s", key);
        out->expired   = 0;
        out->is_bearer = 1;
        out->is_s3     = 0;
        out->is_ceph   = 0;
        return NGX_OK;
    }

    /* Neither .pem nor .token — probe the .s3 file (phase-3 T3). */
    n = snprintf(s3_path, sizeof(s3_path), "%s/%s.s3", dir, key);
    if (n < 0 || (size_t) n >= sizeof(s3_path)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (ucred_read_s3(s3_path, out->s3_ak, sizeof(out->s3_ak),
            out->s3_sk, sizeof(out->s3_sk),
            out->s3_region, sizeof(out->s3_region)) == NGX_OK) {
        snprintf(out->path, sizeof(out->path), "%s", s3_path);
        snprintf(out->key,  sizeof(out->key),  "%s", key);
        out->expired   = 0;
        out->is_bearer = 0;
        out->is_s3     = 1;
        out->is_ceph   = 0;
        return NGX_OK;
    }

    /* Neither .pem, .token, nor .s3 — probe the .keyring file (CephX,
     * ceph-peruser item). */
    n = snprintf(keyring_path, sizeof(keyring_path), "%s/%s.keyring", dir, key);
    if (n < 0 || (size_t) n >= sizeof(keyring_path)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (ucred_read_keyring(keyring_path, out->ceph_keyring,
            sizeof(out->ceph_keyring), out->ceph_user,
            sizeof(out->ceph_user)) != NGX_OK) {
        return NGX_DECLINED;
    }
    snprintf(out->path, sizeof(out->path), "%s", keyring_path);
    snprintf(out->key,  sizeof(out->key),  "%s", key);
    out->expired   = 0;
    out->is_bearer = 0;
    out->is_s3     = 0;
    out->is_ceph   = 1;
    return NGX_OK;
}

/*
 * brix_sd_ucred_select — map an identity to its best available credential.
 *
 * WHAT: Tries literal-key then hash-key candidate; first valid+unexpired PEM
 *       wins (NGX_OK).  On all-missed returns NGX_DECLINED with out->key set
 *       to the hash-form key so the caller can log the file to provision.
 * WHY:  Single entry point for all per-user credential lookups; hides the
 *       two-candidate search and expiry-OR logic from callers.
 * HOW:  Zero *out; derive principal; build up to 2 candidates; resolve each;
 *       return first OK or DECLINED with out->key = hash key.
 */
ngx_int_t
brix_sd_ucred_select(const char *dir, const brix_identity_t *id,
    brix_sd_ucred_t *out)
{
    char      principal[BRIX_UCRED_PRINC_MAX];
    char      lit_key[BRIX_UCRED_KEY_MAX];
    char      hash_key[BRIX_UCRED_KEY_MAX];
    int       has_lit;
    int       any_expired;
    ngx_int_t rc;

    memset(out, 0, sizeof(*out));

    if (brix_sd_ucred_principal(id, principal, sizeof(principal)) != NGX_OK) {
        return NGX_DECLINED;
    }
    snprintf(out->principal, sizeof(out->principal), "%s", principal);

    /* Derive the hash key unconditionally (always needed for the fallback). */
    if (brix_sd_ucred_key(principal, hash_key, sizeof(hash_key)) != NGX_OK) {
        return NGX_DECLINED;
    }

    /* Derive the literal key; flag whether it is usable.
     * ucred_principal_fs_safe guarantees len <= 64 < BRIX_UCRED_KEY_MAX; use
     * memcpy+NUL so the compiler sees a bounded copy (avoids -Wformat-truncation
     * from comparing the declared buf sizes rather than the runtime constraint). */
    has_lit = ucred_principal_fs_safe(principal);
    if (has_lit) {
        size_t plen = strlen(principal);
        memcpy(lit_key, principal, plen);
        lit_key[plen] = '\0';
    }

    any_expired = 0;

    /* Try the literal candidate first (only when fs-safe). */
    if (has_lit) {
        rc = brix_sd_ucred_resolve(dir, lit_key, out);
        if (rc == NGX_OK) {
            /* out->principal already set above; no re-copy needed. */
            return NGX_OK;
        }
        any_expired |= out->expired;
    }

    /* Try the hash candidate. */
    rc = brix_sd_ucred_resolve(dir, hash_key, out);
    if (rc == NGX_OK) {
        /* out->principal already set above; no re-copy needed. */
        return NGX_OK;
    }
    any_expired |= out->expired;

    /* No valid credential found — return DECLINED with the hash key for
     * logging so the operator knows which file to provision. */
    snprintf(out->principal, sizeof(out->principal), "%s", principal);
    snprintf(out->key,       sizeof(out->key),       "%s", hash_key);
    out->expired = any_expired;
    return NGX_DECLINED;
}

/*
 * brix_sd_ucred_wipe — cleanse the secret-bearing fields of a resolved
 * credential once the caller is done with it.  See ucred.h for rationale.
 */
void
brix_sd_ucred_wipe(brix_sd_ucred_t *cred)
{
    if (cred == NULL) {
        return;
    }
    /* Secret material only — bearer token text, S3 secret key, and the CephX
     * keyring PATH (librados reads the file, but the path itself is sensitive
     * routing to key material).  Non-secret identifiers are left for logging. */
    OPENSSL_cleanse(cred->bearer,       sizeof(cred->bearer));
    OPENSSL_cleanse(cred->s3_sk,        sizeof(cred->s3_sk));
    OPENSSL_cleanse(cred->ceph_keyring, sizeof(cred->ceph_keyring));
}
