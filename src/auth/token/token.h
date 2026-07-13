#ifndef BRIX_TOKEN_TOKEN_H
#define BRIX_TOKEN_TOKEN_H

/*
 * token/token.h
 *
 * JWT / WLCG bearer-token validation for nginx-xrootd.
 *
 * Shared between the stream (XRootD) module and the HTTP (WebDAV) module.
 * Requires ngx_core.h (for ngx_log_t etc.) to be included before this header.
 */

#include <openssl/evp.h>
#include <limits.h>

/* ------------------------------------------------------------------ */
/* Tunables                                                             */
/* ------------------------------------------------------------------ */

#define BRIX_MAX_JWKS_KEYS      8

/*
 * Maximum number of scope entries parsed from a single JWT "scope" claim.
 * Real WLCG/SciTokens carry 1-4 scopes; 8 is ample for all known issuers.
 * Reduced from 32 to cut ~6 KB from every brix_ctx_t and every on-stack
 * brix_token_claims_t during validation.
 */
#define BRIX_MAX_TOKEN_SCOPES   8

/*
 * Maximum length of a path component within a WLCG/SciToken scope claim,
 * e.g. the "/data/cms" part of "storage.read:/data/cms".
 * WLCG scope paths are logical namespace prefixes, not filesystem paths;
 * 256 bytes is sufficient for all practical deployments and keeps the
 * brix_token_scope_t struct (and brix_ctx_t) small.
 */
#define BRIX_SCOPE_PATH_MAX  256

/* ------------------------------------------------------------------ */
/* Types                                                                */
/* ------------------------------------------------------------------ */

/* A single public key loaded from a JWKS file. */
typedef struct {
    char       kid[128];        /* Key ID ("kid" claim) */
    EVP_PKEY  *pkey;            /* RSA or EC public key */
} brix_jwks_key_t;

/* A parsed scope entry from the "scope" claim. */
#ifndef BRIX_TOKEN_SCOPE_T_DEFINED
#define BRIX_TOKEN_SCOPE_T_DEFINED
typedef struct {
    char          path[BRIX_SCOPE_PATH_MAX]; /* Scope path (e.g., "/" or "/data") */
    unsigned int  read   : 1;                  /* storage.read */
    unsigned int  write  : 1;                  /* storage.write */
    unsigned int  create : 1;                  /* storage.create */
    unsigned int  modify : 1;                  /* storage.modify */
} brix_token_scope_t;
#endif

/* Extracted claims from a validated JWT. */
typedef struct {
    char    sub[256];           /* Subject */
    char    iss[256];           /* Issuer */
    char    aud[256];           /* Audience */
    int64_t exp;                /* Expiry (Unix timestamp) */
    int64_t nbf;                /* Not-before (Unix timestamp) */
    int64_t iat;                /* Issued-at  (Unix timestamp) */
    char    scope_raw[1024];    /* Raw "scope" claim */
    char    groups[512];        /* Comma-separated groups (from wlcg.groups) */
    int                   scope_count;
    brix_token_scope_t  scopes[BRIX_MAX_TOKEN_SCOPES];
} brix_token_claims_t;

/* ------------------------------------------------------------------ */
/* JWKS loading (called once at startup / config load)                  */
/* ------------------------------------------------------------------ */

/*
 * Load RSA public keys from a JWKS file.
 * Fills keys[] up to max_keys entries.
 * Returns ≥ 0 (count) on success, -1 on error.
 */
int brix_jwks_load(ngx_log_t *log, const char *path,
                     brix_jwks_key_t *keys, int max_keys);

/*
 * Free all loaded JWKS keys.
 */
void brix_jwks_free(brix_jwks_key_t *keys, int count);

/*
 * Register a pool cleanup that frees the EVP_PKEY handles in keys[] when the
 * pool is destroyed.  The handler reads *count at destroy time, so it works
 * with the refresh path (which mutates the same array in place).  Without this,
 * the OpenSSL key objects are leaked on every config reload and at shutdown
 * (the array lives in the conf pool, but EVP_PKEY_free is never called for it).
 * Returns NGX_OK or NGX_ERROR.
 */
ngx_int_t brix_jwks_register_cleanup(ngx_pool_t *pool,
                                       brix_jwks_key_t *keys, int *count);

/* Operation class for registry authorization — selects the scope/path
 * direction the strategy ladder enforces. */
typedef enum {
    BRIX_TOKEN_OP_READ  = 0,
    BRIX_TOKEN_OP_WRITE = 1,
    BRIX_TOKEN_OP_OTHER = 2
} brix_token_op_e;

/* ------------------------------------------------------------------ */
/* Token validation                                                     */
/* ------------------------------------------------------------------ */

/*
 * Extract the "iss" claim WITHOUT verifying the signature, used only to select
 * which registry issuer's keys to verify against (the value is re-read from the
 * verified claims afterwards).  Returns 0 + out on success, -1 otherwise.
 */
int brix_token_peek_iss(const char *token, size_t token_len,
                          char *out, size_t outsz);

/*
 * brix_token_validate_args_t — caller-supplied state for brix_token_validate().
 *
 * WHAT: Bundles the validator's inputs (log sink, raw token bytes, trusted
 *       JWKS keys, expected issuer/audience pins, macaroon secret, clock-skew
 *       window) and its single output (claims) into one struct.
 * WHY:  brix_token_validate() took 11 positional parameters; a named-field
 *       carrier keeps the extern surface at one parameter, makes every
 *       callsite self-documenting, and lets the internal RFC pipeline thread
 *       the same read-only pointer through its static helpers.
 * HOW:  Populated field-by-field at each callsite (zero-init unused optional
 *       fields) and passed read-only; the validator writes only through
 *       ->claims, the caller's output buffer.
 */
typedef struct {
    ngx_log_t              *log;               /* error/audit log sink        */
    const char             *token;             /* raw bearer token bytes      */
    size_t                  token_len;         /* length of token             */
    const brix_jwks_key_t  *keys;              /* trusted JWKS keys (or NULL) */
    int                     key_count;         /* entries in keys[]           */
    const char             *expected_issuer;   /* iss pin; NULL/"" = any      */
    const char             *expected_audience; /* aud pin; NULL/"" = any      */
    const u_char           *macaroon_secret;   /* macaroon HMAC key or NULL   */
    size_t                  secret_len;        /* length of macaroon_secret   */
    int                     clock_skew;        /* exp/nbf tolerance (seconds) */
    brix_token_claims_t    *claims;            /* OUT: verified claims        */
} brix_token_validate_args_t;

/*
 * Validate a JWT bearer token.
 *
 * Checks: structure, signature (RS256), exp, nbf, iss, aud.
 * On success fills `a->claims` with the extracted claim values and
 * parsed scopes.
 *
 * Returns 0 on success, -1 on error.
 */
int brix_token_validate(const brix_token_validate_args_t *a);

/* ------------------------------------------------------------------ */
/* Scope checking                                                       */
/* ------------------------------------------------------------------ */

/*
 * Parse the "scope" claim string into structured scope entries.
 * Returns the number of entries parsed (≥ 0).
 */
int brix_token_parse_scopes(const char *scope_str,
                              brix_token_scope_t *scopes, int max_scopes);

/*
 * Boundary-checked prefix match: does `scope_path` cover `request_path`?
 * "/" matches everything; a trailing "/" is ignored; "/data" does NOT match
 * "/database" (the next char must be '/' or NUL).  Exposed so the SciTokens
 * issuer registry reuses the exact same logic for base_path/restricted_path
 * scoping (phase-59 W1).  Returns 1 if covered, 0 otherwise.
 */
int brix_token_scope_path_matches(const char *scope_path,
                                    const char *request_path);

/*
 * Check if scopes authorise read access to `path`.
 * `path` is relative to the brix_root (e.g. "/data/file.txt").
 * Returns 1 if allowed, 0 if denied.
 */
int brix_token_check_read(const brix_token_scope_t *scopes,
                            int scope_count, const char *path);

/*
 * Check if scopes authorise write access to `path`.
 * Returns 1 if allowed, 0 if denied.
 */
int brix_token_check_write(const brix_token_scope_t *scopes,
                             int scope_count, const char *path);

#endif /* BRIX_TOKEN_TOKEN_H */
