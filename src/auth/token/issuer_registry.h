#ifndef XROOTD_TOKEN_ISSUER_REGISTRY_H
#define XROOTD_TOKEN_ISSUER_REGISTRY_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "token.h"

/*
 * token/issuer_registry.h — SciTokens multi-issuer registry (phase-59 W1).
 *
 * Parses the upstream XRootD `scitokens.cfg` INI grammar ([Global] + one
 * [Issuer <name>] section per trusted issuer) into a fixed-size, read-only
 * table consulted at token-validation time. Per-issuer namespace scoping
 * (base_path / restricted_path), audiences, and the authorization-strategy
 * selector live here; the subject/group mapping bodies land in W1b.
 */

#define XROOTD_TOKEN_MAX_ISSUERS     16
#define XROOTD_TOKEN_MAX_BASEPATHS    8
#define XROOTD_TOKEN_MAX_AUDIENCES    8

/* authorization_strategy bits (ORed; evaluated in capability→group→mapping
 * order by validate.c). */
#define XROOTD_AUTHZ_CAPABILITY  0x1u   /* WLCG storage.* scopes (default)   */
#define XROOTD_AUTHZ_GROUP       0x2u   /* groups_claim ∈ authdb groups (W1b)*/
#define XROOTD_AUTHZ_MAPPING     0x4u   /* subject→authdb user rules    (W1b)*/

typedef struct {
    char      name[64];                 /* "[Issuer <name>]"                  */
    char      issuer[256];              /* iss URL (matched exactly)          */
    char      audiences[XROOTD_TOKEN_MAX_AUDIENCES][256];
    int       audience_count;
    char      base_paths[XROOTD_TOKEN_MAX_BASEPATHS][XROOTD_SCOPE_PATH_MAX];
    int       base_path_count;
    char      restricted_paths[XROOTD_TOKEN_MAX_BASEPATHS][XROOTD_SCOPE_PATH_MAX];
    int       restricted_path_count;
    char      username_claim[64];       /* default "sub"                      */
    char      groups_claim[64];         /* e.g. "wlcg.groups" (W1b)           */
    char      default_user[64];         /* fallback username (W1b)            */
    char      name_mapfile[1024];       /* JSON subject→user map (W1b)        */
    unsigned  map_subject:1;
    unsigned  onmissing_fail:1;         /* 1 = fail, 0 = use default_user     */
    unsigned  enabled:1;
    uint32_t  strategy;                 /* XROOTD_AUTHZ_* bits                */
    char      jwks_path[1024];          /* per-issuer JWKS file (optional)    */
    xrootd_jwks_key_t jwks_keys[XROOTD_MAX_JWKS_KEYS];
    int               jwks_key_count;
    time_t            jwks_mtime;
    int               metric_bucket;    /* low-cardinality metric id          */
} xrootd_token_issuer_t;

typedef struct {
    xrootd_token_issuer_t issuers[XROOTD_TOKEN_MAX_ISSUERS];
    int                   count;
    uint32_t              default_strategy;   /* when an issuer omits strategy */
    char                  global_audiences[XROOTD_TOKEN_MAX_AUDIENCES][256];
    int                   global_audience_count;
    ngx_log_t            *log;
} xrootd_token_registry_t;

/*
 * Parse `cfg_path` (upstream scitokens.cfg grammar) into *reg (caller
 * pre-zeroes and sets reg->log). default_strategy applies to issuers that omit
 * authorization_strategy. Loads each issuer's JWKS file if jwks_file= is set.
 * Returns NGX_OK, or NGX_ERROR with a message in errbuf.
 */
ngx_int_t xrootd_token_registry_load(xrootd_token_registry_t *reg,
    const char *cfg_path, uint32_t default_strategy,
    char *errbuf, size_t errlen);

/* Find an enabled issuer by exact iss URL; NULL if none. */
const xrootd_token_issuer_t *xrootd_token_registry_find(
    const xrootd_token_registry_t *reg, const char *iss);

/*
 * True if req_path is under at least one of the issuer's base_paths AND not
 * under any restricted_path. An issuer with no base_path authorizes nothing.
 */
int xrootd_token_issuer_path_ok(const xrootd_token_issuer_t *is,
    const char *req_path);

/* Parse an authorization_strategy value ("capability group mapping") to bits. */
uint32_t xrootd_token_strategy_parse(const char *value);

/*
 * Config-time helper: allocate a registry from cf->pool, load cfg_path, and
 * register a pool cleanup for each issuer's JWKS keys. On error logs via
 * ngx_conf_log_error and returns NGX_ERROR; on success sets *out. Used by both
 * the stream (config.c) and webdav postconfiguration paths.
 */
ngx_int_t xrootd_token_registry_build(ngx_conf_t *cf, const char *cfg_path,
    uint32_t default_strategy, xrootd_token_registry_t **out);

/*
 * Validate a bearer token against the multi-issuer registry:
 *   1. peek iss → select issuer (deny if unknown)
 *   2. verify signature/exp/nbf with THAT issuer's keys + audiences
 *   3. enforce base_path / restricted_path against req_path
 *   4. run the issuer's authorization_strategy ladder (capability now;
 *      group/mapping land in W1b)
 * On ALLOW returns 0, fills *claims, and sets *out_issuer_bucket to the issuer's
 * low-cardinality metric id; on DENY returns -1.  `op` selects read vs write
 * scope direction.  macaroon_secret/secret_len are forwarded for macaroon
 * tokens (NULL/0 if unused).
 */
int xrootd_token_validate_registry(ngx_log_t *log,
    const char *token, size_t token_len,
    const xrootd_token_registry_t *reg, const char *req_path,
    xrootd_token_op_e op,
    const u_char *macaroon_secret, size_t secret_len,
    xrootd_token_claims_t *claims, int *out_issuer_bucket);

/*
 * AuthN-only half (issuer selection + signature/audience), for the stream
 * path where kXR_auth precedes any path. On success sets *out_issuer to the
 * matched issuer (whose base_path the per-path check then enforces).
 */
int xrootd_token_validate_registry_authn(ngx_log_t *log,
    const char *token, size_t token_len,
    const xrootd_token_registry_t *reg,
    const u_char *macaroon_secret, size_t secret_len,
    xrootd_token_claims_t *claims, const xrootd_token_issuer_t **out_issuer);

/*
 * Per-path issuer authorization: base_path/restricted_path gate + the
 * authorization_strategy ladder for (req_path, op). 1 = ALLOW, 0 = DENY.
 */
int xrootd_token_authz_strategy(const xrootd_token_issuer_t *is,
    const xrootd_token_claims_t *claims, const char *req_path,
    xrootd_token_op_e op);

#endif /* XROOTD_TOKEN_ISSUER_REGISTRY_H */
