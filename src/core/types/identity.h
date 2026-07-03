#ifndef BRIX_TYPES_IDENTITY_H
#define BRIX_TYPES_IDENTITY_H

/*
 * identity.h — protocol-agnostic authenticated principal state.
 *
 * Wire-level authentication remains protocol-specific.  After GSI, token,
 * SSS, or S3 SigV4 credentials are verified, callers fill brix_identity_t
 * so policy and audit code can reason about one canonical principal shape.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "auth/token/token.h"

#define BRIX_AUTHN_NONE     0x00
#define BRIX_AUTHN_GSI      0x01
#define BRIX_AUTHN_TOKEN    0x02
#define BRIX_AUTHN_SSS      0x04
#define BRIX_AUTHN_S3KEY    0x08
#define BRIX_AUTHN_UNIX     0x10
#define BRIX_AUTHN_KRB5     0x20
#define BRIX_AUTHN_HOST     0x40
#define BRIX_AUTHN_PWD      0x80

typedef struct {
    ngx_str_t    dn;            /* GSI DN, SSS user, or empty */
    ngx_str_t    subject;       /* JWT sub or S3 access key */
    ngx_str_t    issuer;        /* JWT iss, empty for non-token auth */

    ngx_array_t *vo_list;       /* ngx_str_t[] VOMS FQANs / JWT groups */
    ngx_array_t *scopes;        /* ngx_str_t[] raw OAuth scope tokens */

    /*
     * Compatibility views used by current policy hot paths.  They are kept in
     * sync with the structured arrays above so Phase 2 can be incremental.
     */
    ngx_str_t    vo_csv;        /* comma-separated VO/group list */

    /*
     * XrdAcc-engine attribute views, derived from vo_csv by parsing each VOMS
     * FQAN / token group into (vorg, role, group).  The three CSVs are kept
     * index-aligned (empty fields preserved) so the engine can pair them
     * positionally.  Populated by brix_identity_set_vos_csv().
     */
    ngx_str_t    acc_vorg_csv;  /* VO names      (e.g. "cms,atlas") */
    ngx_str_t    acc_role_csv;  /* VOMS/token roles (Role=...) */
    ngx_str_t    acc_group_csv; /* group paths   (e.g. "/cms,/atlas") */

    ngx_str_t    scope_raw;     /* raw OAuth scope claim */
    int          token_scope_count;
    brix_token_scope_t token_scopes[BRIX_MAX_TOKEN_SCOPES];
    void        *token_issuer;  /* phase-59 W1: matched brix_token_issuer_t*
                                   when authed via a multi-issuer registry; NULL
                                   otherwise. Adds the per-path base_path gate. */

    ngx_uint_t   auth_method;   /* BRIX_AUTHN_* bitmask */
    unsigned     is_authenticated:1;
    unsigned     is_admin:1;
    unsigned     has_write_scope:1;
    unsigned     has_read_scope:1;
} brix_identity_t;

/*
 * Allocate a zeroed identity on `pool` (auth_method = BRIX_AUTHN_NONE,
 * unauthenticated).  Returns NULL on NULL pool or allocation failure; the
 * result lives for the pool's lifetime and is not separately freed.
 */
brix_identity_t *brix_identity_alloc(ngx_pool_t *pool);

/*
 * Copy C string `src` into `dst` as a pool-allocated, NUL-terminated ngx_str_t
 * (so it is safe to pass to C string APIs).  NULL/empty `src` clears `dst` to a
 * null string and still returns NGX_OK; NGX_ERROR on NULL pool/dst or OOM.
 */
ngx_int_t brix_identity_set_cstr(ngx_pool_t *pool, ngx_str_t *dst,
    const char *src);

/*
 * Copy `dn` (GSI cert DN, SSS user, etc.) into id->dn, OR `auth_method` into
 * id->auth_method, and set is_authenticated.  Bits accumulate across calls (not
 * replaced).  NGX_OK / NGX_ERROR (NULL id or OOM).
 */
ngx_int_t brix_identity_set_dn(brix_identity_t *id, ngx_pool_t *pool,
    const char *dn, ngx_uint_t auth_method);

/*
 * Copy `subject` (JWT sub or S3 access key) into id->subject, OR `auth_method`
 * into id->auth_method, and set is_authenticated.  Bits accumulate (not
 * replaced).  NGX_OK / NGX_ERROR (NULL id or OOM).
 */
ngx_int_t brix_identity_set_subject(brix_identity_t *id, ngx_pool_t *pool,
    const char *subject, ngx_uint_t auth_method);

/*
 * Store VO/group membership in both views: copies `vo_csv` to id->vo_csv and
 * splits it (on commas, empty fields skipped) into id->vo_list.  Does NOT touch
 * auth_method/is_authenticated.  NGX_OK / NGX_ERROR (NULL id or OOM).
 */
ngx_int_t brix_identity_set_vos_csv(brix_identity_t *id,
    ngx_pool_t *pool, const char *vo_csv);

/*
 * Populate the identity from verified token `claims` (borrowed, not retained):
 * sets subject/issuer/scope_raw/vo_list, mirrors sub into dn, splits scope_raw
 * into id->scopes, caches up to BRIX_MAX_TOKEN_SCOPES parsed scopes (excess
 * silently dropped), derives has_read_scope/has_write_scope, and marks the
 * principal BRIX_AUTHN_TOKEN authenticated.  NGX_OK / NGX_ERROR (NULL or OOM).
 */
ngx_int_t brix_identity_set_token_claims(brix_identity_t *id,
    ngx_pool_t *pool, const brix_token_claims_t *claims);

/* DN as a borrowed C string; "" if `id` or the field is unset (never NULL). */
const char *brix_identity_dn_cstr(const brix_identity_t *id);
/* Subject as a borrowed C string; "" if unset (never NULL). */
const char *brix_identity_subject_cstr(const brix_identity_t *id);
/* VO/group CSV as a borrowed C string; "" if unset (never NULL). */
const char *brix_identity_vo_csv_cstr(const brix_identity_t *id);

/* XrdAcc attribute views (derived from the FQANs); "" if unset (never NULL). */
const char *brix_identity_acc_vorg_cstr(const brix_identity_t *id);
const char *brix_identity_acc_role_cstr(const brix_identity_t *id);
const char *brix_identity_acc_group_cstr(const brix_identity_t *id);

/*
 * Authorise `logical_path` against the cached token scopes for read or (when
 * need_write) write/create.  Non-token principals are allowed unconditionally
 * (scopes apply only to token auth).  Returns NGX_OK on grant, NGX_ERROR on
 * denial.
 */
ngx_int_t brix_identity_check_token_scope(const brix_identity_t *id,
    const char *logical_path, int need_write);

/*
 * Build a pool-allocated "dn=... sub=... method=..." one-liner for audit logs;
 * method is the strongest set auth bit (or NONE).  Returns a null ngx_str_t
 * (.data == NULL) on NULL pool or allocation failure.
 */
ngx_str_t brix_identity_describe(const brix_identity_t *id,
    ngx_pool_t *pool);

#endif /* BRIX_TYPES_IDENTITY_H */
