#pragma once

/*
 * identity.h — protocol-agnostic authenticated principal state.
 *
 * Wire-level authentication remains protocol-specific.  After GSI, token,
 * SSS, or S3 SigV4 credentials are verified, callers fill xrootd_identity_t
 * so policy and audit code can reason about one canonical principal shape.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "../token/token.h"

#define XROOTD_AUTHN_NONE     0x00
#define XROOTD_AUTHN_GSI      0x01
#define XROOTD_AUTHN_TOKEN    0x02
#define XROOTD_AUTHN_SSS      0x04
#define XROOTD_AUTHN_S3KEY    0x08
#define XROOTD_AUTHN_UNIX     0x10
#define XROOTD_AUTHN_KRB5     0x20

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
    ngx_str_t    scope_raw;     /* raw OAuth scope claim */
    int          token_scope_count;
    xrootd_token_scope_t token_scopes[XROOTD_MAX_TOKEN_SCOPES];

    ngx_uint_t   auth_method;   /* XROOTD_AUTHN_* bitmask */
    unsigned     is_authenticated:1;
    unsigned     is_admin:1;
    unsigned     has_write_scope:1;
    unsigned     has_read_scope:1;
} xrootd_identity_t;

xrootd_identity_t *xrootd_identity_alloc(ngx_pool_t *pool);

ngx_int_t xrootd_identity_set_cstr(ngx_pool_t *pool, ngx_str_t *dst,
    const char *src);
ngx_int_t xrootd_identity_set_dn(xrootd_identity_t *id, ngx_pool_t *pool,
    const char *dn, ngx_uint_t auth_method);
ngx_int_t xrootd_identity_set_subject(xrootd_identity_t *id, ngx_pool_t *pool,
    const char *subject, ngx_uint_t auth_method);
ngx_int_t xrootd_identity_set_vos_csv(xrootd_identity_t *id,
    ngx_pool_t *pool, const char *vo_csv);
ngx_int_t xrootd_identity_set_token_claims(xrootd_identity_t *id,
    ngx_pool_t *pool, const xrootd_token_claims_t *claims);

const char *xrootd_identity_dn_cstr(const xrootd_identity_t *id);
const char *xrootd_identity_subject_cstr(const xrootd_identity_t *id);
const char *xrootd_identity_vo_csv_cstr(const xrootd_identity_t *id);

ngx_int_t xrootd_identity_check_token_scope(const xrootd_identity_t *id,
    const char *logical_path, int need_write);

ngx_str_t xrootd_identity_describe(const xrootd_identity_t *id,
    ngx_pool_t *pool);
