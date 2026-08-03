/*
 * webdav/auth_token_internal.h — seam between auth_token.c (credential
 * transport + identity plumbing) and auth_token_verify.c (issuer/signature
 * verification).  Carries only what both TUs need; nothing here is part of the
 * module's outward API.
 */
#ifndef BRIX_WEBDAV_AUTH_TOKEN_INTERNAL_H
#define BRIX_WEBDAV_AUTH_TOKEN_INTERNAL_H

#include "webdav_module_internal.h"

/*
 * wt_validate_ctx_t — the immutable inputs shared by every token-validation
 * step (registry, JWKS, grace-period retry).  Bundled into one struct so the
 * validation helpers thread a single context instead of a long, error-prone
 * parameter list; `claims` is the sole out-param and is written only on a
 * successful validation.
 */
typedef struct {
    ngx_http_request_t              *r;
    ngx_http_brix_webdav_loc_conf_t *conf;
    const char                      *token;
    size_t                           token_len;
    const u_char                    *secret;      /* parsed primary secret        */
    ssize_t                          slen;        /* <=0 => no macaroon secret    */
    brix_token_claims_t             *claims;      /* OUT: verified claims         */
} wt_validate_ctx_t;

/* auth_token.c — map the HTTP method to a registry op class.  Read-ish verbs
 * (GET/HEAD/PROPFIND/OPTIONS) authorize against read scopes; everything else is
 * a write.  Non-static because the registry validator derives the op class. */
brix_token_op_e webdav_token_op_class(ngx_http_request_t *r);

/* auth_token_verify.c — validate `v->token`, choosing registry or single-issuer
 * JWKS per the location config and applying the rotation grace retry.  Returns
 * 0 on acceptance with verified claims in *v->claims. */
int wt_check_issuer_keys(const wt_validate_ctx_t *v, int *cache_hit,
    int *via_registry);

#endif /* BRIX_WEBDAV_AUTH_TOKEN_INTERNAL_H */
