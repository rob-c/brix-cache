/* secure.c — scvmfs:// security preamble (EXPERIMENTAL, phase-68 T22).
 *
 * WHAT: transport + client-authz gate that runs before the cvmfs gate on
 *       locations with `brix_scvmfs on`.
 * WHY:  "secure CVMFS" repositories are credential-protected; the site
 *       cache must enforce the same boundary or it becomes a leak. Layering
 *       it as a preamble keeps ONE protocol core — scvmfs can never drift
 *       behaviorally from cvmfs because it IS cvmfs after this function.
 * HOW:  TLS presence comes from the connection (r->connection->ssl); bearer
 *       mode delegates to the shared SciTokens issuer registry
 *       (brix_token_validate_registry — the same engine the WebDAV and
 *       stream token paths use; READ scope suffices for a read-only
 *       protocol). This file contains POLICY GLUE ONLY — zero crypto.
 *       VOMS/GSI client-cert mode is future work (the WebDAV auth_cert
 *       machinery needs a conf-independent seam first); the directive
 *       accepts none|bearer today.
 */
#include "cvmfs.h"
#include "auth/token/issuer_registry.h"
#include "core/compat/cstr.h"
#include "core/types/tunables.h"

#include <limits.h>

/* Extract "Authorization: Bearer <token>" into a NUL-terminated pool copy. */
static ngx_int_t
scvmfs_bearer_token(ngx_http_request_t *r, const char **token, size_t *len)
{
    ngx_str_t  *v;
    u_char     *p;
    size_t      n;

    if (r->headers_in.authorization == NULL) {
        return NGX_DECLINED;
    }
    v = &r->headers_in.authorization->value;
    if (v->len <= sizeof("Bearer ") - 1
        || ngx_strncasecmp(v->data, (u_char *) "Bearer ",
                           sizeof("Bearer ") - 1) != 0)
    {
        return NGX_DECLINED;
    }
    n = v->len - (sizeof("Bearer ") - 1);
    p = ngx_pnalloc(r->pool, n + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(p, v->data + sizeof("Bearer ") - 1, n);
    p[n] = '\0';
    *token = (const char *) p;
    *len = n;
    return NGX_OK;
}

static ngx_int_t
scvmfs_check_bearer(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    const char            *token;
    size_t                 token_len;
    char                   uri_path[PATH_MAX];
    brix_token_claims_t  claims;
    int                    bucket = 0;
    ngx_int_t              rc;

    if (lcf->scvmfs_registry == NULL) {
        /* bearer mode without a loaded issuer registry fails CLOSED —
         * merge-time validation makes this unreachable, but never open up */
        return NGX_HTTP_UNAUTHORIZED;
    }

    rc = scvmfs_bearer_token(r, &token, &token_len);
    if (rc == NGX_DECLINED) {
        return NGX_HTTP_UNAUTHORIZED;              /* no Bearer credential */
    }
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (brix_str_cbuf(uri_path, sizeof(uri_path), &r->uri) == NULL) {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    /* read scope suffices for a read-only protocol */
    if (brix_token_validate_registry(r->connection->log, token, token_len,
            (const brix_token_registry_t *) lcf->scvmfs_registry,
            uri_path, BRIX_TOKEN_OP_READ,
            NULL, 0, BRIX_TOKEN_CLOCK_SKEW_SECS, &claims, &bucket) != 0)
    {
        return NGX_HTTP_UNAUTHORIZED;      /* invalid/expired/out-of-scope */
    }
    return NGX_DECLINED;                   /* authenticated: proceed        */
}

ngx_int_t
brix_scvmfs_preamble(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    ngx_int_t                    rc;

#if (NGX_HTTP_SSL)
    if (r->connection->ssl == NULL)
#endif
    {
        /* nginx core already 400s plain-HTTP-on-ssl-port before we run;
         * this guards mixed listeners and future non-TLS plumbing. */
        return NGX_HTTP_BAD_REQUEST;
    }

    switch (lcf->scvmfs_authz) {
    case BRIX_SCVMFS_AUTHZ_BEARER:
        rc = scvmfs_check_bearer(r, lcf);
        break;
    case BRIX_SCVMFS_AUTHZ_NONE:
    default:
        rc = NGX_DECLINED;
        break;
    }
    if (rc != NGX_DECLINED) {
        BRIX_CVMFS_METRIC_INC(requests_total[BRIX_CVMFS_CLASS_REJECT]);
        return rc;
    }
    ctx->secure = 1;                               /* unlocks https upstream */
    BRIX_CVMFS_METRIC_INC(secure_requests_total);
    return NGX_DECLINED;
}
