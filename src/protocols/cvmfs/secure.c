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
#include "cvmfs_module_internal.h"
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
    {
        brix_token_registry_args_t  ra;

        ra.log             = r->connection->log;
        ra.token           = token;
        ra.token_len       = token_len;
        ra.reg             = (const brix_token_registry_t *) lcf->scvmfs_registry;
        ra.macaroon_secret = NULL;
        ra.secret_len      = 0;
        ra.clock_skew      = BRIX_TOKEN_CLOCK_SKEW_SECS;
        ra.claims          = &claims;

        if (brix_token_validate_registry(&ra, uri_path, BRIX_TOKEN_OP_READ,
                                         &bucket) != 0)
        {
            return NGX_HTTP_UNAUTHORIZED;  /* invalid/expired/out-of-scope */
        }
    }

    /* the VALIDATED subject is the F9 QoS classification key */
    {
        ngx_http_brix_cvmfs_ctx_t *ctx =
            ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);

        if (ctx != NULL) {
            ngx_cpystrn((u_char *) ctx->token_sub, (u_char *) claims.sub,
                        sizeof(ctx->token_sub));
        }
    }
    return NGX_DECLINED;                   /* authenticated: proceed        */
}

/* ---- token-gated repos (phase-85 F3) --------------------------------------
 * brix_cvmfs_repo_authz <repo|*> <scitokens.cfg> — multi-occurrence; each
 * entry gates ONE repo (or "*" = all) behind the named issuer registry.
 * Policy glue only: token validation is the same shared registry engine the
 * scvmfs bearer path above uses (READ scope for a read-only protocol). */

char *
cvmfs_conf_repo_authz(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_cvmfs_loc_conf_t *c = conf;
    ngx_str_t                      *value = cf->args->elts;
    brix_cvmfs_repo_authz_t        *entry;

    (void) cmd;

    if (value[1].len == 0 || value[2].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_repo_authz needs <repo-fqrn|*> <scitokens.cfg>");
        return NGX_CONF_ERROR;
    }

    if (c->repo_authz == NGX_CONF_UNSET_PTR) {
        c->repo_authz = ngx_array_create(cf->pool, 2,
                                         sizeof(brix_cvmfs_repo_authz_t));
        if (c->repo_authz == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    entry = ngx_array_push(c->repo_authz);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }
    entry->repo     = value[1];
    entry->issuers  = value[2];
    entry->registry = NULL;               /* built once at merge time */
    return NGX_CONF_OK;
}

/* The gate entry matching this repo, or NULL = repo not gated. First match
 * wins; "*" is a catch-all so an exact entry listed before it can pin a
 * specific registry while "*" sweeps the rest. */
static brix_cvmfs_repo_authz_t *
cvmfs_repo_authz_match(ngx_http_brix_cvmfs_loc_conf_t *lcf,
    const char *repo, size_t repo_len)
{
    brix_cvmfs_repo_authz_t *e = lcf->repo_authz->elts;
    ngx_uint_t               i;

    for (i = 0; i < lcf->repo_authz->nelts; i++) {
        if (e[i].repo.len == 1 && e[i].repo.data[0] == '*') {
            return &e[i];
        }
        if (e[i].repo.len == repo_len
            && ngx_strncmp(e[i].repo.data, repo, repo_len) == 0)
        {
            return &e[i];
        }
    }
    return NULL;
}

ngx_int_t
brix_cvmfs_repo_authz_eval(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    brix_cvmfs_repo_authz_t     *gate;
    const char                  *token;
    size_t                       token_len;
    char                         uri_path[PATH_MAX];
    brix_token_claims_t          claims;
    int                          bucket = 0;
    ngx_int_t                    rc;

    if (lcf->repo_authz == NULL || ctx->url.repo == NULL) {
        return NGX_DECLINED;
    }

    gate = cvmfs_repo_authz_match(lcf, ctx->url.repo, ctx->url.repo_len);
    if (gate == NULL) {
        return NGX_DECLINED;           /* unmatched repo stays world-readable */
    }

#if (NGX_HTTP_SSL)
    if (r->connection->ssl == NULL)
#endif
    {
        /* a gated repo must never accept (or solicit) a bearer over
         * cleartext — refuse the transport before any token is examined
         * (mirrors the scvmfs transport gate). */
        return NGX_HTTP_BAD_REQUEST;
    }

    if (gate->registry == NULL) {
        /* merge-time build makes this unreachable — never fail open */
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

    {
        brix_token_registry_args_t  ra;

        ra.log             = r->connection->log;
        ra.token           = token;
        ra.token_len       = token_len;
        ra.reg             = (const brix_token_registry_t *) gate->registry;
        ra.macaroon_secret = NULL;
        ra.secret_len      = 0;
        ra.clock_skew      = BRIX_TOKEN_CLOCK_SKEW_SECS;
        ra.claims          = &claims;

        if (brix_token_validate_registry(&ra, uri_path, BRIX_TOKEN_OP_READ,
                                         &bucket) != 0)
        {
            return NGX_HTTP_UNAUTHORIZED;  /* invalid/expired/out-of-scope */
        }
    }

    /* the VALIDATED subject is the F9 QoS classification key */
    ngx_cpystrn((u_char *) ctx->token_sub, (u_char *) claims.sub,
                sizeof(ctx->token_sub));
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

/* ---- per-VO/per-job QoS fill throttling (phase-85 F9) ---------------------
 * brix_cvmfs_qos <class> sub=<subject>|default fills=<n> — multi-occurrence;
 * each entry maps ONE validated token subject (or `default` = everything
 * unclassified) to a fills-per-second budget. Only ORIGIN FILLS are charged
 * (the caller gates on the remote-miss predicate) — cache hits always flow,
 * so a throttled class is bounded at the shared WAN/origin resource, which
 * is exactly the noisy-neighbor surface. fills=0 = unlimited (parity). */

char *
cvmfs_conf_qos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_cvmfs_loc_conf_t *c = conf;
    ngx_str_t                      *value = cf->args->elts;
    brix_cvmfs_qos_t               *entry;
    ngx_int_t                       fills;

    (void) cmd;

    if (value[3].len <= sizeof("fills=") - 1
        || ngx_strncmp(value[3].data, "fills=", sizeof("fills=") - 1) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_qos needs <class> sub=<subject>|default fills=<n>");
        return NGX_CONF_ERROR;
    }
    fills = ngx_atoi(value[3].data + sizeof("fills=") - 1,
                     value[3].len - (sizeof("fills=") - 1));
    if (fills == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_qos: \"%V\" is not a fill rate", &value[3]);
        return NGX_CONF_ERROR;
    }

    if (c->qos == NGX_CONF_UNSET_PTR) {
        c->qos = ngx_array_create(cf->pool, 4, sizeof(brix_cvmfs_qos_t));
        if (c->qos == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    entry = ngx_array_push(c->qos);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(entry, sizeof(*entry));
    entry->name  = value[1];
    entry->fills = (ngx_uint_t) fills;

    if (value[2].len == sizeof("default") - 1
        && ngx_strncmp(value[2].data, "default", value[2].len) == 0)
    {
        /* sub stays empty = the unclassified catch-all */
        return NGX_CONF_OK;
    }
    if (value[2].len <= sizeof("sub=") - 1
        || ngx_strncmp(value[2].data, "sub=", sizeof("sub=") - 1) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_qos: match must be sub=<subject> or default");
        return NGX_CONF_ERROR;
    }
    entry->sub.data = value[2].data + (sizeof("sub=") - 1);
    entry->sub.len  = value[2].len - (sizeof("sub=") - 1);
    return NGX_CONF_OK;
}

/* The class for `sub` ("" = anonymous): first sub= match wins, else the
 * first `default` entry, else NULL (identity unthrottled). */
static brix_cvmfs_qos_t *
cvmfs_qos_class(ngx_http_brix_cvmfs_loc_conf_t *lcf, const char *sub)
{
    brix_cvmfs_qos_t *e = lcf->qos->elts;
    brix_cvmfs_qos_t *def = NULL;
    size_t             sub_len = ngx_strlen(sub);
    ngx_uint_t         i;

    for (i = 0; i < lcf->qos->nelts; i++) {
        if (e[i].sub.len == 0) {
            if (def == NULL) {
                def = &e[i];
            }
            continue;
        }
        if (e[i].sub.len == sub_len
            && ngx_strncmp(e[i].sub.data, sub, sub_len) == 0)
        {
            return &e[i];
        }
    }
    return def;
}

ngx_int_t
brix_cvmfs_qos_check(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    brix_cvmfs_qos_t           *cls;
    ngx_msec_t                  now;

    if (lcf->qos == NULL || ctx == NULL) {
        return NGX_DECLINED;
    }
    cls = cvmfs_qos_class(lcf, ctx->token_sub);
    if (cls == NULL || cls->fills == 0) {
        return NGX_DECLINED;               /* unthrottled / 0 = parity */
    }

    /* Token bucket in milli-fills: capacity fills*1000, refill fills/ms-
     * scaled, one fill costs 1000. Worker-local (COW conf memory), event-
     * loop only — each worker bounds its own share. */
    now = ngx_current_msec;
    if (cls->last == 0) {
        cls->tokens = (ngx_int_t) (cls->fills * 1000);   /* first sight: full */
    } else if (now != cls->last) {
        ngx_int_t cap = (ngx_int_t) (cls->fills * 1000);

        cls->tokens += (ngx_int_t) ((now - cls->last) * cls->fills);
        if (cls->tokens > cap) {
            cls->tokens = cap;
        }
    }
    cls->last = now;

    if (cls->tokens < 1000) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "cvmfs: qos class \"%V\" fill budget exhausted "
            "(sub \"%s\", %ui fills/s) - 429", &cls->name,
            ctx->token_sub[0] != '\0' ? ctx->token_sub : "anonymous",
            cls->fills);
        return NGX_HTTP_TOO_MANY_REQUESTS;
    }
    cls->tokens -= 1000;
    return NGX_DECLINED;
}
