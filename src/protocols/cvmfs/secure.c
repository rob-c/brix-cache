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
 *       x509 mode authenticates the TLS-verified peer by its end-entity (EEC)
 *       subject DN (RFC 3820 proxy certs skipped via brix_px_classify — a GSI
 *       proxy authenticates as its issuing EEC) against an optional DN
 *       allow-glob list; it is still POLICY GLUE — the crypto is nginx's own
 *       ssl_verify_client chain validation plus the shared brix_x509_oneline /
 *       brix_sp_glob_match helpers. voms mode layers a VOMS-VO authorisation
 *       gate on top of x509 via the shared brix_extract_voms_info engine
 *       (per-VO LSC vomsdir + VOMS signing-CA trust); still POLICY GLUE.
 */
#include "cvmfs.h"
#include "cvmfs_module_internal.h"
#include "core/ngx_brix_module.h"           /* brix_extract_voms_info (voms) */
#include "auth/token/issuer_registry.h"
#include "auth/crypto/store_policy.h"       /* brix_x509_oneline, brix_px_classify */
#include "auth/crypto/signing_policy.h"     /* brix_sp_glob_match (DN allow-glob) */
#include "core/compat/cstr.h"
#include "core/types/tunables.h"
#include "secure_internal.h"

#include <limits.h>

#if (NGX_HTTP_SSL)
#include <openssl/ssl.h>
#include <openssl/x509.h>
#endif


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

/* scvmfs_registry_check — shared bearer gate behind both the scvmfs bearer
 * mode and the F3 repo-authz plane: fetch the Bearer credential, canonicalise
 * r->uri, and validate against `reg` with READ scope (a read-only protocol).
 * Returns NGX_DECLINED on success with *claims filled, otherwise the HTTP
 * status to answer with. reg == NULL fails CLOSED — merge-time validation
 * makes that unreachable, but never open up. */
static ngx_int_t
scvmfs_registry_check(ngx_http_request_t *r, const void *reg,
    brix_token_claims_t *claims)
{
    const char  *token;
    size_t       token_len;
    char         uri_path[PATH_MAX];
    int          bucket = 0;
    ngx_int_t    rc;

    if (reg == NULL) {
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
        ra.reg             = (const brix_token_registry_t *) reg;
        ra.macaroon_secret = NULL;
        ra.secret_len      = 0;
        ra.clock_skew      = BRIX_TOKEN_CLOCK_SKEW_SECS;
        ra.claims          = claims;

        if (brix_token_validate_registry(&ra, uri_path, BRIX_TOKEN_OP_READ,
                                         &bucket) != 0)
        {
            return NGX_HTTP_UNAUTHORIZED;  /* invalid/expired/out-of-scope */
        }
    }
    return NGX_DECLINED;
}

static ngx_int_t
scvmfs_check_bearer(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    brix_token_claims_t  claims;
    ngx_int_t            rc;

    rc = scvmfs_registry_check(r, lcf->scvmfs_registry, &claims);
    if (rc != NGX_DECLINED) {
        return rc;
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

/* Is `repo` behind an F3 gate in this location? Pure lookup — no token work.
 * The G15 attest plane uses this to mark sessions that touched gated content
 * and to refuse serving their records under an ungated sibling name. */
ngx_uint_t
brix_cvmfs_repo_authz_gated(ngx_http_brix_cvmfs_loc_conf_t *lcf,
    const char *repo, size_t repo_len)
{
    if (lcf->repo_authz == NULL || repo == NULL || repo_len == 0) {
        return 0;
    }
    return cvmfs_repo_authz_match(lcf, repo, repo_len) != NULL;
}

ngx_int_t
brix_cvmfs_repo_authz_eval(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    brix_cvmfs_repo_authz_t     *gate;
    brix_token_claims_t          claims;
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

    rc = scvmfs_registry_check(r, gate->registry, &claims);
    if (rc != NGX_DECLINED) {
        return rc;
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
    case BRIX_SCVMFS_AUTHZ_X509:
        rc = scvmfs_check_x509(r, lcf);
        break;
    case BRIX_SCVMFS_AUTHZ_VOMS:
        rc = scvmfs_check_voms(r, lcf);
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

#if (NGX_HTTP_SSL)
static ngx_int_t scvmfs_loc_wants_proxy_certs(ngx_http_core_loc_conf_t *clcf);

/* Recurse the static (prefix/exact) location tree looking for an scvmfs
 * x509/voms location. By module postconfiguration nginx has already folded the
 * config-time location queue into this tree (built in ngx_http_merge_servers),
 * so the queue is empty and the tree is the live structure to walk. */
static ngx_int_t
scvmfs_tree_wants_proxy_certs(ngx_http_location_tree_node_t *node)
{
    if (node == NULL) {
        return 0;
    }
    if (node->exact != NULL && scvmfs_loc_wants_proxy_certs(node->exact)) {
        return 1;
    }
    if (node->inclusive != NULL
        && scvmfs_loc_wants_proxy_certs(node->inclusive))
    {
        return 1;
    }
    return scvmfs_tree_wants_proxy_certs(node->left)
        || scvmfs_tree_wants_proxy_certs(node->right)
        || scvmfs_tree_wants_proxy_certs(node->tree);
}

/* Does this location (or any nested location) run scvmfs x509/voms — i.e. want
 * client GSI-proxy chains to verify? scvmfs_authz is a LOCATION directive, so a
 * server-level check alone misses the common `location /cvmfs/ { brix_scvmfs on;
 * ... }` layout; descend the static location tree and any regex locations. */
static ngx_int_t
scvmfs_loc_wants_proxy_certs(ngx_http_core_loc_conf_t *clcf)
{
    ngx_http_brix_cvmfs_loc_conf_t  *lcf;
    ngx_http_core_loc_conf_t       **regex;
    ngx_uint_t                        i;

    /* clcf->loc_conf is set on real location clcfs but is NULL on the server's
     * implicit core loc conf at this stage — guard before dereferencing. */
    if (clcf->loc_conf != NULL) {
        lcf = clcf->loc_conf[ngx_http_brix_cvmfs_module.ctx_index];
        if (lcf != NULL && lcf->scvmfs
            && (lcf->scvmfs_authz == BRIX_SCVMFS_AUTHZ_X509
                || lcf->scvmfs_authz == BRIX_SCVMFS_AUTHZ_VOMS))
        {
            return 1;
        }
    }
    if (scvmfs_tree_wants_proxy_certs(clcf->static_locations)) {
        return 1;
    }
    regex = clcf->regex_locations;
    if (regex != NULL) {
        for (i = 0; regex[i] != NULL; i++) {
            if (scvmfs_loc_wants_proxy_certs(regex[i])) {
                return 1;
            }
        }
    }
    return 0;
}
#endif

/* Enable client GSI-proxy-cert verification on an scvmfs x509/voms server's TLS
 * context. nginx core rejects RFC 3820 proxy certs during ssl_verify_client
 * chain validation unless X509_V_FLAG_ALLOW_PROXY_CERTS is set; x509 mode
 * authenticates a proxy as its issuing EEC and voms mode lifts the proxy's VOMS
 * AC, so both need a proxy chain to VERIFY (X509_V_OK) before the preamble sees
 * it. Mirrors webdav's proxy_certs postconfig hook. Bearer/none modes (and
 * servers with no scvmfs x509/voms location) are left untouched. cscf is an
 * ngx_http_core_srv_conf_t *. */
ngx_int_t
brix_scvmfs_postconf_proxy_certs(ngx_conf_t *cf, void *cscf)
{
#if (NGX_HTTP_SSL)
    ngx_http_core_srv_conf_t       *core_srv = cscf;
    ngx_http_conf_ctx_t            *ctx = core_srv->ctx;
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_brix_cvmfs_loc_conf_t *lcf;
    ngx_http_ssl_srv_conf_t        *sslcf;
    X509_VERIFY_PARAM              *param;
    ngx_int_t                       wants;

    /* Server-level directive (ctx->loc_conf is valid here even though the core
     * loc conf's own ->loc_conf field is not), then the nested location tree. */
    lcf = ctx->loc_conf[ngx_http_brix_cvmfs_module.ctx_index];
    wants = (lcf != NULL && lcf->scvmfs
             && (lcf->scvmfs_authz == BRIX_SCVMFS_AUTHZ_X509
                 || lcf->scvmfs_authz == BRIX_SCVMFS_AUTHZ_VOMS));
    if (!wants) {
        clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
        wants = (clcf != NULL && scvmfs_loc_wants_proxy_certs(clcf));
    }
    if (!wants) {
        return NGX_OK;
    }
    sslcf = ctx->srv_conf[ngx_http_ssl_module.ctx_index];
    if (sslcf == NULL || sslcf->ssl.ctx == NULL) {
        return NGX_OK;                             /* no TLS on this server */
    }
    param = SSL_CTX_get0_param(sslcf->ssl.ctx);
    if (param != NULL) {
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_ALLOW_PROXY_CERTS);
        ngx_log_error(NGX_LOG_INFO, cf->log, 0,
            "scvmfs: enabled X509_V_FLAG_ALLOW_PROXY_CERTS on server %V",
            &core_srv->server_name);
    }
    return NGX_OK;
#else
    (void) cf; (void) cscf;
    return NGX_OK;
#endif
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
