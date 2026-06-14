/*
 * introspect.c — Phase 21 Step C: real-time OIDC token revocation via a
 * non-blocking introspection subrequest.
 *
 * Design (modelled on nginx's auth_request module):
 *
 *   - A dedicated NGX_HTTP_ACCESS_PHASE handler, separate from the main webdav
 *     access handler, so the subrequest suspend/resume re-entry replays ONLY
 *     this handler (the main auth handler is not re-run, and its metrics are
 *     not double-counted).
 *
 *   - The operator defines an internal location that POSTs to the IdP's
 *     RFC 7662 /introspect endpoint, e.g.:
 *
 *         location = /internal/introspect {
 *             internal;
 *             proxy_method      POST;
 *             proxy_set_header  Content-Type application/x-www-form-urlencoded;
 *             proxy_set_body    "token=$arg_token";
 *             proxy_pass        https://iam.example.org/introspect;
 *         }
 *
 *     and names it with `xrootd_webdav_token_introspect_loc /internal/introspect;`.
 *     We fire a subrequest at that URI carrying `?token=<jwt>` (JWTs are
 *     base64url, so they are URL-safe as a query value).
 *
 *   - Fast path: the token fingerprint (SHA-256) is checked against a Phase-20
 *     KV revoke zone first; a cached "revoked" marker short-circuits to 403
 *     without an IdP round-trip.  Only negative results are cached (for
 *     introspect_ttl seconds) so revocation propagates quickly while valid
 *     tokens are not re-introspected on every request (the Phase-20 token
 *     validation cache already amortises those).
 *
 *   - Failure policy: if the IdP is unreachable or returns a non-200, the
 *     request proceeds when fail_open is on (WLCG default) or is rejected with
 *     403 when off.
 */
#include "webdav.h"
#include "../compat/crypto.h"

#include <jansson.h>

/* State carried from the subrequest fire to its completion callback. */
typedef struct {
    ngx_http_xrootd_webdav_req_ctx_t  *parent_ctx;
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    u_char                             key[32];
    unsigned                           have_key:1;
} webdav_introspect_data_t;

/*
 * Parse an RFC 7662 introspection response body.  Returns 1 when the JSON
 * object has "active": true, 0 otherwise (including parse failure — a malformed
 * response is treated as "not active" only by the caller's policy, never here).
 */
static int
webdav_introspect_parse_active(const u_char *body, size_t len)
{
    json_error_t  jerr;
    json_t       *root, *active;
    char         *buf;
    int           result = 0;

    if (body == NULL || len == 0) {
        return 0;
    }
    buf = ngx_alloc(len + 1, ngx_cycle->log);
    if (buf == NULL) {
        return 0;
    }
    ngx_memcpy(buf, body, len);
    buf[len] = '\0';

    root = json_loads(buf, JSON_REJECT_DUPLICATES, &jerr);
    ngx_free(buf);
    if (root == NULL) {
        return 0;
    }

    active = json_object_get(root, "active");
    if (json_is_boolean(active) && json_is_true(active)) {
        result = 1;
    }
    json_decref(root);
    return result;
}

/* Subrequest completion: record active/revoked verdict on the parent ctx. */
static ngx_int_t
webdav_introspect_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    webdav_introspect_data_t          *d    = data;
    ngx_http_xrootd_webdav_req_ctx_t  *pctx = d->parent_ctx;
    ngx_http_xrootd_webdav_loc_conf_t *conf = d->conf;
    ngx_uint_t                         status;
    int                                active;

    status = r->headers_out.status;

    if (rc == NGX_OK && status == NGX_HTTP_OK && r->upstream != NULL) {
        ngx_buf_t *b = &r->upstream->buffer;
        active = webdav_introspect_parse_active(b->pos,
                                                (size_t) (b->last - b->pos));

        /* Cache only negative (revoked) results so revocation propagates. */
        if (!active && conf->revoke_kv != NULL && d->have_key) {
            (void) xrootd_kv_set(conf->revoke_kv, d->key, 32,
                                 (const u_char *) "1", 1,
                                 (ngx_msec_t) conf->introspect_ttl * 1000);
        }
    } else {
        /* IdP unreachable / error → honour the configured failure policy. */
        active = conf->introspect_fail_open ? 1 : 0;
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: token introspection failed "
                      "(rc=%i status=%ui) — %s",
                      rc, status,
                      conf->introspect_fail_open ? "allowing (fail-open)"
                                                 : "denying (fail-closed)");
    }

    pctx->introspect_active = active ? 1 : 0;
    pctx->introspect_done   = 1;
    return rc;
}

static ngx_int_t
webdav_introspect_fire(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_req_ctx_t *ctx,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    const ngx_str_t *token, const u_char key[32], int have_key)
{
    ngx_http_request_t        *sr;
    ngx_http_post_subrequest_t *ps;
    webdav_introspect_data_t   *d;
    ngx_str_t                   args;
    u_char                     *p;

    d = ngx_pcalloc(r->pool, sizeof(*d));
    ps = ngx_palloc(r->pool, sizeof(*ps));
    if (d == NULL || ps == NULL) {
        return NGX_ERROR;
    }
    d->parent_ctx = ctx;
    d->conf       = conf;
    d->have_key   = have_key ? 1 : 0;
    if (have_key) {
        ngx_memcpy(d->key, key, 32);
    }
    ps->handler = webdav_introspect_done;
    ps->data    = d;

    /* args = "token=<jwt>" (JWT is base64url → URL-safe as a query value). */
    args.len  = sizeof("token=") - 1 + token->len;
    args.data = ngx_pnalloc(r->pool, args.len);
    if (args.data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(args.data, "token=", sizeof("token=") - 1);
    ngx_memcpy(p, token->data, token->len);

    if (ngx_http_subrequest(r, &conf->introspect_loc, &args, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED
                            | NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
webdav_introspect_access_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_http_xrootd_webdav_req_ctx_t  *ctx;
    ngx_str_t                          auth, bearer;
    u_char                             key[32];
    int                                have_key = 0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (conf == NULL || conf->introspect_loc.len == 0) {
        return NGX_DECLINED;            /* introspection not configured */
    }

    /* Only main requests; never introspect our own subrequest. */
    if (r != r->main) {
        return NGX_DECLINED;
    }

    /* Needs a Bearer token to introspect. */
    if (r->headers_in.authorization == NULL) {
        return NGX_DECLINED;
    }
    auth = r->headers_in.authorization->value;
    if (xrootd_http_extract_bearer(&auth, &bearer) != NGX_OK
        || bearer.len == 0)
    {
        return NGX_DECLINED;
    }

    /* This access handler may run before the main webdav access handler that
     * normally allocates the request context, so get-or-create it here.  The
     * struct layout matches xrdhttp_get_ctx(), so a later call there reuses it. */
    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_xrootd_webdav_module);
    }

    /* Resume path: the subrequest already produced a verdict. */
    if (ctx->introspect_done) {
        if (!ctx->introspect_active) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: bearer token rejected by"
                          " introspection (revoked)");
            return NGX_HTTP_FORBIDDEN;
        }
        return NGX_DECLINED;            /* active → allow, continue */
    }

    /* Fast path: token fingerprint already known-revoked. */
    if (xrootd_sha256(bearer.data, bearer.len, key) == 1) {
        have_key = 1;
        if (conf->revoke_kv != NULL) {
            u_char  v[4];
            size_t  vl = sizeof(v);
            if (xrootd_kv_get(conf->revoke_kv, key, 32, v, &vl) == 1) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "xrootd_webdav: bearer token rejected"
                              " (revocation cache hit)");
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    /* Slow path: fire the introspection subrequest and suspend. */
    if (webdav_introspect_fire(r, ctx, conf, &bearer, key, have_key)
        != NGX_OK)
    {
        return conf->introspect_fail_open ? NGX_DECLINED : NGX_HTTP_FORBIDDEN;
    }

    return NGX_AGAIN;                   /* suspend until subrequest completes */
}

/* ---- directive: xrootd_webdav_revoke_cache zone=<name>; ---- */

char *
webdav_conf_revoke_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf = conf_ptr;
    ngx_str_t                         *value = cf->args->elts;
    ngx_str_t                          zone = ngx_null_string;
    ngx_uint_t                         i;
    xrootd_kv_t                       *kv;

    (void) cmd;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            zone.data = value[i].data + 5;
            zone.len  = value[i].len - 5;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid xrootd_webdav_revoke_cache parameter \"%V\"",
                &value[i]);
            return NGX_CONF_ERROR;
        }
    }
    if (zone.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_webdav_revoke_cache requires zone=<name>");
        return NGX_CONF_ERROR;
    }

    kv = xrootd_kv_find(&zone);
    if (kv == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_webdav_revoke_cache: unknown zone \"%V\" "
            "(declare it with xrootd_kv_zone first)", &zone);
        return NGX_CONF_ERROR;
    }
    if (kv->key_max < 32 || kv->val_max < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_webdav_revoke_cache zone \"%V\" too small: need key>=32 val>=1",
            &zone);
        return NGX_CONF_ERROR;
    }

    conf->revoke_kv = kv;
    return NGX_CONF_OK;
}
