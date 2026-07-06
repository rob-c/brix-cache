/*
 * access.c - WebDAV access-phase handler: auth gate, CORS, write guards,
 *            token scopes, and common WebDAV request checks.
 *
 * WHAT: Runs in NGX_HTTP_ACCESS_PHASE (before any content handler) for every
 * request in an brix_webdav location.  Handles: CORS headers, request
 * metrics, authentication (GSI proxy cert then bearer token), XrdHttp opaque
 * header extraction, allow_write gate, and token scope enforcement.
 *
 * WHY: Keeping auth/scope checks in the access phase means every native WebDAV
 * content handler sees a pre-authenticated request and can focus on its
 * method-specific path, lock, and filesystem semantics.
 *
 * HOW: Returns NGX_DECLINED when the location has brix_webdav disabled (not
 * our location), NGX_OK to allow content handlers to proceed, or an HTTP error
 * code to reject the request.  webdav_metrics_return() is used for rejections
 * so that the per-method error counters are incremented before returning.
 * webdav_metrics_request() is called once per request at entry.
 */

#include "webdav.h"
#include "observability/metrics/unified.h"
#include "auth/authz/acc/acc.h"

/* Map a WebDAV HTTP method to the XrdAcc operation it requires. */
static brix_acc_op_t
webdav_method_aop(ngx_http_request_t *r)
{
    switch (r->method) {
    case NGX_HTTP_GET:
    case NGX_HTTP_HEAD:      return BRIX_AOP_READ;
    case NGX_HTTP_PUT:       return BRIX_AOP_CREATE;
    case NGX_HTTP_DELETE:    return BRIX_AOP_DELETE;
    case NGX_HTTP_MKCOL:     return BRIX_AOP_MKDIR;
    case NGX_HTTP_MOVE:      return BRIX_AOP_RENAME;
    case NGX_HTTP_COPY:      return BRIX_AOP_READ;     /* source read */
    case NGX_HTTP_PROPFIND:  return BRIX_AOP_READDIR;
    case NGX_HTTP_PROPPATCH: return BRIX_AOP_UPDATE;
    case NGX_HTTP_LOCK:
    case NGX_HTTP_UNLOCK:    return BRIX_AOP_UPDATE;
    case NGX_HTTP_OPTIONS:   return BRIX_AOP_ANY;
    default:                 return BRIX_AOP_STAT;
    }
}

/*
 * webdav_acc_check — XrdAcc tier for WebDAV (when `brix_authdb_format xrdacc`).
 * Returns NGX_OK (allow / not selected) or NGX_HTTP_FORBIDDEN (deny).
 */
static ngx_int_t
webdav_acc_check(ngx_http_request_t *r,
                 ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_http_brix_webdav_req_ctx_t *mctx;
    brix_identity_t                *id = NULL;
    const char                       *name = "", *vorg = "", *role = "", *grp = "";
    char                              host[64], path[1024];
    ngx_int_t                         rc;
    size_t                            n;

    if (conf->acc.format != BRIX_AUTHDB_FORMAT_XRDACC) {
        return NGX_OK;   /* engine not selected */
    }

    mctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (mctx != NULL && mctx->identity != NULL) {
        id = mctx->identity;
        name = brix_identity_dn_cstr(id);
        vorg = brix_identity_acc_vorg_cstr(id);
        role = brix_identity_acc_role_cstr(id);
        grp  = brix_identity_acc_group_cstr(id);
    }

    n = ngx_min(r->connection->addr_text.len, sizeof(host) - 1);
    ngx_memcpy(host, r->connection->addr_text.data, n);
    host[n] = '\0';

    /* Opt-in reverse DNS for `h <host>`/`h .domain` rules (per request). */
    if (conf->acc.resolve_hosts) {
        char        hbuf[256];
        const char *h = brix_acc_resolve_peer(r->connection->sockaddr,
                                                r->connection->socklen,
                                                hbuf, sizeof(hbuf));
        if (h != NULL) {
            n = ngx_min(ngx_strlen(h), sizeof(host) - 1);
            ngx_memcpy(host, h, n);
            host[n] = '\0';
        }
    }

    n = ngx_min(r->uri.len, sizeof(path) - 1);
    ngx_memcpy(path, r->uri.data, n);
    path[n] = '\0';

    rc = brix_acc_http_authorize(r->pool, r->connection->log,
                                   &conf->acc, name, host,
                                   vorg, role, grp,
                                   webdav_method_aop(r), path);

    return (rc == NGX_ERROR) ? NGX_HTTP_FORBIDDEN : NGX_OK;
}

/* Returns non-zero if the HTTP method is a mutating (write) operation. */
static int
webdav_is_write_method(ngx_http_request_t *r)
{
    const brix_http_operation_t *op;

    op = brix_http_operation_find(r, brix_webdav_operations,
                                    brix_webdav_operations_count);

    return (op && (op->flags & BRIX_PROTO_OP_WRITE));
}

/* Returns the method name string for token scope check, or NULL if the method
 * does not require a write-scope token claim (LOCK, UNLOCK). */
static const char *
webdav_scope_method_name(ngx_http_request_t *r)
{
    const brix_http_operation_t *op;

    op = brix_http_operation_find(r, brix_webdav_operations,
                                    brix_webdav_operations_count);

    if (op && (op->flags & BRIX_PROTO_OP_WRITE)) {
        if (ngx_strcmp(op->name, "LOCK") == 0
            || ngx_strcmp(op->name, "UNLOCK") == 0)
            return NULL;

        return op->name;
    }

    return NULL;
}

ngx_int_t
ngx_http_brix_webdav_access_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_int_t                          auth_rc, rc;
    const char                        *scope_method;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (!conf->common.enable) {
        return NGX_DECLINED;
    }

    /* Phase 24: mirror subrequests are internally generated and already
     * authorized by the parent — skip the auth gate so the shadow request is
     * not re-checked (and never double-counted in metrics). */
    {
        ngx_http_brix_webdav_req_ctx_t *mctx =
            ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
        if (r != r->main && mctx != NULL && mctx->is_mirror) {
            return NGX_OK;
        }
    }

    /* CORS headers must appear on every response. */
    if (webdav_add_cors_headers(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Count the request and track IP-version bytes. */
    webdav_metrics_request(r);
    if (r->connection && r->connection->sockaddr) {
        if (r->connection->sockaddr->sa_family == AF_INET6) {
            BRIX_WEBDAV_METRIC_INC(bytes_rx_ipv6_total);
        } else {
            BRIX_WEBDAV_METRIC_INC(bytes_rx_ipv4_total);
        }
    }

    /* Phase 20: per-client-IP request rate limit, applied before the auth
     * burden so a flood of unauthenticated requests is shed cheaply. */
    if (conf->rate_limit.kv != NULL && r->connection != NULL) {
        ngx_str_t *ip = &r->connection->addr_text;

        if (brix_rate_limit_check(&conf->rate_limit,
                                    (const char *) ip->data, ip->len)
            != NGX_OK)
        {
            return webdav_metrics_return(r, NGX_HTTP_TOO_MANY_REQUESTS);
        }
    }

    /* OPTIONS pre-flight: CORS headers are already set; content handler will
     * build the Allow response without needing authentication. */
    if (r->method == NGX_HTTP_OPTIONS) {
        if (webdav_tpc_find_header(r, "Origin", sizeof("Origin") - 1) != NULL
            && webdav_tpc_find_header(r, "Access-Control-Request-Method",
                                      sizeof("Access-Control-Request-Method") - 1)
               != NULL)
        {
            BRIX_WEBDAV_METRIC_INC(cors_total[BRIX_WEBDAV_CORS_PREFLIGHT]);
        }
        return NGX_OK;
    }

    /* Authentication gate */    if (conf->auth != WEBDAV_AUTH_NONE) {
        auth_rc = webdav_verify_proxy_cert(r, conf);
        if (auth_rc != NGX_OK) {
            auth_rc = webdav_verify_bearer_token(r, conf);
            if (auth_rc == NGX_OK) {
                BRIX_WEBDAV_METRIC_INC(
                    auth_total[BRIX_WEBDAV_AUTH_RESULT_TOKEN_OK]);
                brix_metric_auth(BRIX_PROTO_WEBDAV,
                                   BRIX_AUTHN_TOKEN, 1);
            }
        } else {
            BRIX_WEBDAV_METRIC_INC(
                auth_total[BRIX_WEBDAV_AUTH_RESULT_CERT_OK]);
            brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_GSI, 1);
        }

        if (auth_rc != NGX_OK && conf->auth == WEBDAV_AUTH_REQUIRED) {
            BRIX_WEBDAV_METRIC_INC(
                auth_total[BRIX_WEBDAV_AUTH_RESULT_REJECTED]);
            brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 0);
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "brix_webdav: unauthenticated request rejected"
                          " (auth=required)");
            return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
        }

        if (auth_rc != NGX_OK) {
            BRIX_WEBDAV_METRIC_INC(
                auth_total[BRIX_WEBDAV_AUTH_RESULT_ANONYMOUS]);
            brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 1);
        }
    } else {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_NONE]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 1);
    }

    /* XrdHttp: extract client identity, UUID, opaque, and ?tpc.* params.
     * Must run after auth so the request context exists. */
    xrdhttp_parse_request(r);
    xrdhttp_inject_tpc_headers(r);

    /* Upstream proxy mode: auth is done; proxy content handler takes over. */
    if (conf->upstream_proxy) {
        return NGX_OK;
    }

    /* Write-method gate */    if (webdav_is_write_method(r) && !conf->common.allow_write) {
        return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
    }

    /* XrdAcc engine (when brix_authdb_format xrdacc) */    if (webdav_acc_check(r, conf) != NGX_OK) {
        return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
    }

    /* Token scope check (read AND write).  OPTIONS is a capability query
     * (CORS preflight), not a data access, so it is exempt.  For write methods
     * webdav_scope_method_name() returns the canonical name; for read methods
     * fall back to the raw method name from the request line. */
    if (r->method != NGX_HTTP_OPTIONS) {
        scope_method = (webdav_scope_method_name(r) != NULL)
                       ? webdav_scope_method_name(r)
                       : (const char *) (r->method_name.data
                                         ? r->method_name.data
                                         : (u_char *) "GET");
        rc = webdav_check_token_scope(r, scope_method);
        if (rc != NGX_OK) {
            return webdav_metrics_return(r, rc);
        }
    }

    return NGX_OK;
}
