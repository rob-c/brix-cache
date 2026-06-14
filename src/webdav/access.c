/*
 * access.c - WebDAV access-phase handler: auth gate, CORS, write guards,
 *            token scopes, and common WebDAV request checks.
 *
 * WHAT: Runs in NGX_HTTP_ACCESS_PHASE (before any content handler) for every
 * request in an xrootd_webdav location.  Handles: CORS headers, request
 * metrics, authentication (GSI proxy cert then bearer token), XrdHttp opaque
 * header extraction, allow_write gate, and token scope enforcement.
 *
 * WHY: Keeping auth/scope checks in the access phase means every native WebDAV
 * content handler sees a pre-authenticated request and can focus on its
 * method-specific path, lock, and filesystem semantics.
 *
 * HOW: Returns NGX_DECLINED when the location has xrootd_webdav disabled (not
 * our location), NGX_OK to allow content handlers to proceed, or an HTTP error
 * code to reject the request.  webdav_metrics_return() is used for rejections
 * so that the per-method error counters are incremented before returning.
 * webdav_metrics_request() is called once per request at entry.
 */

#include "webdav.h"
#include "../metrics/unified.h"

/* Returns non-zero if the HTTP method is a mutating (write) operation. */
static int
webdav_is_write_method(ngx_http_request_t *r)
{
    const xrootd_http_operation_t *op;

    op = xrootd_http_operation_find(r, xrootd_webdav_operations,
                                    xrootd_webdav_operations_count);

    return (op && (op->flags & XROOTD_PROTO_OP_WRITE));
}

/* Returns the method name string for token scope check, or NULL if the method
 * does not require a write-scope token claim (LOCK, UNLOCK). */
static const char *
webdav_scope_method_name(ngx_http_request_t *r)
{
    const xrootd_http_operation_t *op;

    op = xrootd_http_operation_find(r, xrootd_webdav_operations,
                                    xrootd_webdav_operations_count);

    if (op && (op->flags & XROOTD_PROTO_OP_WRITE)) {
        if (ngx_strcmp(op->name, "LOCK") == 0
            || ngx_strcmp(op->name, "UNLOCK") == 0)
            return NULL;

        return op->name;
    }

    return NULL;
}

ngx_int_t
ngx_http_xrootd_webdav_access_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_int_t                          auth_rc, rc;
    const char                        *scope_method;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (!conf->common.enable) {
        return NGX_DECLINED;
    }

    /* Phase 24: mirror subrequests are internally generated and already
     * authorized by the parent — skip the auth gate so the shadow request is
     * not re-checked (and never double-counted in metrics). */
    {
        ngx_http_xrootd_webdav_req_ctx_t *mctx =
            ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
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
            XROOTD_WEBDAV_METRIC_INC(bytes_rx_ipv6_total);
        } else {
            XROOTD_WEBDAV_METRIC_INC(bytes_rx_ipv4_total);
        }
    }

    /* Phase 20: per-client-IP request rate limit, applied before the auth
     * burden so a flood of unauthenticated requests is shed cheaply. */
    if (conf->rate_limit.kv != NULL && r->connection != NULL) {
        ngx_str_t *ip = &r->connection->addr_text;

        if (xrootd_rate_limit_check(&conf->rate_limit,
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
            XROOTD_WEBDAV_METRIC_INC(cors_total[XROOTD_WEBDAV_CORS_PREFLIGHT]);
        }
        return NGX_OK;
    }

    /* ---- Authentication gate ---- */
    if (conf->auth != WEBDAV_AUTH_NONE) {
        auth_rc = webdav_verify_proxy_cert(r, conf);
        if (auth_rc != NGX_OK) {
            auth_rc = webdav_verify_bearer_token(r, conf);
            if (auth_rc == NGX_OK) {
                XROOTD_WEBDAV_METRIC_INC(
                    auth_total[XROOTD_WEBDAV_AUTH_RESULT_TOKEN_OK]);
                xrootd_metric_auth(XROOTD_PROTO_WEBDAV,
                                   XROOTD_AUTHN_TOKEN, 1);
            }
        } else {
            XROOTD_WEBDAV_METRIC_INC(
                auth_total[XROOTD_WEBDAV_AUTH_RESULT_CERT_OK]);
            xrootd_metric_auth(XROOTD_PROTO_WEBDAV, XROOTD_AUTHN_GSI, 1);
        }

        if (auth_rc != NGX_OK && conf->auth == WEBDAV_AUTH_REQUIRED) {
            XROOTD_WEBDAV_METRIC_INC(
                auth_total[XROOTD_WEBDAV_AUTH_RESULT_REJECTED]);
            xrootd_metric_auth(XROOTD_PROTO_WEBDAV, XROOTD_AUTHN_NONE, 0);
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: unauthenticated request rejected"
                          " (auth=required)");
            return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
        }

        if (auth_rc != NGX_OK) {
            XROOTD_WEBDAV_METRIC_INC(
                auth_total[XROOTD_WEBDAV_AUTH_RESULT_ANONYMOUS]);
            xrootd_metric_auth(XROOTD_PROTO_WEBDAV, XROOTD_AUTHN_NONE, 1);
        }
    } else {
        XROOTD_WEBDAV_METRIC_INC(
            auth_total[XROOTD_WEBDAV_AUTH_RESULT_NONE]);
        xrootd_metric_auth(XROOTD_PROTO_WEBDAV, XROOTD_AUTHN_NONE, 1);
    }

    /* XrdHttp: extract client identity, UUID, opaque, and ?tpc.* params.
     * Must run after auth so the request context exists. */
    xrdhttp_parse_request(r);
    xrdhttp_inject_tpc_headers(r);

    /* Upstream proxy mode: auth is done; proxy content handler takes over. */
    if (conf->upstream_proxy) {
        return NGX_OK;
    }

    /* ---- Write-method gate ---- */
    if (webdav_is_write_method(r) && !conf->common.allow_write) {
        return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
    }

    /* ---- Token scope check ---- */
    scope_method = webdav_scope_method_name(r);
    if (scope_method != NULL) {
        rc = webdav_check_token_write_scope(r, scope_method);
        if (rc != NGX_OK) {
            return webdav_metrics_return(r, rc);
        }
    }

    return NGX_OK;
}
