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
#include "fs/path/path.h"   /* brix_check_authdb_identity, brix_check_vo_acl_identity */
#include "webdav_tpc.h"     /* webdav_tpc_find_header — COPY PULL/PUSH direction */
#include "protocols/shared/deleg_capture.h"  /* phase-70 §5.1 proxy header capture */
#include "fs/backend/sd.h"  /* enum brix_cred_mode / BRIX_CRED_SELECT */

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
    case NGX_HTTP_COPY:
        /* A TPC PULL (Source: header present) WRITES r->uri (the local
         * destination), so it must be authorized as a CREATE — otherwise a
         * read-only principal could pull remote data onto a path it may not
         * write. A PUSH / plain intra-server COPY reads r->uri (the source). */
        if (webdav_tpc_find_header(r, "Source", sizeof("Source") - 1) != NULL) {
            return BRIX_AOP_CREATE;
        }
        return BRIX_AOP_READ;
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


/*
 * access_is_mirror_subrequest — Phase 24 mirror-shadow detection.
 *
 * WHAT: Returns non-zero when the request is an internally generated mirror
 * subrequest that was already authorized by its parent request.
 *
 * WHY: The shadow request must skip the auth gate so it is not re-checked
 * (and never double-counted in metrics).
 *
 * HOW: A mirror subrequest is a non-main request whose module ctx (inherited
 * from the parent) carries the is_mirror flag.
 */
static int
access_is_mirror_subrequest(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *mctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    return (r != r->main && mctx != NULL && mctx->is_mirror);
}

/*
 * access_count_request — per-request entry metrics.
 *
 * WHAT: Counts the request once (webdav_metrics_request) and increments the
 * per-IP-version received-bytes family.
 *
 * WHY: Every request that reaches the access phase must be counted exactly
 * once, before any accept/reject decision, so error counters and totals agree.
 *
 * HOW: Inspects the connection sockaddr family; AF_INET6 goes to the v6
 * counter, everything else to v4.
 */
static void
access_count_request(ngx_http_request_t *r)
{
    webdav_metrics_request(r);
    if (r->connection && r->connection->sockaddr) {
        if (r->connection->sockaddr->sa_family == AF_INET6) {
            BRIX_WEBDAV_METRIC_INC(bytes_rx_ipv6_total);
        } else {
            BRIX_WEBDAV_METRIC_INC(bytes_rx_ipv4_total);
        }
    }
}

/*
 * access_rate_limit — Phase 20 per-client-IP request rate limit.
 *
 * WHAT: Sheds requests from clients exceeding the configured rate.
 *
 * WHY: Applied before the auth burden so a flood of unauthenticated requests
 * is rejected cheaply.
 *
 * HOW: Keys the shared rate-limit table by the textual client address.
 * Returns NGX_OK to continue, or the metrics-counted 429 rejection.
 */
static ngx_int_t
access_rate_limit(ngx_http_request_t *r,
                  ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_str_t *ip;

    if (conf->rate_limit.kv == NULL || r->connection == NULL) {
        return NGX_OK;
    }

    ip = &r->connection->addr_text;

    if (brix_rate_limit_check(&conf->rate_limit,
                                (const char *) ip->data, ip->len)
        != NGX_OK)
    {
        return webdav_metrics_return(r, NGX_HTTP_TOO_MANY_REQUESTS);
    }

    return NGX_OK;
}

/*
 * access_options_preflight — OPTIONS short-circuit.
 *
 * WHAT: Lets OPTIONS through unauthenticated, counting a CORS preflight when
 * the request carries both Origin and Access-Control-Request-Method.
 *
 * WHY: CORS headers are already set at this point; the content handler builds
 * the Allow response without needing authentication.
 *
 * HOW: Always returns NGX_OK — OPTIONS is a capability query, never rejected
 * here.
 */
static ngx_int_t
access_options_preflight(ngx_http_request_t *r)
{
    if (webdav_tpc_find_header(r, "Origin", sizeof("Origin") - 1) != NULL
        && webdav_tpc_find_header(r, "Access-Control-Request-Method",
                                  sizeof("Access-Control-Request-Method") - 1)
           != NULL)
    {
        BRIX_WEBDAV_METRIC_INC(cors_total[BRIX_WEBDAV_CORS_PREFLIGHT]);
    }
    return NGX_OK;
}

/*
 * access_try_cert — GSI proxy-certificate credential source.
 *
 * WHAT: Attempts client-certificate authentication and records the cert-OK
 * metrics on success.
 *
 * WHY: The cert tier is tried FIRST (before bearer token), matching the
 * root:// auth ordering; metrics must attribute the session to GSI.
 *
 * HOW: Thin wrapper over webdav_verify_proxy_cert; returns its verdict.
 */
static ngx_int_t
access_try_cert(ngx_http_request_t *r,
                ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_verify_proxy_cert(r, conf);

    if (rc == NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_CERT_OK]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_GSI, 1);
    }
    return rc;
}

/*
 * access_try_token — bearer-token credential source.
 *
 * WHAT: Attempts bearer-token authentication and records the token-OK metrics
 * on success.
 *
 * WHY: Tried only after the cert tier fails; metrics must attribute the
 * session to TOKEN.
 *
 * HOW: Thin wrapper over webdav_verify_bearer_token; returns its verdict.
 */
static ngx_int_t
access_try_token(ngx_http_request_t *r,
                 ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_verify_bearer_token(r, conf);

    if (rc == NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_TOKEN_OK]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_TOKEN, 1);
    }
    return rc;
}

/*
 * access_try_basic — Basic-password credential source.
 *
 * WHAT: Attempts HTTP Basic authentication against the configured pwd db and
 * records the pwd-OK metrics on success.
 *
 * WHY: Tried LAST (after cert and token) so stronger credentials always win;
 * metrics must attribute the session to PWD.
 *
 * HOW: Thin wrapper over webdav_verify_basic_pwd; returns its verdict.
 */
static ngx_int_t
access_try_basic(ngx_http_request_t *r,
                 ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_verify_basic_pwd(r, conf);

    if (rc == NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_PWD_OK]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_PWD, 1);
    }
    return rc;
}

/*
 * access_basic_challenge — RFC 7617 Basic challenge for browser clients.
 *
 * WHAT: Attaches `WWW-Authenticate: Basic realm="brix"` to the response and
 * returns NGX_HTTP_UNAUTHORIZED, or NGX_HTTP_INTERNAL_SERVER_ERROR on
 * allocation failure.
 *
 * WHY: A browser only shows its login prompt (and re-prompts after a wrong
 * password) on 401 + a challenge header; a bare 403 is a dead end.  Emitted
 * only when Basic is actually enabled on the export, so cert/token-only
 * exports keep their historical 403 and never invite a password prompt that
 * cannot succeed.
 *
 * HOW: The same headers_out wiring nginx's own auth_basic module uses — push
 * the header and point headers_out.www_authenticate at it so the special-
 * response path emits it.
 */
static ngx_int_t
access_basic_challenge(ngx_http_request_t *r)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    h->next = NULL;
    ngx_str_set(&h->key, "WWW-Authenticate");
    ngx_str_set(&h->value, "Basic realm=\"brix\"");
    r->headers_out.www_authenticate = h;
    return NGX_HTTP_UNAUTHORIZED;
}

/*
 * access_authenticate — the authentication gate.
 *
 * WHAT: Runs the credential sources in order (GSI proxy cert, bearer token,
 * then Basic password) and applies the location's auth policy to the outcome.
 *
 * WHY: auth=required rejects unauthenticated requests — with a 401 Basic
 * challenge when a pwd db is configured (so browsers prompt for credentials),
 * else the historical 403; auth=optional lets them proceed as anonymous;
 * auth=none skips verification entirely.  Each outcome increments exactly
 * the same metric slot as before the decomposition.
 *
 * HOW: Returns NGX_OK to continue (authenticated or anonymous) or the
 * metrics-counted rejection.
 */
static ngx_int_t
access_authenticate(ngx_http_request_t *r,
                    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t auth_rc;

    if (conf->auth == WEBDAV_AUTH_NONE) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_NONE]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 1);
        return NGX_OK;
    }

    auth_rc = access_try_cert(r, conf);
    if (auth_rc != NGX_OK) {
        auth_rc = access_try_token(r, conf);
    }
    if (auth_rc != NGX_OK) {
        auth_rc = access_try_basic(r, conf);
    }

    if (auth_rc != NGX_OK && conf->auth == WEBDAV_AUTH_REQUIRED) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_REJECTED]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 0);
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_webdav: unauthenticated request rejected"
                      " (auth=required)");
        if (conf->pwd_file.len > 0) {
            return webdav_metrics_return(r, access_basic_challenge(r));
        }
        return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
    }

    if (auth_rc != NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_ANONYMOUS]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 1);
    }

    return NGX_OK;
}

/*
 * access_capture_deleg_proxy — Phase-70 §5.1 delegated-proxy header capture.
 *
 * WHAT: When this export delegates to a backend, captures an optional
 * user-supplied full x509 proxy (X-Brix-Delegate-Proxy).
 *
 * WHY: Runs only in a delegation mode (skipped for the default SELECT
 * export).  The shared parser enforces TLS-only + leaf-DN==authenticated-
 * identity and rejects (403) a present-but-invalid header; a captured proxy
 * is stashed on the req ctx for the VFS bind sites.
 *
 * HOW: Returns NGX_OK to continue or the metrics-counted rejection code from
 * the shared parser.
 */
static ngx_int_t
access_capture_deleg_proxy(ngx_http_request_t *r,
                           ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_http_brix_webdav_req_ctx_t *dctx;
    ngx_str_t                        proxy_pem;
    ngx_int_t                        cap_rc;

    if (conf->common.backend_delegation == BRIX_CRED_SELECT) {
        return NGX_OK;
    }

    dctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    cap_rc = brix_proto_deleg_capture_proxy_header(r,
        (dctx != NULL) ? dctx->identity : NULL, &proxy_pem);
    if (cap_rc != NGX_OK) {
        return webdav_metrics_return(r, cap_rc);
    }
    if (dctx != NULL && proxy_pem.len > 0) {
        dctx->deleg_proxy_pem = proxy_pem;
    }

    return NGX_OK;
}

/*
 * access_apply_authdb — native authdb + VO ACL read parity with root://.
 *
 * WHAT: Gates READ methods (GET/HEAD/PROPFIND) by the SAME per-DN/VO rules
 * root:// enforces, so a WebDAV read — which may serve CACHED bytes — is
 * authorized identically to a cache miss.
 *
 * WHY: Runs only when brix_webdav_authdb / brix_webdav_require_vo are
 * configured (the check helpers return NGX_OK for empty rule sets, so
 * existing deployments are unaffected).  Write methods keep their
 * allow_write + xrdacc + token-scope gates.  Skips OPTIONS (CORS preflight).
 *
 * HOW: Resolves the confined canonical path, then applies the authdb and VO
 * ACL identity checks.  Returns NGX_OK to continue or the metrics-counted
 * rejection (path-resolution error code, or 403 on rule denial).
 */
static ngx_int_t
access_apply_authdb(ngx_http_request_t *r,
                    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_http_brix_webdav_req_ctx_t *actx;
    const brix_identity_t          *aid;
    char        resolved[PATH_MAX];
    char        peer[NGX_SOCKADDR_STRLEN];
    size_t      pn;
    ngx_int_t   pr;

    if (webdav_is_write_method(r) || r->method == NGX_HTTP_OPTIONS
        || (conf->authdb_rules == NULL && conf->vo_rules == NULL))
    {
        return NGX_OK;
    }

    actx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    aid = (actx != NULL) ? actx->identity : NULL;

    pr = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon,
                                             resolved, sizeof(resolved));
    if (pr != NGX_OK) {
        return webdav_metrics_return(r, pr);
    }
    pn = ngx_min(r->connection->addr_text.len, sizeof(peer) - 1);
    ngx_memcpy(peer, r->connection->addr_text.data, pn);
    peer[pn] = '\0';

    brix_authdb_query_t query = {
        .rules         = conf->authdb_rules,
        .identity      = aid,
        .peer_ip       = peer,
        .resolved_path = resolved,
        .needed_privs  = BRIX_AUTH_READ,
    };

    if (brix_check_authdb_identity(r->connection->log, &query) != NGX_OK
        || brix_check_vo_acl_identity(r->connection->log, resolved,
            conf->vo_rules, aid) != NGX_OK)
    {
        return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
    }

    return NGX_OK;
}

/*
 * access_is_oauth_endpoint — OAuth2 control-plane URI detection.
 *
 * WHAT: Returns non-zero when the request URI ends in /.oauth2/token or
 * /.well-known/oauth-authorization-server.
 *
 * WHY: These control-plane endpoints are not data resources; path-scope
 * checking the endpoint URI conflates the data-resource model with OAuth2.
 * Authority bounding is enforced inside the issuance handler instead.
 *
 * HOW: Suffix comparison against the two static endpoint strings.
 */
static int
access_is_oauth_endpoint(ngx_http_request_t *r)
{
    static const char tok_ep[]  = "/.oauth2/token";
    static const char disc_ep[] = "/.well-known/oauth-authorization-server";

    return (r->uri.len >= sizeof(tok_ep) - 1
            && ngx_memcmp(r->uri.data + r->uri.len - (sizeof(tok_ep) - 1),
                          tok_ep, sizeof(tok_ep) - 1) == 0)
        || (r->uri.len >= sizeof(disc_ep) - 1
            && ngx_memcmp(r->uri.data + r->uri.len - (sizeof(disc_ep) - 1),
                          disc_ep, sizeof(disc_ep) - 1) == 0);
}

/*
 * access_check_scope — token scope check (read AND write).
 *
 * WHAT: Enforces the bearer token's path scope against the method being
 * performed.  Exempt: OPTIONS (capability query / CORS preflight, no data
 * access), LOCK/UNLOCK (advisory locks require no scope claim,
 * pre-existing), and the OAuth2 control-plane endpoints (see
 * access_is_oauth_endpoint).
 *
 * WHY: This is the LAST gate — the global allow_write check has already run
 * (INVARIANT 3: allow_write before token scope).
 *
 * HOW: op->name is a static, null-terminated string, so it is safe to log.
 * Returns NGX_OK to continue or the metrics-counted rejection from
 * webdav_check_token_scope.
 */
static ngx_int_t
access_check_scope(ngx_http_request_t *r)
{
    const brix_http_operation_t *op;
    const char                  *mname;
    ngx_int_t                    rc;
    int                          is_lock;

    if (r->method == NGX_HTTP_OPTIONS) {
        return NGX_OK;
    }

    op = brix_http_operation_find(r, brix_webdav_operations,
                                    brix_webdav_operations_count);
    is_lock = (op != NULL
               && (ngx_strcmp(op->name, "LOCK") == 0
                   || ngx_strcmp(op->name, "UNLOCK") == 0));
    if (is_lock || access_is_oauth_endpoint(r)) {
        return NGX_OK;
    }

    mname = (op != NULL) ? op->name : "GET";
    rc = webdav_check_token_scope(r, mname);
    if (rc != NGX_OK) {
        return webdav_metrics_return(r, rc);
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_brix_webdav_access_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_int_t                          rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (!conf->common.enable) {
        return NGX_DECLINED;
    }

    /* Phase 24: mirror subrequests are already authorized by the parent. */
    if (access_is_mirror_subrequest(r)) {
        return NGX_OK;
    }

    /* CORS headers must appear on every response. */
    if (webdav_add_cors_headers(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Count the request and track IP-version bytes. */
    access_count_request(r);

    /* Phase 20: per-client-IP rate limit, before the auth burden. */
    rc = access_rate_limit(r, conf);
    if (rc != NGX_OK) {
        return rc;
    }

    /* OPTIONS pre-flight: no authentication required. */
    if (r->method == NGX_HTTP_OPTIONS) {
        return access_options_preflight(r);
    }

    /* Authentication gate */
    rc = access_authenticate(r, conf);
    if (rc != NGX_OK) {
        return rc;
    }

    /* XrdHttp: extract client identity, UUID, opaque, and ?tpc.* params.
     * Must run after auth so the request context exists. */
    xrdhttp_parse_request(r);
    xrdhttp_inject_tpc_headers(r);

    /* Phase-70 §5.1: delegated-proxy header capture (delegation modes only). */
    rc = access_capture_deleg_proxy(r, conf);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Upstream proxy mode: auth is done; proxy content handler takes over. */
    if (conf->upstream_proxy) {
        return NGX_OK;
    }

    /* Write-method gate — the GLOBAL allow_write check runs BEFORE the token
     * scope check below (INVARIANT 3). */
    if (webdav_is_write_method(r) && !conf->common.allow_write) {
        return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
    }

    /* XrdAcc engine (when brix_authdb_format xrdacc) */
    if (webdav_acc_check(r, conf) != NGX_OK) {
        return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
    }

    /* Native authdb + VO ACL read parity with root:// */
    rc = access_apply_authdb(r, conf);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Token scope check (read AND write) — after allow_write (INVARIANT 3). */
    rc = access_check_scope(r);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}

/* ---- webdav_vfs_bind_deleg -------------------------------------------------
 *
 * WHAT: Bind the request's captured forwardable credential (bearer JWT and/or
 *       user-supplied full x509 proxy PEM) onto a cred-bound VFS ctx, using the
 *       export's resolved delegation mode. See webdav_auth.h for the contract.
 *
 * WHY:  Called at every WebDAV brix_vfs_ctx_bind_backend_cred site so a delegated
 *       export authenticates the backend leg AS the inbound user rather than the
 *       shared service credential. The bytes were captured once at the auth gate
 *       (bearer in webdav_verify_bearer_token, proxy in the access-phase header
 *       capture) and stashed on the req ctx; here they are handed to the VFS.
 *
 * HOW:  Reads conf->common.backend_delegation as the mode and the req ctx's
 *       bearer_token / deleg_proxy_pem as the bytes; brix_vfs_deleg_bind is a
 *       no-op for SELECT mode or when nothing was captured. */
void
webdav_vfs_bind_deleg(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_req_ctx_t *rctx;

    if (conf->common.backend_delegation == BRIX_CRED_SELECT) {
        return;
    }

    rctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    (void) brix_vfs_deleg_bind(r->pool, vctx,
        (enum brix_cred_mode) conf->common.backend_delegation,
        (rctx != NULL) ? &rctx->bearer_token : NULL,
        (rctx != NULL) ? &rctx->deleg_proxy_pem : NULL);
}
