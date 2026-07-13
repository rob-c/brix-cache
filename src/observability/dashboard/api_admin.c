/*
 * api_admin.c - (kept) routing + shared helpers
 * Phase-38 split of api_admin.c; behavior-identical.
 */
#include "dashboard_api_admin_internal.h"

ngx_int_t
admin_send_ok(ngx_http_request_t *r, const char *result)
{
    json_t *root = json_object();
    if (root == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    dashboard_json_set_schema(root);
    json_object_set_new(root, "result", json_string(result));
    return dashboard_json_send(r, NGX_HTTP_OK, root);
}


ngx_int_t
admin_send_error(ngx_http_request_t *r, ngx_int_t status, const char *code)
{
    json_t *root = json_object();
    if (root == NULL) {
        return status;
    }
    dashboard_json_set_schema(root);
    json_object_set_new(root, "error", json_string(code));
    return dashboard_json_send(r, status, root);
}


/* Whitelist-validate a hostname (1=ok, 0=reject). Allows letters, digits, '.',
 * '-', and ':' (for IPv6 literals); bounded to RFC-1035's 253 chars. Reject,
 * never sanitise — the value flows into the cluster registry and downstream
 * connection logic. */
int
admin_validate_hostname(const char *host)
{
    size_t i, n;

    if (host == NULL) {
        return 0;
    }
    n = ngx_strlen(host);
    if (n == 0 || n > 253) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char) host[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '.' || c == '-'
              || c == ':'))   /* ':' allowed for IPv6 literals */
        {
            return 0;
        }
    }
    return 1;
}


/*
 * WHAT: True (1) if `c` is an ASCII letter or digit, else 0.
 * WHY:  The three admin whitelist validators (hostname/paths/url) all share this
 *       alphanumeric base class; naming it once keeps each per-char predicate a
 *       flat OR of named checks instead of an inline char-range ladder (§8.6).
 * HOW:  Pure range test over the case letters and the digit run.
 */
static int
admin_char_is_alnum(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9');
}


/*
 * WHAT: True (1) if `c` is legal inside a namespace path-list value, else 0.
 * WHY:  Factoring the per-character class out of admin_validate_paths drops that
 *       function's branch count below the gate while leaving the accepted set
 *       byte-identical (alnum plus '/', '.', '-', '_', ':').
 * HOW:  Alnum base class OR the small set of allowed punctuation.
 */
static int
admin_path_char_ok(unsigned char c)
{
    return admin_char_is_alnum(c)
        || c == '/' || c == '.' || c == '-' || c == '_' || c == ':';
}


/* Whitelist-validate a comma/colon-separated namespace path list (1=ok,
 * 0=reject). Bounded by BRIX_SRV_MAX_PATHS, the registry's storage cap. */
int
admin_validate_paths(const char *paths)
{
    size_t i, n;

    if (paths == NULL) {
        return 0;
    }
    n = ngx_strlen(paths);
    if (n == 0 || n >= BRIX_SRV_MAX_PATHS) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (!admin_path_char_ok((unsigned char) paths[i])) {
            return 0;
        }
    }
    return 1;
}



/*
 * WHAT: Authenticate an admin write request via two independent factors:
 *       a source-IP CIDR allowlist and a bearer-token secret.
 * WHY:  The admin API mutates cluster routing and proxy backends; it must fail
 *       closed. If neither factor is configured the API is treated as disabled
 *       (denied) so it is never inadvertently open.
 * HOW:  Compute cidr_ok and secret_ok independently. The bearer is compared in
 *       constant time (CRYPTO_memcmp) and length-checked first to avoid timing
 *       leaks. Combination rule:
 *         require_both ON  -> every CONFIGURED factor must pass (AND);
 *         require_both OFF -> either configured factor passing is enough (OR).
 */
/*
 * WHAT: True (1) if the request's source IP matches the admin CIDR allowlist.
 * WHY:  One of the two independent admin auth factors; naming it keeps the
 *       orchestrator flat and the sockaddr-null guard co-located with its use.
 * HOW:  Require a resolved peer sockaddr, then ngx_cidr_match against the
 *       configured allow array. Frozen: a missing sockaddr never matches.
 */
static int
admin_auth_cidr_ok(ngx_http_request_t *r,
    const ngx_http_brix_dashboard_loc_conf_t *conf)
{
    return r->connection->sockaddr != NULL
        && ngx_cidr_match(r->connection->sockaddr, conf->admin_allow) == NGX_OK;
}


/*
 * WHAT: True (1) if the request carries a bearer token equal to the admin
 *       secret, else 0.
 * WHY:  The second independent admin auth factor. Kept a pure predicate so the
 *       constant-time comparison and its length pre-gate live in one place.
 * HOW:  Extract the bearer, length-gate before the constant-time compare so
 *       unequal lengths short-circuit without a content-dependent comparison,
 *       then CRYPTO_memcmp against the configured secret. Frozen: no Authorization
 *       header never matches.
 */
static int
admin_auth_secret_ok(ngx_http_request_t *r,
    const ngx_http_brix_dashboard_loc_conf_t *conf)
{
    ngx_str_t bearer;
    ngx_str_t hdr;

    if (r->headers_in.authorization == NULL) {
        return 0;
    }
    hdr = r->headers_in.authorization->value;
    return brix_http_extract_bearer(&hdr, &bearer) == NGX_OK
        && bearer.len == conf->admin_secret.len
        && bearer.len > 0
        && CRYPTO_memcmp(bearer.data, conf->admin_secret.data, bearer.len) == 0;
}


/*
 * WHAT: Combine the two configured/passed auth factors into a final verdict.
 * WHY:  Isolates the AND/OR combination rule from the factor evaluation so the
 *       verdict logic is reviewable on its own; behavior byte-frozen.
 * HOW:  require_both ON -> every CONFIGURED factor must pass (an unconfigured
 *       factor is not required); OFF -> any single configured factor passing is
 *       enough (OR).
 */
static brix_admin_auth_result_t
admin_auth_combine(const ngx_http_brix_dashboard_loc_conf_t *conf,
    int has_allow, int cidr_ok, int has_secret, int secret_ok)
{
    if (conf->admin_require_both) {
        if (has_allow && !cidr_ok)    return BRIX_ADMIN_AUTH_DENIED;
        if (has_secret && !secret_ok) return BRIX_ADMIN_AUTH_DENIED;
        return BRIX_ADMIN_AUTH_OK;
    }
    return (cidr_ok || secret_ok)
           ? BRIX_ADMIN_AUTH_OK : BRIX_ADMIN_AUTH_DENIED;
}


brix_admin_auth_result_t
brix_admin_check_auth(ngx_http_request_t *r,
    const ngx_http_brix_dashboard_loc_conf_t *conf)
{
    int has_allow  = (conf->admin_allow != NULL && conf->admin_allow->nelts > 0);
    int has_secret = (conf->admin_secret.len > 0);
    int cidr_ok    = 0;
    int secret_ok  = 0;

    if (!has_allow && !has_secret) {
        return BRIX_ADMIN_AUTH_DENIED;   /* admin API not configured */
    }

    if (has_allow && admin_auth_cidr_ok(r, conf)) {
        cidr_ok = 1;
    }
    if (has_secret && admin_auth_secret_ok(r, conf)) {
        secret_ok = 1;
    }

    return admin_auth_combine(conf, has_allow, cidr_ok, has_secret, secret_ok);
}


/* Structured audit line — separate from the dashboard event ring buffer. */
void
admin_audit(ngx_http_request_t *r, const char *action, const char *target,
    const char *result)
{
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "brix: admin: %V %s target=%s client=%V result=%s",
        &r->method_name, action, target ? target : "-",
        &r->connection->addr_text, result);
}




/*
 * WHAT: Completion callback invoked by nginx once the admin request body is
 *       buffered. Reassembles the body, parses it as a JSON object, and invokes
 *       the per-route handler stashed in the request ctx.
 * WHY:  Body reading is async; this is the re-entry point after
 *       brix_admin_read_body returned NGX_DONE. It owns finalizing the request
 *       on every path (success or error) via ngx_http_finalize_request.
 * HOW:  Sum buffer sizes; if the body spilled to a temp file (not in memory) it
 *       exceeded client_body_buffer_size and is rejected as too large. Enforce
 *       ADMIN_MAX_BODY, then concatenate and json_loadb. Non-object JSON is
 *       rejected so handlers can assume json_object_get works.
 */
void
brix_admin_body_callback(ngx_http_request_t *r)
{
    brix_admin_body_ctx_t *bctx;
    ngx_chain_t             *cl;
    u_char                  *buf;
    size_t                   total = 0, off = 0;
    json_t                  *parsed;
    json_error_t             jerr;
    ngx_int_t                rc;

    bctx = ngx_http_get_module_ctx(r, ngx_http_brix_dashboard_module);

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        ngx_http_finalize_request(r,
            admin_send_error(r, NGX_HTTP_BAD_REQUEST, "empty_body"));
        return;
    }

    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            total += cl->buf->last - cl->buf->pos;
        } else {
            /* Body spilled to a temp file — reject (too large for admin JSON). */
            ngx_http_finalize_request(r,
                admin_send_error(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE,
                                 "body_too_large"));
            return;
        }
    }

    if (total == 0 || total > ADMIN_MAX_BODY) {
        ngx_http_finalize_request(r,
            admin_send_error(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE,
                             "body_too_large"));
        return;
    }

    buf = ngx_palloc(r->pool, total);
    if (buf == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        size_t n = cl->buf->last - cl->buf->pos;
        ngx_memcpy(buf + off, cl->buf->pos, n);
        off += n;
    }

    parsed = json_loadb((char *) buf, total, 0, &jerr);
    if (parsed == NULL || !json_is_object(parsed)) {
        if (parsed != NULL) { json_decref(parsed); }
        ngx_http_finalize_request(r,
            admin_send_error(r, NGX_HTTP_BAD_REQUEST, "invalid_json"));
        return;
    }

    rc = bctx->handler(r, parsed);
    json_decref(parsed);
    ngx_http_finalize_request(r, rc);
}


/*
 * Kick off async body reading for a body-bearing admin route. Stashes `handler`
 * in the request ctx so the shared body callback can dispatch to it once the
 * body is available. Returns NGX_DONE on the normal async path (the callback
 * will finalize), or an error status if nginx failed to start the read.
 */
ngx_int_t
brix_admin_read_body(ngx_http_request_t *r,
    brix_admin_body_handler_t handler)
{
    brix_admin_body_ctx_t *bctx;
    ngx_int_t                rc;

    bctx = ngx_palloc(r->pool, sizeof(*bctx));
    if (bctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    bctx->handler = handler;
    ngx_http_set_ctx(r, bctx, ngx_http_brix_dashboard_module);

    rc = ngx_http_read_client_request_body(r, brix_admin_body_callback);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;
}


/*
 * WHAT: True (1) if `c` is legal inside a backend URL authority/path, else 0.
 * WHY:  Extracting the per-character class out of admin_validate_url drops that
 *       function's branch count below the gate while leaving the accepted set
 *       byte-identical (alnum plus '.', '-', '_', ':', '/').
 * HOW:  Alnum base class OR the small set of allowed URL punctuation.
 */
static int
admin_url_char_ok(unsigned char c)
{
    return admin_char_is_alnum(c)
        || c == '.' || c == '-' || c == '_' || c == ':' || c == '/';
}


/*
 * WHAT: Match the required "http://" or "https://" scheme prefix; on success
 *       store the offset of the first host byte in *off and return 1, else 0.
 * WHY:  Isolating the scheme decision keeps admin_validate_url a flat sequence
 *       of named guards; the two-arm scheme test is the bulk of its branching.
 * HOW:  Longest-prefix first (https before http) so "https://" is not
 *       mis-parsed as "http://" + a leading 's'; offsets frozen at 8 / 7.
 */
static int
admin_url_scheme_off(const char *url, size_t *off)
{
    if (ngx_strncmp(url, "https://", 8) == 0) {
        *off = 8;
        return 1;
    }
    if (ngx_strncmp(url, "http://", 7) == 0) {
        *off = 7;
        return 1;
    }
    return 0;
}


/*
 * Whitelist-validate a backend URL: "http://" or "https://" followed by a
 * host[:port][/path] composed only of safe characters.  Reject — never
 * sanitise — before handing the string to ngx_parse_url() / the SHM pool.
 */
int
admin_validate_url(const char *url)
{
    size_t       i, n, off = 0;
    const char  *host;

    if (url == NULL) {
        return 0;
    }
    n = ngx_strlen(url);
    if (n < 9 || n >= 512) {     /* shortest is "http://h" + something */
        return 0;
    }
    if (!admin_url_scheme_off(url, &off)) {
        return 0;
    }
    host = url + off;
    if (*host == '\0' || *host == '/' || *host == ':') {
        return 0;                /* empty host */
    }
    for (i = off; i < n; i++) {
        if (!admin_url_char_ok((unsigned char) url[i])) {
            return 0;
        }
    }
    return 1;
}


int
admin_uri_eq(ngx_http_request_t *r, const char *s)
{
    size_t n = ngx_strlen(s);
    return r->uri.len == n && ngx_strncmp(r->uri.data, s, n) == 0;
}


/* True if the request URI ends with `action` (e.g. "/drain") — used to pick the
 * sub-action on a "/cluster/servers/{host}/{port}/<action>" path. */
int
admin_uri_has_action(ngx_http_request_t *r, const char *action)
{
    size_t alen = ngx_strlen(action);
    return r->uri.len > alen
        && ngx_strncmp(r->uri.data + r->uri.len - alen, action, alen) == 0;
}


/*
 * WHAT: True (1) if the request URI has ADMIN_PREFIX + `sub` as a strict prefix
 *       (i.e. a sub-resource path, not the exact collection), else 0.
 * WHY:  Both the cluster and proxy route groups gate their sub-resource block on
 *       the same len>prefix + ngx_strncmp idiom; naming it removes a duplicated
 *       sizeof/strncmp pair from the router and reads as one predicate.
 * HOW:  Compare against the compile-time length of ADMIN_PREFIX concatenated
 *       with `sub` via a caller-supplied precomputed length (plen), matching the
 *       original sizeof(literal)-1 bounds exactly.
 */
static int
admin_uri_under(ngx_http_request_t *r, const char *pfx, size_t plen)
{
    return r->uri.len > plen && ngx_strncmp(r->uri.data, pfx, plen) == 0;
}


/*
 * WHAT: Route the io_uring runtime kill-switch endpoint. Sets *matched=1 and
 *       returns the response status when the URI is this endpoint; leaves
 *       *matched=0 (return value unused) otherwise.
 * WHY:  Splitting each endpoint group out of brix_admin_dispatch keeps the
 *       router a flat sequence of match-or-fall-through steps under the gate.
 * HOW:  Exact-match the URI; when enabled, dispatch by method (POST reads body
 *       into admin_io_uring_set, GET serves admin_io_uring_get), else 404/405.
 *       Behavior byte-frozen.
 */
static ngx_int_t
admin_route_io_uring(ngx_http_request_t *r, int *matched)
{
    if (!admin_uri_eq(r, ADMIN_PREFIX "io_uring")) {
        *matched = 0;
        return NGX_OK;
    }
    *matched = 1;

    /* Phase 44: io_uring runtime kill switch (only when enabled) */
    if (!brix_uring_admin_enabled()) {
        return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
    }
    if (r->method == NGX_HTTP_POST) {
        return brix_admin_read_body(r, admin_io_uring_set);
    }
    if (r->method == NGX_HTTP_GET) {
        return admin_io_uring_get(r);
    }
    return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
}


/*
 * WHAT: Route the "/cluster/servers/{host}/{port}[/action]" sub-resource. Sets
 *       *matched per whether the URI is under that prefix.
 * WHY:  Isolates the per-server sub-action ladder (drain/undrain/delete/upsert)
 *       from the router so each stays independently reviewable.
 * HOW:  Prefix-match, then branch on the trailing action or HTTP method.
 *       Behavior byte-frozen.
 */
static ngx_int_t
admin_route_cluster_server(ngx_http_request_t *r, int *matched)
{
    if (!admin_uri_under(r, ADMIN_PREFIX "cluster/servers/",
                         sizeof(ADMIN_PREFIX "cluster/servers/") - 1))
    {
        *matched = 0;
        return NGX_OK;
    }
    *matched = 1;

    if (admin_uri_has_action(r, "/drain")) {
        if (r->method != NGX_HTTP_POST) {
            return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
        }
        return brix_admin_read_body(r, admin_cluster_drain);
    }
    if (admin_uri_has_action(r, "/undrain")) {
        if (r->method != NGX_HTTP_POST) {
            return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
        }
        return admin_cluster_undrain(r);
    }
    if (r->method == NGX_HTTP_DELETE) {
        return admin_cluster_delete(r);
    }
    /* PUT to a specific server path is an upsert — same body handler as
     * POST to the collection; brix_srv_register replaces if it exists. */
    if (r->method == NGX_HTTP_PUT) {
        return brix_admin_read_body(r, admin_cluster_register);  /* upsert */
    }
    return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
}


/*
 * WHAT: Route the cluster registry endpoints (collection + sub-resource). Sets
 *       *matched per whether a cluster route handled the request.
 * WHY:  Groups the two cluster URIs behind one match so the top-level router
 *       reads as one line per endpoint family.
 * HOW:  Try the exact collection URI first (POST registers, else 405), then
 *       delegate the "{host}/{port}" sub-resource. Behavior byte-frozen.
 */
static ngx_int_t
admin_route_cluster(ngx_http_request_t *r, int *matched)
{
    if (admin_uri_eq(r, ADMIN_PREFIX "cluster/servers")) {
        *matched = 1;
        if (r->method == NGX_HTTP_POST) {
            return brix_admin_read_body(r, admin_cluster_register);
        }
        return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
    }
    return admin_route_cluster_server(r, matched);
}


/*
 * WHAT: Route the dynamic proxy pool endpoints (collection + "{id}[/action]").
 *       Sets *matched per whether a proxy route handled the request.
 * WHY:  Groups the two proxy URIs behind one match, mirroring admin_route_cluster.
 * HOW:  Exact collection URI (POST adds, GET lists, else 405), then the id
 *       sub-resource parsed via admin_parse_proxy_uri. Behavior byte-frozen.
 */
static ngx_int_t
admin_route_proxy(ngx_http_request_t *r, int *matched)
{
    uint32_t id = 0;
    char     action[16];

    if (admin_uri_eq(r, ADMIN_PREFIX "proxy/backends")) {
        *matched = 1;
        if (r->method == NGX_HTTP_POST) {
            return brix_admin_read_body(r, admin_proxy_add);
        }
        if (r->method == NGX_HTTP_GET) {
            return admin_proxy_list(r);
        }
        return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
    }
    if (admin_uri_under(r, ADMIN_PREFIX "proxy/backends/",
                        sizeof(ADMIN_PREFIX "proxy/backends/") - 1))
    {
        *matched = 1;
        if (admin_parse_proxy_uri(r, &id, action, sizeof(action)) != NGX_OK) {
            return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "bad_uri");
        }
        return admin_proxy_one(r, action, id);
    }

    *matched = 0;
    return NGX_OK;
}


/*
 * WHAT: Type of an admin endpoint-group router: on a URI match it sets *matched
 *       and returns the response status; otherwise it clears *matched.
 * WHY:  Lets brix_admin_dispatch drive the endpoint groups as a static table
 *       (§8.6 table-driven dispatch) instead of a branch ladder.
 * HOW:  Uniform (request, matched) -> status signature shared by every group.
 */
typedef ngx_int_t (*admin_route_fn)(ngx_http_request_t *r, int *matched);


ngx_int_t
brix_admin_dispatch(ngx_http_request_t *r)
{
    static const admin_route_fn routes[] = {
        admin_route_io_uring,
        admin_route_cluster,
        admin_route_proxy,
    };
    ngx_http_brix_dashboard_loc_conf_t *conf;
    ngx_uint_t                          i;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_dashboard_module);

    if (brix_admin_check_auth(r, conf) != BRIX_ADMIN_AUTH_OK) {
        admin_audit(r, "auth", NULL, "forbidden");
        return admin_send_error(r, NGX_HTTP_FORBIDDEN, "forbidden");
    }

    for (i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        int       matched = 0;
        ngx_int_t rc = routes[i](r, &matched);
        if (matched) {
            return rc;
        }
    }

    return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
}
