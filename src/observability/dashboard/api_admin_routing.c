/*
 * api_admin_routing.c - admin API URI router + per-IP rate gate + dispatch.
 * Phase-38 split of api_admin.c; behavior-identical.
 */
#include "dashboard_api_admin_internal.h"


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


/*
 * ---- Per-IP admin API rate gate (phase-23 "Rate limiting" item) ----
 *
 * WHAT: Charge this request against the source IP's read or write leaky bucket.
 *       Sets *throttled and returns the finalized 429 response status when the
 *       bucket overflows; leaves *throttled 0 and returns NGX_OK to proceed.
 *
 * WHY:  An authorized-but-runaway client (looping script, stuck orchestrator)
 *       must not be able to monopolize the admin surface or churn the registry
 *       SHM.  Reads and writes get separate generous buckets so extensive
 *       legitimate querying under load never starves — or is starved by — the
 *       mutating traffic the phase-23 design caps.  Runs AFTER auth, so an
 *       unauthenticated flood (already answered 403) can neither fill the zone
 *       nor lock out the real operator.
 *
 * HOW:  1. Pass through when the throttle is off or was never finalized
 *          (write.zone == NULL) — brix_rl_check itself fails open on SHM
 *          trouble, so the gate can only ever deny by policy.
 *       2. Classify the method: GET/HEAD -> read rule, else write rule, with
 *          distinct key prefixes so the two buckets never share a node.
 *       3. brix_rl_check the "adm[rw]:<ip>" key; NGX_OK proceeds.
 *       4. On NGX_AGAIN set Retry-After (HTTP throttle convention), audit the
 *          event, and send the 429 JSON error.
 */
static ngx_int_t
admin_rate_gate(ngx_http_request_t *r,
    ngx_http_brix_dashboard_loc_conf_t *conf, int *throttled)
{
    brix_rl_rule_t *rule;
    int               is_read;
    char              key[BRIX_RL_KEY_LEN];
    uint32_t          wait_sec = 0;

    *throttled = 0;
    if (conf == NULL || !conf->admin_rl_enable
        || conf->admin_rl_write.zone == NULL)
    {
        return NGX_OK;
    }

    is_read = (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) != 0;
    rule = is_read ? &conf->admin_rl_read : &conf->admin_rl_write;

    ngx_snprintf((u_char *) key, sizeof(key), "%s:%V%Z",
                 is_read ? "admr" : "admw", &r->connection->addr_text);
    key[sizeof(key) - 1] = '\0';

    if (brix_rl_check(rule, key, &wait_sec) != NGX_AGAIN) {
        return NGX_OK;
    }

    *throttled = 1;
    if (wait_sec > 0) {
        char retry[NGX_INT_T_LEN + 1];
        ngx_snprintf((u_char *) retry, sizeof(retry), "%uD%Z", wait_sec);
        (void) brix_http_set_header(r, "Retry-After", retry, NULL);
    }
    admin_audit(r, "ratelimit", is_read ? "read" : "write", "throttled");
    return admin_send_error(r, NGX_HTTP_TOO_MANY_REQUESTS, "rate_limited");
}


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

    /* Per-IP throttle sits between auth and routing: it therefore runs before
     * any body read or SHM mutation, and only authorized traffic can consume
     * bucket capacity. */
    {
        int       throttled = 0;
        ngx_int_t rc = admin_rate_gate(r, conf, &throttled);
        if (throttled) {
            return rc;
        }
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
