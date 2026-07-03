/*
 * api_admin_proxy.c - extracted concern
 * Phase-38 split of api_admin.c; behavior-identical.
 */
#include "dashboard_api_admin_internal.h"


/* Parse the {id}[/action] tail after "/admin/proxy/backends/". */
ngx_int_t
admin_parse_proxy_uri(ngx_http_request_t *r, uint32_t *id_out,
    char *action_out, size_t action_size)
{
    static const char  pfx[] = ADMIN_PREFIX "proxy/backends/";
    size_t             pfxlen = sizeof(pfx) - 1;
    char               tail[64];
    size_t             taillen;
    char              *slash;
    ngx_int_t          id;

    if (r->uri.len <= pfxlen || ngx_strncmp(r->uri.data, pfx, pfxlen) != 0) {
        return NGX_ERROR;
    }
    taillen = r->uri.len - pfxlen;
    if (taillen == 0 || taillen >= sizeof(tail)) {
        return NGX_ERROR;
    }
    ngx_memcpy(tail, r->uri.data + pfxlen, taillen);
    tail[taillen] = '\0';

    /* Tail is "{id}" or "{id}/{action}". If a '/' is present, the part after it
     * is the action (truncated at any further '/'), and the id is the part
     * before — NUL the '/' so ngx_atoi below sees only the id. */
    action_out[0] = '\0';
    slash = ngx_strchr(tail, '/');
    if (slash != NULL) {
        char *act = slash + 1;
        char *p2  = ngx_strchr(act, '/');
        if (p2 != NULL) { *p2 = '\0'; }   /* drop any trailing slash */
        *slash = '\0';
        if (ngx_strlen(act) < action_size) {
            ngx_cpystrn((u_char *) action_out, (u_char *) act, action_size);
        }
    }

    id = ngx_atoi((u_char *) tail, ngx_strlen(tail));
    if (id == NGX_ERROR || id <= 0) {
        return NGX_ERROR;
    }
    *id_out = (uint32_t) id;
    return NGX_OK;
}


/* Serialise one proxy-backend snapshot entry to JSON (mechanical field mapping;
 * the only logic is the numeric state -> name translation). */
json_t *
admin_proxy_backend_json(const brix_proxy_be_snapshot_t *e)
{
    json_t     *o = json_object();
    const char *state;

    if (o == NULL) {
        return NULL;
    }
    switch (e->state) {
    case BRIX_PROXY_BE_DRAINING: state = "draining"; break;
    case BRIX_PROXY_BE_DEAD:     state = "dead";     break;
    default:                       state = "active";   break;
    }
    json_object_set_new(o, "id",        json_integer(e->id));
    json_object_set_new(o, "host",      json_string(e->host));
    json_object_set_new(o, "port",      json_integer(e->port));
    json_object_set_new(o, "ssl",       e->ssl ? json_true() : json_false());
    json_object_set_new(o, "weight",    json_integer(e->weight));
    json_object_set_new(o, "state",     json_string(state));
    json_object_set_new(o, "in_flight", json_integer(e->in_flight));
    return o;
}


/*
 * admin_url_host_allowed — W6/E1 backend-target allowlist.
 *
 * A compromised admin credential could otherwise point a dynamic proxy backend
 * at an arbitrary host (data exfiltration / SSRF pivot).  When
 * brix_admin_proxy_allow is configured, the host parsed out of the backend
 * URL must match one of the listed hostnames exactly (case-insensitive).
 * When the directive is absent the function returns 1 (back-compat).
 */
int
admin_url_host_allowed(ngx_http_brix_dashboard_loc_conf_t *conf,
    const char *url)
{
    const char *host, *p;
    size_t      host_len, off, i;
    ngx_str_t  *allow;

    if (conf->admin_proxy_allow == NULL) {
        return 1;
    }

    /* admin_validate_url has already confirmed an http(s):// prefix + safe
     * chars; extract the host (up to ':' or '/'). */
    off = (ngx_strncmp(url, "https://", 8) == 0) ? 8 : 7;
    host = url + off;
    p = host;
    while (*p != '\0' && *p != ':' && *p != '/') {
        p++;
    }
    host_len = (size_t) (p - host);

    allow = conf->admin_proxy_allow->elts;
    for (i = 0; i < conf->admin_proxy_allow->nelts; i++) {
        if (allow[i].len == host_len
            && ngx_strncasecmp((u_char *) host, allow[i].data, host_len) == 0)
        {
            return 1;
        }
    }
    return 0;
}


/*
 * POST body handler: add a dynamic proxy backend from a JSON {url, weight}.
 * Security gauntlet before mutating the SHM pool: (1) url present, (2) syntactic
 * whitelist (admin_validate_url), (3) SSRF allowlist (admin_url_host_allowed).
 * weight is clamped to 1..1000. On success returns 201 with the assigned id.
 */
ngx_int_t
admin_proxy_add(ngx_http_request_t *r, json_t *body)
{
    ngx_http_brix_dashboard_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_dashboard_module);
    const char *url    = json_string_value(json_object_get(body, "url"));
    json_int_t  weight = json_integer_value(json_object_get(body, "weight"));
    uint32_t    id     = 0;
    ngx_int_t   rc;
    char        target[64];

    if (url == NULL) {
        admin_audit(r, "proxy/add", url, "bad_request");
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "missing_field");
    }
    if (!admin_validate_url(url)) {
        admin_audit(r, "proxy/add", url, "invalid_field");
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "invalid_field");
    }
    if (!admin_url_host_allowed(conf, url)) {
        admin_audit(r, "proxy/add", url, "host_not_allowed");
        return admin_send_error(r, NGX_HTTP_FORBIDDEN, "host_not_allowed");
    }
    if (weight <= 0)    weight = 1;
    if (weight > 1000)  weight = 1000;

    rc = brix_proxy_pool_add(url, (ngx_uint_t) weight, r->pool,
                               r->connection->log, &id);
    if (rc == NGX_DECLINED) {
        admin_audit(r, "proxy/add", url, "not_enabled");
        return admin_send_error(r, NGX_HTTP_NOT_FOUND, "proxy_pool_disabled");
    }
    if (rc != NGX_OK) {
        admin_audit(r, "proxy/add", url, "add_failed");
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "add_failed");
    }

    (void) ngx_snprintf((u_char *) target, sizeof(target) - 1, "id=%uD%Z", id);
    brix_dashboard_event_add(BRIX_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: proxy backend added", url);
    admin_audit(r, "proxy/add", url, "added");
    {
        json_t *root = json_object();
        if (root == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        dashboard_json_set_schema(root);
        json_object_set_new(root, "result", json_string("added"));
        json_object_set_new(root, "id", json_integer(id));
        return dashboard_json_send(r, NGX_HTTP_CREATED, root);
    }
}


/* GET /admin/proxy/backends: snapshot and list all dynamic proxy backends. */
ngx_int_t
admin_proxy_list(ngx_http_request_t *r)
{
    brix_proxy_be_snapshot_t  snap[BRIX_PROXY_POOL_SLOTS];
    ngx_uint_t                  i, count;
    json_t                     *root, *arr;

    count = brix_proxy_pool_snapshot(snap, BRIX_PROXY_POOL_SLOTS);

    root = json_object();
    arr  = json_array();
    if (root == NULL || arr == NULL) {
        if (root) json_decref(root);
        if (arr)  json_decref(arr);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    for (i = 0; i < count; i++) {
        json_t *o = admin_proxy_backend_json(&snap[i]);
        if (o != NULL) {
            json_array_append_new(arr, o);
        }
    }
    dashboard_json_set_schema(root);
    json_object_set_new(root, "backends", arr);
    return dashboard_json_send(r, NGX_HTTP_OK, root);
}


/*
 * Route a single-backend request "/admin/proxy/backends/{id}[/action]" to the
 * right pool mutation, enforcing the method per (action x verb) matrix:
 *   /drain, /undrain -> POST only
 *   no action        -> DELETE removes, GET reads in-flight count
 * Anything else is 405/404. `id` and `action` are pre-parsed by the caller.
 */
ngx_int_t
admin_proxy_one(ngx_http_request_t *r, const char *action, uint32_t id)
{
    char target[32];
    (void) ngx_snprintf((u_char *) target, sizeof(target) - 1, "id=%uD%Z", id);

    if (ngx_strcmp(action, "drain") == 0) {
        if (r->method != NGX_HTTP_POST) {
            return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
        }
        if (!brix_proxy_pool_drain(id)) {
            admin_audit(r, "proxy/drain", target, "not_found");
            return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
        }
        admin_audit(r, "proxy/drain", target, "drained");
        return admin_send_ok(r, "drained");
    }
    if (ngx_strcmp(action, "undrain") == 0) {
        if (r->method != NGX_HTTP_POST) {
            return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
        }
        if (!brix_proxy_pool_undrain(id)) {
            admin_audit(r, "proxy/undrain", target, "not_found");
            return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
        }
        admin_audit(r, "proxy/undrain", target, "undrained");
        return admin_send_ok(r, "undrained");
    }
    if (action[0] == '\0') {
        if (r->method == NGX_HTTP_DELETE) {
            if (!brix_proxy_pool_remove(id)) {
                admin_audit(r, "proxy/delete", target, "not_found");
                return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
            }
            admin_audit(r, "proxy/delete", target, "removed");
            return admin_send_ok(r, "removed");
        }
        if (r->method == NGX_HTTP_GET) {
            long inflight = brix_proxy_pool_in_flight(id);
            json_t *root;
            if (inflight < 0) {
                return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
            }
            root = json_object();
            if (root == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            dashboard_json_set_schema(root);
            json_object_set_new(root, "id", json_integer(id));
            json_object_set_new(root, "in_flight", json_integer(inflight));
            return dashboard_json_send(r, NGX_HTTP_OK, root);
        }
        return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
    }
    return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
}


/* Directive setter for `brix_admin_proxy_allow <host>...`: the backend-target
 * allowlist consulted by admin_url_host_allowed (SSRF guard). Stores raw host
 * strings (no parsing); matching is case-insensitive at request time. */
char *
brix_admin_set_proxy_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t  *value = cf->args->elts;
    ngx_uint_t  i;

    (void) cmd;

    if (lcf->admin_proxy_allow == NULL) {
        lcf->admin_proxy_allow = ngx_array_create(cf->pool,
                                                  cf->args->nelts - 1,
                                                  sizeof(ngx_str_t));
        if (lcf->admin_proxy_allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *h = ngx_array_push(lcf->admin_proxy_allow);
        if (h == NULL) {
            return NGX_CONF_ERROR;
        }
        *h = value[i];
    }
    return NGX_CONF_OK;
}
