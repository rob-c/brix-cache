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
        unsigned char c = (unsigned char) paths[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '/' || c == '.'
              || c == '-' || c == '_' || c == ':'))
        {
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

    if (has_allow && r->connection->sockaddr != NULL
        && ngx_cidr_match(r->connection->sockaddr, conf->admin_allow) == NGX_OK)
    {
        cidr_ok = 1;
    }

    /* Bearer check: length-gate before the constant-time compare so unequal
     * lengths short-circuit without a content-dependent comparison. */
    if (has_secret && r->headers_in.authorization != NULL) {
        ngx_str_t bearer;
        ngx_str_t hdr = r->headers_in.authorization->value;
        if (brix_http_extract_bearer(&hdr, &bearer) == NGX_OK
            && bearer.len == conf->admin_secret.len
            && bearer.len > 0
            && CRYPTO_memcmp(bearer.data, conf->admin_secret.data,
                             bearer.len) == 0)
        {
            secret_ok = 1;
        }
    }

    /* AND mode: a configured factor that fails is fatal; an unconfigured factor
     * is simply not required. */
    if (conf->admin_require_both) {
        if (has_allow && !cidr_ok)   return BRIX_ADMIN_AUTH_DENIED;
        if (has_secret && !secret_ok) return BRIX_ADMIN_AUTH_DENIED;
        return BRIX_ADMIN_AUTH_OK;
    }
    /* OR mode: any single configured factor passing grants access. */
    return (cidr_ok || secret_ok)
           ? BRIX_ADMIN_AUTH_OK : BRIX_ADMIN_AUTH_DENIED;
}


/* Structured audit line — separate from the dashboard event ring buffer. */
void
admin_audit(ngx_http_request_t *r, const char *action, const char *target,
    const char *result)
{
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "xrootd: admin: %V %s target=%s client=%V result=%s",
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
 * Whitelist-validate a backend URL: "http://" or "https://" followed by a
 * host[:port][/path] composed only of safe characters.  Reject — never
 * sanitise — before handing the string to ngx_parse_url() / the SHM pool.
 */
int
admin_validate_url(const char *url)
{
    size_t       i, n, off;
    const char  *host;

    if (url == NULL) {
        return 0;
    }
    n = ngx_strlen(url);
    if (n < 9 || n >= 512) {     /* shortest is "http://h" + something */
        return 0;
    }
    if (ngx_strncmp(url, "https://", 8) == 0) {
        off = 8;
    } else if (ngx_strncmp(url, "http://", 7) == 0) {
        off = 7;
    } else {
        return 0;
    }
    host = url + off;
    if (*host == '\0' || *host == '/' || *host == ':') {
        return 0;                /* empty host */
    }
    for (i = off; i < n; i++) {
        unsigned char c = (unsigned char) url[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '.' || c == '-'
              || c == '_' || c == ':' || c == '/'))
        {
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


ngx_int_t
brix_admin_dispatch(ngx_http_request_t *r)
{
    ngx_http_brix_dashboard_loc_conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_dashboard_module);

    if (brix_admin_check_auth(r, conf) != BRIX_ADMIN_AUTH_OK) {
        admin_audit(r, "auth", NULL, "forbidden");
        return admin_send_error(r, NGX_HTTP_FORBIDDEN, "forbidden");
    }

    /* Phase 44: io_uring runtime kill switch (only when enabled) */    if (admin_uri_eq(r, ADMIN_PREFIX "io_uring")) {
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

    /* cluster registry */    if (admin_uri_eq(r, ADMIN_PREFIX "cluster/servers")) {
        if (r->method == NGX_HTTP_POST) {
            return brix_admin_read_body(r, admin_cluster_register);
        }
        return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
    }
    if (r->uri.len > sizeof(ADMIN_PREFIX "cluster/servers/") - 1
        && ngx_strncmp(r->uri.data, ADMIN_PREFIX "cluster/servers/",
                       sizeof(ADMIN_PREFIX "cluster/servers/") - 1) == 0)
    {
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

    /* dynamic proxy pool */    if (admin_uri_eq(r, ADMIN_PREFIX "proxy/backends")) {
        if (r->method == NGX_HTTP_POST) {
            return brix_admin_read_body(r, admin_proxy_add);
        }
        if (r->method == NGX_HTTP_GET) {
            return admin_proxy_list(r);
        }
        return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
    }
    if (r->uri.len > sizeof(ADMIN_PREFIX "proxy/backends/") - 1
        && ngx_strncmp(r->uri.data, ADMIN_PREFIX "proxy/backends/",
                       sizeof(ADMIN_PREFIX "proxy/backends/") - 1) == 0)
    {
        uint32_t id = 0;
        char     action[16];
        if (admin_parse_proxy_uri(r, &id, action, sizeof(action)) != NGX_OK) {
            return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "bad_uri");
        }
        return admin_proxy_one(r, action, id);
    }

    return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
}
