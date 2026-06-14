/*
 * api_admin.c — Phase 23 REST admin write API (see api_admin.h).
 */
#include "dashboard.h"
#include "api_admin.h"
#include "../manager/registry.h"
#include "../webdav/proxy_pool.h"
#include "../compat/http_headers.h"

#include <jansson.h>
#include <openssl/crypto.h>   /* CRYPTO_memcmp */

#define ADMIN_PREFIX      "/xrootd/api/v1/admin/"
#define ADMIN_MAX_BODY    65536
#define ADMIN_SECRET_MAX  4096
#define ADMIN_SECRET_MIN  16     /* W6: reject trivially short admin secrets */


/* ------------------------------------------------------------------ */
/* JSON response helpers                                               */
/* ------------------------------------------------------------------ */

/* Serialise `root` (ownership taken — decref'd here) as a no-store JSON
 * response. Two-pass json_dumpb sizes the buffer to the payload. Mirrors
 * dashboard_send_json in api.c but is kept separate so the admin API has no
 * dependency on the read-only dashboard handler. */
static ngx_int_t
admin_send_json(ngx_http_request_t *r, ngx_int_t status, json_t *root)
{
    ngx_buf_t       *b;
    ngx_chain_t      out;
    ngx_table_elt_t *cc;
    ngx_int_t        rc;
    size_t           needed;
    u_char          *buf;

    if (root == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    needed = json_dumpb(root, NULL, 0, JSON_COMPACT);
    if (needed == 0) {
        json_decref(root);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    buf = ngx_palloc(r->pool, needed);
    if (buf == NULL) {
        json_decref(root);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    json_dumpb(root, (char *) buf, needed, JSON_COMPACT);
    json_decref(root);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = b->start = buf;
    b->last = b->end  = buf + needed;
    b->memory   = 1;
    b->last_buf  = 1;

    r->headers_out.status           = status;
    r->headers_out.content_length_n = (off_t) needed;
    r->headers_out.content_type     = (ngx_str_t) ngx_string("application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc != NULL) {
        cc->hash = 1;
        ngx_str_set(&cc->key,   "Cache-Control");
        ngx_str_set(&cc->value, "no-store");
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
admin_send_ok(ngx_http_request_t *r, const char *result)
{
    json_t *root = json_object();
    if (root == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    json_object_set_new(root, "schema", json_string("xrootd-dashboard.v1"));
    json_object_set_new(root, "result", json_string(result));
    return admin_send_json(r, NGX_HTTP_OK, root);
}

static ngx_int_t
admin_send_error(ngx_http_request_t *r, ngx_int_t status, const char *code)
{
    json_t *root = json_object();
    if (root == NULL) {
        return status;
    }
    json_object_set_new(root, "schema", json_string("xrootd-dashboard.v1"));
    json_object_set_new(root, "error", json_string(code));
    return admin_send_json(r, status, root);
}


/* ------------------------------------------------------------------ */
/* Input validation (whitelist — reject, never sanitise)               */
/* ------------------------------------------------------------------ */

/* Whitelist-validate a hostname (1=ok, 0=reject). Allows letters, digits, '.',
 * '-', and ':' (for IPv6 literals); bounded to RFC-1035's 253 chars. Reject,
 * never sanitise — the value flows into the cluster registry and downstream
 * connection logic. */
static int
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
 * 0=reject). Bounded by XROOTD_SRV_MAX_PATHS, the registry's storage cap. */
static int
admin_validate_paths(const char *paths)
{
    size_t i, n;

    if (paths == NULL) {
        return 0;
    }
    n = ngx_strlen(paths);
    if (n == 0 || n >= XROOTD_SRV_MAX_PATHS) {
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


/* ------------------------------------------------------------------ */
/* Admin authentication                                                */
/* ------------------------------------------------------------------ */

typedef enum {
    XROOTD_ADMIN_AUTH_OK = 0,
    XROOTD_ADMIN_AUTH_DENIED,
} xrootd_admin_auth_result_t;

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
static xrootd_admin_auth_result_t
xrootd_admin_check_auth(ngx_http_request_t *r,
    const ngx_http_xrootd_dashboard_loc_conf_t *conf)
{
    int has_allow  = (conf->admin_allow != NULL && conf->admin_allow->nelts > 0);
    int has_secret = (conf->admin_secret.len > 0);
    int cidr_ok    = 0;
    int secret_ok  = 0;

    if (!has_allow && !has_secret) {
        return XROOTD_ADMIN_AUTH_DENIED;   /* admin API not configured */
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
        if (xrootd_http_extract_bearer(&hdr, &bearer) == NGX_OK
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
        if (has_allow && !cidr_ok)   return XROOTD_ADMIN_AUTH_DENIED;
        if (has_secret && !secret_ok) return XROOTD_ADMIN_AUTH_DENIED;
        return XROOTD_ADMIN_AUTH_OK;
    }
    /* OR mode: any single configured factor passing grants access. */
    return (cidr_ok || secret_ok)
           ? XROOTD_ADMIN_AUTH_OK : XROOTD_ADMIN_AUTH_DENIED;
}

/* Structured audit line — separate from the dashboard event ring buffer. */
static void
admin_audit(ngx_http_request_t *r, const char *action, const char *target,
    const char *result)
{
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "xrootd: admin: %V %s target=%s client=%V result=%s",
        &r->method_name, action, target ? target : "-",
        &r->connection->addr_text, result);
}


/* ------------------------------------------------------------------ */
/* Async JSON request-body reader                                      */
/* ------------------------------------------------------------------ */

typedef ngx_int_t (*xrootd_admin_body_handler_t)(ngx_http_request_t *r,
    json_t *body);

typedef struct {
    xrootd_admin_body_handler_t  handler;
} xrootd_admin_body_ctx_t;

/*
 * WHAT: Completion callback invoked by nginx once the admin request body is
 *       buffered. Reassembles the body, parses it as a JSON object, and invokes
 *       the per-route handler stashed in the request ctx.
 * WHY:  Body reading is async; this is the re-entry point after
 *       xrootd_admin_read_body returned NGX_DONE. It owns finalizing the request
 *       on every path (success or error) via ngx_http_finalize_request.
 * HOW:  Sum buffer sizes; if the body spilled to a temp file (not in memory) it
 *       exceeded client_body_buffer_size and is rejected as too large. Enforce
 *       ADMIN_MAX_BODY, then concatenate and json_loadb. Non-object JSON is
 *       rejected so handlers can assume json_object_get works.
 */
static void
xrootd_admin_body_callback(ngx_http_request_t *r)
{
    xrootd_admin_body_ctx_t *bctx;
    ngx_chain_t             *cl;
    u_char                  *buf;
    size_t                   total = 0, off = 0;
    json_t                  *parsed;
    json_error_t             jerr;
    ngx_int_t                rc;

    bctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_dashboard_module);

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
static ngx_int_t
xrootd_admin_read_body(ngx_http_request_t *r,
    xrootd_admin_body_handler_t handler)
{
    xrootd_admin_body_ctx_t *bctx;
    ngx_int_t                rc;

    bctx = ngx_palloc(r->pool, sizeof(*bctx));
    if (bctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    bctx->handler = handler;
    ngx_http_set_ctx(r, bctx, ngx_http_xrootd_dashboard_module);

    rc = ngx_http_read_client_request_body(r, xrootd_admin_body_callback);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;
}


/* ------------------------------------------------------------------ */
/* URI parsing for /cluster/servers/{host}/{port}[/action]             */
/* ------------------------------------------------------------------ */

/*
 * Parse the tail after "/xrootd/api/v1/admin/cluster/servers/" into host,
 * port, and an optional trailing action ("drain"/"undrain"/"").  Returns
 * NGX_OK on success.
 */
static ngx_int_t
admin_parse_server_uri(ngx_http_request_t *r, char *host_out, size_t host_size,
    uint16_t *port_out, char *action_out, size_t action_size)
{
    static const char  pfx[] = "/xrootd/api/v1/admin/cluster/servers/";
    size_t             pfxlen = sizeof(pfx) - 1;
    char               tail[512];
    size_t             taillen;
    char              *seg[3];
    ngx_uint_t         nseg = 0;
    char              *p;
    ngx_int_t          port;

    if (r->uri.len <= pfxlen
        || ngx_strncmp(r->uri.data, pfx, pfxlen) != 0)
    {
        return NGX_ERROR;
    }

    /* Copy the tail into a local NUL-terminated buffer (request URIs are not
     * guaranteed NUL-terminated and must not be mutated in place). */
    taillen = r->uri.len - pfxlen;
    if (taillen == 0 || taillen >= sizeof(tail)) {
        return NGX_ERROR;
    }
    ngx_memcpy(tail, r->uri.data + pfxlen, taillen);
    tail[taillen] = '\0';

    /* In-place split of the mutable tail copy into up to 3 segments by '/':
     * seg[0]=host, seg[1]=port, seg[2]=optional action. Each '/' is replaced
     * with NUL and the next char starts the following segment. */
    p = tail;
    seg[nseg++] = p;
    while (*p != '\0' && nseg < 3) {
        if (*p == '/') {
            *p = '\0';
            seg[nseg++] = p + 1;
        }
        p++;
    }
    /* The 3rd segment captured everything remaining (the loop stopped splitting
     * at nseg==3), so trim it at any further '/' — e.g. a trailing slash. */
    if (nseg == 3) {
        for (p = seg[2]; *p != '\0'; p++) {
            if (*p == '/') { *p = '\0'; break; }
        }
    }

    if (nseg < 2 || seg[0][0] == '\0' || ngx_strlen(seg[0]) >= host_size) {
        return NGX_ERROR;
    }
    ngx_cpystrn((u_char *) host_out, (u_char *) seg[0], host_size);

    port = ngx_atoi((u_char *) seg[1], ngx_strlen(seg[1]));
    if (port == NGX_ERROR || port <= 0 || port > 65535) {
        return NGX_ERROR;
    }
    *port_out = (uint16_t) port;

    action_out[0] = '\0';
    if (nseg == 3 && seg[2][0] != '\0' && ngx_strlen(seg[2]) < action_size) {
        ngx_cpystrn((u_char *) action_out, (u_char *) seg[2], action_size);
    }
    return NGX_OK;
}


/* ------------------------------------------------------------------ */
/* Cluster registry write handlers                                     */
/* ------------------------------------------------------------------ */

/* POST/PUT body handler: upsert a server into the cluster registry. Validates
 * required fields and host/paths character whitelists, clamps util_pct to 0..100
 * and free_mb to >=0, then registers and audits. */
static ngx_int_t
admin_cluster_register(ngx_http_request_t *r, json_t *body)
{
    const char *host  = json_string_value(json_object_get(body, "host"));
    const char *paths = json_string_value(json_object_get(body, "paths"));
    json_int_t  port     = json_integer_value(json_object_get(body, "port"));
    json_int_t  free_mb  = json_integer_value(json_object_get(body, "free_mb"));
    json_int_t  util_pct = json_integer_value(json_object_get(body, "util_pct"));

    if (host == NULL || paths == NULL || port <= 0 || port > 65535) {
        admin_audit(r, "cluster/register", host, "bad_request");
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "missing_field");
    }
    if (!admin_validate_hostname(host) || !admin_validate_paths(paths)) {
        admin_audit(r, "cluster/register", host, "invalid_field");
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "invalid_field");
    }
    if (util_pct < 0)  util_pct = 0;
    if (util_pct > 100) util_pct = 100;
    if (free_mb < 0)   free_mb = 0;

    xrootd_srv_register(host, (uint16_t) port, paths,
                        (uint32_t) free_mb, (uint32_t) util_pct);
    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: server registered", host);
    admin_audit(r, "cluster/register", host, "registered");
    return admin_send_ok(r, "registered");
}

/* POST .../{host}/{port}/drain: blacklist a server for `duration_s` seconds
 * (default 300) so the router stops directing new traffic to it. */
static ngx_int_t
admin_cluster_drain(ngx_http_request_t *r, json_t *body)
{
    char       host[256];
    char       action[16];
    uint16_t   port;
    json_int_t duration_s;

    if (admin_parse_server_uri(r, host, sizeof(host), &port,
                               action, sizeof(action)) != NGX_OK)
    {
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "bad_uri");
    }
    duration_s = json_integer_value(json_object_get(body, "duration_s"));
    if (duration_s <= 0) {
        duration_s = 300;
    }
    xrootd_srv_blacklist(host, port, (ngx_msec_t) duration_s * 1000);
    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: server drained", host);
    admin_audit(r, "cluster/drain", host, "drained");
    return admin_send_ok(r, "drained");
}

/* DELETE .../{host}/{port}: remove a server from the cluster registry. */
static ngx_int_t
admin_cluster_delete(ngx_http_request_t *r)
{
    char     host[256];
    char     action[16];
    uint16_t port;

    if (admin_parse_server_uri(r, host, sizeof(host), &port,
                               action, sizeof(action)) != NGX_OK)
    {
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "bad_uri");
    }
    xrootd_srv_unregister(host, port);
    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: server unregistered", host);
    admin_audit(r, "cluster/delete", host, "removed");
    return admin_send_ok(r, "removed");
}

/* POST .../{host}/{port}/undrain: lift a drain/blacklist. Returns 404 if the
 * server is not currently drained (xrootd_srv_undrain reports false). */
static ngx_int_t
admin_cluster_undrain(ngx_http_request_t *r)
{
    char     host[256];
    char     action[16];
    uint16_t port;

    if (admin_parse_server_uri(r, host, sizeof(host), &port,
                               action, sizeof(action)) != NGX_OK)
    {
        return admin_send_error(r, NGX_HTTP_BAD_REQUEST, "bad_uri");
    }
    if (!xrootd_srv_undrain(host, port)) {
        admin_audit(r, "cluster/undrain", host, "not_found");
        return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
    }
    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: server undrained", host);
    admin_audit(r, "cluster/undrain", host, "undrained");
    return admin_send_ok(r, "undrained");
}


/* ------------------------------------------------------------------ */
/* Proxy pool write handlers (/admin/proxy/backends...)                */
/* ------------------------------------------------------------------ */

/*
 * Whitelist-validate a backend URL: "http://" or "https://" followed by a
 * host[:port][/path] composed only of safe characters.  Reject — never
 * sanitise — before handing the string to ngx_parse_url() / the SHM pool.
 */
static int
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

/* Parse the {id}[/action] tail after "/admin/proxy/backends/". */
static ngx_int_t
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
static json_t *
admin_proxy_backend_json(const xrootd_proxy_be_snapshot_t *e)
{
    json_t     *o = json_object();
    const char *state;

    if (o == NULL) {
        return NULL;
    }
    switch (e->state) {
    case XROOTD_PROXY_BE_DRAINING: state = "draining"; break;
    case XROOTD_PROXY_BE_DEAD:     state = "dead";     break;
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
 * xrootd_admin_proxy_allow is configured, the host parsed out of the backend
 * URL must match one of the listed hostnames exactly (case-insensitive).
 * When the directive is absent the function returns 1 (back-compat).
 */
static int
admin_url_host_allowed(ngx_http_xrootd_dashboard_loc_conf_t *conf,
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
static ngx_int_t
admin_proxy_add(ngx_http_request_t *r, json_t *body)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);
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

    rc = xrootd_proxy_pool_add(url, (ngx_uint_t) weight, r->pool,
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
    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: proxy backend added", url);
    admin_audit(r, "proxy/add", url, "added");
    {
        json_t *root = json_object();
        if (root == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        json_object_set_new(root, "schema", json_string("xrootd-dashboard.v1"));
        json_object_set_new(root, "result", json_string("added"));
        json_object_set_new(root, "id", json_integer(id));
        return admin_send_json(r, NGX_HTTP_CREATED, root);
    }
}

/* GET /admin/proxy/backends: snapshot and list all dynamic proxy backends. */
static ngx_int_t
admin_proxy_list(ngx_http_request_t *r)
{
    xrootd_proxy_be_snapshot_t  snap[XROOTD_PROXY_POOL_SLOTS];
    ngx_uint_t                  i, count;
    json_t                     *root, *arr;

    count = xrootd_proxy_pool_snapshot(snap, XROOTD_PROXY_POOL_SLOTS);

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
    json_object_set_new(root, "schema", json_string("xrootd-dashboard.v1"));
    json_object_set_new(root, "backends", arr);
    return admin_send_json(r, NGX_HTTP_OK, root);
}

/*
 * Route a single-backend request "/admin/proxy/backends/{id}[/action]" to the
 * right pool mutation, enforcing the method per (action x verb) matrix:
 *   /drain, /undrain -> POST only
 *   no action        -> DELETE removes, GET reads in-flight count
 * Anything else is 405/404. `id` and `action` are pre-parsed by the caller.
 */
static ngx_int_t
admin_proxy_one(ngx_http_request_t *r, const char *action, uint32_t id)
{
    char target[32];
    (void) ngx_snprintf((u_char *) target, sizeof(target) - 1, "id=%uD%Z", id);

    if (ngx_strcmp(action, "drain") == 0) {
        if (r->method != NGX_HTTP_POST) {
            return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
        }
        if (!xrootd_proxy_pool_drain(id)) {
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
        if (!xrootd_proxy_pool_undrain(id)) {
            admin_audit(r, "proxy/undrain", target, "not_found");
            return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
        }
        admin_audit(r, "proxy/undrain", target, "undrained");
        return admin_send_ok(r, "undrained");
    }
    if (action[0] == '\0') {
        if (r->method == NGX_HTTP_DELETE) {
            if (!xrootd_proxy_pool_remove(id)) {
                admin_audit(r, "proxy/delete", target, "not_found");
                return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
            }
            admin_audit(r, "proxy/delete", target, "removed");
            return admin_send_ok(r, "removed");
        }
        if (r->method == NGX_HTTP_GET) {
            long inflight = xrootd_proxy_pool_in_flight(id);
            json_t *root;
            if (inflight < 0) {
                return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
            }
            root = json_object();
            if (root == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            json_object_set_new(root, "schema",
                                json_string("xrootd-dashboard.v1"));
            json_object_set_new(root, "id", json_integer(id));
            json_object_set_new(root, "in_flight", json_integer(inflight));
            return admin_send_json(r, NGX_HTTP_OK, root);
        }
        return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
    }
    return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
}


/* ------------------------------------------------------------------ */
/* Dispatch                                                            */
/* ------------------------------------------------------------------ */

static int
admin_uri_eq(ngx_http_request_t *r, const char *s)
{
    size_t n = ngx_strlen(s);
    return r->uri.len == n && ngx_strncmp(r->uri.data, s, n) == 0;
}

/* True if the request URI ends with `action` (e.g. "/drain") — used to pick the
 * sub-action on a "/cluster/servers/{host}/{port}/<action>" path. */
static int
admin_uri_has_action(ngx_http_request_t *r, const char *action)
{
    size_t alen = ngx_strlen(action);
    return r->uri.len > alen
        && ngx_strncmp(r->uri.data + r->uri.len - alen, action, alen) == 0;
}

/*
 * WHAT: Top-level router for the admin write API ("/xrootd/api/v1/admin/...").
 * WHY:  Authentication is enforced HERE, once, before any route is considered —
 *       every mutating handler below assumes the caller is already authorized.
 * HOW:  Auth first (403 + audit on failure), then match the resource (cluster
 *       registry vs dynamic proxy pool) and dispatch by HTTP method. Body-bearing
 *       routes go through xrootd_admin_read_body (async); the rest run inline.
 *       Unknown resource -> 404, wrong method on a known resource -> 405.
 */
ngx_int_t
xrootd_admin_dispatch(ngx_http_request_t *r)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);

    if (xrootd_admin_check_auth(r, conf) != XROOTD_ADMIN_AUTH_OK) {
        admin_audit(r, "auth", NULL, "forbidden");
        return admin_send_error(r, NGX_HTTP_FORBIDDEN, "forbidden");
    }

    /* ---- cluster registry ---- */
    if (admin_uri_eq(r, ADMIN_PREFIX "cluster/servers")) {
        if (r->method == NGX_HTTP_POST) {
            return xrootd_admin_read_body(r, admin_cluster_register);
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
            return xrootd_admin_read_body(r, admin_cluster_drain);
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
         * POST to the collection; xrootd_srv_register replaces if it exists. */
        if (r->method == NGX_HTTP_PUT) {
            return xrootd_admin_read_body(r, admin_cluster_register);  /* upsert */
        }
        return admin_send_error(r, NGX_HTTP_NOT_ALLOWED, "method_not_allowed");
    }

    /* ---- dynamic proxy pool ---- */
    if (admin_uri_eq(r, ADMIN_PREFIX "proxy/backends")) {
        if (r->method == NGX_HTTP_POST) {
            return xrootd_admin_read_body(r, admin_proxy_add);
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


/* ------------------------------------------------------------------ */
/* Directive setters                                                   */
/* ------------------------------------------------------------------ */

/* Directive setter for `xrootd_admin_allow <cidr>...`: append each CIDR arg to
 * the loc-conf allowlist array (created lazily). NGX_DONE from ngx_ptocidr means
 * the address had non-zero host bits, which is a warning, not an error. */
char *
xrootd_admin_set_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t  *value = cf->args->elts;
    ngx_uint_t  i;

    (void) cmd;

    if (lcf->admin_allow == NULL) {
        lcf->admin_allow = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                            sizeof(ngx_cidr_t));
        if (lcf->admin_allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_cidr_t *cidr = ngx_array_push(lcf->admin_allow);
        ngx_int_t   rc;
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }
        rc = ngx_ptocidr(&value[i], cidr);
        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid CIDR \"%V\" in xrootd_admin_allow",
                               &value[i]);
            return NGX_CONF_ERROR;
        }
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "low address bits of \"%V\" in xrootd_admin_allow were ignored",
                &value[i]);
        }
    }
    return NGX_CONF_OK;
}

/*
 * WHAT: Directive setter for `xrootd_admin_secret <file>`: load the bearer token
 *       from a file at config time.
 * WHY:  Keeping the secret in a file (not inline in nginx.conf) limits exposure;
 *       the transient stack copy is OPENSSL_cleanse'd on every exit path so it
 *       does not linger in memory after parsing.
 * HOW:  Read the file, strip trailing whitespace/newlines, reject empty or
 *       sub-ADMIN_SECRET_MIN tokens (brute-force resistance), then copy the
 *       trimmed token into the pool.
 */
char *
xrootd_admin_set_secret(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t   *value = cf->args->elts;
    ngx_str_t    path = value[1];
    ngx_file_t   file;
    u_char       rbuf[ADMIN_SECRET_MAX];
    ssize_t      n;
    size_t       len;

    (void) cmd;

    if (lcf->admin_secret.len > 0) {
        return "is duplicate";
    }
    if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&file, sizeof(file));
    file.name = path;
    file.log  = cf->log;
    file.fd   = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd_admin_secret: cannot open \"%V\"", &path);
        return NGX_CONF_ERROR;
    }

    n = ngx_read_file(&file, rbuf, sizeof(rbuf), 0);
    ngx_close_file(file.fd);
    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_admin_secret: \"%V\" is empty or unreadable",
                           &path);
        return NGX_CONF_ERROR;
    }

    /* Trim trailing whitespace/newlines. */
    len = (size_t) n;
    while (len > 0 && (rbuf[len - 1] == '\n' || rbuf[len - 1] == '\r'
                       || rbuf[len - 1] == ' ' || rbuf[len - 1] == '\t')) {
        len--;
    }
    if (len == 0) {
        OPENSSL_cleanse(rbuf, sizeof(rbuf));
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_admin_secret: \"%V\" contains no token",
                           &path);
        return NGX_CONF_ERROR;
    }
    /* W6/E2 — reject trivially short secrets that invite brute force. */
    if (len < ADMIN_SECRET_MIN) {
        OPENSSL_cleanse(rbuf, sizeof(rbuf));
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_admin_secret: \"%V\" token is too short "
                           "(%uz bytes; need >= %d)", &path, len,
                           (int) ADMIN_SECRET_MIN);
        return NGX_CONF_ERROR;
    }

    lcf->admin_secret.data = ngx_pnalloc(cf->pool, len);
    if (lcf->admin_secret.data == NULL) {
        OPENSSL_cleanse(rbuf, sizeof(rbuf));
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(lcf->admin_secret.data, rbuf, len);
    lcf->admin_secret.len = len;
    /* W6/F1 — scrub the transient stack copy of the secret. */
    OPENSSL_cleanse(rbuf, sizeof(rbuf));
    return NGX_CONF_OK;
}

/* Directive setter for `xrootd_admin_proxy_allow <host>...`: the backend-target
 * allowlist consulted by admin_url_host_allowed (SSRF guard). Stores raw host
 * strings (no parsing); matching is case-insensitive at request time. */
char *
xrootd_admin_set_proxy_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_dashboard_loc_conf_t *lcf = conf;
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
