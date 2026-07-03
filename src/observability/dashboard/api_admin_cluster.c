/*
 * api_admin_cluster.c - extracted concern
 * Phase-38 split of api_admin.c; behavior-identical.
 */
#include "dashboard_api_admin_internal.h"


/*
 * Parse the tail after "/brix/api/v1/admin/cluster/servers/" into host,
 * port, and an optional trailing action ("drain"/"undrain"/"").  Returns
 * NGX_OK on success.
 */
ngx_int_t
admin_parse_server_uri(ngx_http_request_t *r, char *host_out, size_t host_size,
    uint16_t *port_out, char *action_out, size_t action_size)
{
    static const char  pfx[] = "/brix/api/v1/admin/cluster/servers/";
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
    /* A literal IPv6 host is sent bracketed in the URI path ("[::1]") because it
     * contains colons; the cluster registry stores the address bare, so strip
     * the brackets here or the host would never match a registered entry. */
    {
        char  *h  = seg[0];
        size_t hl = ngx_strlen(h);
        if (h[0] == '[' && hl >= 2 && h[hl - 1] == ']') {
            h[hl - 1] = '\0';
            h++;
        }
        if (h[0] == '\0' || ngx_strlen(h) >= host_size) {
            return NGX_ERROR;
        }
        ngx_cpystrn((u_char *) host_out, (u_char *) h, host_size);
    }

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


/* POST/PUT body handler: upsert a server into the cluster registry. Validates
 * required fields and host/paths character whitelists, clamps util_pct to 0..100
 * and free_mb to >=0, then registers and audits. */
ngx_int_t
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

    brix_srv_register(host, (uint16_t) port, paths,
                        (uint32_t) free_mb, (uint32_t) util_pct);
    brix_dashboard_event_add(BRIX_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: server registered", host);
    admin_audit(r, "cluster/register", host, "registered");
    return admin_send_ok(r, "registered");
}


/* POST .../{host}/{port}/drain: blacklist a server for `duration_s` seconds
 * (default 300) so the router stops directing new traffic to it. */
ngx_int_t
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
    brix_srv_blacklist(host, port, (ngx_msec_t) duration_s * 1000);
    brix_dashboard_event_add(BRIX_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: server drained", host);
    admin_audit(r, "cluster/drain", host, "drained");
    return admin_send_ok(r, "drained");
}


/* DELETE .../{host}/{port}: remove a server from the cluster registry. */
ngx_int_t
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
    brix_srv_unregister(host, port);
    brix_dashboard_event_add(BRIX_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: server unregistered", host);
    admin_audit(r, "cluster/delete", host, "removed");
    return admin_send_ok(r, "removed");
}


/* POST .../{host}/{port}/undrain: lift a drain/blacklist. Returns 404 if the
 * server is not currently drained (brix_srv_undrain reports false). */
ngx_int_t
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
    if (!brix_srv_undrain(host, port)) {
        admin_audit(r, "cluster/undrain", host, "not_found");
        return admin_send_error(r, NGX_HTTP_NOT_FOUND, "not_found");
    }
    brix_dashboard_event_add(BRIX_DASH_EVENT_NAMESPACE, 0, 0,
                               "admin: server undrained", host);
    admin_audit(r, "cluster/undrain", host, "undrained");
    return admin_send_ok(r, "undrained");
}
