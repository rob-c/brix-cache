/*
 * dispatch.c - WebDAV content handler and method routing.
 *
 * WHAT: nginx HTTP content handler — routes authenticated, pre-validated
 * WebDAV requests to per-method handlers.  Authentication, CORS, write
 * permission and token scope checks are performed upstream in the access phase
 * handler (access.c); path and lock checks stay in the native method handlers.
 *
 * WHY: Keeping all WebDAV methods in this module gives consistent metrics,
 * logging, lock checks, and path confinement without relying on nginx's
 * built-in ngx_http_dav_module.
 *
 * HOW: For each method, performs any method-specific pre-work not already
 * done by the access handler (lock check for PUT/MOVE before reading body,
 * TPC header inspection for COPY) then calls the appropriate handler.
 * Returns NGX_DECLINED for unrecognised methods so nginx returns 405.
 */

#include "webdav.h"
#include "xrdhttp.h"
#include "tape_rest.h"
#include "delegation.h"
#include "core/http/http_body.h"
#include "auth/impersonate/lifecycle.h"

static ngx_int_t webdav_dispatch_inner(ngx_http_request_t *r);

static ngx_int_t
webdav_dispatch_draining(ngx_http_request_t *r)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);

    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key, "Retry-After");
        ngx_str_set(&h->value, "1");
    }
    r->keepalive = 0;
    return webdav_metrics_return(r, NGX_HTTP_SERVICE_UNAVAILABLE);
}

static void
webdav_dispatch_pmark(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_http_brix_webdav_req_ctx_t *rx;
    const char *vo = "", *us = "";
    u_char      pth[2048], cgi[512];

    if (!conf->common.pmark.enable
        || (r->method != NGX_HTTP_COPY
            && !(conf->common.pmark.http_plain
                 && (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_PUT))))
    {
        return;
    }

    rx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (rx != NULL && rx->identity != NULL) {
        vo = brix_identity_vo_csv_cstr(rx->identity);
        us = brix_identity_dn_cstr(rx->identity);
    }
    ngx_cpystrn(pth, r->uri.data, ngx_min(r->uri.len + 1, sizeof(pth)));
    if (r->args.len) {
        ngx_cpystrn(cgi, r->args.data, ngx_min(r->args.len + 1, sizeof(cgi)));
    } else {
        cgi[0] = '\0';
    }
    brix_pmark_http_mark(&conf->common.pmark, r->pool, r->connection,
        (r->method == NGX_HTTP_PUT || r->method == NGX_HTTP_COPY),
        vo, us, (const char *) pth, (const char *) cgi);
}

static ngx_int_t
webdav_dispatch_macaroon(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    static const char discovery_path[] = "/.well-known/oauth-authorization-server";
    static const char token_path[]     = "/.oauth2/token";
    ngx_int_t         rc;

    if (r->uri.len >= sizeof(discovery_path) - 1
        && ngx_memcmp(r->uri.data + r->uri.len - (sizeof(discovery_path) - 1),
                      discovery_path, sizeof(discovery_path) - 1) == 0)
    {
        return webdav_metrics_return(r, webdav_handle_macaroon_discovery(r));
    }

    if (r->uri.len >= sizeof(token_path) - 1
        && ngx_memcmp(r->uri.data + r->uri.len - (sizeof(token_path) - 1),
                      token_path, sizeof(token_path) - 1) == 0)
    {
        if (r->method != NGX_HTTP_POST) {
            return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED);
        }
        rc = brix_http_read_body(r, webdav_handle_macaroon_token);
        return (rc == NGX_DONE) ? NGX_DONE : webdav_metrics_return(r, rc);
    }

    if (conf->dig_enable) {
        rc = brix_dig_handle(r);
        if (rc != NGX_DECLINED) {
            return webdav_metrics_return(r, rc);
        }
    }

    if (r->method == NGX_HTTP_POST) {
        ngx_str_t         ct = brix_http_get_header(r, "Content-Type");
        static const char mr[] = "application/macaroon-request";
        if (ct.len >= sizeof(mr) - 1
            && ngx_strncasecmp(ct.data, (u_char *) mr, sizeof(mr) - 1) == 0)
        {
            rc = brix_http_read_body(r, webdav_handle_macaroon_request);
            return (rc == NGX_DONE) ? NGX_DONE : webdav_metrics_return(r, rc);
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
webdav_dispatch_delegation_upload(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    static const char delegation_path[] = "/.well-known/brix-delegation";
    ngx_int_t         rc;

    if (!conf->delegation_endpoint
        || r->uri.len < sizeof(delegation_path) - 1
        || ngx_memcmp(r->uri.data + r->uri.len - (sizeof(delegation_path) - 1),
                      delegation_path, sizeof(delegation_path) - 1) != 0)
    {
        return NGX_DECLINED;
    }
    if (r->method != NGX_HTTP_PUT && r->method != NGX_HTTP_POST) {
        return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED);
    }
    rc = brix_http_read_body(r, webdav_delegation_handle);
    return (rc == NGX_DONE) ? NGX_DONE : webdav_metrics_return(r, rc);
}

static ngx_int_t
webdav_dispatch_delegation_gridsite(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    static const char deleg_prefix[] = "/.well-known/brix-delegation/";
    static const char deleg_request[] = "/.well-known/brix-delegation/request";
    size_t            prefix_len = sizeof(deleg_prefix) - 1;
    ngx_int_t         rc;

    if (!conf->delegation_endpoint) {
        return NGX_DECLINED;
    }
    if (r->uri.len == sizeof(deleg_request) - 1
        && ngx_memcmp(r->uri.data, deleg_request, sizeof(deleg_request) - 1) == 0)
    {
        if (r->method != NGX_HTTP_GET) {
            return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED);
        }
        return webdav_metrics_return(r, webdav_delegation_request_handle(r));
    }
    if (r->uri.len <= prefix_len
        || ngx_memcmp(r->uri.data, deleg_prefix, prefix_len) != 0)
    {
        return NGX_DECLINED;
    }
    if (r->method != NGX_HTTP_PUT) {
        return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED);
    }
    rc = brix_http_read_body(r, webdav_delegation_put_handle);
    return (rc == NGX_DONE) ? NGX_DONE : webdav_metrics_return(r, rc);
}

static ngx_int_t
webdav_dispatch_tape_rest(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc;

    if (!conf->tape_rest
        || r->uri.len < sizeof("/api/v1/") - 1
        || ngx_strncmp(r->uri.data, "/api/v1/", sizeof("/api/v1/") - 1) != 0)
    {
        return NGX_DECLINED;
    }
    rc = webdav_tape_handle(r);
    return (rc == NGX_DONE) ? NGX_DONE : webdav_metrics_return(r, rc);
}

static ngx_int_t
webdav_lock_check_request_path(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    char      path[WEBDAV_MAX_PATH];
    ngx_int_t rc = ngx_http_brix_webdav_resolve_path(
                       r, conf->common.root_canon, path, sizeof(path));

    if (rc == NGX_OK) {
        rc = webdav_check_locks(r, path, 1);
    }
    return rc;
}

static ngx_int_t
webdav_dispatch_put(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_lock_check_request_path(r, conf);

    if (rc != NGX_OK) {
        return webdav_metrics_return(r, rc);
    }
    r->request_body_in_single_buf = 1;
    rc = brix_http_read_body(r, webdav_handle_put_body);
    return (rc == NGX_DONE) ? NGX_DONE : webdav_metrics_return(r, rc);
}

static ngx_int_t
webdav_dispatch_copy(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_table_elt_t *source_hdr;
    ngx_table_elt_t *dest_hdr;
    int              tpc_push;

    source_hdr = webdav_tpc_find_header(r, "Source", sizeof("Source") - 1);
    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);
    if (source_hdr != NULL) {
        if (!conf->tpc) {
            return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED);
        }
        return webdav_metrics_return(r, ngx_http_brix_webdav_tpc_handle_copy(r));
    }

    tpc_push = dest_hdr != NULL
               && (webdav_tpc_find_header(r, "Credential",
                                           sizeof("Credential") - 1) != NULL
                   || webdav_tpc_find_header(r, "Credentials",
                                             sizeof("Credentials") - 1) != NULL);
    if (tpc_push) {
        if (!conf->tpc) {
            return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED);
        }
        return webdav_metrics_return(r, ngx_http_brix_webdav_tpc_handle_copy(r));
    }
    return webdav_metrics_return(r, webdav_handle_copy(r));
}

static ngx_int_t
webdav_dispatch_move(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_lock_check_request_path(r, conf);

    if (rc != NGX_OK) {
        return webdav_metrics_return(r, rc);
    }
    return webdav_metrics_return(r, webdav_handle_move(r));
}

static ngx_int_t
webdav_dispatch_lock(ngx_http_request_t *r)
{
    ngx_int_t rc = brix_http_read_body(r, webdav_handle_lock);

    return (rc == NGX_DONE) ? NGX_DONE : webdav_metrics_return(r, rc);
}

static ngx_int_t
webdav_dispatch_core_method(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (r->method == NGX_HTTP_HEAD) {
        return webdav_metrics_return(r, webdav_handle_head(r, 0));
    }
    if (r->method == NGX_HTTP_GET) {
        if (xrdhttp_request_is_stats_query(r)) {
            return webdav_metrics_return(r, xrdhttp_handle_stats_query(r));
        }
        return webdav_metrics_return(r, webdav_handle_get(r));
    }
    if (r->method == NGX_HTTP_PUT) {
        return webdav_dispatch_put(r, conf);
    }
    if (r->method == NGX_HTTP_DELETE) {
        return webdav_metrics_return(r, webdav_handle_delete(r));
    }
    return NGX_DECLINED;
}

static ngx_int_t
webdav_dispatch_copy_move_props(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (r->method_name.len == 5
        && ngx_strncmp(r->method_name.data, "MKCOL", 5) == 0)
    {
        return webdav_metrics_return(r, webdav_handle_mkcol(r));
    }
    if (r->method_name.len == 4
        && ngx_strncmp(r->method_name.data, "COPY", 4) == 0)
    {
        return webdav_dispatch_copy(r, conf);
    }
    if (r->method_name.len == 4
        && ngx_strncmp(r->method_name.data, "MOVE", 4) == 0)
    {
        return webdav_dispatch_move(r, conf);
    }
    if (r->method_name.len == 8
        && ngx_strncmp(r->method_name.data, "PROPFIND", 8) == 0)
    {
        return webdav_metrics_return(r, webdav_handle_propfind(r));
    }
    return NGX_DECLINED;
}

static ngx_int_t
webdav_dispatch_lock_patch_search(ngx_http_request_t *r)
{
    if (r->method_name.len == 4
        && ngx_strncmp(r->method_name.data, "LOCK", 4) == 0)
    {
        return webdav_dispatch_lock(r);
    }
    if (r->method_name.len == 6
        && ngx_strncmp(r->method_name.data, "UNLOCK", 6) == 0)
    {
        return webdav_metrics_return(r, webdav_handle_unlock(r));
    }
    if (r->method_name.len == 9
        && ngx_strncmp(r->method_name.data, "PROPPATCH", 9) == 0)
    {
        return webdav_metrics_return(r, webdav_handle_proppatch(r));
    }
    if (r->method_name.len == 6
        && ngx_strncmp(r->method_name.data, "SEARCH", 6) == 0)
    {
        return webdav_metrics_return(r, webdav_handle_search(r));
    }
    if (r->method_name.len == 3
        && ngx_strncmp(r->method_name.data, "ACL", 3) == 0)
    {
        return webdav_metrics_return(r, webdav_handle_acl(r));
    }
    return NGX_DECLINED;
}

static ngx_int_t
webdav_dispatch_method(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc;

    rc = webdav_dispatch_core_method(r, conf);
    if (rc != NGX_DECLINED) {
        return rc;
    }
    rc = webdav_dispatch_copy_move_props(r, conf);
    if (rc != NGX_DECLINED) {
        return rc;
    }
    return webdav_dispatch_lock_patch_search(r);
}

static ngx_int_t
webdav_dispatch_not_allowed(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_table_elt_t *h_allow;

    r->headers_out.status = NGX_HTTP_NOT_ALLOWED;
    r->headers_out.content_length_n = 0;
    h_allow = ngx_list_push(&r->headers_out.headers);
    if (h_allow != NULL) {
        h_allow->hash = 1;
        ngx_str_set(&h_allow->key, "Allow");
        if (brix_http_operation_allow_header(r->pool,
                brix_webdav_operations, brix_webdav_operations_count,
                BRIX_WEBDAV_ALLOW_FLAGS(conf), &h_allow->value) != NGX_OK)
        {
            ngx_str_set(&h_allow->value,
                "GET, HEAD, OPTIONS, PUT, DELETE, MKCOL,"
                " MOVE, COPY, PROPFIND, PROPPATCH, LOCK, UNLOCK");
        }
    }
    ngx_http_send_header(r);
    return webdav_metrics_return(r, ngx_http_send_special(r, NGX_HTTP_LAST));
}

/*
 * Phase 40 wrapper: bracket the whole synchronous dispatch with the impersonation
 * principal taken from the authenticated identity (no-op unless map mode).  This
 * covers every method that completes inline (GET/HEAD/DELETE/MKCOL/COPY/MOVE/
 * PROPFIND/...).  Methods that read a body asynchronously (PUT/LOCK) return
 * NGX_DONE here — the principal is cleared on return and re-established inside the
 * body callback (see webdav_handle_put_body), so it never leaks across the event
 * loop while a body is pending.
 */
ngx_int_t
ngx_http_brix_webdav_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    ngx_int_t rc;

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    rc = webdav_dispatch_inner(r);
    brix_imp_request_end();
    return rc;
}

static ngx_int_t
webdav_dispatch_inner(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_int_t                       rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (!conf->common.enable) {
        return NGX_DECLINED;
    }

    /*
     * Fast teardown: the worker is draining (graceful reload/quit).  Reject a
     * freshly-arrived request with 503 + Retry-After and force the connection
     * closed, rather than starting a transfer this worker is about to abandon.
     * The client's resilient layer retries against the new worker and resumes
     * a download from its last byte via a Range GET.  Requests already mid-flight
     * are untouched (their handler has long since returned); ngx_close_idle_
     * connections() drops idle keepalive connections for us.
     */
    if (ngx_exiting) {
        return webdav_dispatch_draining(r);
    }

    /* AGPL-3.0 sec.13: offer remote users the source (X-Source header). */
    brix_http_source_offer(r);
    webdav_sess_begin_request(r);
    webdav_sess_attempt_request(r);

    /*
     * SciTags packet marking (phase-34).  TPC (COPY) is always marked; plain
     * GET/PUT only when brix_pmark_http_plain is on (default off = XRootD
     * parity).  Begun here post-auth; ended via a request-pool cleanup.
     */
    webdav_dispatch_pmark(r, conf);

    /* OPTIONS: access handler already added CORS headers and tracked the
     * pre-flight metric; content handler owns the Allow response. */
    if (r->method == NGX_HTTP_OPTIONS) {
        return webdav_metrics_return(r, webdav_handle_options(r));
    }

    /* Macaroon token issuance endpoints — handled before proxy mode because
     * the server issues tokens for itself, not the upstream. */
    rc = webdav_dispatch_macaroon(r, conf);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Phase-2 Task 8: opt-in proxy-upload delegation endpoint. Handled before
     * proxy mode because the server stores the credential itself, not the
     * upstream. Path match mirrors the macaroon endpoints above: suffix
     * match against a well-known path, off by default (falls through to
     * normal dispatch → 404, matching the "endpoint off = not special"
     * contract). */
    rc = webdav_dispatch_delegation_upload(r, conf);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Phase-3 Task 4: standard GridSite two-step getProxyReq/putProxy REST
     * flow, alongside the T8 proxy-upload form above. Same
     * brix_delegation_endpoint gate (off by default = both paths fall
     * through to ordinary dispatch, same "off = not special" contract as
     * T8). Two routes under the SAME well-known path as T8 but with a
     * trailing segment, so they are matched separately from T8's exact
     * suffix match (which requires no trailing "/…" after
     * "/.well-known/brix-delegation"):
     *   GET  /.well-known/brix-delegation/request  — getProxyReq (step 1)
     *   PUT  /.well-known/brix-delegation/<id>     — putProxy    (step 2)
     * request_handle is synchronous (no body to read — GET carries none)
     * and follows the ordinary synchronous-handler contract (like
     * webdav_handle_options): called directly and its return value passed
     * through webdav_metrics_return(), NOT NGX_DONE — it does not read a
     * body asynchronously, so there is no pending async work for NGX_DONE
     * to represent; returning NGX_DONE here would have nginx's content
     * phase finalize the request a second time (see delegation.h's doc
     * comment on webdav_delegation_request_handle). */
    rc = webdav_dispatch_delegation_gridsite(r, conf);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* WLCG HTTP Tape REST API (/api/v1/…) — handled before proxy mode because
     * the server answers it locally, not the upstream. POST dispatches async
     * body reading (NGX_DONE); GET/DELETE return inline. */
    rc = webdav_dispatch_tape_rest(r, conf);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = webdav_dispatch_method(r, conf);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Unrecognised method: send 405 with Allow header (RFC 7231 §6.5.5). */
    return webdav_dispatch_not_allowed(r, conf);
}
