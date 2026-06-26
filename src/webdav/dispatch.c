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
#include "../compat/http_body.h"
#include "../impersonate/lifecycle.h"

static ngx_int_t webdav_dispatch_inner(ngx_http_request_t *r);

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
ngx_http_xrootd_webdav_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    ngx_int_t rc;

    xrootd_imp_request_begin(rx != NULL ? rx->identity : NULL);
    rc = webdav_dispatch_inner(r);
    xrootd_imp_request_end();
    return rc;
}

static ngx_int_t
webdav_dispatch_inner(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_int_t                          rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
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
        ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
        if (h != NULL) {
            h->hash = 1;
            ngx_str_set(&h->key, "Retry-After");
            ngx_str_set(&h->value, "1");
        }
        r->keepalive = 0;
        return webdav_metrics_return(r, NGX_HTTP_SERVICE_UNAVAILABLE);
    }

    /* AGPL-3.0 sec.13: offer remote users the source (X-Source header). */
    xrootd_http_source_offer(r);

    /*
     * SciTags packet marking (phase-34).  TPC (COPY) is always marked; plain
     * GET/PUT only when xrootd_pmark_http_plain is on (default off = XRootD
     * parity).  Begun here post-auth; ended via a request-pool cleanup.
     */
    if (conf->common.pmark.enable
        && (r->method == NGX_HTTP_COPY
            || (conf->common.pmark.http_plain
                && (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_PUT))))
    {
        ngx_http_xrootd_webdav_req_ctx_t *rx =
            ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
        const char *vo = "", *us = "";
        u_char      pth[2048], cgi[512];

        if (rx != NULL && rx->identity != NULL) {
            vo = xrootd_identity_vo_csv_cstr(rx->identity);
            us = xrootd_identity_dn_cstr(rx->identity);
        }
        ngx_cpystrn(pth, r->uri.data, ngx_min(r->uri.len + 1, sizeof(pth)));
        if (r->args.len) {
            ngx_cpystrn(cgi, r->args.data, ngx_min(r->args.len + 1, sizeof(cgi)));
        } else {
            cgi[0] = '\0';
        }
        xrootd_pmark_http_mark(&conf->common.pmark, r->pool, r->connection,
            (r->method == NGX_HTTP_PUT || r->method == NGX_HTTP_COPY),
            vo, us, (const char *) pth, (const char *) cgi);
    }

    /* OPTIONS: access handler already added CORS headers and tracked the
     * pre-flight metric; content handler owns the Allow response. */
    if (r->method == NGX_HTTP_OPTIONS) {
        return webdav_metrics_return(r, webdav_handle_options(r));
    }

    /* Macaroon token issuance endpoints — handled before proxy mode because
     * the server issues tokens for itself, not the upstream. */
    {
        static const char discovery_path[] = "/.well-known/oauth-authorization-server";
        static const char token_path[]     = "/.oauth2/token";

        if (r->uri.len >= sizeof(discovery_path) - 1
            && ngx_memcmp(r->uri.data + r->uri.len - (sizeof(discovery_path) - 1),
                          discovery_path, sizeof(discovery_path) - 1) == 0)
        {
            return webdav_metrics_return(r,
                webdav_handle_macaroon_discovery(r));
        }

        if (r->uri.len >= sizeof(token_path) - 1
            && ngx_memcmp(r->uri.data + r->uri.len - (sizeof(token_path) - 1),
                          token_path, sizeof(token_path) - 1) == 0)
        {
            if (r->method != NGX_HTTP_POST) {
                return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED);
            }
            rc = xrootd_http_read_body(r, webdav_handle_macaroon_token);
            if (rc != NGX_DONE) {
                return webdav_metrics_return(r, rc);
            }
            return NGX_DONE;
        }

        /* §3 XrdDig: read-only diagnostics under /.well-known/dig/ (default off).
         * Declines (falls through) when disabled or not a dig path. */
        if (conf->dig_enable) {
            rc = xrootd_dig_handle(r);
            if (rc != NGX_DECLINED) {
                return webdav_metrics_return(r, rc);
            }
        }

        /* dCache / XrdMacaroons convention: any POST carrying the
         * application/macaroon-request content type is a token-issue request,
         * regardless of path (the target path becomes the base caveat). */
        if (r->method == NGX_HTTP_POST) {
            ngx_str_t         ct = xrootd_http_get_header(r, "Content-Type");
            static const char mr[] = "application/macaroon-request";
            if (ct.len >= sizeof(mr) - 1
                && ngx_strncasecmp(ct.data, (u_char *) mr, sizeof(mr) - 1) == 0)
            {
                rc = xrootd_http_read_body(r, webdav_handle_macaroon_request);
                if (rc != NGX_DONE) {
                    return webdav_metrics_return(r, rc);
                }
                return NGX_DONE;
            }
        }
    }

    /* WLCG HTTP Tape REST API (/api/v1/…) — handled before proxy mode because
     * the server answers it locally, not the upstream. POST dispatches async
     * body reading (NGX_DONE); GET/DELETE return inline. */
    if (conf->tape_rest
        && r->uri.len >= sizeof("/api/v1/") - 1
        && ngx_strncmp(r->uri.data, "/api/v1/", sizeof("/api/v1/") - 1) == 0)
    {
        ngx_int_t trc = webdav_tape_handle(r);
        if (trc == NGX_DONE) {
            return NGX_DONE;
        }
        return webdav_metrics_return(r, trc);
    }

    /* Upstream proxy mode: access handler ran auth; delegate transport. */
    if (conf->upstream_proxy) {
        return webdav_metrics_return(r, webdav_proxy_handler(r));
    }

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
        /* Lock check: resolve path and verify no conflicting lock before
         * reading the request body (reading body is async / NGX_DONE). */
        {
            char      path[WEBDAV_MAX_PATH];
            ngx_int_t res = ngx_http_xrootd_webdav_resolve_path(
                                r, conf->common.root_canon, path, sizeof(path));
            if (res == NGX_OK) {
                res = webdav_check_locks(r, path, 1);
                if (res != NGX_OK) {
                    return webdav_metrics_return(r, res);
                }
            }
        }

        r->request_body_in_single_buf = 1;
        rc = xrootd_http_read_body(r, webdav_handle_put_body);
        if (rc != NGX_DONE) {
            return webdav_metrics_return(r, rc);
        }
        return NGX_DONE;
    }

    if (r->method == NGX_HTTP_DELETE) {
        return webdav_metrics_return(r, webdav_handle_delete(r));
    }

    if (r->method_name.len == 5
        && ngx_strncmp(r->method_name.data, "MKCOL", 5) == 0)
    {
        return webdav_metrics_return(r, webdav_handle_mkcol(r));
    }

    if (r->method_name.len == 4
        && ngx_strncmp(r->method_name.data, "COPY", 4) == 0)
    {
        ngx_table_elt_t *source_hdr;
        ngx_table_elt_t *dest_hdr;

        source_hdr = webdav_tpc_find_header(r, "Source", sizeof("Source") - 1);
        dest_hdr   = webdav_tpc_find_header(r, "Destination",
                                            sizeof("Destination") - 1);

        /* TPC pull: Source: header is unambiguous (always third-party copy) */
        if (source_hdr != NULL) {
            if (!conf->tpc) {
                return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED);
            }
            return webdav_metrics_return(r,
                                         ngx_http_xrootd_webdav_tpc_handle_copy(r));
        }

        /* TPC push: Credential: header signals a WLCG HTTP-TPC request. */
        if (dest_hdr != NULL
            && (webdav_tpc_find_header(r, "Credential",
                                       sizeof("Credential") - 1) != NULL
                || webdav_tpc_find_header(r, "Credentials",
                                          sizeof("Credentials") - 1) != NULL))
        {
            if (!conf->tpc) {
                return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED);
            }
            return webdav_metrics_return(r,
                                         ngx_http_xrootd_webdav_tpc_handle_copy(r));
        }

        /* Server-side copy (RFC 4918 §9.8): local copy within the export root */
        return webdav_metrics_return(r, webdav_handle_copy(r));
    }

    if (r->method_name.len == 4
        && ngx_strncmp(r->method_name.data, "MOVE", 4) == 0)
    {
        char      path[WEBDAV_MAX_PATH];
        ngx_int_t res = ngx_http_xrootd_webdav_resolve_path(
                            r, conf->common.root_canon, path, sizeof(path));
        if (res == NGX_OK) {
            res = webdav_check_locks(r, path, 1);
            if (res != NGX_OK) {
                return webdav_metrics_return(r, res);
            }
        }
        return webdav_metrics_return(r, webdav_handle_move(r));
    }

    if (r->method_name.len == 8
        && ngx_strncmp(r->method_name.data, "PROPFIND", 8) == 0)
    {
        return webdav_metrics_return(r, webdav_handle_propfind(r));
    }

    if (r->method_name.len == 4
        && ngx_strncmp(r->method_name.data, "LOCK", 4) == 0)
    {
        rc = xrootd_http_read_body(r, webdav_handle_lock);
        if (rc != NGX_DONE) {
            return webdav_metrics_return(r, rc);
        }
        return NGX_DONE;
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

    /* Unrecognised method: send 405 with Allow header (RFC 7231 §6.5.5). */
    r->headers_out.status = NGX_HTTP_NOT_ALLOWED;
    r->headers_out.content_length_n = 0;
    {
        ngx_table_elt_t *h_allow = ngx_list_push(&r->headers_out.headers);
        if (h_allow != NULL) {
            h_allow->hash = 1;
            ngx_str_set(&h_allow->key, "Allow");
            if (xrootd_http_operation_allow_header(r->pool,
                    xrootd_webdav_operations, xrootd_webdav_operations_count,
                    XROOTD_WEBDAV_ALLOW_FLAGS(conf), &h_allow->value) != NGX_OK)
            {
                ngx_str_set(&h_allow->value,
                    "GET, HEAD, OPTIONS, PUT, DELETE, MKCOL,"
                    " MOVE, COPY, PROPFIND, PROPPATCH, LOCK, UNLOCK");
            }
        }
    }
    ngx_http_send_header(r);
    return webdav_metrics_return(r, ngx_http_send_special(r, NGX_HTTP_LAST));
}
