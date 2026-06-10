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
#include "../compat/http_body.h"

ngx_int_t
ngx_http_xrootd_webdav_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_int_t                          rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (!conf->common.enable) {
        return NGX_DECLINED;
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
