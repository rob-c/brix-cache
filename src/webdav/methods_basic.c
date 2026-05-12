/*
 * methods_basic.c - OPTIONS and HEAD handlers.
 */

#include "webdav.h"

/*
 * webdav_handle_options — respond to HTTP OPTIONS with DAV: 1 and the Allow
 * header listing which methods are enabled for this location.
 *
 * The Allow list is derived from conf->allow_write:
 *   read-only: OPTIONS, GET, HEAD, PROPFIND
 *   write-enabled: + PUT, DELETE, MKCOL, MOVE, COPY
 *
 * Also emits CORS response headers (webdav_add_cors_headers).
 */
ngx_int_t
webdav_handle_options(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t                   *h;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "DAV");
    ngx_str_set(&h->value, "1, 2");

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Allow");
    if (conf->allow_write) {
        ngx_str_set(&h->value,
            "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, PROPFIND, PROPPATCH, LOCK, UNLOCK");
    } else {
        ngx_str_set(&h->value, "OPTIONS, GET, HEAD, PROPFIND");
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "MS-Author-Via");
    ngx_str_set(&h->value, "DAV");

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

ngx_int_t
webdav_handle_head(ngx_http_request_t *r, int send_body)
{
    char                               path[WEBDAV_MAX_PATH];
    struct stat                        sb;
    ngx_int_t                          rc;
    ngx_table_elt_t                   *h;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = S_ISDIR(sb.st_mode) ? 0 : sb.st_size;
    r->headers_out.last_modified_time = sb.st_mtime;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    if (S_ISDIR(sb.st_mode)) {
        ngx_str_set(&h->value, "httpd/unix-directory");
    } else {
        ngx_str_set(&h->value, "application/octet-stream");
    }

    rc = webdav_add_last_modified(r, sb.st_mtime);
    if (rc != NGX_OK) {
        return rc;
    }

    if (!S_ISDIR(sb.st_mode)) {
        rc = webdav_add_etag(r, sb.st_mtime, sb.st_size);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    ngx_http_send_header(r);

    if (!send_body || r->header_only) {
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    return NGX_OK;
}

/*
 * webdav_handle_proppatch — RFC 4918 §9.2 PROPPATCH.
 *
 * Dead properties (arbitrary client metadata) are not stored.  We drain the
 * request body and return 207 Multi-Status with HTTP/1.1 200 OK per property,
 * which is the minimal response that unblocks clients such as Cyberduck and
 * rucio that issue PROPPATCH after PUT and treat 501 as a hard error.
 */
ngx_int_t
webdav_handle_proppatch(ngx_http_request_t *r)
{
    ngx_chain_t     *head = NULL;
    ngx_chain_t     *tail = NULL;
    ngx_pool_t      *pool = r->pool;
    off_t            total_len = 0;
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;
    ngx_int_t        rc;
    char            *safe_href;

    ngx_http_discard_request_body(r);

    safe_href = webdav_escape_xml_text(pool, (const char *) r->uri.data);
    if (safe_href == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (webdav_propfind_append(pool, &head, &tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:multistatus xmlns:D=\"DAV:\">"
            "<D:response>"
            "<D:href>%s</D:href>"
            "<D:propstat>"
            "<D:prop/>"
            "<D:status>HTTP/1.1 200 OK</D:status>"
            "</D:propstat>"
            "</D:response>"
            "</D:multistatus>",
            safe_href) == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    for (lc = head; lc != NULL; lc = lc->next) {
        total_len += lc->buf->last - lc->buf->pos;
    }

    r->headers_out.status = 207;
    r->headers_out.content_length_n = total_len;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    ngx_str_set(&h->value, "application/xml; charset=\"utf-8\"");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, head);
}
