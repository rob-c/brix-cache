/*
 * acl.c - WebDAV ACL method handling (RFC 3744).
 *
 * nginx-xrootd exposes ACL discovery properties through PROPFIND, but the
 * effective authorization model is configured by nginx/xrootd directives and
 * token scopes.  Client-side ACL mutation is therefore protected.
 */

#include "webdav.h"
#include "core/http/http_xml.h"

ngx_int_t
webdav_handle_acl(ngx_http_request_t *r)
{
    ngx_chain_t     *head = NULL, *tail = NULL, *lc;
    ngx_table_elt_t *h;
    off_t            total_len = 0;
    ngx_int_t        rc;

    ngx_http_discard_request_body(r);

    if (brix_http_chain_appendf(r->pool, &head, &tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:error xmlns:D=\"DAV:\">"
            "<D:cannot-modify-protected-property/>"
            "</D:error>") == NULL)
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

    r->headers_out.status = NGX_HTTP_FORBIDDEN;
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
