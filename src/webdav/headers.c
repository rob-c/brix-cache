/*
 * headers.c - shared HTTP response header helpers for WebDAV handlers.
 */

#include "webdav.h"

#include <stdio.h>
#include <string.h>

/*
 * webdav_add_last_modified — append a Last-Modified response header.
 *
 * Pool allocation: ngx_pstrdup(r->pool, ...) — value buffer is freed when
 *   the request pool is destroyed at response completion.
 *
 * Returns: NGX_OK on success, NGX_HTTP_INTERNAL_SERVER_ERROR on OOM.
 */
ngx_int_t
webdav_add_last_modified(ngx_http_request_t *r, time_t mtime)
{
    ngx_table_elt_t *h;
    ngx_str_t        value;
    char             date_buf[64];

    webdav_http_date(mtime, date_buf, sizeof(date_buf));

    value.len = strlen(date_buf);
    value.data = (u_char *) date_buf;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Last-Modified");
    h->value.data = ngx_pstrdup(r->pool, &value);
    if (h->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->value.len = value.len;

    return NGX_OK;
}

/*
 * webdav_etag_str — format a weak ETag string into buf.
 *
 * The ETag is derived from mtime and file size.  This is the same scheme
 * used by the nginx static-file module and many other servers; it is not
 * cryptographically strong but sufficient to detect file replacement.
 *
 * The "W/" prefix marks it as a weak validator per RFC 7232 §2.1.
 */
void
webdav_etag_str(char *buf, size_t bufsz, time_t mtime, off_t size)
{
    snprintf(buf, bufsz, "W/\"%lx-%llx\"",
             (unsigned long) mtime, (unsigned long long) size);
}

/*
 * webdav_add_etag — append an ETag response header and register it with
 * nginx's not_modified filter.
 *
 * Setting r->headers_out.etag enables nginx's built-in If-None-Match /
 * If-Match conditional-request processing via the not_modified header filter.
 * Without this assignment, nginx would not know which header is the ETag.
 *
 * Returns: NGX_OK on success, NGX_HTTP_INTERNAL_SERVER_ERROR on OOM.
 */
ngx_int_t
webdav_add_etag(ngx_http_request_t *r, time_t mtime, off_t size)
{
    ngx_table_elt_t *h;
    ngx_str_t        value;
    char             etag_buf[64];

    webdav_etag_str(etag_buf, sizeof(etag_buf), mtime, size);

    value.len  = strlen(etag_buf);
    value.data = (u_char *) etag_buf;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "ETag");
    h->value.data = ngx_pstrdup(r->pool, &value);
    if (h->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->value.len = value.len;

    /* Register with nginx's not_modified filter for If-None-Match/If-Match */
    r->headers_out.etag = h;

    return NGX_OK;
}
