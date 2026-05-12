/*
 * propfind.c - WebDAV PROPFIND and Multi-Status XML generation.
 */

#include "webdav.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/*
 * webdav_propfind_append — append a printf-formatted XML fragment to the growing
 * Multi-Status response chain.
 */
ngx_buf_t *
webdav_propfind_append(ngx_pool_t *pool, ngx_chain_t **head, ngx_chain_t **tail,
                       const char *fmt, ...)
{
    va_list      ap;
    va_list      ap_copy;
    char         tmp[2048];
    char        *src;
    int          n;
    ngx_buf_t   *b;
    ngx_chain_t *lc;

    va_start(ap, fmt);
    va_copy(ap_copy, ap);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (n < 0) {
        va_end(ap_copy);
        return NULL;
    }

    if ((size_t) n >= sizeof(tmp)) {
        src = ngx_pnalloc(pool, (size_t) n + 1);
        if (src == NULL) {
            va_end(ap_copy);
            return NULL;
        }
        (void) vsnprintf(src, (size_t) n + 1, fmt, ap_copy);
    } else {
        src = tmp;
    }

    va_end(ap_copy);

    if (n == 0) {
        return (*tail != NULL) ? (*tail)->buf : NULL;
    }

    b = ngx_create_temp_buf(pool, (size_t) n);
    if (b == NULL) {
        return NULL;
    }
    ngx_memcpy(b->pos, src, (size_t) n);
    b->last = b->pos + n;

    lc = ngx_alloc_chain_link(pool);
    if (lc == NULL) {
        return NULL;
    }
    lc->buf = b;
    lc->next = NULL;

    if (*tail == NULL) {
        *head = lc;
        *tail = lc;
    } else {
        (*tail)->next = lc;
        *tail = lc;
    }

    return b;
}

static ngx_int_t
propfind_entry(ngx_http_request_t *r, ngx_chain_t **head, ngx_chain_t **tail,
               const char *href, const char *path, struct stat *sb)
{
    char  date_buf[64];
    char *safe_href;
    ngx_pool_t *pool = r->pool;

    webdav_http_date(sb->st_mtime, date_buf, sizeof(date_buf));

    safe_href = webdav_escape_xml_text(pool, href);
    if (safe_href == NULL) {
        return NGX_ERROR;
    }

    if (webdav_propfind_append(pool, head, tail,
            "<D:response>"
            "<D:href>%s</D:href>"
            "<D:propstat>"
            "<D:prop>", safe_href) == NULL)
    {
        return NGX_ERROR;
    }

    if (S_ISDIR(sb->st_mode)) {
        if (webdav_propfind_append(pool, head, tail,
                "<D:resourcetype><D:collection/></D:resourcetype>"
                "<D:getcontentlength>0</D:getcontentlength>") == NULL)
        {
            return NGX_ERROR;
        }
    } else if (webdav_propfind_append(pool, head, tail,
                   "<D:resourcetype/>"
                   "<D:getcontentlength>%lld</D:getcontentlength>",
                   (long long) sb->st_size) == NULL)
    {
        return NGX_ERROR;
    }

    if (webdav_propfind_append(pool, head, tail,
            "<D:getlastmodified>%s</D:getlastmodified>", date_buf) == NULL)
    {
        return NGX_ERROR;
    }

    {
        char etag_buf[64];
        webdav_etag_str(etag_buf, sizeof(etag_buf), sb->st_mtime, sb->st_size);
        if (webdav_propfind_append(pool, head, tail,
                "<D:getetag>%s</D:getetag>", etag_buf) == NULL)
        {
            return NGX_ERROR;
        }
    }

    {
        char cdate_buf[32];
        webdav_iso8601_date(sb->st_ctime, cdate_buf, sizeof(cdate_buf));
        if (webdav_propfind_append(pool, head, tail,
                "<D:creationdate>%s</D:creationdate>", cdate_buf) == NULL)
        {
            return NGX_ERROR;
        }
    }

    {
        /* displayname is the last path component, XML-escaped */
        const char *name = href + strlen(href);
        char       *safe_name;

        while (name > href && *(name - 1) != '/') {
            name--;
        }
        safe_name = webdav_escape_xml_text(pool, name);
        if (safe_name != NULL
            && webdav_propfind_append(pool, head, tail,
                   "<D:displayname>%s</D:displayname>", safe_name) == NULL)
        {
            return NGX_ERROR;
        }
    }

    /* Lock discovery info */
    (void) webdav_lock_append_supported(r, head, tail);
    (void) webdav_lock_append_discovery(r, path, head, tail);

    if (webdav_propfind_append(pool, head, tail,
            "</D:prop>"
            "<D:status>HTTP/1.1 200 OK</D:status>"
            "</D:propstat>"
            "</D:response>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static int
propfind_depth_is_one(ngx_http_request_t *r)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *hdr = part->elts;
    ngx_uint_t       i;

    for (;;) {
        for (i = 0; i < part->nelts; i++) {
            if (hdr[i].key.len == 5
                && ngx_strncasecmp(hdr[i].key.data,
                                   (u_char *) "Depth", 5) == 0)
            {
                if (hdr[i].value.len == 1 && hdr[i].value.data[0] == '1') {
                    return 1;
                }
            }
        }

        if (part->next == NULL) {
            break;
        }
        part = part->next;
        hdr = part->elts;
    }

    return 0;
}

ngx_int_t
webdav_handle_propfind(ngx_http_request_t *r)
{
    char             path[WEBDAV_MAX_PATH];
    struct stat      sb;
    ngx_int_t        rc;
    int              depth;
    ngx_chain_t     *head = NULL;
    ngx_chain_t     *tail = NULL;
    off_t            total_len = 0;
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;
    ngx_uint_t       entry_count = 0;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    depth = propfind_depth_is_one(r);
    XROOTD_WEBDAV_METRIC_INC(
        propfind_depth_total[depth ? XROOTD_WEBDAV_PROPFIND_DEPTH_1
                                   : XROOTD_WEBDAV_PROPFIND_DEPTH_0]);

    if (webdav_propfind_append(r->pool, &head, &tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:multistatus xmlns:D=\"DAV:\">") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    {
        char   href[WEBDAV_MAX_PATH + 2];
        size_t uri_len = r->uri.len;

        if (uri_len >= sizeof(href) - 1) {
            uri_len = sizeof(href) - 2;
        }
        ngx_memcpy(href, r->uri.data, uri_len);
        href[uri_len] = '\0';

        if (propfind_entry(r, &head, &tail, href, path, &sb) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        entry_count++;
    }

    if (depth == 1 && S_ISDIR(sb.st_mode)) {
        DIR *dp = opendir(path);

        if (dp != NULL) {
            struct dirent *de;

            while ((de = readdir(dp)) != NULL) {
                char        child_path[WEBDAV_MAX_PATH];
                struct stat csb;
                char        href[WEBDAV_MAX_PATH + 2];
                const char *base;
                size_t      blen;

                if (de->d_name[0] == '.') {
                    continue;
                }

                if ((size_t) snprintf(child_path, sizeof(child_path),
                                      "%s/%s", path, de->d_name)
                    >= sizeof(child_path))
                {
                    continue;
                }

                if (stat(child_path, &csb) != 0) {
                    continue;
                }

                base = (const char *) r->uri.data;
                blen = r->uri.len;
                if (blen == 0 || base[blen - 1] != '/') {
                    if ((size_t) snprintf(href, sizeof(href), "%.*s/%s",
                                          (int) blen, base, de->d_name)
                        >= sizeof(href))
                    {
                        continue;
                    }
                } else if ((size_t) snprintf(href, sizeof(href), "%.*s%s",
                                             (int) blen, base, de->d_name)
                           >= sizeof(href))
                {
                    continue;
                }

                if (propfind_entry(r, &head, &tail, href, child_path, &csb)
                    != NGX_OK)
                {
                    closedir(dp);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                entry_count++;
            }
            closedir(dp);
        }
    }

    if (webdav_propfind_append(r->pool, &head, &tail, "</D:multistatus>") == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    for (lc = head; lc != NULL; lc = lc->next) {
        total_len += lc->buf->last - lc->buf->pos;
    }

    XROOTD_WEBDAV_METRIC_ADD(propfind_entries_total, entry_count);

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

    XROOTD_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) total_len);

    return ngx_http_output_filter(r, head);
}
