/*
 * get.c - WebDAV GET with Range support, sendfile, and fd-cache fast path.
 */

#include "webdav.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * webdav_handle_get — serve a file via HTTP GET with Range support.
 *
 * Fast path: if the fd-cache already holds an open fd for the requested URI
 * hash, the stat and open system calls are skipped entirely.  The cached fd
 * remains owned by the fd-cache; the cleanup handler registered below uses
 * NGX_INVALID_FILE so it does not close it a second time.
 *
 * Range handling: a single "bytes=start-end" or "bytes=-suffix" range is
 * parsed and served as 206 Partial Content.  Multi-range requests and
 * overlapping ranges are not supported; clients that send them receive the
 * full file (200 OK).
 *
 * ngx_http_send_header + r->header_only: after calling ngx_http_send_header(),
 * always check r->header_only.  If true, the client sent HEAD — return
 * immediately without sending a body.  The check at line ~244 handles this.
 *
 * Pool allocation: ngx_pcalloc(r->pool, ...) for ngx_buf_t and ngx_file_t —
 *   both are freed when the request pool is destroyed after the response
 *   is sent.
 *
 * Ownership of fd:
 *   - If fd came from the fd-cache (fd_from_table=1), the cleanup handler
 *     stores NGX_INVALID_FILE so the fd-cache retains ownership.
 *   - If fd was opened here (fd_from_table=0), the cleanup handler closes it.
 */
ngx_int_t
webdav_handle_get(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char                path[WEBDAV_MAX_PATH];
    struct stat         sb;
    ngx_int_t           rc;
    ngx_fd_t            fd;
    off_t               range_start = 0;
    off_t               range_end = 0;
    off_t               send_len;
    int                 has_range = 0;
    int                 fd_from_table = 0;
    ngx_buf_t          *b;
    ngx_chain_t         out;
    ngx_table_elt_t    *h;
    char                cr_buf[64];
    webdav_fd_table_t  *fdt;
    ngx_pool_cleanup_t *cln;
    ngx_pool_cleanup_file_t *clnf;
    char                uri_decoded[WEBDAV_MAX_PATH];
    uint64_t            uri_h = 0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    path[0] = '\0';
    fd = NGX_INVALID_FILE;

    fdt = webdav_get_fd_table(r->connection);

    {
        ngx_int_t   urc;
        const char *cached_path = NULL;

        urc = webdav_urldecode(r->uri.data, r->uri.len,
                               uri_decoded, sizeof(uri_decoded));
        if (urc == NGX_OK) {
            size_t dlen = strlen(uri_decoded);

            while (dlen > 1 && uri_decoded[dlen - 1] == '/') {
                uri_decoded[--dlen] = '\0';
            }

            uri_h = webdav_uri_hash(uri_decoded);
            fd = webdav_fd_table_get_by_uri(fdt, uri_h, &sb, &cached_path);

            if (fd != NGX_INVALID_FILE) {
                if (S_ISDIR(sb.st_mode)) {
                    return NGX_HTTP_FORBIDDEN;
                }
                if (cached_path != NULL) {
                    ngx_cpystrn((u_char *) path, (u_char *) cached_path,
                                sizeof(path));
                }
                fd_from_table = 1;
            }
        }
    }

    if (!fd_from_table) {
        rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
                                                 sizeof(path));
        if (rc != NGX_OK) {
            return rc;
        }

        fd = xrootd_open_confined_canon(r->connection->log, conf->root_canon,
                                        path, O_RDONLY, 0);
        if (fd == NGX_INVALID_FILE) {
            if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_ENOTDIR) {
                return NGX_HTTP_NOT_FOUND;
            }
            ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                                 NGX_LOG_ERR,
                                                 ngx_errno,
                                                 "xrootd_webdav: open() failed for",
                                                 path);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (fstat(fd, &sb) != 0) {
            ngx_close_file(fd);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (S_ISDIR(sb.st_mode)) {
            ngx_close_file(fd);
            return NGX_HTTP_FORBIDDEN;
        }

        if (fdt != NULL) {
            webdav_fd_table_put(fdt, path, &sb, fd, uri_h);
            fd_from_table = 1;
        }
    }

    /* RFC 7232 §3.3 — If-Modified-Since: return 304 if not modified since then */
    if (r->headers_in.if_modified_since != NULL) {
        ngx_str_t ims_str = r->headers_in.if_modified_since->value;
        time_t    ims_time = ngx_parse_http_time(ims_str.data, ims_str.len);

        if (ims_time != NGX_ERROR && sb.st_mtime <= ims_time) {
            r->headers_out.status           = NGX_HTTP_NOT_MODIFIED;
            r->headers_out.content_length_n = 0;
            ngx_http_send_header(r);
            return ngx_http_send_special(r, NGX_HTTP_LAST);
        }
    }

    if (r->headers_in.range != NULL) {
        ngx_str_t rv = r->headers_in.range->value;

        if (rv.len > 6 && ngx_strncmp(rv.data, "bytes=", 6) == 0) {
            u_char *p = rv.data + 6;
            u_char *end = rv.data + rv.len;
            u_char *dash = ngx_strlchr(p, end, '-');

            if (dash != NULL) {
                if (dash == p) {
                    off_t suffix = 0;
                    u_char *q;

                    for (q = dash + 1; q < end; q++) {
                        suffix = suffix * 10 + (*q - '0');
                    }
                    range_start = (suffix >= sb.st_size) ? 0
                                                         : sb.st_size - suffix;
                    range_end = sb.st_size - 1;
                } else {
                    u_char *q;

                    range_start = 0;
                    for (q = p; q < dash; q++) {
                        range_start = range_start * 10 + (*q - '0');
                    }
                    if (dash + 1 < end && *(dash + 1) != '\0') {
                        range_end = 0;
                        for (q = dash + 1; q < end; q++) {
                            range_end = range_end * 10 + (*q - '0');
                        }
                    } else {
                        range_end = sb.st_size - 1;
                    }
                }
                has_range = 1;
            }
        }
    }

    if (!has_range) {
        range_start = 0;
        range_end = sb.st_size - 1;
    }

    if (sb.st_size == 0) {
        if (has_range) {
            XROOTD_WEBDAV_METRIC_INC(
                range_total[XROOTD_WEBDAV_RANGE_UNSATISFIED]);
            r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
            r->headers_out.content_length_n = 0;
            ngx_http_send_header(r);
            return ngx_http_send_special(r, NGX_HTTP_LAST);
        }
        range_start = 0;
        range_end = 0;
        send_len = 0;
    } else {
        if (range_end >= sb.st_size) {
            range_end = sb.st_size - 1;
        }
        if (range_start > range_end) {
            XROOTD_WEBDAV_METRIC_INC(
                range_total[XROOTD_WEBDAV_RANGE_UNSATISFIED]);
            r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
            r->headers_out.content_length_n = 0;
            ngx_http_send_header(r);
            return ngx_http_send_special(r, NGX_HTTP_LAST);
        }
        send_len = range_end - range_start + 1;
    }

    if (has_range) {
        XROOTD_WEBDAV_METRIC_INC(range_total[XROOTD_WEBDAV_RANGE_PARTIAL]);
    } else {
        XROOTD_WEBDAV_METRIC_INC(range_total[XROOTD_WEBDAV_RANGE_FULL]);
    }

    if (send_len > 0) {
        webdav_fadvise_willneed(r->connection->log, fd, range_start,
                                (size_t) send_len);
    }

    r->headers_out.status = has_range ? NGX_HTTP_PARTIAL_CONTENT
                                      : NGX_HTTP_OK;
    r->headers_out.content_length_n = send_len;
    r->headers_out.last_modified_time = sb.st_mtime;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    ngx_str_set(&h->value, "application/octet-stream");

    rc = webdav_add_last_modified(r, sb.st_mtime);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_add_etag(r, sb.st_mtime, sb.st_size);
    if (rc != NGX_OK) {
        return rc;
    }

    if (has_range) {
        snprintf(cr_buf, sizeof(cr_buf),
                 "bytes %lld-%lld/%lld",
                 (long long) range_start,
                 (long long) range_end,
                 (long long) sb.st_size);
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        h->hash = 1;
        ngx_str_set(&h->key, "Content-Range");
        h->value.data = ngx_pstrdup(r->pool, &(ngx_str_t) {
            strlen(cr_buf), (u_char *) cr_buf
        });
        h->value.len = strlen(cr_buf);
    }

    rc = ngx_http_send_header(r);
    /* r->header_only is set for HEAD requests — never send a body. */
    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    XROOTD_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) send_len);

    /* Track per-IP-version bytes for this GET body transfer. */
    if (r->connection && r->connection->sockaddr) {
        switch (r->connection->sockaddr->sa_family) {
        case AF_INET6:
            XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total, (size_t) send_len);
            break;
        default:
            XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total, (size_t) send_len);
            break;
        }
    }

    if (send_len == 0) {
        if (!fd_from_table) {
            ngx_close_file(fd);
        }
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file->name.len = ngx_strlen(path);
    b->file->name.data = ngx_pnalloc(r->pool, b->file->name.len + 1);
    if (b->file->name.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_cpystrn(b->file->name.data, (u_char *) path, b->file->name.len + 1);

    b->in_file = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;
    b->file->fd = fd;
    b->file->log = r->connection->log;
    b->file_pos = range_start;
    b->file_last = range_start + send_len;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln != NULL) {
        cln->handler = ngx_pool_cleanup_file;
        clnf = cln->data;
        clnf->fd = fd;
        clnf->name = b->file->name.data;
        clnf->log = r->pool->log;

        if (fd_from_table) {
            clnf->fd = NGX_INVALID_FILE;
        }
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}
