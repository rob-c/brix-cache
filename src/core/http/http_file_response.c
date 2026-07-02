/*
 * http_file_response.c - shared HTTP file/range response helpers.
 *
 * WebDAV and S3 both serve local files through nginx's file-backed buffers.
 * Keeping the header allocation, ETag/Content-Range formatting, HEAD handling,
 * and optional fd cleanup in one place prevents the two HTTP protocols from
 * drifting on range and sendfile behavior.
 */

#include "http_file_response.h"
#include "etag.h"
#include "http_headers.h"

#include <stdio.h>
#include <string.h>
#include "core/compat/alloc_guard.h"

/*
 * xrootd_http_chain_append_file_range - append one file-backed ngx_buf_t to a chain.
 *
 * Allocates ngx_buf_t + ngx_file_t from r->pool, sets in_file / file_pos / file_last
 * for [start, end] (inclusive), links it onto the chain tail, and registers a pool
 * cleanup to close fd if close_fd=1.
 */

ngx_int_t
xrootd_http_chain_append_file_range(ngx_http_request_t *r,
    ngx_chain_t **tail, ngx_fd_t fd, const char *path,
    off_t start, off_t end, ngx_flag_t close_fd)
{
    ngx_buf_t               *b;
    ngx_chain_t             *link;
    ngx_pool_cleanup_t      *cln;
    ngx_pool_cleanup_file_t *clnf;
    size_t                   path_len;

    XROOTD_PCALLOC_OR_RETURN(b, r->pool, sizeof(ngx_buf_t), NGX_ERROR);
    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_ERROR;
    }

    path_len = ngx_strlen(path);
    b->file->name.data = ngx_pnalloc(r->pool, path_len + 1);
    if (b->file->name.data == NULL) {
        return NGX_ERROR;
    }
    ngx_cpystrn(b->file->name.data, (u_char *) path, path_len + 1);
    b->file->name.len = path_len;
    b->file->fd  = fd;
    b->file->log = r->connection->log;

    b->file_pos  = start;
    b->file_last = end + 1;
    b->in_file   = 1;

    if (close_fd) {
        cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
        if (cln == NULL) {
            return NGX_ERROR;
        }
        cln->handler = ngx_pool_cleanup_file;
        clnf         = cln->data;
        clnf->fd     = fd;
        clnf->name   = b->file->name.data;
        clnf->log    = r->pool->log;
    }

    link = ngx_alloc_chain_link(r->pool);
    if (link == NULL) {
        return NGX_ERROR;
    }
    link->buf  = b;
    link->next = NULL;

    if (*tail != NULL) {
        (*tail)->next = link;
    }
    *tail = link;

    return NGX_OK;
}

/*
 * xrootd_http_add_etag_header - generate ETag from mtime/size and set as response header.
 *
 * WHAT: Calls xrootd_http_etag_str() to format ETag string, then xrootd_http_set_header()
 *       to insert "ETag" into r->headers_out. Optionally registers h as
 *       r->headers_out.etag for later conditional-request comparison (If-None-Match).
 *
 * WHY: RFC 7232 §2.3 requires servers to emit ETags on responses with payload.
 *      WebDAV PROPFIND and S3 HEAD/GET both need ETag headers. Registering
 *      r->headers_out.etag enables downstream conditional-request checks.
 *
 * HOW: etag_str(mtime, size, flags) → set_header("ETag", etag_buf). If register_not_modified,
 *      sets r->headers_out.etag = h for later ngx_http_check_if_none_match() use.
 */

ngx_int_t
xrootd_http_add_etag_header(ngx_http_request_t *r, time_t mtime, off_t size,
    unsigned etag_flags, ngx_flag_t register_not_modified)
{
    char             etag_buf[64];
    ngx_table_elt_t *h;
    ngx_int_t        rc;

    xrootd_http_etag_str(etag_buf, sizeof(etag_buf), mtime, size, etag_flags);

    rc = xrootd_http_set_header(r, "ETag", etag_buf, &h);
    if (rc != NGX_OK) {
        return rc;
    }

    if (register_not_modified) {
        r->headers_out.etag = h;
    }

    return NGX_OK;
}

/*
 * xrootd_http_add_content_range_header - set Content-Range header for partial responses.
 *
 * WHAT: Formats "bytes start-end/size" into the Content-Range response header via
 *       snprintf and xrootd_http_set_header().
 *
 * WHY: HTTP Range requests (RFC 7233 §4.2) require servers to return 206 Partial
 *      Content with a Content-Range header specifying served byte range and total size.
 *      WebDAV GET/HEAD with Range and S3 GET with Range both use this.
 *
 * HOW: snprintf("bytes %lld-%lld/%lld") → set_header("Content-Range", cr_buf).
 */

ngx_int_t
xrootd_http_add_content_range_header(ngx_http_request_t *r,
    off_t start, off_t end, off_t size)
{
    char cr_buf[80];

    snprintf(cr_buf, sizeof(cr_buf), "bytes %lld-%lld/%lld",
             (long long) start, (long long) end, (long long) size);

    return xrootd_http_set_header(r, "Content-Range", cr_buf, NULL);
}

/*
 * xrootd_http_set_file_headers - set standard file-serving response headers.
 */

ngx_int_t
xrootd_http_set_file_headers(ngx_http_request_t *r,
    time_t mtime, off_t total_size, off_t send_len,
    const char *content_type, unsigned etag_flags,
    int has_range, off_t range_start, off_t range_end)
{
    r->headers_out.status             = has_range ? NGX_HTTP_PARTIAL_CONTENT
                                                  : NGX_HTTP_OK;
    r->headers_out.content_length_n   = send_len;
    r->headers_out.last_modified_time = mtime;

    if (content_type != NULL) {
        if (xrootd_http_set_header(r, "Content-Type", content_type, NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else {
        /* Use nginx types{} hash to map file extension → MIME type.
         * Falls back to application/octet-stream if no match. */
        ngx_http_set_content_type(r);
    }

    /* register_not_modified=1: sets r->headers_out.etag so nginx's built-in
     * not-modified filter can evaluate If-Match / If-None-Match conditionals. */
    if (xrootd_http_add_etag_header(r, mtime, total_size, etag_flags, 1)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (has_range) {
        if (xrootd_http_add_content_range_header(r, range_start, range_end,
                                                 total_size) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * xrootd_http_send_file_range - build file-backed ngx_buf_t for byte range and dispatch.
 *
 * WHAT: Allocates ngx_buf_t + ngx_file_t from r->pool, sets in_file/last_buf,
 *       file_pos=file_last=start+len. Optionally adds pool cleanup (ngx_pool_cleanup_file)
 *       to auto-close fd after response sent. Sends header via ngx_http_send_header(),
 *       then filters chain through nginx output.
 *
 * WHY: WebDAV GET with Range and S3 GET need zero-copy sendfile from disk. This
 *      function handles buffer setup, cleanup registration, and response dispatch
 *      in one call — avoiding duplicated alloc/filter code across modules.
 *
 * HOW: ngx_pcalloc buf+file → set fields (fd, name, pos/last) → if close_fd:
 *      ngx_pool_cleanup_add(ngx_pool_cleanup_file). ngx_http_send_header() →
 *      ngx_http_output_filter(r, &out) or ngx_http_send_special(r, NGX_HTTP_LAST).
 */

ngx_int_t
xrootd_http_send_file_range(ngx_http_request_t *r, ngx_fd_t fd,
    const char *path, off_t start, off_t len, ngx_flag_t close_fd)
{
    ngx_buf_t                *b;
    ngx_chain_t              out;
    ngx_pool_cleanup_t      *cln;
    ngx_pool_cleanup_file_t *clnf;
    ngx_int_t                rc;

    b = NULL;
    clnf = NULL;
    ngx_memzero(&out, sizeof(out));

    if (len > 0) {
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            if (close_fd) {
                ngx_close_file(fd);
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
        if (b->file == NULL) {
            if (close_fd) {
                ngx_close_file(fd);
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->file->name.len = ngx_strlen(path);
        b->file->name.data = ngx_pnalloc(r->pool, b->file->name.len + 1);
        if (b->file->name.data == NULL) {
            if (close_fd) {
                ngx_close_file(fd);
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_cpystrn(b->file->name.data, (u_char *) path,
                    b->file->name.len + 1);

        b->in_file = 1;
        b->last_buf = 1;
        b->last_in_chain = 1;
        b->file->fd = fd;
        b->file->log = r->connection->log;
        b->file_pos = start;
        b->file_last = start + len;

        if (close_fd) {
            cln = ngx_pool_cleanup_add(r->pool,
                                       sizeof(ngx_pool_cleanup_file_t));
            if (cln == NULL) {
                ngx_close_file(fd);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            cln->handler = ngx_pool_cleanup_file;
            clnf = cln->data;
            clnf->fd = fd;
            clnf->name = b->file->name.data;
            clnf->log = r->pool->log;
        }

        out.buf = b;
        out.next = NULL;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) {
        if (close_fd) {
            ngx_close_file(fd);
            if (clnf != NULL) {
                clnf->fd = NGX_INVALID_FILE;
            }
        }
        return rc;
    }

    if (len == 0) {
        if (close_fd) {
            ngx_close_file(fd);
        }
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    return ngx_http_output_filter(r, &out);
}
