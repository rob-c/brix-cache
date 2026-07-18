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
 * brix_http_chain_append_file_range - append one file-backed ngx_buf_t to a chain.
 *
 * Allocates ngx_buf_t + ngx_file_t from r->pool, sets in_file / file_pos / file_last
 * for [start, end] (inclusive), links it onto the chain tail, and registers a pool
 * cleanup to close fd if close_fd=1.
 */

ngx_int_t
brix_http_chain_append_file_range(ngx_http_request_t *r,
    ngx_chain_t **tail, ngx_fd_t fd, const char *path,
    off_t start, off_t end, ngx_flag_t close_fd)
{
    ngx_buf_t               *b;
    ngx_chain_t             *link;
    ngx_pool_cleanup_t      *cln;
    ngx_pool_cleanup_file_t *clnf;
    size_t                   path_len;

    BRIX_PCALLOC_OR_RETURN(b, r->pool, sizeof(ngx_buf_t), NGX_ERROR);
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
 * brix_http_add_etag_header - generate ETag from mtime/size and set as response header.
 *
 * WHAT: Calls brix_http_etag_str() to format ETag string, then brix_http_set_header()
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
brix_http_add_etag_header(ngx_http_request_t *r, time_t mtime, off_t size,
    unsigned etag_flags, ngx_flag_t register_not_modified)
{
    char             etag_buf[64];
    ngx_table_elt_t *h;
    ngx_int_t        rc;

    brix_http_etag_str(etag_buf, sizeof(etag_buf), mtime, size, etag_flags);

    rc = brix_http_set_header(r, "ETag", etag_buf, &h);
    if (rc != NGX_OK) {
        return rc;
    }

    if (register_not_modified) {
        r->headers_out.etag = h;
    }

    return NGX_OK;
}

/*
 * brix_http_add_content_range_header - set Content-Range header for partial responses.
 *
 * WHAT: Formats "bytes start-end/size" into the Content-Range response header via
 *       snprintf and brix_http_set_header().
 *
 * WHY: HTTP Range requests (RFC 7233 §4.2) require servers to return 206 Partial
 *      Content with a Content-Range header specifying served byte range and total size.
 *      WebDAV GET/HEAD with Range and S3 GET with Range both use this.
 *
 * HOW: snprintf("bytes %lld-%lld/%lld") → set_header("Content-Range", cr_buf).
 */

ngx_int_t
brix_http_add_content_range_header(ngx_http_request_t *r,
    off_t start, off_t end, off_t size)
{
    char cr_buf[80];

    snprintf(cr_buf, sizeof(cr_buf), "bytes %lld-%lld/%lld",
             (long long) start, (long long) end, (long long) size);

    return brix_http_set_header(r, "Content-Range", cr_buf, NULL);
}

/*
 * brix_http_set_file_headers - set standard file-serving response headers.
 */

ngx_int_t
brix_http_set_file_headers(ngx_http_request_t *r,
    time_t mtime, off_t total_size, off_t send_len,
    const char *content_type, unsigned etag_flags,
    int has_range, off_t range_start, off_t range_end)
{
    r->headers_out.status             = has_range ? NGX_HTTP_PARTIAL_CONTENT
                                                  : NGX_HTTP_OK;
    r->headers_out.content_length_n   = send_len;
    r->headers_out.last_modified_time = mtime;

    if (content_type != NULL) {
        if (brix_http_set_header(r, "Content-Type", content_type, NULL)
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
    if (brix_http_add_etag_header(r, mtime, total_size, etag_flags, 1)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (has_range) {
        if (brix_http_add_content_range_header(r, range_start, range_end,
                                                 total_size) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * brix_http_build_range_buf - allocate and populate a file-backed ngx_buf_t.
 *
 * WHAT: Allocates ngx_buf_t + ngx_file_t + a null-terminated copy of path from
 *       r->pool and fills them so the buffer sends [start, start+len) of fd via
 *       sendfile as the final buffer of the response. Returns the buffer, or NULL
 *       on any allocation failure. Performs no fd cleanup or closing.
 *
 * WHY: Isolating pure buffer construction from fd-lifecycle handling keeps the
 *      send orchestrator flat: this helper only allocates and never has to know
 *      whether the fd is owned (close_fd) or borrowed.
 *
 * HOW: (1) ngx_pcalloc the buf, then its ngx_file_t; (2) copy path into a pool
 *      buffer sized name.len+1; (3) set in_file/last_buf/last_in_chain plus
 *      file fd, log, and file_pos/file_last from start and len.
 */

static ngx_buf_t *
brix_http_build_range_buf(ngx_http_request_t *r, ngx_fd_t fd,
    const char *path, off_t start, off_t len)
{
    ngx_buf_t *b;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NULL;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NULL;
    }

    b->file->name.len = ngx_strlen(path);
    b->file->name.data = ngx_pnalloc(r->pool, b->file->name.len + 1);
    if (b->file->name.data == NULL) {
        return NULL;
    }
    ngx_cpystrn(b->file->name.data, (u_char *) path, b->file->name.len + 1);

    b->in_file = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;
    b->file->fd = fd;
    b->file->log = r->connection->log;
    b->file_pos = start;
    b->file_last = start + len;

    return b;
}

/*
 * brix_http_arm_fd_cleanup - register a pool cleanup that closes fd after send.
 *
 * WHAT: Adds an ngx_pool_cleanup_file handler on r->pool for fd, using name for
 *       error logging. On success returns NGX_OK and stores the cleanup record in
 *       *clnf_out (so the caller can disarm it); on allocation failure returns
 *       NGX_ERROR and leaves *clnf_out untouched.
 *
 * WHY: When close_fd is set the fd is owned by this response; a pool cleanup
 *      guarantees it is closed exactly once when the request pool is destroyed.
 *      Handing the record back lets the header-failure path disarm it before it
 *      closes the fd a second time.
 *
 * HOW: ngx_pool_cleanup_add(sizeof ngx_pool_cleanup_file_t) → wire handler,
 *      fd, name, log → publish via *clnf_out.
 */

static ngx_int_t
brix_http_arm_fd_cleanup(ngx_http_request_t *r, ngx_fd_t fd,
    u_char *name, ngx_pool_cleanup_file_t **clnf_out)
{
    ngx_pool_cleanup_t      *cln;
    ngx_pool_cleanup_file_t *clnf;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_pool_cleanup_file;
    clnf = cln->data;
    clnf->fd = fd;
    clnf->name = name;
    clnf->log = r->pool->log;

    *clnf_out = clnf;
    return NGX_OK;
}

/*
 * brix_http_prepare_file_send - build the send buffer and arm fd cleanup.
 *
 * WHAT: Builds the file-backed range buffer for [start, start+len) and, when
 *       close_fd is set, registers a pool cleanup to close fd. Returns NGX_OK with
 *       *b_out (and *clnf_out when close_fd) populated. On any failure it closes fd
 *       when close_fd is set and returns NGX_HTTP_INTERNAL_SERVER_ERROR.
 *
 * WHY: Concentrates the "allocate then own the fd" error handling — closing the
 *      owned fd on every failure branch — so the top-level function stays a flat
 *      sequence of steps.
 *
 * HOW: (1) brix_http_build_range_buf(); NULL → close owned fd, return 500.
 *      (2) if close_fd: brix_http_arm_fd_cleanup(); failure → close fd, return 500.
 */

static ngx_int_t
brix_http_prepare_file_send(ngx_http_request_t *r, ngx_fd_t fd,
    const char *path, off_t start, off_t len, ngx_flag_t close_fd,
    ngx_buf_t **b_out, ngx_pool_cleanup_file_t **clnf_out)
{
    ngx_buf_t *b;

    b = brix_http_build_range_buf(r, fd, path, start, len);
    if (b == NULL) {
        if (close_fd) {
            ngx_close_file(fd);
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (close_fd) {
        if (brix_http_arm_fd_cleanup(r, fd, b->file->name.data, clnf_out)
            != NGX_OK)
        {
            ngx_close_file(fd);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    *b_out = b;
    return NGX_OK;
}

/*
 * brix_http_send_file_range - build file-backed ngx_buf_t for byte range and dispatch.
 *
 * WHAT: For len>0 allocates a file-backed buffer over [start, start+len), optionally
 *       registering a pool cleanup that closes fd after the response is sent. Sends the
 *       header, then either filters the buffer through nginx output (len>0) or emits the
 *       last-buf special (len==0). Returns the send_header/output_filter status.
 *
 * WHY: WebDAV GET with Range and S3 GET need zero-copy sendfile from disk. This
 *      function handles buffer setup, cleanup registration, and response dispatch
 *      in one call — avoiding duplicated alloc/filter code across modules.
 *
 * HOW: (1) len>0 → brix_http_prepare_file_send() builds buf + arms cleanup, wire into
 *      out chain. (2) ngx_http_send_header(); on error or header_only close owned fd and
 *      disarm the cleanup, return status. (3) len==0 → close owned fd, ngx_http_send_special.
 *      (4) else ngx_http_output_filter(r, &out).
 */

ngx_int_t
brix_http_send_file_range(ngx_http_request_t *r, ngx_fd_t fd,
    const char *path, off_t start, off_t len, ngx_flag_t close_fd)
{
    ngx_buf_t                *b;
    ngx_chain_t              out;
    ngx_pool_cleanup_file_t *clnf;
    ngx_int_t                rc;

    b = NULL;
    clnf = NULL;
    ngx_memzero(&out, sizeof(out));

    if (len > 0) {
        rc = brix_http_prepare_file_send(r, fd, path, start, len, close_fd,
                                         &b, &clnf);
        if (rc != NGX_OK) {
            return rc;
        }

        out.buf = b;
        out.next = NULL;
    }

    rc = ngx_http_send_header(r);
    /* rc > NGX_OK is a special-response code from the header-filter chain (e.g.
     * nginx's core range filter mapping a malformed "bytes=" spec to 416): the
     * chain short-circuited WITHOUT writing header bytes, so we must NOT push a
     * body — return the code and let ngx_http_finalize_request emit the error
     * response. Sending the file here would put raw body bytes on a wire that
     * has no status line, i.e. an HTTP/0.9 corruption. (Canonical nginx static-
     * handler guard; the memory-backed sibling in file_serve.c already has it.) */
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
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
