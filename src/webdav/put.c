/*
 * put.c - WebDAV PUT body handling, including optional thread-pool writes.
 */

#include "webdav.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#if (NGX_THREADS)
typedef struct {
    ngx_http_request_t  *r;
    ngx_fd_t             fd;
    const u_char        *data;
    size_t               len;
    off_t                offset;
    ssize_t              nwritten;
    int                  io_errno;
    int                  created;
    char                 path[WEBDAV_MAX_PATH];
} webdav_put_aio_t;

static void webdav_put_aio_thread(void *data, ngx_log_t *log);
static void webdav_put_aio_done(ngx_event_t *ev);

static void
webdav_put_aio_thread(void *data, ngx_log_t *log)
{
    webdav_put_aio_t *t = data;
    size_t            remaining = t->len;
    off_t             off = t->offset;
    const u_char     *p = t->data;

    (void) log;

    t->nwritten = 0;
    t->io_errno = 0;

    while (remaining > 0) {
        ssize_t n = pwrite(t->fd, p, remaining, off);

        if (n < 0) {
            t->io_errno = errno;
            t->nwritten = -1;
            return;
        }

        p += n;
        off += n;
        remaining -= (size_t) n;
        t->nwritten += n;
    }
}

static void
webdav_put_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    webdav_put_aio_t   *t = task->ctx;
    ngx_http_request_t *r = t->r;
    ngx_int_t           status;
    webdav_fd_table_t  *fdt;

    if (t->nwritten < 0 || (size_t) t->nwritten < t->len) {
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                             NGX_LOG_ERR,
                                             (ngx_uint_t) t->io_errno,
                                             "xrootd_webdav: async write() failed for",
                                             t->path);
        ngx_close_file(t->fd);
        fdt = webdav_get_fd_table(r->connection);
        webdav_fd_table_evict(fdt, t->path);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_close_file(t->fd);

    fdt = webdav_get_fd_table(r->connection);
    webdav_fd_table_evict(fdt, t->path);

    status = t->created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    webdav_metrics_finalize_request(r, ngx_http_send_special(r,
                                                             NGX_HTTP_LAST));
}
#endif

/*
 * webdav_handle_put_body — write the request body to the destination file.
 *
 * This is the ngx_http_read_client_request_body() completion callback.  By
 * the time it runs, nginx has either buffered the body in memory
 * (r->request_body->bufs with in_file=0) or spooled it to a temp file
 * (in_file=1).
 *
 * The function chooses one of three write paths in order of preference:
 *   1. Thread-pool async write (NGX_THREADS && memory body only): copies
 *      the body to a single contiguous buffer and dispatches a
 *      webdav_put_aio_t task.  Returns NGX_DONE; webdav_put_aio_done()
 *      sends the response when the write completes.
 *   2. Synchronous spooled-file copy: reads from the nginx temp file in
 *      chunks (webdav_copy_spooled_file).
 *   3. Synchronous in-memory write: pwrite() directly from buf->pos.
 *
 * Preconditions: the caller holds a reference count increment on r->main
 *   (done by ngx_http_read_client_request_body) so nginx will not free the
 *   request while this callback is pending.
 *
 * Ownership: fd is opened here and closed before the response is sent
 *   (or in the async completion handler).  It is NOT pool-managed; do not
 *   rely on pool cleanup to close it.
 *
 * Pool allocation lifetime: all ngx_palloc calls here use r->pool
 *   (request lifetime — freed when the response is finalised).
 */
void
webdav_handle_put_body(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char               path[WEBDAV_MAX_PATH];
    ngx_int_t          rc;
    ngx_fd_t           fd;
    ngx_buf_t         *buf;
    ngx_chain_t       *chain;
    int                created = 0;
    struct stat        sb;
    ngx_int_t          status;
    u_char            *copy_scratch = NULL;
    off_t              write_offset = 0;
    webdav_fd_table_t *fdt;
    size_t             total_body_size = 0;
    int                has_memory_body = 0;
    int                has_spooled_body = 0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
                                             sizeof(path));
    if (rc != NGX_OK) {
        /* RFC 4918 §9.7.1: missing intermediate collection → 409 Conflict */
        if (rc == NGX_HTTP_NOT_FOUND) {
            webdav_metrics_finalize_request(r, NGX_HTTP_CONFLICT);
            return;
        }
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    created = (stat(path, &sb) != 0);

    /* RFC 7232 §3.2 — If-None-Match: * on existing file → 412 */
    if (!created && r->headers_in.if_none_match != NULL) {
        ngx_str_t inm = r->headers_in.if_none_match->value;
        if (inm.len == 1 && inm.data[0] == '*') {
            webdav_metrics_finalize_request(r,
                                            NGX_HTTP_PRECONDITION_FAILED);
            return;
        }
    }

    /* RFC 7232 §3.1 — If-Match: <tag> on existing file, but ETag differs → 412 */
    if (!created && r->headers_in.if_match != NULL) {
        ngx_str_t  im = r->headers_in.if_match->value;
        char       etag_buf[64];

        webdav_etag_str(etag_buf, sizeof(etag_buf), sb.st_mtime, sb.st_size);

        /* Accept both weak W/"..." and the bare "..." forms in the header */
        if (!(im.len == 1 && im.data[0] == '*')) {
            ngx_str_t tag  = { strlen(etag_buf), (u_char *) etag_buf };
            /* strip W/ prefix for comparison if present */
            u_char *tag_data = tag.data;
            size_t  tag_len  = tag.len;
            if (tag_len >= 2 && tag_data[0] == 'W' && tag_data[1] == '/') {
                tag_data += 2;
                tag_len  -= 2;
            }
            u_char *hdr_data = im.data;
            size_t  hdr_len  = im.len;
            if (hdr_len >= 2 && hdr_data[0] == 'W' && hdr_data[1] == '/') {
                hdr_data += 2;
                hdr_len  -= 2;
            }
            if (hdr_len != tag_len
                || ngx_strncmp(hdr_data, tag_data, tag_len) != 0)
            {
                webdav_metrics_finalize_request(r,
                                                NGX_HTTP_PRECONDITION_FAILED);
                return;
            }
        }
    }

    /* Open for write, creating if absent, truncating if present.
     * ngx_open_file argument order: (name, mode, create, access).
     * NGX_FILE_DEFAULT_ACCESS is the 0644 permission octal — it goes in
     * the access (4th) position, NOT the create position.  Passing 0644
     * as create would set O_EXCL (0200 bit) and break concurrent writes. */
    fd = xrootd_open_confined_canon(r->connection->log, conf->root_canon,
                                    path, O_WRONLY | O_CREAT | O_TRUNC,
                                    NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_ENOTDIR) {
            /* RFC 4918 §9.7.1 — PUT to non-existent parent collection is 409 */
            webdav_metrics_finalize_request(r, NGX_HTTP_CONFLICT);
            return;
        }
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                             ngx_errno,
                                             "xrootd_webdav: open() for write failed for",
                                             path);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    fdt = webdav_get_fd_table(r->connection);
    webdav_fd_table_evict(fdt, path);

    if (r->request_body != NULL) {
        for (chain = r->request_body->bufs; chain != NULL; chain = chain->next) {
            buf = chain->buf;
            if (buf->in_file) {
                has_spooled_body = 1;
                if (buf->file_last > buf->file_pos) {
                    total_body_size += (size_t) (buf->file_last
                                                 - buf->file_pos);
                }
            } else if (buf->pos < buf->last) {
                has_memory_body = 1;
                total_body_size += (size_t) (buf->last - buf->pos);
            }
        }

        XROOTD_WEBDAV_METRIC_ADD(bytes_rx_total, total_body_size);

#if (NGX_THREADS)
        if (!has_spooled_body && total_body_size > 0
            && conf->thread_pool != NULL)
        {
            ngx_thread_task_t *task;
            webdav_put_aio_t  *t;
            u_char            *wbuf;

            task = ngx_thread_task_alloc(r->pool, sizeof(webdav_put_aio_t));
            if (task == NULL) {
                ngx_close_file(fd);
                webdav_metrics_finalize_request(r,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            t = task->ctx;
            t->r = r;
            t->fd = fd;
            t->offset = 0;
            t->len = total_body_size;
            t->created = created;
            ngx_cpystrn((u_char *) t->path, (u_char *) path,
                        sizeof(t->path));

            wbuf = ngx_palloc(r->pool, total_body_size);
            if (wbuf == NULL) {
                ngx_close_file(fd);
                webdav_metrics_finalize_request(r,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            {
                u_char *wp = wbuf;

                for (chain = r->request_body->bufs;
                     chain != NULL;
                     chain = chain->next)
                {
                    size_t n;

                    buf = chain->buf;
                    n = (size_t) (buf->last - buf->pos);
                    if (n > 0) {
                        ngx_memcpy(wp, buf->pos, n);
                        wp += n;
                    }
                }
            }
            t->data = wbuf;

            task->handler = webdav_put_aio_thread;
            task->event.handler = webdav_put_aio_done;
            task->event.data = task;

            if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
                ngx_close_file(fd);
                webdav_metrics_finalize_request(r,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            XROOTD_WEBDAV_METRIC_INC(put_body_total[XROOTD_WEBDAV_PUT_THREADED]);
            r->main->count++;
            return;
        }
#endif

        if (has_spooled_body) {
            XROOTD_WEBDAV_METRIC_INC(put_body_total[XROOTD_WEBDAV_PUT_SPOOLED]);
        } else if (has_memory_body) {
            XROOTD_WEBDAV_METRIC_INC(put_body_total[XROOTD_WEBDAV_PUT_MEMORY]);
        } else {
            XROOTD_WEBDAV_METRIC_INC(put_body_total[XROOTD_WEBDAV_PUT_EMPTY]);
        }

        for (chain = r->request_body->bufs; chain != NULL; chain = chain->next) {
            buf = chain->buf;
            if (buf->in_file) {
                if (webdav_copy_spooled_file(r, fd, buf, path, &copy_scratch)
                    != NGX_OK)
                {
                    ngx_close_file(fd);
                    webdav_metrics_finalize_request(
                        r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
            } else if (buf->pos < buf->last) {
                size_t  blen = (size_t) (buf->last - buf->pos);
                ssize_t n = pwrite(fd, buf->pos, blen, write_offset);

                if (n < 0 || (size_t) n < blen) {
                    ngx_http_xrootd_webdav_log_safe_path(
                        r->connection->log, NGX_LOG_ERR, ngx_errno,
                        "xrootd_webdav: write() failed for",
                        path);
                    ngx_close_file(fd);
                    webdav_metrics_finalize_request(
                        r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
                write_offset += n;
            }
        }
    } else {
        XROOTD_WEBDAV_METRIC_INC(put_body_total[XROOTD_WEBDAV_PUT_EMPTY]);
    }

    ngx_close_file(fd);

    status = created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    /* r->header_only is false for PUT (clients don't send HEAD-like PUT);
     * no need to check it here, but ngx_http_send_special handles it. */
    webdav_metrics_finalize_request(r, ngx_http_send_special(r,
                                                             NGX_HTTP_LAST));
}
