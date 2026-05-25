/*
 * put.c — S3 PUT handler: body callback, directory-sentinel mkdir,
 *          atomic write via temp file + rename.
 *
 * Thread-pool path (NGX_THREADS): for in-memory bodies, dispatches the
 * pwrite + staged commit to a worker thread via ngx_thread_task_post so the
 * nginx event loop is not blocked during large object writes.
 */
/*
 * ============================================================
 * WHAT: S3 PutObject handler — body callback after client request
 *      is fully read by nginx.
 * ============================================================
 *
 * This file implements the completion callback for S3 PUT requests.
 * ngx_http_s3_handler() sets r->ctx to the resolved filesystem path,
 * then calls ngx_http_read_client_request_body(). When the body is
 * fully received, s3_put_body_handler() fires as the async callback.
 *
 * Two paths:
 *   1. Directory sentinel — key ends with S3_DIR_SENTINEL ("_$folder$")
 *      → mkdir parent + create zero-byte sentinel file.
 *   2. Normal object write — body to temp file via O_EXCL, then rename.
 *      The temp file guarantees atomicity: no concurrent PUT can corrupt
 *      the final path because O_EXCL fails if the tmp file already exists.
 * ============================================================
 *
 * WHY atomic temp+rename:
 *   - If the process crashes mid-write, only the .tmp.{pid}.{random} file
 *     is orphaned (cleaned up by staged_abort). The final path is untouched.
 *   - Clients never see a partially-written object.
 * ============================================================
 *
 * Body write modes:
 *   XROOTD_S3_PUT_EMPTY — no body bytes (e.g. sentinel)
 *   XROOTD_S3_PUT_MEMORY — all buffers in-memory (buf->in_file=0)
 *   XROOTD_S3_PUT_SPOOLED — all buffers spooled to nginx temp files
 *     (buf->in_file=1, read via pread())
 *   XROOTD_S3_PUT_MIXED — combination of both modes
 * ============================================================
 *
 * Security/integrity:
 *   - O_EXCL on temp file prevents concurrent PUT corruption
 *   - Confined canon check via xrootd_open_confined_canon() and
 *     xrootd_staged_commit() (rename confined to root_canon)
 *   - Path escape detection already done in handler.c (s3_resolve_key)
 *   - allow_write config gate checked before body read starts
 */

#include "s3.h"
#include "../compat/http_body.h"
#include "../compat/http_headers.h"
#include "../compat/staged_file.h"
#include "../path/path.h"
#include "../dashboard/dashboard_tracking.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

static void s3_put_finalize_error(ngx_http_request_t *r);
static void s3_put_finalize_empty_ok(ngx_http_request_t *r);

static const char *
s3_dashboard_put_op(ngx_http_request_t *r)
{
    char upload_id[128];
    char part_num[16];

    if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))
        && s3_get_query_param(r, "partNumber", part_num, sizeof(part_num)))
    {
        return "UploadPart";
    }

    return "PutObject";
}

static void
s3_dashboard_identity(ngx_http_s3_loc_conf_t *cf, char *out, size_t outsz)
{
    if (out == NULL || outsz == 0) {
        return;
    }

    if (cf->access_key.len > 0 && cf->access_key.data != NULL) {
        size_t n = cf->access_key.len < outsz - 1
                   ? cf->access_key.len
                   : outsz - 1;
        ngx_memcpy(out, cf->access_key.data, n);
        out[n] = '\0';
        return;
    }

    ngx_cpystrn((u_char *) out, (u_char *) "anonymous", outsz);
}

typedef struct {
    ngx_http_request_t   *r;
    xrootd_staged_file_t  staged;
    const u_char         *data;
    size_t                len;
    ssize_t               nwritten;
    int                   io_errno;
    ngx_uint_t            body_mode;
    size_t                body_bytes;
    char                  final_path[PATH_MAX];
    char                  root_canon[PATH_MAX];
} s3_put_aio_t;

static void
s3_put_aio_thread(void *data, ngx_log_t *log)
{
    s3_put_aio_t *t = data;
    size_t        remaining = t->len;
    off_t         off = 0;
    const u_char *p = t->data;

    (void) log;

    t->nwritten = 0;
    t->io_errno = 0;

    while (remaining > 0) {
        ssize_t n = pwrite(t->staged.fd, p, remaining, off);
        if (n < 0) {
            t->io_errno = errno;
            t->nwritten = -1;
            return;
        }
        p         += n;
        off       += n;
        remaining -= (size_t) n;
        t->nwritten += n;
    }
}

static void
s3_put_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    s3_put_aio_t       *t = task->ctx;
    ngx_http_request_t *r = t->r;
    ngx_log_t          *log = r->connection->log;

    if (t->nwritten < 0 || (size_t) t->nwritten < t->len) {
        xrootd_log_safe_path(log, NGX_LOG_ERR,
                             (ngx_uint_t) t->io_errno,
                             "s3: async write() failed for: \"%s\"",
                             t->final_path);
        xrootd_staged_abort(log, t->root_canon, &t->staged, 1);
        s3_put_finalize_error(r);
        return;
    }

    ngx_close_file(t->staged.fd);
    t->staged.fd = NGX_INVALID_FILE;

    if (xrootd_staged_commit(log, t->root_canon, &t->staged,
                             t->final_path) != NGX_OK)
    {
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "s3: async staged commit to \"%s\" failed",
                             t->final_path);
        s3_put_finalize_error(r);
        return;
    }

    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) t->body_bytes);
    XROOTD_S3_METRIC_ADD(bytes_rx_total, t->body_bytes);
    XROOTD_S3_METRIC_INC(put_body_total[t->body_mode]);
    s3_put_finalize_empty_ok(r);
}
/*
 * s3_put_body_mode — classify the body into one of four modes.
 *
 * WHY this classification:
 *   Prometheus metrics track put operations by body mode so we can see
 *   how much traffic is in-memory vs spooled. The enum values are used
 *   as indices into XROOTD_S3_METRIC_INC(put_body_total[...]).
 */

static ngx_uint_t
s3_put_body_mode(const xrootd_http_body_summary_t *summary)
{
    if (summary->has_spooled && summary->has_memory) {
        return XROOTD_S3_PUT_MIXED;
    }
    if (summary->has_spooled) {
        return XROOTD_S3_PUT_SPOOLED;
    }
    if (summary->has_memory) {
        return XROOTD_S3_PUT_MEMORY;
    }
    return XROOTD_S3_PUT_EMPTY;
}
/*
 * s3_put_finalize_error — send 500 and increment internal-error metric.
 *
 * Called from any failure path inside the handler. The response is final;
 * this function does not return NGX_DONE (the caller already incremented
 * r->main->count via ngx_http_read_client_request_body).
 */

static void
s3_put_finalize_error(ngx_http_request_t *r)
{
    xrootd_dashboard_http_error(r, "s3 write failed");
    xrootd_dashboard_http_finish(r);
    XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT,
                                       NGX_HTTP_INTERNAL_SERVER_ERROR);
}

static void
s3_put_finalize_empty_ok(ngx_http_request_t *r)
{
    ngx_int_t rc;

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);

    rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    xrootd_dashboard_http_finish(r);
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT, rc);
}

static void
s3_put_finalize_ok(ngx_http_request_t *r, size_t body_bytes,
    ngx_uint_t body_mode)
{
    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) body_bytes);
    XROOTD_S3_METRIC_ADD(bytes_rx_total, body_bytes);
    XROOTD_S3_METRIC_INC(put_body_total[body_mode]);
    s3_put_finalize_empty_ok(r);
}

/*
 * s3_put_finalize_ok — send 200 with ETag header and update metrics.
 *
 * Parameters:
 *   body_bytes   — total bytes written from the client request body
 *   body_mode    — classification enum (XROOTD_S3_PUT_*), used as metric index
 *
 * Flow:
 *   1. Increment bytes_rx_total by body_bytes
 *   2. Increment put_body_total[body_mode]
 *   3. Call s3_put_finalize_empty_ok() which sends the HTTP response
 */
/*
 * s3_put_body_handler — ngx_http_read_client_request_body() completion
 * callback for S3 PutObject.
 *
 * Retrieves the filesystem path from the per-request module context (set by
 * ngx_http_s3_handler before calling ngx_http_read_client_request_body).
 *
 * Special case — directory sentinels: S3 clients represent directories as
 * zero-byte objects whose key ends with the S3_DIR_SENTINEL suffix (typically
 * "_$folder$").  These are handled by creating the real directory rather than
 * a file.
 *
 * Normal case: write body to a temp file (O_EXCL for atomicity), then rename
 * onto the final path.  On any error the temp file is unlinked.
 *
 * Ownership: the response is finalised via s3_put_finalize_ok() which calls
 *   ngx_http_send_header() and ngx_http_send_special().  The function must not
 *   return NGX_DONE (the caller already incremented r->main->count via
 *   ngx_http_read_client_request_body).
 */
void
s3_put_body_handler(ngx_http_request_t *r)
{
    u_char              *fs_path;
    ngx_http_s3_loc_conf_t *cf;
    int                  fd = -1;
    int                  is_sentinel;
    int                  window_bits = 0;
    size_t               body_bytes = 0;
    ngx_uint_t           body_mode = XROOTD_S3_PUT_EMPTY;
    xrootd_staged_file_t staged;
    xrootd_http_body_summary_t body_summary;
    char                 identity[128];

    cf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    fs_path = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);

    if (fs_path == NULL) {
        s3_put_finalize_error(r);
        return;
    }

    /* Check for directory sentinel */
    {
        size_t plen = ngx_strlen(fs_path);
        size_t slen = sizeof(S3_DIR_SENTINEL) - 1;
        is_sentinel = (plen >= slen
            && ngx_strncmp(fs_path + plen - slen,
                           (u_char *) S3_DIR_SENTINEL, slen) == 0);
    }

    if (is_sentinel) {
        /* Create the directory that the sentinel lives in */
        char parent[PATH_MAX];
        size_t plen = ngx_strlen(fs_path);
        if (plen >= sizeof(parent)) {
            s3_put_finalize_error(r);
            return;
        }
        memcpy(parent, fs_path, plen + 1);
        char *slash = strrchr(parent, '/');
        if (slash != NULL) {
            *slash = '\0';
        }
        if (xrootd_mkdir_confined_canon(r->connection->log, cf->common.root_canon,
                                        parent, 0755) != 0
            && errno != EEXIST)
        {
            xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                                 "s3: mkdir(\"%s\") failed", parent);
            s3_put_finalize_error(r);
            return;
        }

        /* Write the zero-byte sentinel */
        fd = xrootd_open_confined_canon(r->connection->log, cf->common.root_canon,
                                        (const char *) fs_path,
                                        O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                                 "s3: open(\"%s\") for sentinel failed",
                                 (const char *) fs_path);
            s3_put_finalize_error(r);
            return;
        }
        close(fd);

        s3_dashboard_identity(cf, identity, sizeof(identity));
        (void) xrootd_dashboard_http_start_identity(r, (const char *) fs_path,
            identity, "", XROOTD_XFER_PROTO_S3, XROOTD_XFER_DIR_WRITE,
            "PutObjectSentinel", 0);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_DIR_SENTINEL]);
        XROOTD_S3_METRIC_INC(put_body_total[XROOTD_S3_PUT_EMPTY]);
        s3_put_finalize_empty_ok(r);
        return;
    }

    /* Create parent directories if needed using the shared confined mkdir helper. */
    {
        char   parent[PATH_MAX];
        char  *last_slash;
        size_t flen = strlen((const char *) fs_path);

        if (flen < sizeof(parent)) {
            memcpy(parent, fs_path, flen + 1);
            last_slash = strrchr(parent, '/');
            if (last_slash && last_slash != parent) {
                *last_slash = '\0';
                if (xrootd_mkdir_recursive_confined_canon(
                        r->connection->log, cf->common.root_canon,
                        parent, 0755, NULL) != 0
                    && errno != EEXIST) {
                    xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                         ngx_errno,
                                         "s3: mkdirs_for(\"%s\") failed",
                                         (const char *) fs_path);
                    s3_put_finalize_error(r);
                    return;
                }
            }
        }
    }

    if (xrootd_staged_open(r->connection->log, cf->common.root_canon,
                           (const char *) fs_path, O_WRONLY, 0600, 16,
                           &staged) != NGX_OK)
    {
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "s3: staged open for \"%s\" failed",
                             (const char *) fs_path);
        s3_put_finalize_error(r);
        return;
    }

    if (xrootd_http_body_summary(r, &body_summary) != NGX_OK) {
        xrootd_staged_abort(r->connection->log, cf->common.root_canon, &staged, 1);
        s3_put_finalize_error(r);
        return;
    }

    body_bytes = body_summary.bytes;
    body_mode = s3_put_body_mode(&body_summary);
    s3_dashboard_identity(cf, identity, sizeof(identity));
    (void) xrootd_dashboard_http_start_identity(r, (const char *) fs_path,
        identity, "", XROOTD_XFER_PROTO_S3, XROOTD_XFER_DIR_WRITE,
        s3_dashboard_put_op(r), (int64_t) body_bytes);

    {
        ngx_table_elt_t  *ce = xrootd_http_find_header(
            r, "Content-Encoding", sizeof("Content-Encoding") - 1);
        if (ce != NULL) {
            if (ce->value.len == 4
                && ngx_strncasecmp(ce->value.data,
                                   (u_char *) "gzip", 4) == 0)
            {
                window_bits = 15 + 16;
            } else if (ce->value.len == 7
                       && ngx_strncasecmp(ce->value.data,
                                          (u_char *) "deflate", 7) == 0)
            {
                window_bits = 15;
            }
        }
    }

    if (!body_summary.has_spooled && body_summary.bytes > 0
        && window_bits == 0 && cf->common.thread_pool != NULL)
    {
        ngx_thread_task_t *task;
        s3_put_aio_t      *t;
        u_char            *wbuf;
        ngx_buf_t         *buf;
        ngx_chain_t       *chain;

        task = ngx_thread_task_alloc(r->pool, sizeof(s3_put_aio_t));
        if (task == NULL) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon, &staged, 1);
            s3_put_finalize_error(r);
            return;
        }

        t = task->ctx;
        t->r         = r;
        t->staged    = staged;
        t->len       = body_summary.bytes;
        t->body_mode = body_mode;
        t->body_bytes = body_bytes;
        ngx_cpystrn((u_char *) t->final_path, fs_path, sizeof(t->final_path));
        ngx_cpystrn((u_char *) t->root_canon,
                    (u_char *) cf->common.root_canon, sizeof(t->root_canon));

        wbuf = ngx_palloc(r->pool, body_summary.bytes);
        if (wbuf == NULL) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon, &staged, 1);
            s3_put_finalize_error(r);
            return;
        }

        {
            u_char *wp = wbuf;
            for (chain = r->request_body->bufs; chain != NULL;
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

        task->handler       = s3_put_aio_thread;
        task->event.handler = s3_put_aio_done;
        task->event.data    = task;

        if (ngx_thread_task_post(cf->common.thread_pool, task) != NGX_OK) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon, &staged, 1);
            s3_put_finalize_error(r);
            return;
        }

        r->main->count++;
        return;
    }

    {
        ngx_int_t  wrc;

        if (window_bits != 0) {
            wrc = xrootd_http_body_inflate_to_fd(r, staged.fd,
                                                  (const char *) fs_path,
                                                  window_bits, &body_summary);
        } else {
            wrc = xrootd_http_body_write_to_fd(r, staged.fd,
                                                (const char *) fs_path,
                                                &body_summary);
        }
        if (wrc != NGX_OK) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                &staged, 1);
            s3_put_finalize_error(r);
            return;
        }
    }

    if (xrootd_staged_commit(r->connection->log, cf->common.root_canon, &staged,
                             (const char *) fs_path) != NGX_OK)
    {
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "s3: staged commit to \"%s\" failed",
                             (const char *) fs_path);
        s3_put_finalize_error(r);
        return;
    }

    /* S3 API requires ETag on PutObject 200 response */
    {
        struct stat  final_sb;
        char         etag_buf[48];

        if (stat((const char *) fs_path, &final_sb) == 0) {
            s3_etag(&final_sb, etag_buf, sizeof(etag_buf));
            (void) s3_set_header(r, "ETag", etag_buf);
        }
    }

    s3_put_finalize_ok(r, body_bytes, body_mode);
}
