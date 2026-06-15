/*
 * put.c - WebDAV PUT body handling, including optional thread-pool writes.
 *
 * Phase 39 (WS8/HTTP-4): the body is written to a staged temp file and atomically
 * renamed onto the final path on success (xrootd_staged_open/commit/abort, the
 * same crash-safe lifecycle S3 PUT uses).  So a client that drops mid-upload, a
 * crash, or a failed inflate never leaves a partial/truncated object at the final
 * path, and a concurrent GET only ever observes the old or the new object — never
 * a half-written one.
 */

#include "webdav.h"
#include "../compat/etag.h"
#include "../compat/http_body.h"
#include "../compat/http_conditionals.h"
#include "../compat/staged_file.h"
#include "../dashboard/dashboard_tracking.h"
#include "../impersonate/lifecycle.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    ngx_http_request_t  *r;
    xrootd_staged_file_t staged;
    size_t               len;
    ssize_t              nwritten;
    int                  io_errno;
    int                  created;
    char                 path[WEBDAV_MAX_PATH];   /* final path (commit target) */
    char                 root_canon[PATH_MAX];    /* confinement root for commit */
} webdav_put_aio_t;

static void webdav_put_aio_thread(void *data, ngx_log_t *log);
static void webdav_put_aio_done(ngx_event_t *ev);

static void
webdav_put_aio_thread(void *data, ngx_log_t *log)
{
    webdav_put_aio_t *t = data;

    (void) log;

    t->io_errno = 0;

    /*
     * Phase 31 W2: stream the body straight from nginx's own request buffers
     * to the staged temp fd — no full-body contiguous copy.  The body for this
     * path is all in-memory bufs anchored in r->pool (the caller gates spooled
     * bodies to the synchronous streaming path), so they are stable for the
     * lifetime of the request (held alive by r->main->count++).  This helper
     * only does pwrite(2), so it is safe to run on the thread pool — no nginx
     * pool allocation or event-loop calls.
     */
    if (xrootd_http_body_write_to_fd(t->r, t->staged.fd, t->path, NULL)
        != NGX_OK)
    {
        t->io_errno = errno;
        t->nwritten = -1;
        return;
    }

    t->nwritten = (ssize_t) t->len;
}

static void
webdav_put_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    webdav_put_aio_t   *t = task->ctx;
    ngx_http_request_t *r = t->r;
    ngx_int_t           status;

    /* Balance the r->main->count++ in webdav_handle_put_body that keeps the
     * request alive across the async thread dispatch. */
    r->main->count--;

    if (t->nwritten < 0 || (size_t) t->nwritten < t->len) {

        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR,
                             (ngx_uint_t) t->io_errno,
                             "xrootd_webdav: async write() failed for: \"%s\"",
                             t->path);
        xrootd_dashboard_http_error(r, "webdav PUT async write failed");
        xrootd_dashboard_http_finish(r);
        /* Abort the staged temp (close + unlink) — the final path is untouched. */
        xrootd_staged_abort(r->connection->log, t->root_canon, &t->staged, 1);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Atomically publish the completed temp onto the final path. */
    if (xrootd_staged_commit(r->connection->log, t->root_canon, &t->staged,
                             t->path) != NGX_OK)
    {
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "xrootd_webdav: async staged commit failed for: "
                             "\"%s\"", t->path);
        xrootd_dashboard_http_error(r, "webdav PUT staged commit failed");
        xrootd_dashboard_http_finish(r);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) t->len);
    xrootd_dashboard_http_finish(r);

    status = t->created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    webdav_metrics_finalize_request(r, ngx_http_send_special(r,
                                                             NGX_HTTP_LAST));
}

/*
 * webdav_handle_put_body — write the request body to the destination file.
 *
 * This is the ngx_http_read_client_request_body() completion callback.  By
 * the time it runs, nginx has either buffered the body in memory
 * (r->request_body->bufs with in_file=0) or spooled it to a temp file
 * (in_file=1).
 *
 * The body is always written to a STAGED temp file (xrootd_staged_open) and
 * atomically committed onto the final path on success (xrootd_staged_commit) or
 * aborted on any error (xrootd_staged_abort) — so a partial/failed/aborted PUT
 * never leaves a readable object at the final path (WS8/HTTP-4).
 *
 * The function chooses one of three write paths in order of preference:
 *   1. Thread-pool async write (NGX_THREADS && memory body only): streams the
 *      body to the staged fd on the pool and commits in webdav_put_aio_done().
 *   2. Synchronous spooled-file copy.
 *   3. Synchronous in-memory write (+ optional inflate).
 *
 * Preconditions: the caller holds a reference count increment on r->main
 *   (done by ngx_http_read_client_request_body) so nginx will not free the
 *   request while this callback is pending.
 *
 * Ownership: the staged temp is opened here.  The async path transfers the
 *   staged struct into the task (committed/aborted in the done handler); the
 *   synchronous paths commit or abort before sending the response.
 *
 * Pool allocation lifetime: all ngx_palloc calls here use r->pool.
 */
static void webdav_put_body_inner(ngx_http_request_t *r);

/*
 * Phase 40: the PUT body is read asynchronously, so the outer dispatch wrapper
 * has already cleared the impersonation principal by the time this callback runs.
 * Re-establish it for the duration of the (synchronous) body write — the staged
 * open (xrootd_staged_open) then routes to the broker and the new file is
 * owned by the mapped user.  No-op unless map mode is active.
 */
void
webdav_handle_put_body(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    xrootd_imp_request_begin(rx != NULL ? rx->identity : NULL);
    webdav_put_body_inner(r);
    xrootd_imp_request_end();
}

static void
webdav_put_body_inner(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char               path[WEBDAV_MAX_PATH];
    ngx_int_t          rc;
    xrootd_staged_file_t staged;
    int                created = 0;
    int                window_bits = 0;
    struct stat        sb;
    ngx_int_t          status;
    xrootd_http_body_summary_t body_summary;
    ngx_http_xrootd_webdav_req_ctx_t *wctx;
    const char        *identity;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon, path,
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

    rc = xrootd_http_check_etag_preconditions(
        r, !created, &sb, XROOTD_ETAG_WEAK, XROOTD_HTTP_COND_WEAK_EQUIV);
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /*
     * Open a staged temp file beside the final path (O_EXCL, unique name, up to
     * 16 attempts).  The body is written here and atomically renamed onto the
     * final path only on success — never exposing a partial object.
     */
    if (xrootd_staged_open(r->connection->log, conf->common.root_canon, path,
                           O_WRONLY, NGX_FILE_DEFAULT_ACCESS, 16, &staged)
        != NGX_OK)
    {
        if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_ENOTDIR) {
            /* RFC 4918 §9.7.1 — PUT to non-existent parent collection is 409 */
            webdav_metrics_finalize_request(r, NGX_HTTP_CONFLICT);
            return;
        }
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "xrootd_webdav: staged open for write failed for: "
                             "\"%s\"", path);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->request_body != NULL) {
        if (xrootd_http_body_summary(r, &body_summary) != NGX_OK) {
            xrootd_staged_abort(r->connection->log, conf->common.root_canon,
                                &staged, 1);
            webdav_metrics_finalize_request(r,
                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        wctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
        identity = (wctx != NULL && wctx->dn[0] != '\0')
                   ? wctx->dn : "anonymous";
        (void) xrootd_dashboard_http_start_identity(r, path, identity, "",
            XROOTD_XFER_PROTO_WEBDAV, XROOTD_XFER_DIR_WRITE, "PUT",
            (int64_t) body_summary.bytes);

        XROOTD_WEBDAV_METRIC_ADD(bytes_rx_total, body_summary.bytes);

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
            && window_bits == 0 && conf->common.thread_pool != NULL)
        {
            ngx_thread_task_t *task;
            webdav_put_aio_t  *t;

            task = ngx_thread_task_alloc(r->pool, sizeof(webdav_put_aio_t));
            if (task == NULL) {
                xrootd_dashboard_http_error(r, "webdav PUT task allocation failed");
                xrootd_dashboard_http_finish(r);
                xrootd_staged_abort(r->connection->log, conf->common.root_canon,
                                    &staged, 1);
                webdav_metrics_finalize_request(r,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            t = task->ctx;
            t->r = r;
            t->staged = staged;        /* transfer staged ownership to the task */
            t->len = body_summary.bytes;
            t->created = created;
            ngx_cpystrn((u_char *) t->path, (u_char *) path, sizeof(t->path));
            ngx_cpystrn((u_char *) t->root_canon,
                        (u_char *) conf->common.root_canon,
                        sizeof(t->root_canon));

            /*
             * Phase 31 W2: no full-body collection — the thread streams the
             * in-memory body bufs straight to the staged fd (see
             * webdav_put_aio_thread); the done handler commits/aborts.
             */

            task->handler = webdav_put_aio_thread;
            task->event.handler = webdav_put_aio_done;
            task->event.data = task;

            if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
                xrootd_dashboard_http_error(r, "webdav PUT task post failed");
                xrootd_dashboard_http_finish(r);
                xrootd_staged_abort(r->connection->log, conf->common.root_canon,
                                    &t->staged, 1);
                webdav_metrics_finalize_request(r,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            XROOTD_WEBDAV_METRIC_INC(put_body_total[XROOTD_WEBDAV_PUT_THREADED]);
            r->main->count++;
            return;
        }

        if (body_summary.has_spooled) {
            XROOTD_WEBDAV_METRIC_INC(put_body_total[XROOTD_WEBDAV_PUT_SPOOLED]);
        } else if (body_summary.has_memory) {
            XROOTD_WEBDAV_METRIC_INC(put_body_total[XROOTD_WEBDAV_PUT_MEMORY]);
        } else {
            XROOTD_WEBDAV_METRIC_INC(put_body_total[XROOTD_WEBDAV_PUT_EMPTY]);
        }

        {
            ngx_int_t  wrc;

            if (window_bits != 0) {
                wrc = xrootd_http_body_inflate_to_fd(r, staged.fd, path,
                                                      window_bits,
                                                      &body_summary);
            } else {
                wrc = xrootd_http_body_write_to_fd(r, staged.fd, path,
                                                    &body_summary);
            }
            if (wrc != NGX_OK) {
                xrootd_dashboard_http_error(r, "webdav PUT body write failed");
                xrootd_dashboard_http_finish(r);
                /* Abort the staged temp — the final path is never touched, so a
                 * failed write (e.g. a corrupt Content-Encoding that fails to
                 * inflate) can never leave a readable partial object. */
                xrootd_staged_abort(r->connection->log, conf->common.root_canon,
                                    &staged, 1);
                webdav_metrics_finalize_request(r,
                    NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
        xrootd_dashboard_http_add(r, (ngx_atomic_int_t) body_summary.bytes);
    } else {
        wctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
        identity = (wctx != NULL && wctx->dn[0] != '\0')
                   ? wctx->dn : "anonymous";
        (void) xrootd_dashboard_http_start_identity(r, path, identity, "",
            XROOTD_XFER_PROTO_WEBDAV, XROOTD_XFER_DIR_WRITE, "PUT", 0);
        XROOTD_WEBDAV_METRIC_INC(put_body_total[XROOTD_WEBDAV_PUT_EMPTY]);
    }

    xrootd_dashboard_http_finish(r);

    /* Atomically publish the staged temp onto the final path (an empty PUT
     * commits an empty file). */
    if (xrootd_staged_commit(r->connection->log, conf->common.root_canon,
                             &staged, path) != NGX_OK)
    {
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "xrootd_webdav: staged commit failed for: \"%s\"",
                             path);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    status = created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    /* r->header_only is false for PUT (clients don't send HEAD-like PUT);
     * no need to check it here, but ngx_http_send_special handles it. */
    webdav_metrics_finalize_request(r, ngx_http_send_special(r,
                                                             NGX_HTTP_LAST));
}
