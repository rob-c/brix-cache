/*
 * put_body.c - WebDAV PUT body-write phase (split from put.c).
 *
 * Getting the request body onto the open staged temp: the thread-pool async
 * offload (task + done handler), the Content-Encoding codec gate, the
 * synchronous write dispatch, and the checksum-on-ingest persistence (§8.3)
 * shared with the resumable and sync-commit paths.
 */

#include "webdav.h"
#include "core/http/etag.h"
#include "core/http/http_body.h"
#include "core/compat/integrity_info.h"
#include "core/http/http_conditionals.h"
#include "core/compat/range.h"
#include "core/compat/staged_file.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "fs/vfs/vfs.h"
#include "fs/xfer/xfer.h"   /* brix_xfer_finish — unified transfer ledger */
#include "auth/impersonate/lifecycle.h"
#include "fs/path/path.h"
#include "core/compat/cstr.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "put_internal.h"

typedef struct {
    ngx_http_request_t  *r;
    brix_vfs_writer_t   *writer;  /* VFS-owned write session (pool-allocated) */
    size_t               len;
    ssize_t              nwritten;
    int                  io_errno;
    int                  created;
    char                 path[WEBDAV_MAX_PATH];   /* final path (commit target) */
} webdav_put_aio_t;

/*
 * webdav_put_persist_checksums — §8.3 checksum-on-ingest.
 *
 * After a successful PUT commit, when brix_webdav_checksum_on_write names one or
 * more algorithms, compute+persist each digest on the freshly committed file via
 * the integrity service (xattr, or .cks sidecar fallback §8.2). Best-effort and
 * opt-in (default off): any failure is ignored — the digest simply stays lazy.
 * Synchronous (the operator opts in knowing the cost); large-file async offload is
 * a future refinement.
 */
void
webdav_put_persist_checksums(ngx_http_request_t *r, const char *path)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char  algs[256];
    char *save = NULL, *tok;
    int   fd;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (conf->checksum_on_write.len == 0
        || brix_str_cbuf(algs, sizeof(algs), &conf->checksum_on_write) == NULL)
    {
        return;
    }

    /* Re-open the just-committed export file through the VFS (confined beneath
     * the export root, impersonation-aware) to compute its digests. */
    fd = brix_vfs_open_fd(r->connection->log, conf->common.root_canon, path,
                           O_RDONLY, 0);
    if (fd < 0) {
        return;
    }
    for (tok = strtok_r(algs, ", \t", &save); tok != NULL;
         tok = strtok_r(NULL, ", \t", &save))
    {
        brix_integrity_info_t info;
        brix_integrity_opts_t o;
        ngx_memzero(&o, sizeof(o));
        o.allow_xattr_cache    = 1;
        o.update_xattr_cache   = 1;
        o.require_regular_file = 1;
        (void) brix_integrity_get_fd(r->connection->log, fd, NULL, path, tok,
                                       &o, &info);
    }
    (void) close(fd);
}

static void
webdav_put_aio_thread(void *data, ngx_log_t *log)
{
    webdav_put_aio_t *t = data;

    (void) log;

    t->io_errno = 0;

    /*
     * Phase 31 W2: stream the body straight from nginx's own request buffers
     * into the write session — no full-body contiguous copy.  The body for this
     * path is all in-memory bufs anchored in r->pool (the caller gates spooled
     * bodies to the synchronous streaming path), so they are stable for the
     * lifetime of the request (held alive by r->main->count++).  The writer does
     * only pwrite(2)/staged-write here (the commit + verify read-back are deferred
     * to the done handler on the event thread), so it is safe on the thread pool —
     * no nginx pool allocation or event-loop calls.  The writer dispatches the
     * POSIX-temp-fd vs driver-object path internally.
     */
    if (brix_http_body_write_to_writer(t->r, t->writer) != NGX_OK) {
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

        brix_log_safe_path(r->connection->log, NGX_LOG_ERR,
                             (ngx_uint_t) t->io_errno,
                             "brix_webdav: async write() failed for: \"%s\"",
                             t->path);
        brix_dashboard_http_error(r, "webdav PUT async write failed");
        brix_dashboard_http_finish(r);
        /* Abort the session (close + unlink temp) — the final path is untouched. */
        brix_vfs_writer_abort(t->writer);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Client->server body integrity: verify any asserted ingest digest over the
     * fully-staged bytes before publishing (or refuse a digest-less PUT under
     * require_digest). A rejection aborts the session — the final path is never
     * touched, so poisoned bytes never land. */
    {
        ngx_int_t vrc = webdav_put_verify_ingest_digest(r,
            ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module),
            t->writer, (const char *) t->path);
        if (vrc != NGX_OK) {
            brix_log_safe_path(r->connection->log, NGX_LOG_ERR, 0,
                "brix_webdav: async PUT ingest digest rejected for: \"%s\"",
                t->path);
            brix_dashboard_http_error(r, "webdav PUT ingest digest mismatch");
            brix_dashboard_http_finish(r);
            brix_vfs_writer_abort(t->writer);
            webdav_metrics_finalize_request(r, (ngx_uint_t) vrc);
            return;
        }
    }

    /* Atomically publish the completed temp onto the final path (folding the
     * verify read-back when the export opts in; a mismatch unlinks + fails). */
    if (brix_vfs_writer_commit(t->writer) != NGX_OK) {
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "brix_webdav: async staged commit failed for: "
                             "\"%s\"", t->path);
        /* A direct WebDAV PUT is a STAGE-class ingest — record the failed
         * publish in the unified ledger (mirrors webdav_put_commit). */
        brix_xfer_finish(BRIX_XFER_STAGE, "in", (const char *) t->path, NULL,
                         t->len, BRIX_XFER_COMMIT_ERR, ngx_errno,
                         r->connection->log);
        brix_dashboard_http_error(r, "webdav PUT staged commit failed");
        brix_dashboard_http_finish(r);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    brix_dashboard_http_add(r, (ngx_atomic_int_t) t->len);
    brix_dashboard_http_finish(r);

    /* Unified transfer ledger: the async PUT publish (mirrors the sync path). */
    brix_xfer_finish(BRIX_XFER_STAGE, "in", (const char *) t->path, NULL,
                     t->len, BRIX_XFER_OK, 0, r->connection->log);

    webdav_put_persist_checksums(r, (const char *) t->path);   /* §8.3 */

    status = t->created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    webdav_send_status_only(r, (ngx_uint_t) status);
}

/*
 * Shared state for the body-write phase (thread offload, codec select, and the
 * synchronous write) — bundled so the phase helpers thread one struct instead
 * of a long argument list.  `body_summary` is the mutable working summary the
 * decode path may update; the other fields are the resolved staged target and
 * write parameters.
 */
typedef struct {
    const char               *path;         /* final commit-target path       */
    brix_vfs_writer_t        *writer;       /* open write session             */
    brix_http_body_summary_t  body_summary; /* body shape/byte count          */
    brix_codec_id_t           put_codec;    /* Content-Encoding codec (or id) */
    int                       created;      /* 1 = new file (→ 201 on commit) */
} webdav_put_body_ctx_t;

/*
 * webdav_put_try_threaded — offload an in-memory body write to the thread pool.
 *
 * WHAT: When the body is entirely in memory, non-empty, identity-coded, and a
 *   thread pool is configured, allocates the AIO task, transfers staged
 *   ownership into it, and posts it — returning WEBDAV_PUT_DONE (the done
 *   handler commits/aborts and sends the response).  Returns
 *   WEBDAV_PUT_CONTINUE only when the threaded path does not apply (caller falls
 *   through to the synchronous write); a task alloc/post failure aborts the
 *   staged temp, sends 500, and returns WEBDAV_PUT_DONE.
 *
 * WHY: Isolates the async offload decision + task lifecycle so the synchronous
 *   fallback in the orchestrator stays linear.  The r->main->count++ that keeps
 *   the request alive across the dispatch and the ownership transfer are
 *   preserved exactly.
 *
 * HOW:
 *   1. If the threaded preconditions do not hold, return CONTINUE.
 *   2. Allocate the task; on failure abort staged, finalize 500, return DONE.
 *   3. Populate the task ctx (r, staged, len, created, path).
 *   4. Bind + post; on post failure abort staged, finalize 500, return DONE.
 *   5. On success bump the threaded metric, r->main->count++, return DONE.
 */
static webdav_put_step_t
webdav_put_try_threaded(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const webdav_put_body_ctx_t *bctx)
{
    ngx_thread_task_t *task;
    webdav_put_aio_t  *t;

    if (bctx->body_summary.has_spooled || bctx->body_summary.bytes == 0
        || bctx->put_codec != BRIX_CODEC_IDENTITY
        || conf->common.thread_pool == NULL)
    {
        return WEBDAV_PUT_CONTINUE;
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(webdav_put_aio_t));
    if (task == NULL) {
        brix_dashboard_http_error(r, "webdav PUT task allocation failed");
        brix_dashboard_http_finish(r);
        brix_vfs_writer_abort(bctx->writer);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return WEBDAV_PUT_DONE;
    }

    t = task->ctx;
    t->r = r;
    t->writer = bctx->writer;  /* transfer session ownership to the task */
    t->len = bctx->body_summary.bytes;
    t->created = bctx->created;
    ngx_cpystrn((u_char *) t->path, (u_char *) bctx->path, sizeof(t->path));

    /*
     * Phase 31 W2: no full-body collection — the thread streams the
     * in-memory body bufs straight to the staged fd (see
     * webdav_put_aio_thread); the done handler commits/aborts.
     */

    brix_task_bind(task, webdav_put_aio_thread, webdav_put_aio_done);

    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        brix_dashboard_http_error(r, "webdav PUT task post failed");
        brix_dashboard_http_finish(r);
        brix_vfs_writer_abort(t->writer);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return WEBDAV_PUT_DONE;
    }

    BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_THREADED]);
    r->main->count++;
    return WEBDAV_PUT_DONE;
}

/*
 * webdav_put_select_codec — pick the body's Content-Encoding codec.
 *
 * WHAT: Reads the Content-Encoding header; sets `bctx->put_codec` to the decoded
 *   codec id and returns WEBDAV_PUT_CONTINUE, or returns WEBDAV_PUT_DONE after
 *   aborting the staged temp and sending 415 for an unknown/not-compiled-in
 *   coding.  A missing header leaves `bctx->put_codec` as identity.
 *
 * WHY: Never store undecoded bytes for a coding we cannot reverse (would
 *   silently corrupt the object) — this is the single gate enforcing that, kept
 *   out of the write-dispatch body.
 *
 * HOW:
 *   1. Find Content-Encoding; absent/empty → CONTINUE (identity).
 *   2. Resolve the codec descriptor; NULL or unavailable → abort staged,
 *      finalize 415, return DONE.
 *   3. Otherwise record the codec id and return CONTINUE.
 */
static webdav_put_step_t
webdav_put_select_codec(ngx_http_request_t *r, webdav_put_body_ctx_t *bctx)
{
    ngx_table_elt_t *ce = brix_http_find_header(
        r, "Content-Encoding", sizeof("Content-Encoding") - 1);

    bctx->put_codec = BRIX_CODEC_IDENTITY;

    if (ce != NULL && ce->value.len > 0) {
        const brix_codec_desc_t *d = brix_codec_by_http_token(
            (const char *) ce->value.data, ce->value.len);
        if (d == NULL || !d->available) {
            /* Unknown or not-compiled-in Content-Encoding: never store the
             * undecoded bytes (would silently corrupt the object). 415. */
            brix_dashboard_http_error(r,
                "webdav PUT unsupported Content-Encoding");
            brix_dashboard_http_finish(r);
            brix_vfs_writer_abort(bctx->writer);
            webdav_metrics_finalize_request(r,
                NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
            return WEBDAV_PUT_DONE;
        }
        bctx->put_codec = d->id;

        /* A non-identity Content-Encoding declares the body IS an encoded
         * stream, but no codec emits a zero-byte stream (gzip/zstd/… all
         * carry a header/trailer). An empty body with a real codec is
         * therefore malformed — reject it (same contract as a truncated
         * stream) instead of storing a spurious empty object. */
        if (bctx->put_codec != BRIX_CODEC_IDENTITY
            && !bctx->body_summary.has_spooled && bctx->body_summary.bytes == 0)
        {
            brix_dashboard_http_error(r,
                "webdav PUT empty body with Content-Encoding");
            brix_dashboard_http_finish(r);
            brix_vfs_writer_abort(bctx->writer);
            webdav_metrics_finalize_request(r,
                NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
            return WEBDAV_PUT_DONE;
        }
    }

    return WEBDAV_PUT_CONTINUE;
}

/*
 * webdav_put_write_sync — synchronously stream/decode the body to the staged fd.
 *
 * WHAT: Bumps the per-body-shape metric, then writes the body to the staged
 *   target — decode-to-fd for a coded body, staged-driver stream for object
 *   backends, or write-to-fd for a POSIX temp — and accounts the bytes.
 *   Returns WEBDAV_PUT_CONTINUE on success, or WEBDAV_PUT_DONE after aborting
 *   the staged temp and finalizing the precise failure status (415/413/400/501/
 *   500) on a write error.
 *
 * WHY: Confines the three-way write dispatch and its abort-on-failure invariant
 *   (a failed write must never leave a readable partial at the final path) to
 *   one place, mirroring the thread path's error handling.
 *
 * HOW:
 *   1. Increment the SPOOLED/MEMORY/EMPTY body-shape metric.
 *   2. Coded body: NOSYS/501 on a driver target (no kernel fd), else
 *      brix_http_body_decode_to_fd (reports its own precise status).
 *   3. Identity body: staged-driver stream or write-to-fd.
 *   4. On write failure abort staged, finalize the reported status, return DONE.
 *   5. On success account the bytes via brix_dashboard_http_add, return CONTINUE.
 */
static webdav_put_step_t
webdav_put_write_sync(ngx_http_request_t *r, webdav_put_body_ctx_t *bctx)
{
    ngx_int_t wrc;
    ngx_int_t decode_status = NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (bctx->body_summary.has_spooled) {
        BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_SPOOLED]);
    } else if (bctx->body_summary.has_memory) {
        BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_MEMORY]);
    } else {
        BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_EMPTY]);
    }

    if (bctx->put_codec != BRIX_CODEC_IDENTITY) {
        /* A Content-Encoding decode writes plaintext straight to the session's
         * kernel temp fd (the decode engine owns the streaming + bomb guard);
         * a driver-backed object exposes no fd (NGX_INVALID_FILE) →
         * decode-to-object is a follow-up. These bytes bypass the writer's CRC
         * accumulator, so a verifying session leaves them unverified (its commit
         * read-back is a no-op when nothing went through the accumulator) —
         * verify-on-write does not cover coded bodies. */
        ngx_fd_t wfd = brix_vfs_writer_fd(bctx->writer);
        if (wfd == NGX_INVALID_FILE) {
            errno = ENOSYS;
            wrc = NGX_ERROR;
            decode_status = NGX_HTTP_NOT_IMPLEMENTED;
        } else {
            wrc = brix_http_body_decode_to_fd(r, wfd, bctx->path,
                                                bctx->put_codec,
                                                BRIX_DECODE_MAX_OUTPUT,
                                                &bctx->body_summary,
                                                &decode_status);
        }
    } else {
        /* Identity body: one common verified-write call — the writer dispatches
         * memory bufs, spooled temp-fd bufs, and driver-object targets. */
        wrc = brix_http_body_write_to_writer(r, bctx->writer);
    }
    if (wrc != NGX_OK) {
        brix_dashboard_http_error(r, "webdav PUT body write failed");
        brix_dashboard_http_finish(r);
        /* Abort the session — the final path is never touched, so a failed
         * write (e.g. a corrupt/over-large Content-Encoding that fails to
         * decode) can never leave a readable partial object. The decode path
         * reports the precise status (413 bomb / 400 corrupt). */
        brix_vfs_writer_abort(bctx->writer);
        webdav_metrics_finalize_request(r, decode_status);
        return WEBDAV_PUT_DONE;
    }

    brix_dashboard_http_add(r, (ngx_atomic_int_t) bctx->body_summary.bytes);
    return WEBDAV_PUT_CONTINUE;
}

/*
 * webdav_put_stream_body — write the request body (async or sync) to staged.
 *
 * WHAT: Summarizes the body, starts dashboard tracking, and drives the body to
 *   the staged temp: for a request with a body it tries the thread-pool offload
 *   then falls through the codec-select + synchronous write; an empty PUT just
 *   records the EMPTY metric.  Returns WEBDAV_PUT_CONTINUE when the caller
 *   should proceed to commit synchronously, or WEBDAV_PUT_DONE when the body
 *   phase has already answered the request (threaded dispatch, or a handled
 *   error).
 *
 * WHY: Groups the whole "get the bytes onto the staged fd" concern — including
 *   the async/sync/empty split — behind one call so the orchestrator commits
 *   only what the sync/empty paths leave staged.  Behavior (metrics, statuses,
 *   ownership) is unchanged from the prior inline block.
 *
 * HOW:
 *   1. No request body → start dashboard(0), EMPTY metric, CONTINUE.
 *   2. Body present → summarize (failure aborts + 500 → DONE), start dashboard,
 *      add bytes_rx metric.
 *   3. Try the threaded offload; if it took over or failed, return DONE.
 *   4. Select the codec (415 → DONE), then synchronously write (error → DONE).
 *   5. CONTINUE — the staged temp holds the full body, ready to commit.
 */
webdav_put_step_t
webdav_put_stream_body(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    brix_vfs_writer_t *writer, int created)
{
    webdav_put_body_ctx_t bctx;

    if (r->request_body == NULL) {
        webdav_put_start_dashboard(r, path, 0);
        BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_EMPTY]);
        return WEBDAV_PUT_CONTINUE;
    }

    ngx_memzero(&bctx, sizeof(bctx));
    bctx.path      = path;
    bctx.writer    = writer;
    bctx.created   = created;
    bctx.put_codec = BRIX_CODEC_IDENTITY;

    if (brix_http_body_summary(r, &bctx.body_summary) != NGX_OK) {
        brix_vfs_writer_abort(writer);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return WEBDAV_PUT_DONE;
    }

    webdav_put_start_dashboard(r, path, (int64_t) bctx.body_summary.bytes);
    BRIX_WEBDAV_METRIC_ADD(bytes_rx_total, bctx.body_summary.bytes);

    if (webdav_put_select_codec(r, &bctx) == WEBDAV_PUT_DONE) {
        return WEBDAV_PUT_DONE;
    }

    if (webdav_put_try_threaded(r, conf, &bctx) == WEBDAV_PUT_DONE) {
        return WEBDAV_PUT_DONE;
    }

    return webdav_put_write_sync(r, &bctx);
}
