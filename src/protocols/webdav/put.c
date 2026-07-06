/*
 * put.c - WebDAV PUT body handling, including optional thread-pool writes.
 *
 * Phase 39 (WS8/HTTP-4): the body is written to a staged temp file and atomically
 * renamed onto the final path on success (brix_staged_open/commit/abort, the
 * same crash-safe lifecycle S3 PUT uses).  So a client that drops mid-upload, a
 * crash, or a failed inflate never leaves a partial/truncated object at the final
 * path, and a concurrent GET only ever observes the old or the new object — never
 * a half-written one.
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
#include "auth/impersonate/lifecycle.h"
#include "fs/path/path.h"
#include "core/compat/cstr.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    ngx_http_request_t  *r;
    brix_vfs_staged_t *staged;   /* VFS-owned staged temp (pool-allocated) */
    size_t               len;
    ssize_t              nwritten;
    int                  io_errno;
    int                  created;
    char                 path[WEBDAV_MAX_PATH];   /* final path (commit target) */
} webdav_put_aio_t;

/*
 * Build a transient VFS ctx for the staged-write lifecycle on the final `path`
 * (mirrors the canonical construction in get.c).  PUT is allow_write-gated at
 * the access phase, so brix_vfs_staged_open's write-gate never fires here.
 */
static void
webdav_put_vfs_ctx_init(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    int is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(vctx, r->pool, r->connection->log,
        BRIX_PROTO_WEBDAV, conf->common.root_canon,
        conf->cache_root_canon, conf->common.allow_write, is_tls,
        (wctx != NULL) ? wctx->identity : NULL, path);
    /* Route through the export's selected storage backend (NULL ⇒ default POSIX). */
    vctx->sd = brix_webdav_backend_instance(conf, r->connection->log);
}

static void webdav_put_aio_thread(void *data, ngx_log_t *log);
static void webdav_put_aio_done(ngx_event_t *ev);

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
static void
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
     * to the staged temp fd — no full-body contiguous copy.  The body for this
     * path is all in-memory bufs anchored in r->pool (the caller gates spooled
     * bodies to the synchronous streaming path), so they are stable for the
     * lifetime of the request (held alive by r->main->count++).  This helper
     * only does pwrite(2), so it is safe to run on the thread pool — no nginx
     * pool allocation or event-loop calls.
     */
    /* A driver-backed (object) staged target has no kernel fd — stream the body
     * through the staged-write primitive; otherwise write straight to the temp fd. */
    if (brix_vfs_staged_is_driver(t->staged)
            ? brix_http_body_write_to_staged(t->r, t->staged) != NGX_OK
            : brix_http_body_write_to_fd(t->r, brix_vfs_staged_fd(t->staged),
                                           t->path, NULL) != NGX_OK)
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

        brix_log_safe_path(r->connection->log, NGX_LOG_ERR,
                             (ngx_uint_t) t->io_errno,
                             "brix_webdav: async write() failed for: \"%s\"",
                             t->path);
        brix_dashboard_http_error(r, "webdav PUT async write failed");
        brix_dashboard_http_finish(r);
        /* Abort the staged temp (close + unlink) — the final path is untouched. */
        brix_vfs_staged_abort(t->staged, 1);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Atomically publish the completed temp onto the final path. */
    if (brix_vfs_staged_commit(t->staged, 0) != NGX_OK) {
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "brix_webdav: async staged commit failed for: "
                             "\"%s\"", t->path);
        brix_dashboard_http_error(r, "webdav PUT staged commit failed");
        brix_dashboard_http_finish(r);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    brix_dashboard_http_add(r, (ngx_atomic_int_t) t->len);
    brix_dashboard_http_finish(r);

    webdav_put_persist_checksums(r, (const char *) t->path);   /* §8.3 */

    status = t->created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    webdav_send_status_only(r, (ngx_uint_t) status);
}

/*
 * webdav_handle_put_body — write the request body to the destination file.
 *
 * This is the ngx_http_read_client_request_body() completion callback.  By
 * the time it runs, nginx has either buffered the body in memory
 * (r->request_body->bufs with in_file=0) or spooled it to a temp file
 * (in_file=1).
 *
 * The body is always written to a STAGED temp file (brix_staged_open) and
 * atomically committed onto the final path on success (brix_staged_commit) or
 * aborted on any error (brix_staged_abort) — so a partial/failed/aborted PUT
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
 * open (brix_staged_open) then routes to the broker and the new file is
 * owned by the mapped user.  No-op unless map mode is active.
 */
void
webdav_handle_put_body(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    webdav_put_body_inner(r);
    brix_imp_request_end();
}

/* Add an "X-Upload-Offset: <off>" response header (the resumable-PUT progress
 * marker the client reads to know where to continue).  Best-effort. */
static void
webdav_set_upload_offset(ngx_http_request_t *r, off_t off)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "X-Upload-Offset");
    h->value.data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
    if (h->value.data == NULL) {
        h->hash = 0;
        return;
    }
    h->value.len = ngx_sprintf(h->value.data, "%O", off) - h->value.data;
}

/*
 * Resumable Content-Range PUT (brix_webdav_upload_resume on).  Writes this
 * chunk to a persistent, identity-keyed partial at its absolute offset and
 * commits (atomic rename) only when the upload is complete.  Across separate PUT
 * requests — and across an nginx restart — the partial survives, so the client
 * resumes from X-Upload-Offset.  Append-only: the chunk must start exactly at the
 * current partial size, else 409 + X-Upload-Offset tells the client the truth.
 */
static void
webdav_put_ranged_resume(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    const brix_http_content_range_t *cr)
{
    brix_staged_file_t        staged;
    off_t                       cur = 0;
    brix_http_body_summary_t  bs;
    ngx_http_brix_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    const char *principal = (wctx != NULL && wctx->dn[0] != '\0')
                            ? wctx->dn : NULL;
    const char *stage_dir = conf->upload_stage_dir_canon[0]
                            ? conf->upload_stage_dir_canon : NULL;

    if (brix_staged_open_resume(r->connection->log, conf->common.root_canon,
            path, principal, stage_dir, NGX_FILE_DEFAULT_ACCESS, &staged, &cur)
        != NGX_OK)
    {
        ngx_int_t st = brix_http_map_errno(ngx_errno);
        webdav_metrics_finalize_request(r,
            st >= 500 ? NGX_HTTP_INTERNAL_SERVER_ERROR : st);
        return;
    }

    /* Append-only contiguity: the chunk must begin at the current partial size.
     * If it doesn't, report the real resume offset and let the client re-issue —
     * keep the partial (close without unlink). */
    if (cr->start != cur) {
        brix_staged_abort(r->connection->log, conf->common.root_canon,
                            &staged, 0 /* keep */);
        webdav_set_upload_offset(r, cur);
        webdav_send_status_only(r, NGX_HTTP_CONFLICT);
        return;
    }

    if (r->request_body != NULL) {
        if (brix_http_body_write_to_fd_at(r, staged.fd, path, &bs, cr->start)
            != NGX_OK)
        {
            /* keep the partial; the client can re-send this chunk */
            brix_staged_abort(r->connection->log, conf->common.root_canon,
                                &staged, 0 /* keep */);
            webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        BRIX_WEBDAV_METRIC_ADD(bytes_rx_total, bs.bytes);
        cur = cr->end + 1;
        /* Flush so the reported resume offset is durable across a restart. */
        (void) fsync(staged.fd);
    }

    /* Final chunk (last byte of the declared total) → commit; else keep partial
     * and report the next expected offset. */
    if (cr->total >= 0 && cr->end + 1 >= cr->total) {
        /* Commit the staged partial onto the destination — atomic rename on the
         * same filesystem, or copy-then-rename when staging on a different device
         * (brix_webdav_stage_dir).  brix_commit_staged owns neither close nor
         * the active flag, so finalize the staged struct ourselves.  On a stage
         * device, record a durable pending-commit marker first so an interrupted
         * cross-device move is finished by the reaper across a restart. */
        ngx_flag_t stage_tracked = (stage_dir != NULL);
        ngx_int_t  crc;
        if (stage_tracked) {
            (void) brix_stage_mark_pending(staged.tmp_path, path,
                                             r->connection->log);
        }
        crc = brix_commit_staged(staged.fd, staged.tmp_path, path,
                                   staged.final_mode, r->connection->log);
        if (staged.fd != NGX_INVALID_FILE) {
            ngx_close_file(staged.fd);
            staged.fd = NGX_INVALID_FILE;
        }
        staged.active = 0;
        if (crc != NGX_OK) {
            /* Keep the marker + partial — the reaper / a client retry completes it. */
            webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        if (stage_tracked) {
            brix_stage_unmark_pending(staged.tmp_path);
        }
        webdav_put_persist_checksums(r, (const char *) path);   /* §8.3 */
        webdav_send_status_only(r, NGX_HTTP_CREATED);
        return;
    }

    brix_staged_abort(r->connection->log, conf->common.root_canon,
                        &staged, 0 /* keep partial for the next chunk */);
    webdav_set_upload_offset(r, cur);
    webdav_send_status_only(r, NGX_HTTP_OK);
}

static void
webdav_put_body_inner(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char               path[WEBDAV_MAX_PATH];
    ngx_int_t          rc;
    brix_vfs_ctx_t   vctx;
    brix_vfs_staged_t *staged;
    int                staged_err = 0;
    int                created = 0;
    brix_codec_id_t  put_codec = BRIX_CODEC_IDENTITY;
    struct stat        sb;
    ngx_int_t          status;
    brix_http_body_summary_t body_summary;
    ngx_http_brix_webdav_req_ctx_t *wctx;
    const char        *identity;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon, path,
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

    /*
     * Resumable upload: a Content-Range PUT places its chunk at an absolute
     * offset on a persistent identity-keyed partial and commits only when the
     * upload completes (brix_webdav_upload_resume on).  Handled before the
     * whole-body staged-write path below.  A malformed Content-Range is 400.
     */
    if (conf->upload_resume) {
        ngx_table_elt_t *crh = brix_http_find_header(
            r, "Content-Range", sizeof("Content-Range") - 1);
        if (crh != NULL && crh->value.len > 0) {
            brix_http_content_range_t cr;
            brix_http_parse_content_range(crh->value.data, crh->value.len, &cr);
            if (!cr.present) {
                webdav_metrics_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                return;
            }
            webdav_put_ranged_resume(r, conf, path, &cr);
            return;
        }
    }

    {
        ngx_http_brix_webdav_req_ctx_t *rx =
            ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
        brix_vfs_ctx_t  pctx;
        brix_vfs_stat_t pst;
        int               is_tls = 0;

#if (NGX_HTTP_SSL)
        is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
        ngx_memzero(&sb, sizeof(sb));
        brix_vfs_ctx_init(&pctx, r->pool, r->connection->log,
            BRIX_PROTO_WEBDAV, conf->common.root_canon, conf->cache_root_canon,
            conf->common.allow_write, is_tls,
            (rx != NULL) ? rx->identity : NULL, path);
        if (brix_vfs_probe(&pctx, 0 /* follow */, &pst) == NGX_OK) {
            created = 0;   /* target exists — sb populated for the ETag check */
            sb.st_mtime = pst.mtime;
            sb.st_size  = pst.size;
            sb.st_mode  = (mode_t) pst.mode;
        } else {
            created = 1;   /* new file — sb unused (etag check sees !exists) */
        }
    }

    rc = brix_http_check_etag_preconditions(
        r, !created, &sb, BRIX_ETAG_WEAK, BRIX_HTTP_COND_WEAK_EQUIV);
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /*
     * Open a staged temp file beside the final path (O_EXCL, unique name, up to
     * 16 attempts) through the metered VFS staged surface.  The body is written
     * here and atomically renamed onto the final path only on success — never
     * exposing a partial object.
     */
    webdav_put_vfs_ctx_init(r, conf, path, &vctx);

    staged = brix_vfs_staged_open(&vctx, NGX_FILE_DEFAULT_ACCESS, 16,
                                    &staged_err);
    if (staged == NULL) {
        /* Use the errno the VFS open captured (logging may clobber errno). */
        int open_errno = staged_err;

        if (open_errno == NGX_ENOENT || open_errno == NGX_ENOTDIR) {
            /* RFC 4918 §9.7.1 — PUT to non-existent parent collection is 409 */
            webdav_metrics_finalize_request(r, NGX_HTTP_CONFLICT);
            return;
        }
        /*
         * A DAC-denied staged-temp create (e.g. the accessor lacks write on the
         * parent collection → EACCES/EPERM, EXDEV/ELOOP on a confinement-blocked
         * traversal) is a forbidden, bounded request — surface it as a clean 4xx
         * via the shared errno map (EACCES/EPERM → 403, ENOSPC → 507, …), not a
         * blanket 500.  Only an errno with no clean 4xx contract (e.g. EIO) keeps
         * the internal-error path.  This mirrors S3 PUT's s3_put_finalize_fs_error.
         */
        status = brix_http_map_errno(open_errno);
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR,
                             (ngx_uint_t) open_errno,
                             "brix_webdav: staged open for write failed for: "
                             "\"%s\"", path);
        webdav_metrics_finalize_request(
            r, status >= 500 ? NGX_HTTP_INTERNAL_SERVER_ERROR : status);
        return;
    }

    if (r->request_body != NULL) {
        if (brix_http_body_summary(r, &body_summary) != NGX_OK) {
            brix_vfs_staged_abort(staged, 1);
            webdav_metrics_finalize_request(r,
                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
        identity = (wctx != NULL && wctx->dn[0] != '\0')
                   ? wctx->dn : "anonymous";
        (void) brix_dashboard_http_start_identity(r, path, identity, "",
            BRIX_XFER_PROTO_WEBDAV, BRIX_XFER_DIR_WRITE, "PUT",
            (int64_t) body_summary.bytes);

        BRIX_WEBDAV_METRIC_ADD(bytes_rx_total, body_summary.bytes);

        {
            ngx_table_elt_t  *ce = brix_http_find_header(
                r, "Content-Encoding", sizeof("Content-Encoding") - 1);
            if (ce != NULL && ce->value.len > 0) {
                const brix_codec_desc_t *d = brix_codec_by_http_token(
                    (const char *) ce->value.data, ce->value.len);
                if (d == NULL || !d->available) {
                    /* Unknown or not-compiled-in Content-Encoding: never store the
                     * undecoded bytes (would silently corrupt the object). 415. */
                    brix_dashboard_http_error(r,
                        "webdav PUT unsupported Content-Encoding");
                    brix_dashboard_http_finish(r);
                    brix_vfs_staged_abort(staged, 1);
                    webdav_metrics_finalize_request(r,
                        NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
                    return;
                }
                put_codec = d->id;
            }
        }

        if (!body_summary.has_spooled && body_summary.bytes > 0
            && put_codec == BRIX_CODEC_IDENTITY
            && conf->common.thread_pool != NULL)
        {
            ngx_thread_task_t *task;
            webdav_put_aio_t  *t;

            task = ngx_thread_task_alloc(r->pool, sizeof(webdav_put_aio_t));
            if (task == NULL) {
                brix_dashboard_http_error(r, "webdav PUT task allocation failed");
                brix_dashboard_http_finish(r);
                brix_vfs_staged_abort(staged, 1);
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

            /*
             * Phase 31 W2: no full-body collection — the thread streams the
             * in-memory body bufs straight to the staged fd (see
             * webdav_put_aio_thread); the done handler commits/aborts.
             */

            brix_task_bind(task, webdav_put_aio_thread, webdav_put_aio_done);

            if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
                brix_dashboard_http_error(r, "webdav PUT task post failed");
                brix_dashboard_http_finish(r);
                brix_vfs_staged_abort(t->staged, 1);
                webdav_metrics_finalize_request(r,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_THREADED]);
            r->main->count++;
            return;
        }

        if (body_summary.has_spooled) {
            BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_SPOOLED]);
        } else if (body_summary.has_memory) {
            BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_MEMORY]);
        } else {
            BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_EMPTY]);
        }

        {
            ngx_int_t  wrc;
            ngx_int_t  decode_status = NGX_HTTP_INTERNAL_SERVER_ERROR;

            if (put_codec != BRIX_CODEC_IDENTITY) {
                if (brix_vfs_staged_is_driver(staged)) {
                    /* Content-Encoding decode targets a kernel fd; an object
                     * backend exposes none. Decode-to-staged is a follow-up. */
                    errno = ENOSYS;
                    wrc = NGX_ERROR;
                    decode_status = NGX_HTTP_NOT_IMPLEMENTED;
                } else {
                    wrc = brix_http_body_decode_to_fd(r,
                                                        brix_vfs_staged_fd(staged),
                                                        path, put_codec,
                                                        BRIX_DECODE_MAX_OUTPUT,
                                                        &body_summary,
                                                        &decode_status);
                }
            } else if (brix_vfs_staged_is_driver(staged)) {
                wrc = brix_http_body_write_to_staged(r, staged);
            } else {
                wrc = brix_http_body_write_to_fd(r,
                                                    brix_vfs_staged_fd(staged),
                                                    path, &body_summary);
            }
            if (wrc != NGX_OK) {
                brix_dashboard_http_error(r, "webdav PUT body write failed");
                brix_dashboard_http_finish(r);
                /* Abort the staged temp — the final path is never touched, so a
                 * failed write (e.g. a corrupt/over-large Content-Encoding that
                 * fails to decode) can never leave a readable partial object. The
                 * decode path reports the precise status (413 bomb / 400 corrupt). */
                brix_vfs_staged_abort(staged, 1);
                webdav_metrics_finalize_request(r, decode_status);
                return;
            }
        }
        brix_dashboard_http_add(r, (ngx_atomic_int_t) body_summary.bytes);
    } else {
        wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
        identity = (wctx != NULL && wctx->dn[0] != '\0')
                   ? wctx->dn : "anonymous";
        (void) brix_dashboard_http_start_identity(r, path, identity, "",
            BRIX_XFER_PROTO_WEBDAV, BRIX_XFER_DIR_WRITE, "PUT", 0);
        BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_EMPTY]);
    }

    brix_dashboard_http_finish(r);

    /* Atomically publish the staged temp onto the final path (an empty PUT
     * commits an empty file).  excl=0 == replace (the prior brix_staged_commit
     * non-EXCL semantics). */
    if (brix_vfs_staged_commit(staged, 0) != NGX_OK) {
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "brix_webdav: staged commit failed for: \"%s\"",
                             path);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    webdav_put_persist_checksums(r, (const char *) path);   /* §8.3 */

    status = created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    /* r->header_only is false for PUT (clients don't send HEAD-like PUT);
     * no need to check it here, but ngx_http_send_special handles it. */
    webdav_metrics_finalize_request(r, ngx_http_send_special(r,
                                                             NGX_HTTP_LAST));
}
