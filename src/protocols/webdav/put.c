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
    brix_vfs_ctx_bind_backend_cred(vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    /* Phase-2 T9: opt-in minting for GSI/token identities that have no
     * pre-provisioned proxy. No-op unless a mint CA is configured. */
    brix_vfs_ctx_bind_backend_mint(vctx,
        &conf->common.storage_credential_mint_ca_cert,
        &conf->common.storage_credential_mint_ca_key,
        conf->common.storage_credential_mint_ttl);
    /* Phase-70: bind captured bearer/proxy for backend PASSTHROUGH (no-op on SELECT). */
    webdav_vfs_bind_deleg(r, conf, vctx);
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

    {
    brix_staged_open_req_t staged_req = {
        .root_canon = conf->common.root_canon,
        .final_path = path,
        .mode       = NGX_FILE_DEFAULT_ACCESS,
        .principal  = principal,
        .stage_dir  = stage_dir,
    };
    if (brix_staged_open_resume(r->connection->log, &staged_req, &staged, &cur)
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
}

/*
 * Outcome of a per-phase PUT helper, telling the orchestrator how to proceed.
 * The helpers own their own error responses (metrics/status already sent), so
 * the orchestrator only branches on whether to continue, stop, or (for the
 * resumable branch) treat the request as fully handled.
 */
typedef enum {
    WEBDAV_PUT_CONTINUE = 0,   /* phase succeeded — proceed to the next phase   */
    WEBDAV_PUT_DONE            /* request fully handled/responded — stop, return */
} webdav_put_step_t;

/*
 * webdav_put_precheck — resolve the target and run pre-write gating.
 *
 * WHAT: Resolves the request path into `path`, dispatches a resumable
 *   Content-Range PUT (which fully handles its own response), probes the target
 *   for existence, and evaluates the ETag preconditions.  Returns
 *   WEBDAV_PUT_CONTINUE to proceed to the staged-write path with `*created`
 *   set, or WEBDAV_PUT_DONE when the request has already been answered (path
 *   error → 409/4xx, resumable handled, or an ETag precondition failed).
 *
 * WHY: Consolidates every gate that must pass before a staged temp is opened,
 *   keeping the orchestrator a flat sequence and the "never open before we know
 *   we should" invariant in one place.  Behavior is byte-identical to the prior
 *   inline block (same status codes, same order of checks).
 *
 * HOW:
 *   1. Resolve the path; a missing intermediate collection is RFC 4918 §9.7.1
 *      409 Conflict, any other resolve error propagates its status.
 *   2. If resumable uploads are on and a Content-Range header is present, parse
 *      it (malformed → 400) and hand off to webdav_put_ranged_resume; DONE.
 *   3. Probe the target through the metered VFS to populate a local stat for the
 *      ETag check and decide `*created` (0 = exists, 1 = new).
 *   4. Run the weak-ETag precondition check; a failure sends its status. DONE.
 */
static webdav_put_step_t
webdav_put_precheck(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, char *path, int *created)
{
    struct stat sb;
    ngx_int_t   rc;

    *created = 0;
    ngx_memzero(&sb, sizeof(sb));

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon, path,
                                             WEBDAV_MAX_PATH);
    if (rc != NGX_OK) {
        /* RFC 4918 §9.7.1: missing intermediate collection → 409 Conflict */
        if (rc == NGX_HTTP_NOT_FOUND) {
            webdav_metrics_finalize_request(r, NGX_HTTP_CONFLICT);
            return WEBDAV_PUT_DONE;
        }
        webdav_metrics_finalize_request(r, rc);
        return WEBDAV_PUT_DONE;
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
                return WEBDAV_PUT_DONE;
            }
            webdav_put_ranged_resume(r, conf, path, &cr);
            return WEBDAV_PUT_DONE;
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
        brix_vfs_ctx_init(&pctx, r->pool, r->connection->log,
            BRIX_PROTO_WEBDAV, conf->common.root_canon, conf->cache_root_canon,
            conf->common.allow_write, is_tls,
            (rx != NULL) ? rx->identity : NULL, path);
        brix_vfs_ctx_bind_backend_cred(&pctx,
            &conf->common.storage_credential_dir,
            conf->common.storage_credential_fallback);
        webdav_vfs_bind_deleg(r, conf, &pctx);
        if (brix_vfs_probe(&pctx, 0 /* follow */, &pst) == NGX_OK) {
            *created = 0;   /* target exists — sb populated for the ETag check */
            sb.st_mtime = pst.mtime;
            sb.st_size  = pst.size;
            sb.st_mode  = (mode_t) pst.mode;
        } else {
            *created = 1;   /* new file — sb unused (etag check sees !exists) */
        }
    }

    rc = brix_http_check_etag_preconditions(
        r, !*created, &sb, BRIX_ETAG_WEAK, BRIX_HTTP_COND_WEAK_EQUIV);
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return WEBDAV_PUT_DONE;
    }

    return WEBDAV_PUT_CONTINUE;
}

/*
 * webdav_put_open_target — open the staged temp for the final path.
 *
 * WHAT: Builds the staged-write VFS ctx and opens a staged temp file
 *   (O_EXCL, unique name, up to 16 attempts) through the metered VFS surface.
 *   On success returns WEBDAV_PUT_CONTINUE with `*out_staged` set; on failure
 *   maps the captured errno to a clean 4xx (or 500 for no-4xx-contract errnos),
 *   sends it, and returns WEBDAV_PUT_DONE.
 *
 * WHY: Keeps the "body is written to a staged temp and atomically renamed only
 *   on success" invariant (WS8/HTTP-4) and its errno→status mapping in one
 *   place, matching S3 PUT's s3_put_finalize_fs_error.  Status codes unchanged.
 *
 * HOW:
 *   1. Init the staged-write ctx via webdav_put_vfs_ctx_init.
 *   2. brix_vfs_staged_open; a non-NULL result is the success path.
 *   3. ENOENT/ENOTDIR (missing parent collection) → 409 (RFC 4918 §9.7.1).
 *   4. Otherwise map errno via brix_http_map_errno, log the path, and finalize
 *      with the mapped 4xx or 500.
 */
static webdav_put_step_t
webdav_put_open_target(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    brix_vfs_ctx_t *vctx, brix_vfs_staged_t **out_staged)
{
    brix_vfs_staged_t *staged;
    int                staged_err = 0;
    ngx_int_t          status;

    *out_staged = NULL;

    /*
     * Open a staged temp file beside the final path (O_EXCL, unique name, up to
     * 16 attempts) through the metered VFS staged surface.  The body is written
     * here and atomically renamed onto the final path only on success — never
     * exposing a partial object.
     */
    webdav_put_vfs_ctx_init(r, conf, path, vctx);

    staged = brix_vfs_staged_open(vctx, NGX_FILE_DEFAULT_ACCESS, 16,
                                    &staged_err);
    if (staged != NULL) {
        *out_staged = staged;
        return WEBDAV_PUT_CONTINUE;
    }

    /* Use the errno the VFS open captured (logging may clobber errno). */
    {
        int open_errno = staged_err;

        if (open_errno == NGX_ENOENT || open_errno == NGX_ENOTDIR) {
            /* RFC 4918 §9.7.1 — PUT to non-existent parent collection is 409 */
            webdav_metrics_finalize_request(r, NGX_HTTP_CONFLICT);
            return WEBDAV_PUT_DONE;
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
        return WEBDAV_PUT_DONE;
    }
}

/*
 * webdav_put_start_dashboard — begin dashboard/metric tracking for this PUT.
 *
 * WHAT: Resolves the request identity (DN or "anonymous") and opens a
 *   dashboard transfer record for the write of `bytes` to `path`.  No return
 *   value — best-effort tracking start.
 *
 * WHY: The dashboard-start call is issued identically from both the body and
 *   the empty-PUT branch; factoring it removes the duplicated identity lookup
 *   and keeps the two callsites in lockstep.
 *
 * HOW:
 *   1. Look up the WebDAV request ctx; use wctx->dn if non-empty else
 *      "anonymous".
 *   2. Call brix_dashboard_http_start_identity with the WRITE direction and the
 *      declared byte count.
 */
static void
webdav_put_start_dashboard(ngx_http_request_t *r, const char *path,
    int64_t bytes)
{
    ngx_http_brix_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    const char *identity = (wctx != NULL && wctx->dn[0] != '\0')
                           ? wctx->dn : "anonymous";

    (void) brix_dashboard_http_start_identity(r, path, identity, "",
        BRIX_XFER_PROTO_WEBDAV, BRIX_XFER_DIR_WRITE, "PUT", bytes);
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
    brix_vfs_staged_t        *staged;       /* open staged temp               */
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
        brix_vfs_staged_abort(bctx->staged, 1);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return WEBDAV_PUT_DONE;
    }

    t = task->ctx;
    t->r = r;
    t->staged = bctx->staged;  /* transfer staged ownership to the task */
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
        brix_vfs_staged_abort(t->staged, 1);
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
            brix_vfs_staged_abort(bctx->staged, 1);
            webdav_metrics_finalize_request(r,
                NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
            return WEBDAV_PUT_DONE;
        }
        bctx->put_codec = d->id;
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
        if (brix_vfs_staged_is_driver(bctx->staged)) {
            /* Content-Encoding decode targets a kernel fd; an object
             * backend exposes none. Decode-to-staged is a follow-up. */
            errno = ENOSYS;
            wrc = NGX_ERROR;
            decode_status = NGX_HTTP_NOT_IMPLEMENTED;
        } else {
            wrc = brix_http_body_decode_to_fd(r,
                                                brix_vfs_staged_fd(bctx->staged),
                                                bctx->path, bctx->put_codec,
                                                BRIX_DECODE_MAX_OUTPUT,
                                                &bctx->body_summary,
                                                &decode_status);
        }
    } else if (brix_vfs_staged_is_driver(bctx->staged)) {
        wrc = brix_http_body_write_to_staged(r, bctx->staged);
    } else {
        wrc = brix_http_body_write_to_fd(r,
                                            brix_vfs_staged_fd(bctx->staged),
                                            bctx->path, &bctx->body_summary);
    }
    if (wrc != NGX_OK) {
        brix_dashboard_http_error(r, "webdav PUT body write failed");
        brix_dashboard_http_finish(r);
        /* Abort the staged temp — the final path is never touched, so a
         * failed write (e.g. a corrupt/over-large Content-Encoding that
         * fails to decode) can never leave a readable partial object. The
         * decode path reports the precise status (413 bomb / 400 corrupt). */
        brix_vfs_staged_abort(bctx->staged, 1);
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
static webdav_put_step_t
webdav_put_stream_body(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path,
    brix_vfs_staged_t *staged, int created)
{
    webdav_put_body_ctx_t bctx;

    if (r->request_body == NULL) {
        webdav_put_start_dashboard(r, path, 0);
        BRIX_WEBDAV_METRIC_INC(put_body_total[BRIX_WEBDAV_PUT_EMPTY]);
        return WEBDAV_PUT_CONTINUE;
    }

    ngx_memzero(&bctx, sizeof(bctx));
    bctx.path      = path;
    bctx.staged    = staged;
    bctx.created   = created;
    bctx.put_codec = BRIX_CODEC_IDENTITY;

    if (brix_http_body_summary(r, &bctx.body_summary) != NGX_OK) {
        brix_vfs_staged_abort(staged, 1);
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

/*
 * webdav_put_commit — atomically publish the staged temp and reply.
 *
 * WHAT: Commits the staged temp onto the final path (excl=0 == replace),
 *   persists any on-write checksums, and sends the terminal 201/204 with a
 *   zero-length body.  A commit failure logs the path and finalizes 500.
 *
 * WHY: The commit + checksum + status trio is the single success epilogue for
 *   the sync and empty-PUT paths; keeping it here mirrors the async done
 *   handler's tail and keeps the orchestrator flat.  Status codes/headers are
 *   byte-identical to the prior inline tail.
 *
 * HOW:
 *   1. brix_vfs_staged_commit; failure → log + finalize 500, return.
 *   2. Persist checksum-on-write digests (§8.3, best-effort).
 *   3. Emit 201 Created (new file) or 204 No Content, content-length 0, send
 *      headers, and finalize with ngx_http_send_special(NGX_HTTP_LAST).
 */
static void
webdav_put_commit(ngx_http_request_t *r, const char *path,
    brix_vfs_staged_t *staged, int created)
{
    ngx_int_t status;

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

    webdav_put_persist_checksums(r, path);   /* §8.3 */

    status = created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    /* r->header_only is false for PUT (clients don't send HEAD-like PUT);
     * no need to check it here, but ngx_http_send_special handles it. */
    webdav_metrics_finalize_request(r, ngx_http_send_special(r,
                                                             NGX_HTTP_LAST));
}

static void
webdav_put_body_inner(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                             path[WEBDAV_MAX_PATH];
    brix_vfs_ctx_t                   vctx;
    brix_vfs_staged_t               *staged = NULL;
    int                              created = 0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    if (webdav_put_precheck(r, conf, path, &created) == WEBDAV_PUT_DONE) {
        return;
    }

    if (webdav_put_open_target(r, conf, path, &vctx, &staged)
        == WEBDAV_PUT_DONE)
    {
        return;
    }

    if (webdav_put_stream_body(r, conf, path, staged, created)
        == WEBDAV_PUT_DONE)
    {
        return;
    }

    webdav_put_commit(r, path, staged, created);
}
