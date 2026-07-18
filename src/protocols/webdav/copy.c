/*
 * copy.c - WebDAV COPY handler (RFC 4918 §9.8).
 */

#include "webdav.h"
#include "protocols/webdav/fs/copy_engine.h"
#include "protocols/webdav/methods/copy_conditionals.h"
#include "core/http/http_conditionals.h"
#include "core/compat/error_mapping.h"
#include "core/compat/namespace_ops.h"
#include "core/compat/tmp_path.h"
#include "fs/vfs/vfs.h"
#include "auth/impersonate/impersonate.h"
#include "fs/path/path.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Map a VFS single-file-copy errno to the same HTTP status the prior
 * brix_ns_local_copy → status mapping produced.  brix_vfs_copy() returns
 * NGX_ERROR with errno set (the namespace sys_errno), so reconstruct the
 * namespace status the same way namespace_ops' errno_to_ns_status does and feed
 * it to brix_http_map_ns_status — guaranteeing byte-for-byte parity with the
 * old code (including DENIED→403, TOO_LONG→414, NO_SPACE→507, CONFLICT→409,
 * IO_ERROR→500).  The two COPY-specific overrides (EXISTS→412, NOT_FOUND→409)
 * are applied by the caller before this helper is reached.
 */
static ngx_int_t
webdav_copy_errno_to_status(int err)
{
    brix_ns_status_t status;

    switch (err) {
    case 0:            status = BRIX_NS_OK;        break;
    case ENOENT:       status = BRIX_NS_NOT_FOUND; break;
    case EACCES:
    case EPERM:
    case EXDEV:
    case ELOOP:        status = BRIX_NS_DENIED;    break;
    case EEXIST:       status = BRIX_NS_EXISTS;    break;
    case ENOTEMPTY:    status = BRIX_NS_NOT_EMPTY; break;
    case ENAMETOOLONG: status = BRIX_NS_TOO_LONG;  break;
    case ENOSPC:       status = BRIX_NS_NO_SPACE;  break;
#ifdef EDQUOT
    case EDQUOT:       status = BRIX_NS_NO_SPACE;  break;
#endif
    case EBUSY:
    case EINVAL:       status = BRIX_NS_CONFLICT;  break;
    default:           status = BRIX_NS_IO_ERROR;  break;
    }

    return brix_http_map_ns_status(status);
}

/*
 * WHAT: The immutable parameter set of one collection (directory) COPY — the
 * confinement root, the source and destination paths, the source directory
 * mode, and the overwrite/depth flags derived from the request.
 *
 * WHY: The collection copy is executed either inline on the event loop or on a
 * thread-pool worker, and it is described by eight loosely-related values. A
 * struct threads them as a single unit through the execute / post-task /
 * per-phase helpers — one job, one owner — instead of an eight-argument
 * signature that trips the complexity gate and is easy to mis-order at a call
 * site. It is thread-safe by construction: it holds copied stack-buffer paths
 * (no ngx_http_request_t handle), so a worker thread reads only its own copy.
 *
 * HOW: Populated once by the caller from resolved paths and header-derived
 * flags, then passed by const pointer to the execute helpers. The async task
 * struct embeds a job plus the fields the event loop needs to reply.
 */
typedef struct {
    ngx_log_t  *log;
    char        root_canon[WEBDAV_MAX_PATH];
    char        src_path[WEBDAV_MAX_PATH];
    char        dst_path[WEBDAV_MAX_PATH];
    mode_t      src_mode;
    ngx_flag_t  dst_existed;
    ngx_flag_t  dst_was_dir;
    ngx_flag_t  depth_infinity;
} webdav_copy_job_t;

typedef struct {
    webdav_copy_job_t   job;
    ngx_http_request_t *r;
    ngx_int_t           http_status;
} webdav_copy_collection_task_t;

/*
 * WHAT: The resolved, validated state of one COPY request: the confined source
 * and destination paths, their stat records, and the overwrite/depth flags plus
 * whether the destination already existed.
 *
 * WHY: The COPY handler's pre-flight (parse → resolve → validate) produces a
 * cluster of related values that the file and collection execute paths both
 * consume. Threading them as one struct keeps the orchestrator flat and each
 * pre-flight helper single-purpose, instead of a long function with a dozen
 * loose locals.
 *
 * HOW: Filled incrementally — webdav_copy_parse_request sets the flags and the
 * decoded destination, webdav_copy_resolve_pair fills the paths/stats/existed —
 * then read by the execute helpers. Zero-initialised at declaration.
 */
typedef struct {
    char         src_path[WEBDAV_MAX_PATH];
    char         dst_path[WEBDAV_MAX_PATH];
    char         dest_decoded[WEBDAV_MAX_PATH];
    struct stat  src_sb;
    struct stat  dst_sb;
    int          dst_existed;
    int          overwrite;
    int          depth_infinity;
} webdav_copy_req_t;

/*
 * WHAT: Populate a webdav_copy_job_t from a resolved COPY request and the
 * export root, deep-copying the stack-buffer paths into the job's own storage.
 *
 * WHY: The collection-copy job derives entirely from the resolved request; a
 * single builder keeps the inline and threaded paths in lock step and
 * guarantees the job never aliases a caller stack buffer that could go out of
 * scope before a worker thread reads it.
 *
 * HOW: Assigns the scalar flags/mode from req (dst_was_dir = existed && dir),
 * and uses ngx_cpystrn (bounded, always NUL-terminating) for each path,
 * matching the prior per-field copies.
 */
static void
webdav_copy_job_init(webdav_copy_job_t *job, ngx_log_t *log,
    const char *root_canon, const webdav_copy_req_t *req)
{
    job->log            = log;
    job->src_mode       = req->src_sb.st_mode;
    job->dst_existed    = req->dst_existed;
    job->dst_was_dir    = req->dst_existed && S_ISDIR(req->dst_sb.st_mode);
    job->depth_infinity = req->depth_infinity;

    ngx_cpystrn((u_char *) job->root_canon, (u_char *) root_canon,
                sizeof(job->root_canon));
    ngx_cpystrn((u_char *) job->src_path, (u_char *) req->src_path,
                sizeof(job->src_path));
    ngx_cpystrn((u_char *) job->dst_path, (u_char *) req->dst_path,
                sizeof(job->dst_path));
}

/*
 * WHAT: Stage the copied tree into a sibling temp directory: make the temp dir,
 * clone dead props + fattrs, and (depth:infinity) recurse the contents.
 *
 * WHY: The atomic-rename strategy needs the whole copy built out of band before
 * the final rename; isolating the build keeps webdav_copy_collection_execute a
 * flat sequence and gives one place that reports the build-phase HTTP status.
 *
 * HOW: mkdir maps ENOENT-on-parent to 409 Conflict (any other failure to 500);
 * on a recursion failure it removes the temp tree and returns 500. On success
 * it returns NGX_OK with tmp_path filled for the commit phase.
 */
static ngx_int_t
webdav_copy_collection_stage(const webdav_copy_job_t *job, char *tmp_path,
    size_t tmp_path_size)
{
    if (brix_make_tmp_path(job->dst_path, tmp_path, tmp_path_size) != NGX_OK) {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    if (brix_vfs_mkdir_path(job->log, job->root_canon, tmp_path,
                            job->src_mode & 0777) != 0)
    {
        if (errno == ENOENT) {
            return NGX_HTTP_CONFLICT;
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    webdav_dead_props_copy(job->log, job->src_path, tmp_path);
    brix_ns_copy_fattrs(job->log, job->src_path, tmp_path);

    if (job->depth_infinity
        && webdav_copy_dir_recursive(job->log, job->root_canon, job->src_path,
                                     tmp_path) != NGX_OK)
    {
        (void) webdav_delete_path_recursive(job->log, job->root_canon, tmp_path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Commit a fully-staged temp tree onto the destination: drop a pre-existing
 * destination directory (rename cannot replace a non-empty dir) then rename the
 * temp tree into place.
 *
 * WHY: Splitting the commit from the stage keeps each phase single-purpose and
 * confines the "remove temp on any failure" cleanup to one linear path.
 *
 * HOW: If the destination existed as a directory it is removed first; a failure
 * there or in the rename removes the temp tree and returns 500. On success it
 * returns 204 (replaced) or 201 (created) matching the prior end-of-function
 * status.
 */
static ngx_int_t
webdav_copy_collection_commit(const webdav_copy_job_t *job, const char *tmp_path)
{
    if (job->dst_existed && job->dst_was_dir) {
        if (webdav_delete_path_recursive(job->log, job->root_canon,
                                         job->dst_path) != NGX_OK)
        {
            (void) webdav_delete_path_recursive(job->log, job->root_canon,
                                                tmp_path);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (brix_rename_confined_canon(job->log, job->root_canon, tmp_path,
                                   job->dst_path) != 0)
    {
        brix_log_safe_path(job->log, NGX_LOG_ERR, ngx_errno,
                             "brix_webdav COPY: dir rename failed: \"%s\"",
                             job->dst_path);
        (void) webdav_delete_path_recursive(job->log, job->root_canon, tmp_path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return job->dst_existed ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
}

/*
 * Copy a collection (directory) atomically.
 * Strategy: build the whole copy in a sibling temp directory, then rename it
 * into place — so a concurrent reader never sees a half-copied tree
 * (stage → commit). Every failure after the temp dir exists removes it, so no
 * orphan is left. Returns 201/204 on success or an HTTP error status.  May run
 * on a worker thread (see webdav_copy_collection_thread), so it uses only its
 * job parameters and thread-safe confined-FS helpers — no ngx_http_request_t
 * access.
 */
static ngx_int_t
webdav_copy_collection_execute(const webdav_copy_job_t *job)
{
    char      tmp_path[WEBDAV_MAX_PATH];
    ngx_int_t rc;

    rc = webdav_copy_collection_stage(job, tmp_path, sizeof(tmp_path));
    if (rc != NGX_OK) {
        return rc;
    }

    return webdav_copy_collection_commit(job, tmp_path);
}

/*
 * Thread-pool worker: runs the (potentially long) recursive collection copy off
 * the event loop.  Only writes t->http_status; the response is sent later by
 * webdav_copy_collection_done back on the event loop.
 */
static void
webdav_copy_collection_thread(void *data, ngx_log_t *log)
{
    webdav_copy_collection_task_t *t = data;

    (void) log;

    t->http_status = webdav_copy_collection_execute(&t->job);
}

/*
 * Completion handler (event loop): the async re-entry point after the worker
 * finishes.  Sends 201/204 on success or finalizes with the error status, and
 * releases the request reference taken in webdav_copy_collection_post_task.
 */
static void
webdav_copy_collection_done(ngx_event_t *ev)
{
    ngx_thread_task_t             *task = ev->data;
    webdav_copy_collection_task_t *t = task->ctx;
    ngx_http_request_t            *r = t->r;
    ngx_int_t                      status = t->http_status;

    if (status == NGX_HTTP_CREATED || status == NGX_HTTP_NO_CONTENT) {
        webdav_send_status_only(r, (ngx_uint_t) status);
        return;
    }

    webdav_metrics_finalize_request(r, status);
}

/*
 * WHAT: Resolve the WebDAV location's collection-copy thread pool, caching the
 * lookup on conf->common.thread_pool for reuse.
 *
 * WHY: postconfig only wires the pool for server-level loc_conf; nested location
 * blocks may still have a NULL pool, so it must be resolved lazily. Isolating
 * the lookup keeps the offload path a flat sequence.
 *
 * HOW: Returns the cached pool if present; otherwise looks it up by the
 * configured name (defaulting to "default"), caches a hit, and returns it (NULL
 * when no pool is available, i.e. the caller must run synchronously).
 */
static ngx_thread_pool_t *
webdav_copy_thread_pool(ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_thread_pool_t *pool = conf->common.thread_pool;

    if (pool == NULL) {
        static ngx_str_t default_name = ngx_string("default");
        ngx_str_t *pname = conf->common.thread_pool_name.len > 0
                           ? &conf->common.thread_pool_name : &default_name;
        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
        if (pool != NULL) {
            conf->common.thread_pool = pool;
        }
    }

    return pool;
}

/*
 * Try to offload a collection COPY to the thread pool.
 * Returns NGX_DONE if queued (request kept alive via r->main->count++),
 * NGX_DECLINED if no thread pool is available (caller runs it synchronously),
 * NGX_ERROR on allocation/post failure.  The job's stack-buffer paths are
 * copied into the task context so they remain valid after this returns.
 */
static ngx_int_t
webdav_copy_collection_post_task(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const webdav_copy_job_t *job)
{
    ngx_thread_task_t             *task;
    webdav_copy_collection_task_t *t;
    ngx_thread_pool_t             *pool;

    /*
     * Under impersonation the per-worker broker socket is a single fd shared by
     * the event-loop thread; a thread-pool task issuing confined ops would use
     * it concurrently and corrupt the request/reply framing, wedging the whole
     * worker's broker channel.  The thread also lacks the per-worker principal.
     * Force the synchronous (NGX_DECLINED) path so the recursive copy runs on
     * the event-loop thread where the principal is set and the broker socket
     * has exactly one user.
     */
    if (brix_imp_enabled()) {
        return NGX_DECLINED;
    }

    pool = webdav_copy_thread_pool(conf);
    if (pool == NULL) {
        return NGX_DECLINED;
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(webdav_copy_collection_task_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    t->r = r;
    t->job = *job;
    t->job.log = r->connection->log;
    t->http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;

    brix_task_bind(task, webdav_copy_collection_thread, webdav_copy_collection_done);
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "brix_webdav: offloaded collection COPY to thread pool");

    r->main->count++;
    return NGX_DONE;
}

/*
 * webdav_copy_probe — confined stat of `path` (follow semantics, matching the
 * prior brix_lstat_confined_canon nofollow=0) through the VFS probe, projected
 * into the struct stat fields the COPY handler needs (ino/dev for the self-copy
 * guard, mode for is-dir, mtime/size for the conditional checks). Non-metered
 * (the COPY op accounts for itself). Returns NGX_OK / NGX_DECLINED (errno kept).
 */
static ngx_int_t
webdav_copy_probe(ngx_http_request_t *r, const char *path, struct stat *sb)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t  *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    brix_vfs_ctx_t   vctx;
    brix_vfs_stat_t  vst;
    int                is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        conf->common.root_canon, conf->cache_root_canon, conf->common.allow_write,
        is_tls, (rx != NULL) ? rx->identity : NULL, path);
    /* Bind the export's per-user backend credential policy so this pre-copy
     * probe (existence/self-copy/overwrite check) enforces deny for the
     * REQUESTING USER on a remote-backed export, before any copy attempt. */
    brix_vfs_ctx_bind_backend_cred(&vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    webdav_vfs_bind_deleg(r, conf, &vctx);

    if (brix_vfs_probe(&vctx, 0 /* follow */, &vst) != NGX_OK) {
        return NGX_DECLINED;
    }

    ngx_memzero(sb, sizeof(*sb));
    sb->st_mode  = (mode_t) vst.mode;
    sb->st_size  = vst.size;
    sb->st_mtime = vst.mtime;
    sb->st_ino   = vst.ino;
    sb->st_dev   = vst.dev;
    return NGX_OK;
}

/*
 * WHAT: Parse the COPY request headers into req: decode the Destination URI into
 * req->dest_decoded and set req->overwrite and req->depth_infinity.
 *
 * WHY: Header extraction/decoding is a self-contained first phase; isolating it
 * keeps the handler a flat sequence of resolve → validate → execute.
 *
 * HOW: Requires a Destination header (400 if absent); Overwrite:F clears
 * overwrite; Depth:"0" selects depth:0 (default is infinity). Extracts the path
 * component of the Destination and URL-decodes it, propagating any helper error
 * status. Returns NGX_OK on success.
 */
static ngx_int_t
webdav_copy_parse_request(ngx_http_request_t *r, webdav_copy_req_t *req)
{
    ngx_table_elt_t *dest_hdr;
    ngx_table_elt_t *depth_hdr;
    const u_char    *dest_path_start;
    size_t           dest_path_len;
    ngx_int_t        rc;

    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);
    if (dest_hdr == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    req->overwrite = !brix_http_overwrite_forbidden(r);

    depth_hdr = webdav_tpc_find_header(r, "Depth", sizeof("Depth") - 1);
    if (depth_hdr != NULL
        && depth_hdr->value.len == 1 && depth_hdr->value.data[0] == '0')
    {
        req->depth_infinity = 0;
    }

    dest_path_start = dest_hdr->value.data;
    dest_path_len = dest_hdr->value.len;
    rc = webdav_destination_extract_path(dest_path_start, dest_path_len,
                                         &dest_path_start, &dest_path_len);
    if (rc != NGX_OK) {
        return rc;
    }

    return webdav_urldecode(dest_path_start, dest_path_len,
                            req->dest_decoded, sizeof(req->dest_decoded));
}

/*
 * WHAT: Resolve and validate the source/destination pair: fill req->src_path,
 * req->dst_path, their stat records, and req->dst_existed, then run the lock,
 * self-copy, overwrite and conditional checks.
 *
 * WHY: This is the security/precondition gate between parsing and executing the
 * copy — it enforces root confinement, INVARIANT 5's recursive child-lock check
 * on the destination tree, the RFC 4918 §9.8.5 self-copy rejection, the
 * Overwrite:F precondition, and If-Match/If-None-Match. Keeping it in one helper
 * makes the deny paths auditable in isolation.
 *
 * HOW: Resolves the source under root_canon and probes it (ENOENT→404, else
 * 500); resolves the destination and probes it (existence recorded, not
 * required); runs webdav_check_locks_tree; rejects a same-(dev,ino) self-copy
 * with 403; a pre-existing destination with Overwrite:F with 412; then the COPY
 * conditionals. Returns NGX_OK when the copy may proceed, else the HTTP status.
 */
static ngx_int_t
webdav_copy_resolve_pair(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, webdav_copy_req_t *req)
{
    ngx_int_t rc;

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon,
                                           req->src_path, sizeof(req->src_path));
    if (rc != NGX_OK) {
        return rc;
    }

    if (webdav_copy_probe(r, req->src_path, &req->src_sb) != NGX_OK) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = webdav_resolve_destination_path(r->connection->log, "COPY",
                                         conf->common.root_canon,
                                         req->dest_decoded, req->dst_path,
                                         sizeof(req->dst_path),
                                         conf->common.cache_store_endpoint);
    if (rc != NGX_OK) {
        return rc;
    }

    req->dst_existed = (webdav_copy_probe(r, req->dst_path, &req->dst_sb)
                        == NGX_OK);

    rc = webdav_check_locks_tree(r, req->dst_path);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Reject copy-onto-self: same (dev, ino) means source and destination are
     * the same file, which would corrupt/truncate it. RFC 4918 §9.8.5 -> 403. */
    if (req->dst_existed
        && req->src_sb.st_ino == req->dst_sb.st_ino
        && req->src_sb.st_dev == req->dst_sb.st_dev)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    if (req->dst_existed && !req->overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    return webdav_check_copy_conditionals(r, req->dst_path, req->dst_existed,
                                          &req->dst_sb);
}

/*
 * WHAT: Execute a collection (directory) COPY for a resolved request — offload
 * to the thread pool when possible, else run it inline.
 *
 * WHY: Isolates the S_ISDIR branch of the handler, keeping the depth:infinity
 * offload / fall-through / inline-run decision in one place.
 *
 * HOW: Builds a webdav_copy_job_t from the resolved request. For depth:infinity
 * it tries the thread pool: NGX_DONE means queued (returned as-is so the handler
 * finishes), NGX_ERROR maps to 500, NGX_DECLINED (no pool) falls through. It
 * then runs the copy inline; a non-201/204 status is returned as the failure,
 * NGX_OK means success (the handler emits the final status). Depth:0 always runs
 * inline (it only creates the top directory).
 */
static ngx_int_t
webdav_copy_do_collection(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const webdav_copy_req_t *req)
{
    webdav_copy_job_t job;
    ngx_int_t         rc;

    webdav_copy_job_init(&job, r->connection->log, conf->common.root_canon,
                         req);

    if (req->depth_infinity) {
        rc = webdav_copy_collection_post_task(r, conf, &job);
        if (rc == NGX_DONE) {
            return NGX_DONE;
        }
        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        /* rc == NGX_DECLINED: no thread pool, fall through to run inline. */
    }

    rc = webdav_copy_collection_execute(&job);
    if (rc != NGX_HTTP_CREATED && rc != NGX_HTTP_NO_CONTENT) {
        return rc;
    }

    return NGX_OK;
}

/*
 * WHAT: Build the VFS context for a file COPY, binding the export's per-user
 * backend credential policy, opt-in credential minting, and delegation.
 *
 * WHY: The data-plane copy must present the REQUESTING USER's credential to a
 * remote-backed export (not the shared service credential); centralising the
 * binding keeps the file-copy path readable and matches the pre-copy probe's
 * credential policy.
 *
 * HOW: Initialises the context under root_canon for the requesting identity,
 * then binds the credential dir/fallback, the mint CA cert/key/ttl, and the
 * delegation from the request — identical to the prior inline block.
 */
static void
webdav_copy_file_vfs_init(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *src_path,
    brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    int is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        conf->common.root_canon, conf->cache_root_canon,
        conf->common.allow_write, is_tls,
        (wctx != NULL) ? wctx->identity : NULL, src_path);
    brix_vfs_ctx_bind_backend_cred(vctx, &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    brix_vfs_ctx_bind_backend_mint(vctx,
        &conf->common.storage_credential_mint_ca_cert,
        &conf->common.storage_credential_mint_ca_key,
        conf->common.storage_credential_mint_ttl);
    webdav_vfs_bind_deleg(r, conf, vctx);
}

/*
 * WHAT: Execute a single-file COPY for a resolved request through the metered
 * VFS copy surface.
 *
 * WHY: Isolates the file branch of the handler, including the pre-delete of a
 * destination directory (rename(2) cannot atomically replace a directory with a
 * file) and the COPY-specific errno→HTTP mapping.
 *
 * HOW: Pre-deletes a pre-existing destination directory; builds the VFS context;
 * runs brix_vfs_copy with staged-commit + xattr preservation. On failure it maps
 * EEXIST→412 and ENOENT→409 (RFC 4918 overrides), everything else through the
 * canonical mapper. On success it clones dead props and returns NGX_OK.
 */
static ngx_int_t
webdav_copy_do_file(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const webdav_copy_req_t *req)
{
    brix_vfs_copy_opts_t copy_opts;
    brix_vfs_ctx_t       vctx;

    if (req->dst_existed && S_ISDIR(req->dst_sb.st_mode)) {
        (void) webdav_delete_path_recursive(r->connection->log,
                                            conf->common.root_canon,
                                            req->dst_path);
    }

    webdav_copy_file_vfs_init(r, conf, req->src_path, &vctx);

    ngx_memzero(&copy_opts, sizeof(copy_opts));
    copy_opts.overwrite       = req->overwrite ? 1 : 0;
    copy_opts.preserve_xattrs = 1;
    copy_opts.staged_commit   = 1;

    if (brix_vfs_copy(&vctx, req->dst_path, &copy_opts) != NGX_OK) {
        /* COPY-specific RFC 4918 semantics that differ from the generic
         * namespace→HTTP mapping: an existing dst with Overwrite:F is a
         * precondition failure (412, not 409), and a missing destination
         * parent is a Conflict (409, not 404).  brix_vfs_copy reports the
         * namespace failure via errno. */
        int err = errno;
        if (err == EEXIST) {
            return NGX_HTTP_PRECONDITION_FAILED;
        }
        if (err == ENOENT) {
            return NGX_HTTP_CONFLICT;
        }
        /* Everything else (DENIED→403, TOO_LONG→414, NO_SPACE→507,
         * IO_ERROR→500) goes through the canonical mapper so a DAC denial
         * — e.g. an impersonated cross-tenant copy into a 0700 dir — is a
         * clean 403, not a blanket 500. */
        return webdav_copy_errno_to_status(err);
    }

    webdav_dead_props_copy(r->connection->log, req->src_path, req->dst_path);
    return NGX_OK;
}

/*
 *
 * WHAT: Implements RFC 4918 §9.8 WebDAV COPY operation for server-side file/directory duplication within the same export root. Orchestrates the complete copy lifecycle: parses Destination/Overwrite/Depth headers, resolves both source and destination paths under root confinement, validates locks on destination, handles conditional checks (If-Match/If-None-Match), performs atomic copy via an intermediate staged temp path, then renames to final destination. Returns 201 Created when target didn't exist or 204 No Content when replacing existing resource; cleanup on failure ensures no orphaned temp files remain.
 *
 * WHY: WebDAV clients need an HTTP endpoint that can duplicate resources within the same filesystem namespace — unlike xrdcp native TPC which transfers between different servers, this COPY is local-only (same root). The tmp_path atomic rename strategy prevents partial copies from being visible to other clients; if copy fails the temp file is immediately deleted. Lock validation ensures no concurrent modifications interfere with the operation. Depth=0 means single-item copy; Depth=infinity recursively copies subdirectories (delegated to webdav_copy_dir_recursive in fs/copy_engine.c).
 *
 * HOW: Extracts and decodes Destination URI from request headers (strips scheme prefix to get filesystem path); resolves source via resolve_path() with root_canon confinement; resolves destination via webdav_resolve_destination_path(); checks both paths exist via stat(); validates locks on destination (including recursive child locks if depth=infinity); compares inode/dev numbers to reject self-copy attempt; applies Overwrite header semantics (F=don't overwrite, default=T=allow overwrite); runs copy_conditionals() for If-Match/If-None-Match; creates a staged temp file for file copies or a temp directory for collection copies; copies data via webdav_copy_file() or webdav_copy_dir_recursive(); commits temp→dst via confined rename. */
ngx_int_t
webdav_handle_copy(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    webdav_copy_req_t                req;
    ngx_int_t                        rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    ngx_memzero(&req, sizeof(req));
    req.depth_infinity = 1;

    rc = webdav_copy_parse_request(r, &req);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_copy_resolve_pair(r, conf, &req);
    if (rc != NGX_OK) {
        return rc;
    }

    if (S_ISDIR(req.src_sb.st_mode)) {
        rc = webdav_copy_do_collection(r, conf, &req);
    } else {
        rc = webdav_copy_do_file(r, conf, &req);
    }

    /* NGX_DONE = collection copy offloaded to a thread (response sent later);
     * any non-OK status is a failure to surface now. */
    if (rc != NGX_OK) {
        return rc;
    }

    return webdav_send_no_body(r, req.dst_existed ? NGX_HTTP_NO_CONTENT
                                                  : NGX_HTTP_CREATED);
}
