/*
 * copy_collection.c - WebDAV COPY collection (directory) machinery:
 * atomic stage→commit of a recursively-copied tree, plus the thread-pool
 * offload path.  Split out of copy.c for the file-size guard.
 */

#include "webdav.h"
#include "copy_internal.h"
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
ngx_int_t
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
