/*
 * move.c - WebDAV MOVE handler (RFC 4918 §9.9).
 */

#include "webdav.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_rename (ctx-bound) + brix_vfs_probe */
#include "core/http/http_conditionals.h"
#include "auth/impersonate/impersonate.h"
#include "fs/path/path.h"
#include "protocols/shared/backend_async_http.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    ngx_http_request_t   *r;
    ngx_log_t            *log;
    brix_sd_instance_t *sd;   /* selected storage backend (NULL = POSIX) */
    char               root_canon[WEBDAV_MAX_PATH];
    char               src_path[WEBDAV_MAX_PATH];
    char               dst_path[WEBDAV_MAX_PATH];
    ngx_flag_t         dst_existed;
    ngx_flag_t         overwrite;
    ngx_int_t          http_status;
    int                sys_errno;
} webdav_move_collection_task_t;

/*
 * webdav_move_req_t — a single MOVE request's resolved, confined state, passed
 * by reference to the stage helpers so none of them needs the full 6–7 scalar
 * argument list.  Every field is derived once by webdav_handle_move before any
 * rename is attempted (paths are already resolve_path/resolve_destination
 * confined and NUL-terminated).
 *
 * WHY:  Collapses the previously 7-param webdav_move_execute_cred and 6-param
 *       webdav_move_collection_post_task onto one file-local struct — no
 *       behavior change, only the calling convention.  Kept file-local (static
 *       linkage callers only) so the frozen extern seams are untouched.
 *
 * HOW:  Populated in webdav_handle_move; read (never mutated) by the execute /
 *       dispatch / offload helpers.  `sd` is the selected backend instance
 *       (NULL = POSIX default).
 */
typedef struct {
    ngx_http_request_t              *r;
    ngx_http_brix_webdav_loc_conf_t *conf;
    brix_sd_instance_t              *sd;
    const char                      *src_path;
    const char                      *dst_path;
    ngx_flag_t                       overwrite;
    ngx_flag_t                       dst_existed;
} webdav_move_req_t;

/*
 * webdav_move_probe — confined stat of `path` (follow, matching the prior
 * lstat nofollow=0) via the VFS probe, projected to the struct stat fields MOVE
 * reads (ino/dev for the self-move guard, mode for the dir branch). Non-metered.
 * NGX_OK / NGX_DECLINED (errno kept).
 */
static ngx_int_t
webdav_move_probe(ngx_http_request_t *r, const char *path, struct stat *sb)
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
    /* Bind the export's per-user backend credential policy so a remote-backed
     * export's probe (and the deny gate it enforces) sees the REQUESTING
     * USER's credential, not the shared service credential — this probe is
     * also the pre-rename existence/self-move check, so deny must be
     * enforced here before MOVE ever reaches the rename. */
    brix_vfs_ctx_bind_backend_cred(&vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    webdav_vfs_bind_deleg(r, conf, &vctx);
    if (brix_vfs_probe(&vctx, 0 /* follow */, &vst) != NGX_OK) {
        return NGX_DECLINED;
    }
    ngx_memzero(sb, sizeof(*sb));
    sb->st_mode = (mode_t) vst.mode;
    sb->st_ino  = vst.ino;
    sb->st_dev  = vst.dev;
    return NGX_OK;
}

/*
 * webdav_move_execute_cred — perform the actual rename through the ctx-bound
 * brix_vfs_rename (rather than the pool-less brix_vfs_rename_path this
 * replaced) and map the namespace result to an HTTP status:
 *   OK        -> 204 (replaced) / 201 (created)
 *   EXISTS    -> 412 (Overwrite:F race)
 *   CONFLICT / NOT_FOUND -> 409 (missing parent / non-empty dst dir)
 *   FORBIDDEN -> 403 (per-user backend credential gate denied)
 *   anything else -> 500.
 * The raw errno is reported via *sys_errno for the caller's log.
 *
 * WHY:  Building the ctx here and binding brix_vfs_ctx_bind_backend_cred so a
 *       remote-backed export sees the REQUESTING USER's credential (not the
 *       shared service credential) for the rename — matching root:// mv.c.
 *       Both MOVE callers (the synchronous single-file path and the
 *       thread-pool collection-MOVE offload) share this one function.
 *
 * HOW:  Called from both the event loop (webdav_handle_move) and a
 *       thread-pool worker (webdav_move_collection_thread); the ctx is built
 *       fresh here each call using `r`'s pool/connection/identity, which stay
 *       valid for either caller's lifetime (the collection-offload caller
 *       took r->main->count++ before posting the task). req->overwrite is
 *       threaded into brix_vfs_rename as overwrite_dirs so Overwrite:T can
 *       replace an existing DIRECTORY destination (RFC 4918 §9.9.4 — the
 *       target tree is removed before the rename); Overwrite:F was already
 *       rejected as 412 before either path reaches this function.
 *
 * The 7 scalar arguments this once took are now carried on a file-local
 * webdav_move_req_t (see above) — no behavior change, only the calling
 * convention; *sys_errno reports the raw errno for the caller's log.
 */
static ngx_int_t
webdav_move_execute_cred(const webdav_move_req_t *req, int *sys_errno)
{
    ngx_http_request_t              *r = req->r;
    ngx_http_brix_webdav_loc_conf_t *conf = req->conf;
    ngx_http_brix_webdav_req_ctx_t  *wctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    brix_vfs_ctx_t     vctx;
    brix_path_result_t dst_result;

    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        conf->common.root_canon, conf->cache_root_canon,
        conf->common.allow_write, 0 /* is_tls: irrelevant off the wire */,
        (wctx != NULL) ? wctx->identity : NULL, req->src_path);
    brix_vfs_ctx_bind_backend_cred(&vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    webdav_vfs_bind_deleg(r, conf, &vctx);
    vctx.sd = req->sd;

    ngx_memzero(&dst_result, sizeof(dst_result));
    dst_result.is_confined = 1;
    dst_result.resolved.data = (u_char *) req->dst_path;
    dst_result.resolved.len = ngx_strlen(req->dst_path);

    if (brix_vfs_rename(&vctx, &dst_result,
                          req->overwrite ? 1 : 0) == NGX_OK) {
        if (sys_errno != NULL) {
            *sys_errno = 0;
        }
        return req->dst_existed ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
    }

    if (sys_errno != NULL) {
        *sys_errno = errno;
    }

    if (errno == EEXIST) {                       /* NS_EXISTS */
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    if (errno == ENOTDIR || errno == ENOENT) {   /* NS_CONFLICT / NS_NOT_FOUND */
        return NGX_HTTP_CONFLICT;
    }

    if (errno == EACCES || errno == EPERM) {      /* deny-mode credential gate */
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/* Thread-pool worker: runs the rename off the event loop and records the result
 * (status + errno) for webdav_move_collection_done to consume. */
static void
webdav_move_collection_thread(void *data, ngx_log_t *log)
{
    webdav_move_collection_task_t *t = data;
    webdav_move_req_t              req;

    (void) log;

    ngx_memzero(&req, sizeof(req));
    req.r           = t->r;
    req.conf        = ngx_http_get_module_loc_conf(t->r,
                          ngx_http_brix_webdav_module);
    req.sd          = t->sd;
    req.src_path    = t->src_path;
    req.dst_path    = t->dst_path;
    req.overwrite   = t->overwrite;
    req.dst_existed = t->dst_existed;

    t->http_status = webdav_move_execute_cred(&req, &t->sys_errno);
}

/*
 * Completion handler (event loop): async re-entry after the worker finishes.
 * Sends 201/204 on success, logs the rename errno on 500, finalizes with the
 * status, and releases the request reference taken in the post function.
 */
static void
webdav_move_collection_done(ngx_event_t *ev)
{
    ngx_thread_task_t             *task = ev->data;
    webdav_move_collection_task_t *t = task->ctx;
    ngx_http_request_t            *r = t->r;
    ngx_int_t                      status = t->http_status;

    if (status == NGX_HTTP_CREATED || status == NGX_HTTP_NO_CONTENT) {
        webdav_send_status_only(r, (ngx_uint_t) status);
        return;
    }

    if (status == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR, t->sys_errno,
                             "brix_webdav MOVE: rename() failed for: \"%s\"",
                             t->src_path);
    }

    webdav_metrics_finalize_request(r, status);
}

/*
 * Try to offload a collection MOVE to the thread pool.  Returns NGX_DONE when
 * queued (request held via r->main->count++), NGX_DECLINED when no pool is
 * available (caller runs the rename synchronously), NGX_ERROR on failure.
 */
static ngx_int_t
webdav_move_collection_post_task(const webdav_move_req_t *req)
{
    ngx_http_request_t              *r = req->r;
    ngx_http_brix_webdav_loc_conf_t *conf = req->conf;
    ngx_thread_task_t               *task;
    webdav_move_collection_task_t   *t;
    ngx_thread_pool_t               *pool;

    /*
     * Under impersonation the per-worker broker socket is a single fd used by
     * the event-loop thread; a thread-pool task issuing confined ops would race
     * it and corrupt the broker framing (and lacks the per-worker principal).
     * Force the synchronous rename path (NGX_DECLINED).  See copy.c for detail.
     */
    if (brix_imp_enabled()) {
        return NGX_DECLINED;
    }

    /* postconfig only visits server-level loc_conf; resolve lazily for nested
     * location blocks where conf->common.thread_pool may still be NULL. */
    pool = conf->common.thread_pool;
    if (pool == NULL) {
        static ngx_str_t default_name = ngx_string("default");
        ngx_str_t *pname = conf->common.thread_pool_name.len > 0
                           ? &conf->common.thread_pool_name : &default_name;
        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
        if (pool != NULL) {
            conf->common.thread_pool = pool;
        }
    }
    if (pool == NULL) {
        return NGX_DECLINED;
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(webdav_move_collection_task_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    t->r = r;
    t->log = r->connection->log;
    t->dst_existed = req->dst_existed;
    t->overwrite = req->overwrite;
    t->http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    t->sys_errno = 0;
    t->sd = req->sd;

    ngx_cpystrn((u_char *) t->root_canon, (u_char *) conf->common.root_canon,
                sizeof(t->root_canon));
    ngx_cpystrn((u_char *) t->src_path, (u_char *) req->src_path,
                sizeof(t->src_path));
    ngx_cpystrn((u_char *) t->dst_path, (u_char *) req->dst_path,
                sizeof(t->dst_path));

    brix_task_bind(task, webdav_move_collection_thread, webdav_move_collection_done);
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "brix_webdav: offloaded collection MOVE to thread pool");

    r->main->count++;
    return NGX_DONE;
}

/*
 * webdav_move_resolve_dest — stage 1 of MOVE destination handling: read the
 * mandatory Destination header, strip its scheme://authority, URL-decode it,
 * and resolve+confine it to `dst_path`.
 *
 * WHAT: Turns the raw Destination request header into a confined absolute
 *       filesystem path (dst_path, capacity dst_cap).
 * WHY:  Lifts the four sequential "extract → decode → resolve" steps (each with
 *       its own early-return) out of webdav_handle_move so the top-level MOVE
 *       reads as a linear sequence of stages, dropping its branch count.
 * HOW:  Returns NGX_OK on success; on any failure returns the exact HTTP status
 *       the original inline code returned (400 for a missing Destination header,
 *       otherwise the sub-helper's rc) so the wire behavior is unchanged.
 */
static ngx_int_t
webdav_move_resolve_dest(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, char *dst_path, size_t dst_cap)
{
    ngx_table_elt_t *dest_hdr;
    char             dest_decoded[WEBDAV_MAX_PATH];
    const u_char    *dest_path_start;
    size_t           dest_path_len;
    ngx_int_t        rc;

    /* Require Destination header (RFC 4918 §9.9.4 — missing → 400) */
    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);
    if (dest_hdr == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Extract path component from Destination URL, stripping scheme://authority. */
    dest_path_start = dest_hdr->value.data;
    dest_path_len   = dest_hdr->value.len;
    rc = webdav_destination_extract_path(dest_path_start, dest_path_len,
                                         &dest_path_start, &dest_path_len);
    if (rc != NGX_OK) {
        return rc;
    }

    /* URL-decode the destination path */
    rc = webdav_urldecode(dest_path_start, dest_path_len,
                          dest_decoded, sizeof(dest_decoded));
    if (rc != NGX_OK) {
        return rc;
    }

    /* Resolve destination */
    return webdav_resolve_destination_path(r->connection->log, "MOVE",
                                           conf->common.root_canon, dest_decoded,
                                           dst_path, dst_cap,
                                           conf->common.cache_store_endpoint);
}

/*
 * webdav_move_run_sync — stage: perform the rename on the event-loop thread
 * (used for non-directory moves and directory moves when no thread pool is
 * available) and map the namespace result to the final HTTP response.
 *
 * WHAT: Runs webdav_move_execute_cred synchronously and returns the terminal
 *       value webdav_handle_move should hand back to nginx.
 * WHY:  Isolates the success/forbidden/500-log/412-409 status ladder from the
 *       top-level handler, cutting its cyclomatic complexity without changing
 *       any status code or the 500 rename-failure log line.
 * HOW:  Sends 201/204 via webdav_send_no_body on success; on 500 logs the raw
 *       rename errno against the source path; returns 403/412/409 verbatim and
 *       falls back to 500 for anything else — byte-for-byte the prior inline
 *       block.
 */
static ngx_int_t
webdav_move_run_sync(const webdav_move_req_t *req)
{
    ngx_http_request_t *r = req->r;
    int                 sys_errno = 0;
    ngx_int_t           rc;

    rc = webdav_move_execute_cred(req, &sys_errno);

    if (rc == NGX_HTTP_CREATED || rc == NGX_HTTP_NO_CONTENT) {
        return webdav_send_no_body(r, (ngx_uint_t) rc);
    }

    if (rc == NGX_HTTP_FORBIDDEN) {
        return rc;
    }

    if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR, sys_errno,
                             "brix_webdav MOVE: rename() failed for: \"%s\"",
                             req->src_path);
    }

    if (rc == NGX_HTTP_PRECONDITION_FAILED || rc == NGX_HTTP_CONFLICT) {
        return rc;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * webdav_move_dispatch — stage: route a fully-resolved MOVE to its executor.
 *
 * WHAT: For a directory source, tries the thread-pool offload; for everything
 *       else (and for a directory when no pool is available) runs the rename
 *       synchronously.  Returns the terminal value for webdav_handle_move.
 * WHY:  Collapses the S_ISDIR offload branch + its NGX_DONE/NGX_ERROR/NGX_DECLINED
 *       handling and the synchronous fall-through into one helper, keeping the
 *       collection-recursion contract (child-lock checks already done upstream)
 *       intact while removing branches from the top-level handler.
 * HOW:  NGX_DONE from the offload ends the request here (already returned to
 *       nginx); NGX_ERROR maps to 500; NGX_DECLINED (no pool / impersonation)
 *       falls through to webdav_move_run_sync — identical to the prior inline
 *       control flow.  `is_dir` is the source's S_ISDIR bit, computed by the
 *       caller from the same stat used for the self-move guard.
 */
static ngx_int_t
webdav_move_dispatch(const webdav_move_req_t *req, int is_dir)
{
    ngx_int_t rc;

    /* Directories are offloaded to a thread when one is available (NGX_DONE ends
     * the request here); NGX_DECLINED (no pool) and all non-directory moves fall
     * through to the synchronous rename below — rename(2) itself is fast, the
     * offload mainly isolates the worker from rare slow-fs stalls. */
    if (is_dir) {
        rc = webdav_move_collection_post_task(req);
        if (rc == NGX_DONE) {
            return NGX_DONE;
        }
        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        /* NGX_DECLINED: no thread pool, fall through to synchronous rename. */
    }

    return webdav_move_run_sync(req);
}

/*
 * Async-queue wake for a deferred fresh-destination MOVE: render the response
 * for the batch's rename result and finalise. The destination did not exist when
 * the request was accepted (the intercept requires !dst_existed), so success is
 * always 201 Created; the error ladder mirrors webdav_move_execute_cred. Runs on
 * the event loop after the flush; ctx is unused.
 */
static void
webdav_move_async_render(ngx_http_request_t *r, void *ctx, int op_errno)
{
    ngx_int_t status;

    (void) ctx;

    if (op_errno == 0) {
        webdav_metrics_finalize_request(r,
            webdav_send_no_body(r, NGX_HTTP_CREATED));
        return;
    }
    if (op_errno == EEXIST) {
        status = NGX_HTTP_PRECONDITION_FAILED;
    } else if (op_errno == ENOTDIR || op_errno == ENOENT) {
        status = NGX_HTTP_CONFLICT;
    } else if (op_errno == EACCES || op_errno == EPERM) {
        status = NGX_HTTP_FORBIDDEN;
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, op_errno,
                      "brix_webdav MOVE: async rename() failed");
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    webdav_metrics_finalize_request(r, status);
}

/*
 * webdav_handle_move — implement RFC 4918 §9.9 MOVE.
 *
 * Key protocol requirements enforced:
 *   - Destination header is mandatory (RFC 4918 §9.9.4).
 *   - Overwrite:F with an existing destination → 412 Precondition Failed.
 *   - Moving a resource onto itself → 403 Forbidden.
 *   - Non-empty destination directory → 409 Conflict (renameat ENOTEMPTY).
 *
 * Atomicity: rename(2) is atomic within the same filesystem.  Both source
 *   and destination must be within root_canon, so cross-device moves are
 *   impossible (they would be caught by realpath confinement).
 *
 * Fd-cache eviction: both source and destination paths are evicted from the
 *   per-connection fd-cache after a successful rename to prevent stale fds.
 */
ngx_int_t
webdav_handle_move(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    webdav_move_req_t   req;
    char                src_path[WEBDAV_MAX_PATH];
    char                dst_path[WEBDAV_MAX_PATH];
    ngx_int_t           rc;
    struct stat         src_sb;
    struct stat         dst_sb;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    /* Resolve source */
    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon,
                                              src_path, sizeof(src_path));
    if (rc != NGX_OK) {
        return rc;
    }

    if (webdav_move_probe(r, src_path, &src_sb) != NGX_OK) {
        return NGX_HTTP_NOT_FOUND;
    }

    /* MOVE on a collection recursively checks child locks (source subtree). */
    rc = webdav_check_locks_tree(r, src_path);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Read + strip + decode + confine the Destination header. */
    rc = webdav_move_resolve_dest(r, conf, dst_path, sizeof(dst_path));
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&req, sizeof(req));
    req.r           = r;
    req.conf        = conf;
    req.sd          = (brix_sd_instance_t *)
                          brix_webdav_backend_instance(conf, r->connection->log);
    req.src_path    = src_path;
    req.dst_path    = dst_path;
    req.overwrite   = !brix_http_overwrite_forbidden(r);
    req.dst_existed = (webdav_move_probe(r, dst_path, &dst_sb) == NGX_OK);

    /* MOVE on a collection recursively checks child locks (dest subtree). */
    rc = webdav_check_locks_tree(r, dst_path);
    if (rc != NGX_OK) {
        return rc;
    }

    /* RFC 4918 §9.9.4 — Overwrite:F and destination exists → 412 */
    if (req.dst_existed && !req.overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    /* Prevent moving a resource onto itself */
    if (req.dst_existed && src_sb.st_ino == dst_sb.st_ino
        && src_sb.st_dev == dst_sb.st_dev)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    /* Async backend: defer the rename to the coalescing queue and park the
     * request until the batch flushes. Scoped to the fresh-destination, non-
     * directory case (!dst_existed && !S_ISDIR): the queue's rename applies
     * overwrite=0 and models a single leaf rename, so it exactly matches this
     * branch (success => 201 Created) without diverging from the Overwrite:T
     * replacement or collection-tree offload the sync dispatch handles. The
     * Overwrite/self-move/412 preconditions above have all been checked
     * synchronously, and MOVE is allow_write-gated at the access phase, so the
     * mutation is fully authorised before it reaches the queue. Keyed by the
     * absolute confined src_path/dst_path (matching the sync VFS rename). */
    if (conf->common.backend_async && !req.dst_existed
        && !S_ISDIR(src_sb.st_mode))
    {
        if (brix_baq_http_try(r, &conf->common, BRIX_BAQ_RENAME,
                              conf->common.root_canon, src_path, dst_path, 0,
                              webdav_move_async_render, NULL) == NGX_DONE)
        {
            return NGX_DONE;
        }
    }

    return webdav_move_dispatch(&req, S_ISDIR(src_sb.st_mode));
}
