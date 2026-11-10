/*
 * move.c - WebDAV MOVE handler (RFC 4918 §9.9).
 */

#include "core/compat/log_event.h"
#include "webdav.h"
#include "move_destination.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_rename (ctx-bound) + brix_vfs_probe */
#include "core/http/http_conditionals.h"
#include "protocols/webdav/locks/request.h" /* webdav_lock_token_header (C7) */
#include "auth/impersonate/impersonate.h"
#include "fs/path/path.h"

#include <errno.h>

/* RFC 4918 §11.1: 423 Locked */
#ifndef NGX_HTTP_LOCKED
#define NGX_HTTP_LOCKED 423
#endif
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
 * reads (ino/dev for brix_webdav_same_object, mode for the dir branch). Non-metered.
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

    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        conf->common.root_canon, conf->common.cache_root_canon,
        brix_vfs_policy_from_write_enable(conf->common.allow_write),
        brix_http_request_is_tls(r), (rx != NULL) ? rx->identity : NULL, path);
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
        conf->common.root_canon, conf->common.cache_root_canon,
        brix_vfs_policy_from_write_enable(conf->common.allow_write),
        0 /* is_tls: irrelevant off the wire */,
        (wctx != NULL) ? wctx->identity : NULL, req->src_path);
    brix_vfs_ctx_bind_backend_cred(&vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    webdav_vfs_bind_deleg(r, conf, &vctx);
    vctx.sd = req->sd;

    /* phase-107 C7: the rename's VFS lock gate (src and destination) must see
     * the If/Lock-Token bytes the edge matched, or the OWNER's MOVE of its
     * own locked resource reads as foreign. Pure header lookup — a borrowed
     * pointer into the parked request, safe on the thread-pool worker too. */
    vctx.lock_token = webdav_lock_token_header(r);

    ngx_memzero(&dst_result, sizeof(dst_result));
    dst_result.is_confined = 1;
    dst_result.resolved.data = (u_char *) req->dst_path;
    dst_result.resolved.len = ngx_strlen(req->dst_path);

    if (brix_vfs_rename(&vctx, &dst_result,
                          req->overwrite ? 1 : 0) == NGX_OK) {
        if (sys_errno != NULL) {
            *sys_errno = 0;
        }
        /* NO CNS emit here: this function also runs on a thread-pool worker
         * (collection MOVE), and the emit writes to the worker's CMS connection,
         * which belongs to the event loop. Both callers report from their own
         * event-loop completion instead. */
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
    if (errno == EBUSY) {                         /* VFS lock gate (C7) */
        return NGX_HTTP_LOCKED;
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
        /* Back on the event loop, which is the only place the CMS connection may
         * be touched — the rename itself ran on a pool thread. */
        webdav_cns_note_moved(r, t->src_path, t->dst_path);
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
    pool = brix_shared_thread_pool(&conf->common);
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

    BRIX_LOG(NGX_LOG_INFO, r->connection->log, 0,
                  "brix_webdav: offloaded collection MOVE to thread pool");

    r->main->count++;
    return NGX_DONE;
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
        webdav_cns_note_moved(r, req->src_path, req->dst_path);
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

/* ---- Authorize one MOVE operand -----------------------------------------
 *
 * WHAT: Authorizes one paired logical/resolved MOVE resource and returns
 *       NGX_OK or the edge-owned HTTP refusal.
 *
 * WHY: Source removal, destination creation/update, and overwrite removal are
 *      distinct authority decisions but must use one representation-safe path.
 *
 * HOW: Populate the exact VFS authorization descriptor from explicit inputs
 *      and delegate to the authoritative WebDAV resource gate.
 */
static ngx_int_t
webdav_move_authorize(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *logical_path,
    const char *resolved_path, const char *operation, uint32_t needed_privs,
    brix_acc_op_t acc_op)
{
    brix_vfs_authz_exact_t exact = {
        .logical_path  = logical_path,
        .resolved_path = resolved_path,
        .operation     = operation,
        .needed_privs  = needed_privs,
        .acc_op        = acc_op,
        .need_write    = 1,
    };

    return webdav_authorize_resource(r, conf, &exact);
}

/* ---- Require authority to replace an existing MOVE destination ----------
 *
 * WHAT: Returns NGX_OK when no replacement occurs or when the caller may
 *       delete the existing destination; otherwise returns the HTTP refusal.
 *
 * WHY: Overwrite:T removes the destination identity in addition to updating
 *      its name, so destination update authority alone is insufficient.
 *
 * HOW: Bypass the extra decision for fresh or Overwrite:F targets; otherwise
 *      authorize DELETE on the same paired destination representation.
 */
static ngx_int_t
webdav_move_authorize_overwrite(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    const webdav_move_destination_t *dest, ngx_flag_t existed,
    ngx_flag_t overwrite)
{
    if (!existed || !overwrite) {
        return NGX_OK;
    }
    return webdav_move_authorize(r, conf, dest->logical, dest->resolved,
                                 "MOVE overwrite destination",
                                 BRIX_AUTH_DELETE, BRIX_AOP_DELETE);
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
    webdav_move_destination_t dest;
    char                src_logical[WEBDAV_MAX_PATH];
    char                src_path[WEBDAV_MAX_PATH];
    ngx_int_t           rc;
    struct stat         src_sb;
    struct stat         dst_sb;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    /* Keep the source's client-visible and confined forms paired for the
     * authoritative edge decision. */
    rc = webdav_decode_request_path(r, src_logical, sizeof(src_logical));
    if (rc != NGX_OK) {
        return rc;
    }
    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon,
                                              src_path, sizeof(src_path));
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_move_authorize(r, conf, src_logical, src_path,
                               "MOVE source", BRIX_AUTH_DELETE,
                               BRIX_AOP_RENAME);
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
    rc = webdav_move_resolve_dest(r, conf, &dest);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Destination INSERT is required before even probing the target.  This
     * denies cross-scope existence and lock oracles to a source-only caller. */
    rc = webdav_move_authorize(r, conf, dest.logical, dest.resolved,
                               "MOVE destination", BRIX_AUTH_UPDATE,
                               BRIX_AOP_INSERT);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&req, sizeof(req));
    req.r           = r;
    req.conf        = conf;
    req.sd          = (brix_sd_instance_t *)
                          brix_webdav_backend_instance(conf, r->connection->log);
    req.src_path    = src_path;
    req.dst_path    = dest.resolved;
    req.overwrite   = !brix_http_overwrite_forbidden(r);
    req.dst_existed = (webdav_move_probe(r, dest.resolved, &dst_sb) == NGX_OK);

    /* Replacing an existing resource removes that destination identity too.
     * Require DELETE before its lock state, metadata, or contents are inspected. */
    rc = webdav_move_authorize_overwrite(r, conf, &dest, req.dst_existed,
                                         req.overwrite);
    if (rc != NGX_OK) {
        return rc;
    }

    /* MOVE on a collection recursively checks child locks (dest subtree). */
    rc = webdav_check_locks_tree(r, dest.resolved);
    if (rc != NGX_OK) {
        return rc;
    }

    /* RFC 4918 §9.9.4 — Overwrite:F and destination exists → 412 */
    if (req.dst_existed && !req.overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    /* Prevent moving a resource onto itself — the same predicate COPY applies,
     * including the reason an inode-only test cannot be it on a remote export. */
    if (req.dst_existed
        && brix_webdav_same_object(src_path, dest.resolved, &src_sb, &dst_sb))
    {
        return NGX_HTTP_FORBIDDEN;
    }

    /* MOVE deliberately does not use the durable backend queue.  A replayed
     * rename has no request identity or rule generation with which to preserve
     * the exact source/destination decisions above.  The identity-aware VFS
     * path remains fully functional; brix_backend_async still applies to the
     * single-resource DELETE operations whose edge authority is complete. */
    return webdav_move_dispatch(&req, S_ISDIR(src_sb.st_mode));
}
