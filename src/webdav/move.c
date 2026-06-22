/*
 * move.c - WebDAV MOVE handler (RFC 4918 §9.9).
 */

#include "webdav.h"
#include "../compat/namespace_ops.h"
#include "../compat/http_conditionals.h"
#include "../impersonate/impersonate.h"
#include "../path/path.h"

#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    ngx_http_request_t *r;
    ngx_log_t         *log;
    char               root_canon[WEBDAV_MAX_PATH];
    char               src_path[WEBDAV_MAX_PATH];
    char               dst_path[WEBDAV_MAX_PATH];
    ngx_flag_t         dst_existed;
    ngx_flag_t         overwrite;
    ngx_int_t          http_status;
    int                sys_errno;
} webdav_move_collection_task_t;

/*
 * Perform the actual rename and map the namespace result to an HTTP status:
 *   OK        -> 204 (replaced) / 201 (created)
 *   EXISTS    -> 412 (Overwrite:F race)
 *   CONFLICT / NOT_FOUND -> 409 (missing parent / non-empty dst dir)
 *   anything else -> 500.
 * The raw errno is reported via *sys_errno for the caller's log.  May run on a
 * worker thread, so it touches only its parameters and thread-safe FS helpers.
 */
static ngx_int_t
webdav_move_execute(ngx_log_t *log, const char *root_canon,
    const char *src_path, const char *dst_path, ngx_flag_t overwrite,
    ngx_flag_t dst_existed, int *sys_errno)
{
    xrootd_ns_result_t res;

    res = xrootd_ns_rename(log, root_canon, src_path, dst_path, overwrite);

    if (sys_errno != NULL) {
        *sys_errno = res.sys_errno;
    }

    if (res.status == XROOTD_NS_OK) {
        return dst_existed ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
    }

    if (res.status == XROOTD_NS_EXISTS) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    if (res.status == XROOTD_NS_CONFLICT || res.status == XROOTD_NS_NOT_FOUND) {
        return NGX_HTTP_CONFLICT;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/* Thread-pool worker: runs the rename off the event loop and records the result
 * (status + errno) for webdav_move_collection_done to consume. */
static void
webdav_move_collection_thread(void *data, ngx_log_t *log)
{
    webdav_move_collection_task_t *t = data;

    (void) log;

    t->http_status = webdav_move_execute(t->log, t->root_canon,
                                         t->src_path, t->dst_path,
                                         t->overwrite, t->dst_existed,
                                         &t->sys_errno);
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
        r->headers_out.status = (ngx_uint_t) status;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        webdav_metrics_finalize_request(r, ngx_http_send_special(r,
                                                                 NGX_HTTP_LAST));
        return;
    }

    if (status == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, t->sys_errno,
                             "xrootd_webdav MOVE: rename() failed for: \"%s\"",
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
webdav_move_collection_post_task(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *src_path,
    const char *dst_path, ngx_flag_t overwrite, ngx_flag_t dst_existed)
{
    ngx_thread_task_t             *task;
    webdav_move_collection_task_t *t;
    ngx_thread_pool_t             *pool;

    /*
     * Under impersonation the per-worker broker socket is a single fd used by
     * the event-loop thread; a thread-pool task issuing confined ops would race
     * it and corrupt the broker framing (and lacks the per-worker principal).
     * Force the synchronous rename path (NGX_DECLINED).  See copy.c for detail.
     */
    if (xrootd_imp_enabled()) {
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
    t->dst_existed = dst_existed;
    t->overwrite = overwrite;
    t->http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    t->sys_errno = 0;

    ngx_cpystrn((u_char *) t->root_canon, (u_char *) conf->common.root_canon,
                sizeof(t->root_canon));
    ngx_cpystrn((u_char *) t->src_path, (u_char *) src_path,
                sizeof(t->src_path));
    ngx_cpystrn((u_char *) t->dst_path, (u_char *) dst_path,
                sizeof(t->dst_path));

    task->handler = webdav_move_collection_thread;
    task->event.handler = webdav_move_collection_done;
    task->event.data = task;
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "xrootd_webdav: offloaded collection MOVE to thread pool");

    r->main->count++;
    return NGX_DONE;
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
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t    *dest_hdr;
    char                src_path[WEBDAV_MAX_PATH];
    char                dst_path[WEBDAV_MAX_PATH];
    char                dest_decoded[WEBDAV_MAX_PATH];
    const u_char       *dest_path_start;
    size_t              dest_path_len;
    ngx_int_t           rc;
    int                 overwrite = 1;
    int                 dst_existed;
    struct stat         src_sb;
    struct stat         dst_sb;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    /* Require Destination header (RFC 4918 §9.9.4 — missing → 400) */
    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);
    if (dest_hdr == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    overwrite = !xrootd_http_overwrite_forbidden(r);

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

    /* Resolve source */
    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon,
                                              src_path, sizeof(src_path));
    if (rc != NGX_OK) {
        return rc;
    }

    if (xrootd_lstat_confined_canon(r->connection->log, conf->common.root_canon,
                                    src_path, &src_sb, 0) != 0) {
        return NGX_HTTP_NOT_FOUND;
    }

    rc = webdav_check_locks_tree(r, src_path);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Resolve destination */
    rc = webdav_resolve_destination_path(r->connection->log, "MOVE",
                                         conf->common.root_canon, dest_decoded,
                                         dst_path, sizeof(dst_path));
    if (rc != NGX_OK) {
        return rc;
    }

    dst_existed = (xrootd_lstat_confined_canon(r->connection->log,
                       conf->common.root_canon, dst_path, &dst_sb, 0) == 0);

    rc = webdav_check_locks_tree(r, dst_path);
    if (rc != NGX_OK) {
        return rc;
    }

    /* RFC 4918 §9.9.4 — Overwrite:F and destination exists → 412 */
    if (dst_existed && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    /* Prevent moving a resource onto itself */
    if (dst_existed && src_sb.st_ino == dst_sb.st_ino
        && src_sb.st_dev == dst_sb.st_dev)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    /* Directories are offloaded to a thread when one is available (NGX_DONE ends
     * the request here); NGX_DECLINED (no pool) and all non-directory moves fall
     * through to the synchronous rename below — rename(2) itself is fast, the
     * offload mainly isolates the worker from rare slow-fs stalls. */
    if (S_ISDIR(src_sb.st_mode)) {
        rc = webdav_move_collection_post_task(r, conf, src_path, dst_path,
                                              overwrite, dst_existed);
        if (rc == NGX_DONE) {
            return NGX_DONE;
        }
        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        /* NGX_DECLINED: no thread pool, fall through to synchronous rename. */
    }

    {
        int sys_errno = 0;

        rc = webdav_move_execute(r->connection->log, conf->common.root_canon,
                                 src_path, dst_path, overwrite, dst_existed,
                                 &sys_errno);

        if (rc == NGX_HTTP_CREATED || rc == NGX_HTTP_NO_CONTENT) {
            return webdav_send_no_body(r, (ngx_uint_t) rc);
        }

        if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
            xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, sys_errno,
                                 "xrootd_webdav MOVE: rename() failed for: \"%s\"",
                                 src_path);
        }

        if (rc == NGX_HTTP_PRECONDITION_FAILED || rc == NGX_HTTP_CONFLICT) {
            return rc;
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}
