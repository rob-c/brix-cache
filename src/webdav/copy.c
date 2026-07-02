/*
 * copy.c - WebDAV COPY handler (RFC 4918 §9.8).
 */

#include "webdav.h"
#include "webdav/fs/copy_engine.h"
#include "webdav/methods/copy_conditionals.h"
#include "core/compat/http_conditionals.h"
#include "core/compat/error_mapping.h"
#include "core/compat/namespace_ops.h"
#include "core/compat/tmp_path.h"
#include "fs/vfs.h"
#include "auth/impersonate/impersonate.h"
#include "path/path.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Map a VFS single-file-copy errno to the same HTTP status the prior
 * xrootd_ns_local_copy → status mapping produced.  xrootd_vfs_copy() returns
 * NGX_ERROR with errno set (the namespace sys_errno), so reconstruct the
 * namespace status the same way namespace_ops' errno_to_ns_status does and feed
 * it to xrootd_http_map_ns_status — guaranteeing byte-for-byte parity with the
 * old code (including DENIED→403, TOO_LONG→414, NO_SPACE→507, CONFLICT→409,
 * IO_ERROR→500).  The two COPY-specific overrides (EXISTS→412, NOT_FOUND→409)
 * are applied by the caller before this helper is reached.
 */
static ngx_int_t
webdav_copy_errno_to_status(int err)
{
    xrootd_ns_status_t status;

    switch (err) {
    case 0:            status = XROOTD_NS_OK;        break;
    case ENOENT:       status = XROOTD_NS_NOT_FOUND; break;
    case EACCES:
    case EPERM:
    case EXDEV:
    case ELOOP:        status = XROOTD_NS_DENIED;    break;
    case EEXIST:       status = XROOTD_NS_EXISTS;    break;
    case ENOTEMPTY:    status = XROOTD_NS_NOT_EMPTY; break;
    case ENAMETOOLONG: status = XROOTD_NS_TOO_LONG;  break;
    case ENOSPC:       status = XROOTD_NS_NO_SPACE;  break;
    case EBUSY:
    case EINVAL:       status = XROOTD_NS_CONFLICT;  break;
    default:           status = XROOTD_NS_IO_ERROR;  break;
    }

    return xrootd_http_map_ns_status(status);
}

typedef struct {
    ngx_http_request_t *r;
    ngx_log_t         *log;
    char               root_canon[WEBDAV_MAX_PATH];
    char               src_path[WEBDAV_MAX_PATH];
    char               dst_path[WEBDAV_MAX_PATH];
    mode_t             src_mode;
    ngx_flag_t         dst_existed;
    ngx_flag_t         dst_was_dir;
    ngx_flag_t         depth_infinity;
    ngx_int_t          http_status;
} webdav_copy_collection_task_t;

/*
 * Copy a collection (directory) atomically.
 * Strategy: build the whole copy in a sibling temp directory, then rename it
 * into place — so a concurrent reader never sees a half-copied tree.
 *   1. mkdir temp dir (ENOENT on the parent -> 409 Conflict);
 *   2. copy dead props + fattrs, then (depth:infinity) recurse the contents;
 *   3. if the destination already existed as a dir, remove it (rename can't
 *      replace a non-empty dir);
 *   4. rename temp -> dst.
 * Every failure after the temp dir exists removes it, so no orphan is left.
 * Returns 201/204 on success or an HTTP error status.  May run on a worker
 * thread (see webdav_copy_collection_thread), so it uses only its parameters
 * and thread-safe confined-FS helpers — no ngx_http_request_t access.
 */
static ngx_int_t
webdav_copy_collection_execute(ngx_log_t *log, const char *root_canon,
    const char *src_path, const char *dst_path, mode_t src_mode,
    ngx_flag_t dst_existed, ngx_flag_t dst_was_dir,
    ngx_flag_t depth_infinity)
{
    char      tmp_path[WEBDAV_MAX_PATH];
    ngx_int_t rc;

    if (xrootd_make_tmp_path(dst_path, tmp_path, sizeof(tmp_path)) != NGX_OK) {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    if (xrootd_vfs_mkdir_path(log, root_canon, tmp_path, src_mode & 0777) != 0) {
        if (errno == ENOENT) {
            return NGX_HTTP_CONFLICT;
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    webdav_dead_props_copy(log, src_path, tmp_path);
    xrootd_ns_copy_fattrs(log, src_path, tmp_path);

    if (depth_infinity) {
        rc = webdav_copy_dir_recursive(log, root_canon, src_path, tmp_path);
    } else {
        rc = NGX_OK;
    }

    if (rc != NGX_OK) {
        (void) webdav_delete_path_recursive(log, root_canon, tmp_path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (dst_existed && dst_was_dir) {
        if (webdav_delete_path_recursive(log, root_canon, dst_path) != NGX_OK) {
            (void) webdav_delete_path_recursive(log, root_canon, tmp_path);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (xrootd_rename_confined_canon(log, root_canon, tmp_path, dst_path) != 0) {
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "xrootd_webdav COPY: dir rename failed: \"%s\"",
                             dst_path);
        (void) webdav_delete_path_recursive(log, root_canon, tmp_path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return dst_existed ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
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

    t->http_status = webdav_copy_collection_execute(t->log, t->root_canon,
                                                    t->src_path, t->dst_path,
                                                    t->src_mode,
                                                    t->dst_existed,
                                                    t->dst_was_dir,
                                                    t->depth_infinity);
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
 * Try to offload a collection COPY to the thread pool.
 * Returns NGX_DONE if queued (request kept alive via r->main->count++),
 * NGX_DECLINED if no thread pool is available (caller runs it synchronously),
 * NGX_ERROR on allocation/post failure.  Stack-buffer paths are copied into the
 * task context so they remain valid after this returns.
 */
static ngx_int_t
webdav_copy_collection_post_task(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *src_path,
    const char *dst_path, mode_t src_mode, ngx_flag_t dst_existed,
    ngx_flag_t dst_was_dir, ngx_flag_t depth_infinity)
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

    task = ngx_thread_task_alloc(r->pool, sizeof(webdav_copy_collection_task_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    t->r = r;
    t->log = r->connection->log;
    t->src_mode = src_mode;
    t->dst_existed = dst_existed;
    t->dst_was_dir = dst_was_dir;
    t->depth_infinity = depth_infinity;
    t->http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;

    ngx_cpystrn((u_char *) t->root_canon, (u_char *) conf->common.root_canon,
                sizeof(t->root_canon));
    ngx_cpystrn((u_char *) t->src_path, (u_char *) src_path,
                sizeof(t->src_path));
    ngx_cpystrn((u_char *) t->dst_path, (u_char *) dst_path,
                sizeof(t->dst_path));

    xrootd_task_bind(task, webdav_copy_collection_thread, webdav_copy_collection_done);
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "xrootd_webdav: offloaded collection COPY to thread pool");

    r->main->count++;
    return NGX_DONE;
}

/*
 * webdav_copy_probe — confined stat of `path` (follow semantics, matching the
 * prior xrootd_lstat_confined_canon nofollow=0) through the VFS probe, projected
 * into the struct stat fields the COPY handler needs (ino/dev for the self-copy
 * guard, mode for is-dir, mtime/size for the conditional checks). Non-metered
 * (the COPY op accounts for itself). Returns NGX_OK / NGX_DECLINED (errno kept).
 */
static ngx_int_t
webdav_copy_probe(ngx_http_request_t *r, const char *path, struct stat *sb)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    ngx_http_xrootd_webdav_req_ctx_t  *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    xrootd_vfs_ctx_t   vctx;
    xrootd_vfs_stat_t  vst;
    int                is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    xrootd_vfs_ctx_init(&vctx, r->pool, r->connection->log, XROOTD_PROTO_WEBDAV,
        conf->common.root_canon, conf->cache_root_canon, conf->common.allow_write,
        is_tls, (rx != NULL) ? rx->identity : NULL, path);

    if (xrootd_vfs_probe(&vctx, 0 /* follow */, &vst) != NGX_OK) {
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
 *
 * WHAT: Implements RFC 4918 §9.8 WebDAV COPY operation for server-side file/directory duplication within the same export root. Orchestrates the complete copy lifecycle: parses Destination/Overwrite/Depth headers, resolves both source and destination paths under root confinement, validates locks on destination, handles conditional checks (If-Match/If-None-Match), performs atomic copy via an intermediate staged temp path, then renames to final destination. Returns 201 Created when target didn't exist or 204 No Content when replacing existing resource; cleanup on failure ensures no orphaned temp files remain.
 *
 * WHY: WebDAV clients need an HTTP endpoint that can duplicate resources within the same filesystem namespace — unlike xrdcp native TPC which transfers between different servers, this COPY is local-only (same root). The tmp_path atomic rename strategy prevents partial copies from being visible to other clients; if copy fails the temp file is immediately deleted. Lock validation ensures no concurrent modifications interfere with the operation. Depth=0 means single-item copy; Depth=infinity recursively copies subdirectories (delegated to webdav_copy_dir_recursive in fs/copy_engine.c).
 *
 * HOW: Extracts and decodes Destination URI from request headers (strips scheme prefix to get filesystem path); resolves source via resolve_path() with root_canon confinement; resolves destination via webdav_resolve_destination_path(); checks both paths exist via stat(); validates locks on destination (including recursive child locks if depth=infinity); compares inode/dev numbers to reject self-copy attempt; applies Overwrite header semantics (F=don't overwrite, default=T=allow overwrite); runs copy_conditionals() for If-Match/If-None-Match; creates a staged temp file for file copies or a temp directory for collection copies; copies data via webdav_copy_file() or webdav_copy_dir_recursive(); commits temp→dst via confined rename. */
ngx_int_t
webdav_handle_copy(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t    *dest_hdr;
    ngx_table_elt_t    *depth_hdr;
    char                src_path[WEBDAV_MAX_PATH];
    char                dst_path[WEBDAV_MAX_PATH];
    char                dest_decoded[WEBDAV_MAX_PATH];
    const u_char       *dest_path_start;
    size_t              dest_path_len;
    struct stat         src_sb;
    struct stat         dst_sb;
    ngx_int_t           rc;
    int                 overwrite;
    int                 dst_existed;
    int                 depth_infinity = 1;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);
    if (dest_hdr == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    overwrite = !xrootd_http_overwrite_forbidden(r);

    depth_hdr = webdav_tpc_find_header(r, "Depth", sizeof("Depth") - 1);
    if (depth_hdr != NULL) {
        if (depth_hdr->value.len == 1 && depth_hdr->value.data[0] == '0') {
            depth_infinity = 0;
        }
    }

    dest_path_start = dest_hdr->value.data;
    dest_path_len = dest_hdr->value.len;
    rc = webdav_destination_extract_path(dest_path_start, dest_path_len,
                                         &dest_path_start, &dest_path_len);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_urldecode(dest_path_start, dest_path_len,
                          dest_decoded, sizeof(dest_decoded));
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon,
                                             src_path, sizeof(src_path));
    if (rc != NGX_OK) {
        return rc;
    }

    if (webdav_copy_probe(r, src_path, &src_sb) != NGX_OK) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = webdav_resolve_destination_path(r->connection->log, "COPY",
                                         conf->common.root_canon, dest_decoded,
                                         dst_path, sizeof(dst_path));
    if (rc != NGX_OK) {
        return rc;
    }

    dst_existed = (webdav_copy_probe(r, dst_path, &dst_sb) == NGX_OK);

    rc = webdav_check_locks_tree(r, dst_path);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Reject copy-onto-self: same (dev, ino) means source and destination are
     * the same file, which would corrupt/truncate it. RFC 4918 §9.8.5 -> 403. */
    if (dst_existed
        && src_sb.st_ino == dst_sb.st_ino
        && src_sb.st_dev == dst_sb.st_dev)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    if (dst_existed && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    rc = webdav_check_copy_conditionals(r, dst_path, dst_existed, &dst_sb);
    if (rc != NGX_OK) {
        return rc;
    }

    if (S_ISDIR(src_sb.st_mode)) {
        /* Collection copy. For depth:infinity (potentially large), try to
         * offload to a thread first: NGX_DONE means queued (we are finished
         * here), NGX_ERROR is fatal, and NGX_DECLINED (no thread pool) falls
         * through to the synchronous execute below.  Depth:0 always runs
         * synchronously since it only creates the top directory. */
        if (depth_infinity) {
            rc = webdav_copy_collection_post_task(r, conf, src_path, dst_path,
                                                  src_sb.st_mode, dst_existed,
                                                  dst_existed
                                                      && S_ISDIR(dst_sb.st_mode),
                                                  depth_infinity);
            if (rc == NGX_DONE) {
                return NGX_DONE;
            }
            if (rc == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            /* rc == NGX_DECLINED: no thread pool, fall through to run inline. */
        }

        rc = webdav_copy_collection_execute(r->connection->log,
                                            conf->common.root_canon, src_path,
                                            dst_path, src_sb.st_mode,
                                            dst_existed,
                                            dst_existed
                                                && S_ISDIR(dst_sb.st_mode),
                                            depth_infinity);
        if (rc != NGX_HTTP_CREATED && rc != NGX_HTTP_NO_CONTENT) {
            return rc;
        }
    } else {
        /* File COPY: route the data move through the metered VFS copy surface
         * (delegates to the same namespace_ops local-copy service underneath).
         * Pre-delete destination directory if overwrite is enabled; rename(2)
         * cannot atomically replace a directory with a file. */
        xrootd_vfs_copy_opts_t copy_opts;
        xrootd_vfs_ctx_t       vctx;

        if (dst_existed && S_ISDIR(dst_sb.st_mode)) {
            (void) webdav_delete_path_recursive(r->connection->log,
                                                conf->common.root_canon, dst_path);
        }

        {
            ngx_http_xrootd_webdav_req_ctx_t *wctx =
                ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
            int is_tls = 0;
#if (NGX_HTTP_SSL)
            is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
            xrootd_vfs_ctx_init(&vctx, r->pool, r->connection->log,
                XROOTD_PROTO_WEBDAV, conf->common.root_canon,
                conf->cache_root_canon, conf->common.allow_write, is_tls,
                (wctx != NULL) ? wctx->identity : NULL, src_path);
        }

        ngx_memzero(&copy_opts, sizeof(copy_opts));
        copy_opts.overwrite       = overwrite ? 1 : 0;
        copy_opts.preserve_xattrs = 1;
        copy_opts.staged_commit   = 1;

        if (xrootd_vfs_copy(&vctx, dst_path, &copy_opts) != NGX_OK) {
            /* COPY-specific RFC 4918 semantics that differ from the generic
             * namespace→HTTP mapping: an existing dst with Overwrite:F is a
             * precondition failure (412, not 409), and a missing destination
             * parent is a Conflict (409, not 404).  xrootd_vfs_copy reports the
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

        webdav_dead_props_copy(r->connection->log, src_path, dst_path);
    }

    return webdav_send_no_body(r, dst_existed ? NGX_HTTP_NO_CONTENT
                                              : NGX_HTTP_CREATED);
}
