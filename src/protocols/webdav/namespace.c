/*
 * namespace.c - WebDAV DELETE and MKCOL namespace operations.
 */

#include "webdav.h"
#include "core/compat/fs_walk.h"
#include "fs/vfs/vfs.h"
#include "protocols/shared/backend_async_http.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Build a transient VFS ctx for a confined namespace op on `path` (mirrors the
 * canonical construction in get.c).  Used by DELETE so the unlink/rmdir is
 * metered as OP_DELETE while keeping identical confinement and write-gating.
 */
static void
webdav_ns_vfs_ctx_init(ngx_http_request_t *r, const char *path,
    brix_vfs_ctx_t *vctx)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
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
    /* Wire per-user backend credential gate (Phase 2 Task 1) so that
     * DELETE/MKCOL namespace ops on a remote backend use the per-user
     * credential and deny mode rejects before opening any origin session. */
    brix_vfs_ctx_bind_backend_cred(vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    webdav_vfs_bind_deleg(r, conf, vctx);
}

/*
 * webdav_delete_path_recursive — recursively delete a directory and all its members.
 *
 * Uses opendir/readdir to traverse the tree.  Files are unlinked; directories
 * are emptied recursively and then rmdir'd.  Root confinement is enforced
 * via brix_unlink_confined_canon.
 *
 * Returns: NGX_OK on success, NGX_ERROR on any failure.
 */
ngx_int_t
webdav_delete_path_recursive(ngx_log_t *log, const char *root_canon,
                             const char *path)
{
    return brix_fs_remove_tree_confined(log, root_canon, path);
}

/*
 * Map a completed DELETE's result (op_errno 0 = removed) to the WebDAV response.
 * Shared by the synchronous handler and the async-queue wake so both render the
 * same status: 0 -> 204; ENOTEMPTY -> 409; ENOENT -> 404; EACCES -> 403 (deny-mode
 * per-user backend credential rejection); else 500. Success sends the body here;
 * error branches return the status code for the caller to finalise.
 */
static ngx_int_t
webdav_delete_respond(ngx_http_request_t *r, int op_errno)
{
    if (op_errno == 0) {
        return webdav_send_no_body(r, NGX_HTTP_NO_CONTENT);
    }
    if (op_errno == ENOTEMPTY) {
        return NGX_HTTP_CONFLICT;
    }
    if (op_errno == ENOENT) {
        return NGX_HTTP_NOT_FOUND;
    }
    if (op_errno == EACCES) {
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * Async-queue wake for a deferred DELETE: render the response for the batch's
 * unlink/rmdir result and finalise the request. Runs on the event loop after the
 * flush; ctx is unused (WebDAV finalises by rc, not a metrics slot).
 */
static void
webdav_delete_async_render(ngx_http_request_t *r, void *ctx, int op_errno)
{
    (void) ctx;
    webdav_metrics_finalize_request(r, webdav_delete_respond(r, op_errno));
}

/*
 * webdav_handle_delete — handle HTTP DELETE: remove a file or directory.
 *
 * RFC 4918 §9.6.1: DELETE on a collection MUST recursively delete all its
 * members and all their properties.
 *
 * The fd-cache entry for the path is evicted before the delete to prevent
 * use-after-free on cached file descriptors.
 */
ngx_int_t
webdav_handle_delete(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    char                              path[WEBDAV_MAX_PATH];
    struct stat                       sb;
    ngx_int_t                         rc;
    brix_vfs_ctx_t                  vctx;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_check_locks_tree(r, path);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Async backend: enqueue the unlink/rmdir and park the request until the
     * batch flushes. DELETE is already allow_write-gated at the access phase, so
     * the write gate has passed before we reach the queue. The queue drives the
     * same confined-VFS primitive as the sync path, keyed by the absolute
     * resolved `path`; a directory maps to RMDIR (non-recursive => require-empty,
     * the Standard WebDAV module policy), a file/symlink to UNLINK. NGX_DECLINED
     * (async off / enqueue failure) falls through to the inline op. */
    if (conf->common.backend_async) {
        brix_baq_op_t op = S_ISDIR(sb.st_mode) ? BRIX_BAQ_RMDIR
                                               : BRIX_BAQ_UNLINK;
        if (brix_baq_http_try(r, &conf->common, op, conf->common.root_canon,
                              path, NULL, 0, webdav_delete_async_render, NULL)
            == NGX_DONE)
        {
            return NGX_DONE;
        }
    }

    /* Route the delete through the metered VFS surface. webdav_resolve_stat
     * lstat'd the target (vfs_stat does not follow symlinks), so S_ISDIR here
     * agrees with brix_ns_delete's own lstat dispatch: a directory goes to
     * rmdir (non-recursive => require-empty, the Standard WebDAV module policy);
     * a file or symlink goes to unlink. DELETE is already allow_write-gated at
     * the access phase, so the VFS write-gate never fires here. */
    webdav_ns_vfs_ctx_init(r, path, &vctx);

    if (S_ISDIR(sb.st_mode)) {
        rc = brix_vfs_rmdir(&vctx, 0);
    } else {
        rc = brix_vfs_unlink(&vctx);
    }

    return webdav_delete_respond(r, (rc == NGX_OK) ? 0 : errno);
}

ngx_int_t
webdav_handle_mkcol(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    brix_vfs_ctx_t                   vctx;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon, path,
                                             sizeof(path));
    if (rc == (ngx_int_t) NGX_HTTP_NOT_FOUND) {
        return NGX_HTTP_CONFLICT;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_check_locks(r, path, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Route MKCOL through the metered VFS surface (non-recursive: a missing
     * parent component is a 409, matching the prior BRIX_NS_NOT_FOUND mapping).
     * MKCOL is allow_write-gated at the access phase, so the VFS write-gate never
     * fires here. errno after a failed vfs_mkdir mirrors brix_ns_mkdir:
     * EEXIST (target present) -> 405, ENOENT (parent missing) -> 409. */
    webdav_ns_vfs_ctx_init(r, path, &vctx);

    if (brix_vfs_mkdir(&vctx, 0755, 0 /* no parents */) == NGX_OK) {
        return webdav_send_no_body(r, NGX_HTTP_CREATED);
    }

    if (errno == EEXIST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (errno == ENOENT) {
        return NGX_HTTP_CONFLICT;
    }

    if (errno == EACCES) {
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
