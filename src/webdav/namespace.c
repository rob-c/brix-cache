/*
 * namespace.c - WebDAV DELETE and MKCOL namespace operations.
 */

#include "webdav.h"
#include "../compat/namespace_ops.h"
#include "../compat/fs_walk.h"
#include "../fs/vfs.h"

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
    xrootd_vfs_ctx_t *vctx)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    ngx_http_xrootd_webdav_req_ctx_t *wctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    int is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    xrootd_vfs_ctx_init(vctx, r->pool, r->connection->log,
        XROOTD_PROTO_WEBDAV, conf->common.root_canon,
        conf->cache_root_canon, conf->common.allow_write, is_tls,
        (wctx != NULL) ? wctx->identity : NULL, path);
}

/*
 * webdav_delete_path_recursive — recursively delete a directory and all its members.
 *
 * Uses opendir/readdir to traverse the tree.  Files are unlinked; directories
 * are emptied recursively and then rmdir'd.  Root confinement is enforced
 * via xrootd_unlink_confined_canon.
 *
 * Returns: NGX_OK on success, NGX_ERROR on any failure.
 */
ngx_int_t
webdav_delete_path_recursive(ngx_log_t *log, const char *root_canon,
                             const char *path)
{
    return xrootd_fs_remove_tree_confined(log, root_canon, path);
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
    char                              path[WEBDAV_MAX_PATH];
    struct stat                       sb;
    ngx_int_t                         rc;
    xrootd_vfs_ctx_t                  vctx;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_check_locks_tree(r, path);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Route the delete through the metered VFS surface. webdav_resolve_stat
     * lstat'd the target (vfs_stat does not follow symlinks), so S_ISDIR here
     * agrees with xrootd_ns_delete's own lstat dispatch: a directory goes to
     * rmdir (non-recursive => require-empty, the Standard WebDAV module policy);
     * a file or symlink goes to unlink. DELETE is already allow_write-gated at
     * the access phase, so the VFS write-gate never fires here. */
    webdav_ns_vfs_ctx_init(r, path, &vctx);

    if (S_ISDIR(sb.st_mode)) {
        rc = xrootd_vfs_rmdir(&vctx, 0);
    } else {
        rc = xrootd_vfs_unlink(&vctx);
    }

    if (rc == NGX_OK) {
        return webdav_send_no_body(r, NGX_HTTP_NO_CONTENT);
    }

    /* Preserve the prior status mapping: ENOTEMPTY (XROOTD_NS_NOT_EMPTY) -> 409,
     * ENOENT (XROOTD_NS_NOT_FOUND) -> 404, anything else -> 500. */
    if (errno == ENOTEMPTY) {
        return NGX_HTTP_CONFLICT;
    }

    if (errno == ENOENT) {
        return NGX_HTTP_NOT_FOUND;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

ngx_int_t
webdav_handle_mkcol(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    xrootd_ns_result_t                 res;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon, path,
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

    res = xrootd_ns_mkdir(r->connection->log, conf->common.root_canon, path, 0755, 0);

    if (res.status == XROOTD_NS_OK) {
        return webdav_send_no_body(r, NGX_HTTP_CREATED);
    }

    if (res.status == XROOTD_NS_EXISTS) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (res.status == XROOTD_NS_NOT_FOUND) {
        return NGX_HTTP_CONFLICT;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
