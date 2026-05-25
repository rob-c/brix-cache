/*
 * namespace.c - WebDAV DELETE and MKCOL namespace operations.
 */

#include "webdav.h"
#include "../compat/namespace_ops.h"
#include "../compat/fs_walk.h"

#include <sys/stat.h>
#include <unistd.h>

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
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    xrootd_ns_result_t                res;
    xrootd_ns_delete_opts_t           opts;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_check_locks(r, path, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.idempotent_missing = 0;
    opts.require_empty_dir  = 1;  /* Standard WebDAV module policy */

    res = xrootd_ns_delete(r->connection->log, conf->common.root_canon, path, &opts);

    if (res.status == XROOTD_NS_OK) {
        r->headers_out.status = NGX_HTTP_NO_CONTENT;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    if (res.status == XROOTD_NS_NOT_EMPTY) {
        return NGX_HTTP_CONFLICT;
    }

    if (res.status == XROOTD_NS_NOT_FOUND) {
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
        r->headers_out.status = NGX_HTTP_CREATED;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    if (res.status == XROOTD_NS_EXISTS) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (res.status == XROOTD_NS_NOT_FOUND) {
        return NGX_HTTP_CONFLICT;
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
