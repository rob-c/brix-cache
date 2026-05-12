/*
 * resource.c - shared path resolution for WebDAV resource handlers.
 */

#include "webdav.h"

#include <errno.h>

/*
 * webdav_resolve_stat — resolve the request URI to a filesystem path within
 * the export root, then stat(2) the result.
 *
 * Fills path[0..pathsz-1] with the canonicalised absolute path on success.
 * On ENOENT returns NGX_HTTP_NOT_FOUND; all other stat errors return
 * NGX_HTTP_INTERNAL_SERVER_ERROR.
 *
 * Precondition: path[] must be at least WEBDAV_MAX_PATH bytes.
 */
ngx_int_t
webdav_resolve_stat(ngx_http_request_t *r, char *path, size_t pathsz,
    struct stat *sb)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_int_t                          rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
                                             pathsz);
    if (rc != NGX_OK) {
        return rc;
    }

    if (stat(path, sb) != 0) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}
