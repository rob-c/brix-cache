/*
 * namespace.c - WebDAV DELETE and MKCOL namespace operations.
 */

#include "webdav.h"

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
    DIR           *dp;
    struct dirent *de;
    char           child[WEBDAV_MAX_PATH];
    struct stat    sb;
    ngx_int_t      rc = NGX_OK;

    dp = opendir(path);
    if (dp == NULL) {
        if (errno == ENOENT) {
            return NGX_OK;
        }
        ngx_http_xrootd_webdav_log_safe_path(log, NGX_LOG_ERR, errno,
            "xrootd_webdav: delete opendir failed for", path);
        return NGX_ERROR;
    }

    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
            (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;
        }

        if ((size_t) snprintf(child, sizeof(child), "%s/%s", path, de->d_name)
            >= sizeof(child))
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd_webdav: delete path too long: \"%s/%s\"",
                          path, de->d_name);
            rc = NGX_ERROR;
            break;
        }

        if (lstat(child, &sb) != 0) {
            if (errno == ENOENT) continue;
            ngx_http_xrootd_webdav_log_safe_path(log, NGX_LOG_ERR, errno,
                "xrootd_webdav: delete lstat failed for", child);
            rc = NGX_ERROR;
            break;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (webdav_delete_path_recursive(log, root_canon, child) != NGX_OK) {
                rc = NGX_ERROR;
                break;
            }
        } else {
            if (xrootd_unlink_confined_canon(log, root_canon, child, 0) != 0) {
                ngx_http_xrootd_webdav_log_safe_path(log, NGX_LOG_ERR, errno,
                    "xrootd_webdav: delete unlink failed for", child);
                rc = NGX_ERROR;
                break;
            }
        }
    }

    closedir(dp);

    if (rc == NGX_OK) {
        if (xrootd_unlink_confined_canon(log, root_canon, path, 1) != 0) {
            ngx_http_xrootd_webdav_log_safe_path(log, NGX_LOG_ERR, errno,
                "xrootd_webdav: delete rmdir failed for", path);
            rc = NGX_ERROR;
        }
    }

    return rc;
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
    char               path[WEBDAV_MAX_PATH];
    struct stat        sb;
    ngx_int_t          rc;
    webdav_fd_table_t *fdt;
    ngx_http_xrootd_webdav_loc_conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    fdt = webdav_get_fd_table(r->connection);
    if (fdt != NULL) {
        webdav_fd_table_evict(fdt, path);
    }

    rc = webdav_check_locks(r, path, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    if (S_ISDIR(sb.st_mode)) {
        /* Check if directory is non-empty — refuse to delete non-empty dirs. */
        DIR           *dp;
        struct dirent *de;
        int            non_empty = 0;

        dp = opendir(path);
        if (dp != NULL) {
            while ((de = readdir(dp)) != NULL) {
                if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
                    (de->d_name[1] == '.' && de->d_name[2] == '\0')))
                {
                    continue;
                }
                non_empty = 1;
                break;
            }
            closedir(dp);
        }

        if (non_empty) {
            return NGX_HTTP_CONFLICT;
        }

        if (webdav_delete_path_recursive(r->connection->log, conf->root_canon,
                                         path) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else if (xrootd_unlink_confined_canon(r->connection->log,
                                            conf->root_canon, path, 0) != 0) {
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                             ngx_errno,
                                             "xrootd_webdav DELETE: unlink failed for",
                                             path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

ngx_int_t
webdav_handle_mkcol(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
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

    if (xrootd_mkdir_confined_canon(r->connection->log, conf->root_canon,
                                    path, 0755) != 0) {
        if (errno == EEXIST) {
            return NGX_HTTP_NOT_ALLOWED;
        }
        if (errno == ENOENT) {
            return NGX_HTTP_CONFLICT;
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_CREATED;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}
