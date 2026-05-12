/*
 * move.c - WebDAV MOVE handler (RFC 4918 §9.9).
 */

#include "webdav.h"

#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


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
    ngx_table_elt_t    *overwrite_hdr;
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

    /* Parse Overwrite header; default is "T" (RFC 4918 §10.6) */
    overwrite_hdr = webdav_tpc_find_header(r, "Overwrite",
                                           sizeof("Overwrite") - 1);
    if (overwrite_hdr != NULL) {
        ngx_str_t ov = overwrite_hdr->value;
        if (ov.len == 1 && (ov.data[0] == 'F' || ov.data[0] == 'f')) {
            overwrite = 0;
        }
    }

    /* Extract path component from Destination URL.
     * Destination may be an absolute URL (http://host/path) or a path (/path).
     */
    dest_path_start = dest_hdr->value.data;
    dest_path_len   = dest_hdr->value.len;

    /* Skip scheme://authority if present */
    {
        const u_char *p   = dest_path_start;
        const u_char *end = p + dest_path_len;
        const u_char *scheme_end;

        scheme_end = ngx_strlchr((u_char *) p, (u_char *) end, ':');
        if (scheme_end != NULL && scheme_end + 2 < end
            && scheme_end[1] == '/' && scheme_end[2] == '/')
        {
            /* skip to the next '/' after authority */
            p = scheme_end + 3;
            while (p < end && *p != '/') {
                p++;
            }
            dest_path_start = p;
            dest_path_len   = (size_t) (end - p);
        }
    }

    if (dest_path_len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* URL-decode the destination path */
    rc = webdav_urldecode(dest_path_start, dest_path_len,
                          dest_decoded, sizeof(dest_decoded));
    if (rc != NGX_OK) {
        return rc;
    }

    /* Resolve source */
    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon,
                                              src_path, sizeof(src_path));
    if (rc != NGX_OK) {
        return rc;
    }

    if (stat(src_path, &src_sb) != 0) {
        return NGX_HTTP_NOT_FOUND;
    }

    rc = webdav_check_locks(r, src_path, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Resolve destination */
    rc = webdav_resolve_destination_path(r->connection->log, "MOVE",
                                         conf->root_canon, dest_decoded,
                                         dst_path, sizeof(dst_path));
    if (rc != NGX_OK) {
        return rc;
    }

    dst_existed = (stat(dst_path, &dst_sb) == 0);

    rc = webdav_check_locks(r, dst_path, 1);
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

    /* If destination exists and we are overwriting, remove it if it's a dir.
     * rename(2) only overwrites if both are files or both are directories
     * (and the destination is empty).  To match RFC 4918 §9.9.1 we must
     * perform a DELETE on the destination first. */
    if (dst_existed && overwrite) {
        if (S_ISDIR(dst_sb.st_mode)) {
            (void) webdav_delete_path_recursive(r->connection->log,
                                                conf->root_canon, dst_path);
        }
    }

    if (xrootd_rename_confined_canon(r->connection->log, conf->root_canon,
                                     src_path, dst_path) != 0)
    {
        if (errno == ENOTEMPTY || errno == EEXIST) {
            /* Destination dir is non-empty — can't atomically overwrite dir */
            return NGX_HTTP_CONFLICT;
        }
        if (errno == ENOENT) {
            /* Source vanished or destination parent missing */
            return NGX_HTTP_CONFLICT;
        }
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                             ngx_errno,
                                             "xrootd_webdav MOVE: rename() failed for",
                                             src_path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Evict both paths from fd cache */
    {
        webdav_fd_table_t *fdt = webdav_get_fd_table(r->connection);
        if (fdt != NULL) {
            webdav_fd_table_evict(fdt, src_path);
            webdav_fd_table_evict(fdt, dst_path);
        }
    }

    r->headers_out.status           = dst_existed ? NGX_HTTP_NO_CONTENT
                                                   : NGX_HTTP_CREATED;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}
