/*
 * copy.c - WebDAV COPY handler (RFC 4918 §9.8).
 *
 * Server-side copy: copies a file or collection within the same export root
 * without spawning an external process.  The Depth: 0 and Depth: infinity
 * headers are supported for collections.  The destination is written
 * atomically via a temp path that is renamed into place on success.
 *
 * The copy engine uses copy_file_range(2) on Linux (zero-copy on supported
 * filesystems such as XFS and ext4 with reflinks) and falls back to a
 * pread/write loop when the syscall is unavailable or unsupported by the
 * underlying filesystem.
 */

#include "webdav.h"
#include "../fattr/ngx_xrootd_fattr.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>


/*
 * webdav_copy_fds — copy src_size bytes from src_fd to dst_fd.
 *
 * Tries copy_file_range(2) first (Linux 4.5+, intra-kernel zero-copy on
 * supported filesystems).  Falls back to a pread/write loop on ENOSYS,
 * EOPNOTSUPP, EINVAL, EXDEV, or EPERM (cross-device / unsupported FS).
 *
 * scratch must point to a WEBDAV_PUT_COPY_BUFSZ byte buffer used only by
 * the fallback path.
 *
 * Returns: NGX_OK on success, NGX_ERROR on any I/O failure.
 */
static ngx_int_t
webdav_copy_fds(ngx_log_t *log, int src_fd, int dst_fd, off_t src_size,
                const char *dst_path, u_char *scratch)
{
    size_t  remaining;
    off_t   src_off;

    remaining = (size_t) src_size;
    src_off   = 0;

#if defined(__linux__) && defined(SYS_copy_file_range)
    while (remaining > 0) {
        size_t  want;
        ssize_t copied;

        want   = remaining > WEBDAV_PUT_COPY_CHUNK ? WEBDAV_PUT_COPY_CHUNK
                                                   : remaining;
        copied = syscall(SYS_copy_file_range, src_fd, &src_off, dst_fd, NULL,
                         want, 0);
        if (copied > 0) {
            remaining -= (size_t) copied;
            continue;
        }
        if (copied == 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd_webdav COPY: copy_file_range unexpected EOF");
            return NGX_ERROR;
        }
        if (errno == EINTR) {
            continue;
        }
        /* Kernel or filesystem doesn't support copy_file_range */
        if (errno == ENOSYS || errno == EOPNOTSUPP || errno == EINVAL
            || errno == EXDEV || errno == EPERM)
        {
            break;
        }
        ngx_http_xrootd_webdav_log_safe_path(log, NGX_LOG_ERR, errno,
            "xrootd_webdav COPY: copy_file_range failed for", dst_path);
        return NGX_ERROR;
    }

    if (remaining == 0) {
        return NGX_OK;
    }

    /* Adjust read offset to pick up where copy_file_range left off */
    src_off = (off_t) src_size - (off_t) remaining;
#endif  /* Linux copy_file_range */

    /* pread/write fallback */
    while (remaining > 0) {
        size_t  chunk;
        ssize_t nread;

        chunk = remaining > WEBDAV_PUT_COPY_BUFSZ ? WEBDAV_PUT_COPY_BUFSZ
                                                  : remaining;
        nread = pread(src_fd, scratch, chunk, src_off);
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            ngx_http_xrootd_webdav_log_safe_path(log, NGX_LOG_ERR, errno,
                "xrootd_webdav COPY: pread failed for", dst_path);
            return NGX_ERROR;
        }
        if (nread == 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd_webdav COPY: pread unexpected EOF");
            return NGX_ERROR;
        }
        if (webdav_write_full(dst_fd, scratch, (size_t) nread) != NGX_OK) {
            ngx_http_xrootd_webdav_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                "xrootd_webdav COPY: write failed for", dst_path);
            return NGX_ERROR;
        }
        src_off   += (off_t) nread;
        remaining -= (size_t) nread;
    }

    return NGX_OK;
}

/*
 * webdav_copy_xattrs — copy all "user.U.*" attributes from src to dst.
 */
static void
webdav_copy_xattrs(ngx_log_t *log, const char *src, const char *dst)
{
    ssize_t  list_len, vlen;
    char    *list = NULL;
    char    *p, *name;
    u_char   value[XROOTD_FATTR_MAX_VBUF];

    list_len = listxattr(src, NULL, 0);
    if (list_len <= 0) {
        return;
    }

    list = malloc(list_len);
    if (list == NULL) {
        return;
    }

    list_len = listxattr(src, list, list_len);
    if (list_len <= 0) {
        free(list);
        return;
    }

    for (p = list; p < list + list_len; p += strlen(p) + 1) {
        name = p;

        /* Only copy the XRootD-mapped attributes */
        if (strncmp(name, XROOTD_FATTR_XKEY_PFX, XROOTD_FATTR_XKEY_PFX_LEN) != 0) {
            continue;
        }

        vlen = getxattr(src, name, value, sizeof(value));
        if (vlen > 0) {
            (void) setxattr(dst, name, value, (size_t) vlen, 0);
        }
    }

    free(list);
}


/*
 * webdav_copy_file — copy a single file from src to dst.
 */
static ngx_int_t
webdav_copy_file(ngx_log_t *log, const char *root_canon,
                 const char *src, const char *dst,
                 u_char *scratch)
{
    int         src_fd;
    int         dst_fd;
    struct stat sb;
    ngx_int_t   rc;

    if (stat(src, &sb) != 0) {
        return NGX_ERROR;
    }

    src_fd = xrootd_open_confined_canon(log, root_canon, src,
                                        O_RDONLY | O_CLOEXEC, 0);
    if (src_fd < 0) {
        return NGX_ERROR;
    }

    dst_fd = xrootd_open_confined_canon(log, root_canon, dst,
                                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                                        sb.st_mode & 0777);
    if (dst_fd < 0) {
        (void) close(src_fd);
        return NGX_ERROR;
    }

    rc = webdav_copy_fds(log, src_fd, dst_fd, sb.st_size, dst, scratch);

    (void) close(src_fd);
    (void) close(dst_fd);

    if (rc == NGX_OK) {
        webdav_copy_xattrs(log, src, dst);
    }

    return rc;
}


/*
 * webdav_copy_dir_recursive — recursively copy src directory to dst.
 * dst must already exist as a directory.
 */
static ngx_int_t
webdav_copy_dir_recursive(ngx_log_t *log, const char *root_canon,
                          const char *src, const char *dst,
                          u_char *scratch)
{
    DIR           *dp;
    struct dirent *de;
    char           src_child[WEBDAV_MAX_PATH];
    char           dst_child[WEBDAV_MAX_PATH];
    struct stat    sb;
    ngx_int_t      rc = NGX_OK;

    dp = opendir(src);
    if (dp == NULL) {
        ngx_http_xrootd_webdav_log_safe_path(log, NGX_LOG_ERR, errno,
            "xrootd_webdav COPY: opendir failed for", src);
        return NGX_ERROR;
    }

    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
            (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        {
            continue;
        }

        if ((size_t) snprintf(src_child, sizeof(src_child), "%s/%s",
                              src, de->d_name) >= sizeof(src_child)
            || (size_t) snprintf(dst_child, sizeof(dst_child), "%s/%s",
                                 dst, de->d_name) >= sizeof(dst_child))
        {
            rc = NGX_ERROR;
            break;
        }

        if (lstat(src_child, &sb) != 0) {
            continue;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (xrootd_mkdir_confined_canon(log, root_canon, dst_child,
                                            sb.st_mode & 0777) != 0)
            {
                if (errno != EEXIST) {
                    rc = NGX_ERROR;
                    break;
                }
            }
            if (webdav_copy_dir_recursive(log, root_canon, src_child,
                                          dst_child, scratch) != NGX_OK)
            {
                rc = NGX_ERROR;
                break;
            }
        } else if (S_ISREG(sb.st_mode)) {
            if (webdav_copy_file(log, root_canon, src_child, dst_child,
                                 scratch) != NGX_OK)
            {
                rc = NGX_ERROR;
                break;
            }
        }
        /* Skip other file types (symlinks, devices, etc.) for COPY */
    }

    closedir(dp);
    return rc;
}


/*
 * webdav_check_copy_conditionals — evaluate If-Match / If-None-Match against
 * the COPY destination resource (RFC 9110 §13, RFC 4918 §9.8).
 *
 * Called after the destination has been stat'd and before the copy is
 * performed.  Returns NGX_HTTP_PRECONDITION_FAILED (412) when a conditional
 * header is present and the condition is not met; NGX_OK otherwise.
 *
 * Rules (RFC 9110 §13.1.1 / §13.1.2 applied to the destination):
 *   If-Match:
 *     - Destination does not exist → 412 (no current representation).
 *     - Destination exists, ETag does not match any listed tag → 412.
 *   If-None-Match:
 *     - "*": destination must NOT exist → 412 if it does.
 *     - Specific ETag: 412 if destination exists and its ETag matches.
 */
static ngx_int_t
webdav_check_copy_conditionals(ngx_http_request_t *r,
    const char *dst_path, int dst_exists, const struct stat *dst_sb)
{
    ngx_table_elt_t  *if_match;
    ngx_table_elt_t  *if_none_match;
    char              etag_buf[64];   /* "W/\"mtime-size\"" */
    const char       *etag;           /* points into etag_buf, no leading W/ */

    if_match      = r->headers_in.if_match;
    if_none_match = r->headers_in.if_none_match;

    /* Fast path: no conditional headers present */
    if (if_match == NULL && if_none_match == NULL) {
        return NGX_OK;
    }

    /* Compute destination ETag only when the destination exists */
    etag = NULL;
    if (dst_exists) {
        webdav_etag_str(etag_buf, sizeof(etag_buf),
                        dst_sb->st_mtime, dst_sb->st_size);
        /*
         * etag_buf now holds e.g. W/"1746974400-3039".
         * For header comparison we compare the full token including the W/
         * prefix, because clients must send the tag exactly as received.
         */
        etag = etag_buf;
    }

    /* --- If-Match -------------------------------------------------------- */
    if (if_match != NULL) {
        const char  *hdr;
        size_t       hlen;

        /* If the destination does not exist there is no current representation
         * to match against → condition fails unconditionally. */
        if (!dst_exists) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xrootd_webdav COPY: If-Match: destination absent: %s",
                           dst_path);
            return NGX_HTTP_PRECONDITION_FAILED;
        }

        hdr  = (const char *) if_match->value.data;
        hlen = if_match->value.len;

        /*
         * RFC 9110 §13.1.1: the header value is a comma-separated list of
         * entity-tags, or "*".  We accept "*" as a match-any wildcard (if
         * the destination exists the condition is satisfied).  For a list of
         * tags we look for an exact match of our computed ETag.
         */
        if (hlen == 1 && hdr[0] == '*') {
            /* "*" with an existing destination → condition met */
            return NGX_OK;
        }

        /* Search the comma-separated list for our ETag token */
        {
            const char *p   = hdr;
            const char *end = hdr + hlen;

            while (p < end) {
                const char *tok_start;
                const char *tok_end;
                size_t      tok_len;

                /* Skip leading whitespace and commas */
                while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
                    p++;
                }
                if (p >= end) {
                    break;
                }

                tok_start = p;
                /* Advance to the next comma or end */
                while (p < end && *p != ',') {
                    p++;
                }
                tok_end = p;

                /* Trim trailing whitespace */
                while (tok_end > tok_start
                       && (tok_end[-1] == ' ' || tok_end[-1] == '\t'))
                {
                    tok_end--;
                }

                tok_len = (size_t)(tok_end - tok_start);
                if (tok_len == strlen(etag)
                    && ngx_strncmp(tok_start, etag, tok_len) == 0)
                {
                    return NGX_OK;   /* matched */
                }
            }
        }

        /* No tag in the list matched the destination ETag → 412 */
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrootd_webdav COPY: If-Match failed: etag=%s dst=%s",
                       etag, dst_path);
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    /* --- If-None-Match --------------------------------------------------- */
    if (if_none_match != NULL) {
        const char  *hdr;
        size_t       hlen;

        hdr  = (const char *) if_none_match->value.data;
        hlen = if_none_match->value.len;

        /* "*": destination must not exist */
        if (hlen == 1 && hdr[0] == '*') {
            if (dst_exists) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "xrootd_webdav COPY: If-None-Match: * and "
                               "destination exists: %s", dst_path);
                return NGX_HTTP_PRECONDITION_FAILED;
            }
            return NGX_OK;
        }

        /* Specific ETag list: 412 if destination exists and ETag matches */
        if (dst_exists) {
            const char *p   = hdr;
            const char *end = hdr + hlen;

            while (p < end) {
                const char *tok_start;
                const char *tok_end;
                size_t      tok_len;

                while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
                    p++;
                }
                if (p >= end) {
                    break;
                }

                tok_start = p;
                while (p < end && *p != ',') {
                    p++;
                }
                tok_end = p;

                while (tok_end > tok_start
                       && (tok_end[-1] == ' ' || tok_end[-1] == '\t'))
                {
                    tok_end--;
                }

                tok_len = (size_t)(tok_end - tok_start);
                if (tok_len == strlen(etag)
                    && ngx_strncmp(tok_start, etag, tok_len) == 0)
                {
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "xrootd_webdav COPY: If-None-Match failed: "
                                   "etag=%s dst=%s", etag, dst_path);
                    return NGX_HTTP_PRECONDITION_FAILED;
                }
            }
        }
    }

    return NGX_OK;
}


/*
 * webdav_handle_copy — RFC 4918 §9.8 server-side COPY.
 *
 * Copies a regular file or collection within the export root.
 */
ngx_int_t
webdav_handle_copy(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t    *dest_hdr;
    ngx_table_elt_t    *overwrite_hdr;
    ngx_table_elt_t    *depth_hdr;
    char                src_path[WEBDAV_MAX_PATH];
    char                dst_path[WEBDAV_MAX_PATH];
    char                tmp_path[WEBDAV_MAX_PATH];
    char                dest_decoded[WEBDAV_MAX_PATH];
    const u_char       *dest_path_start;
    size_t              dest_path_len;
    struct stat         src_sb;
    struct stat         dst_sb;
    ngx_int_t           rc;
    int                 overwrite;
    int                 dst_existed;
    ngx_int_t           copy_rc;
    u_char             *scratch;
    int                 depth_infinity = 1;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    /* Destination header is mandatory (RFC 4918 §9.8.4) */
    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);
    if (dest_hdr == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Parse Overwrite header; default is "T" (RFC 4918 §10.6) */
    overwrite = 1;
    overwrite_hdr = webdav_tpc_find_header(r, "Overwrite",
                                           sizeof("Overwrite") - 1);
    if (overwrite_hdr != NULL) {
        ngx_str_t ov = overwrite_hdr->value;
        if (ov.len == 1 && (ov.data[0] == 'F' || ov.data[0] == 'f')) {
            overwrite = 0;
        }
    }

    /* Parse Depth header (RFC 4918 §9.8.3) */
    depth_hdr = webdav_tpc_find_header(r, "Depth", sizeof("Depth") - 1);
    if (depth_hdr != NULL) {
        if (depth_hdr->value.len == 1 && depth_hdr->value.data[0] == '0') {
            depth_infinity = 0;
        }
    }

    /* Extract path component from Destination URL. */
    dest_path_start = dest_hdr->value.data;
    dest_path_len   = dest_hdr->value.len;
    {
        const u_char *p   = dest_path_start;
        const u_char *end = p + dest_path_len;
        const u_char *scheme_end;

        scheme_end = ngx_strlchr((u_char *) p, (u_char *) end, ':');
        if (scheme_end != NULL && scheme_end + 2 < end
            && scheme_end[1] == '/' && scheme_end[2] == '/')
        {
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

    rc = webdav_urldecode(dest_path_start, dest_path_len,
                          dest_decoded, sizeof(dest_decoded));
    if (rc != NGX_OK) {
        return rc;
    }

    /* Resolve source path from the request URI */
    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon,
                                              src_path, sizeof(src_path));
    if (rc != NGX_OK) {
        return rc;
    }

    if (stat(src_path, &src_sb) != 0) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Resolve destination path */
    rc = webdav_resolve_destination_path(r->connection->log, "COPY",
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

    /* Prevent copying a file onto itself */
    if (dst_existed
        && src_sb.st_ino == dst_sb.st_ino
        && src_sb.st_dev == dst_sb.st_dev)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    if (dst_existed && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    /* Evaluate If-Match / If-None-Match conditional headers against the
     * destination resource (RFC 9110 §13, RFC 4918 §9.8). */
    rc = webdav_check_copy_conditionals(r, dst_path, dst_existed, &dst_sb);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Build temp path for atomic rename */
    if ((size_t) snprintf(tmp_path, sizeof(tmp_path),
                          "%s.nginx-xrootd-copy.%ld.%ld",
                          dst_path, (long) getpid(), (long) time(NULL))
        >= sizeof(tmp_path))
    {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    /* Scratch buffer for pread/write fallback */
    scratch = ngx_palloc(r->pool, WEBDAV_PUT_COPY_BUFSZ);
    if (scratch == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISDIR(src_sb.st_mode)) {
        /* Create temporary directory */
        if (xrootd_mkdir_confined_canon(r->connection->log, conf->root_canon,
                                        tmp_path, src_sb.st_mode & 0777) != 0)
        {
            if (errno == ENOENT) return NGX_HTTP_CONFLICT;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (depth_infinity) {
            copy_rc = webdav_copy_dir_recursive(r->connection->log,
                                                 conf->root_canon,
                                                 src_path, tmp_path, scratch);
        } else {
            copy_rc = NGX_OK;
        }
    } else {
        copy_rc = webdav_copy_file(r->connection->log, conf->root_canon,
                                   src_path, tmp_path, scratch);
    }

    if (copy_rc != NGX_OK) {
        if (S_ISDIR(src_sb.st_mode)) {
            (void) webdav_delete_path_recursive(r->connection->log,
                                                conf->root_canon, tmp_path);
        } else {
            (void) xrootd_unlink_confined_canon(r->connection->log,
                                                conf->root_canon, tmp_path, 0);
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* If destination exists and we are overwriting, remove it if it's a dir.
     * rename(2) only overwrites if both are files or both are directories
     * (and the destination is empty).  To match RFC 4918 §9.8.5 we must
     * replace the entire collection. */
    if (dst_existed) {
        if (S_ISDIR(dst_sb.st_mode)) {
            (void) webdav_delete_path_recursive(r->connection->log,
                                                conf->root_canon, dst_path);
        }
    }

    if (xrootd_rename_confined_canon(r->connection->log, conf->root_canon,
                                     tmp_path, dst_path) != 0)
    {
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                             ngx_errno,
                                             "xrootd_webdav COPY: rename failed for",
                                             dst_path);
        if (S_ISDIR(src_sb.st_mode)) {
            (void) webdav_delete_path_recursive(r->connection->log,
                                                conf->root_canon, tmp_path);
        } else {
            (void) xrootd_unlink_confined_canon(r->connection->log,
                                                conf->root_canon, tmp_path, 0);
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Evict destination from fd cache */
    {
        webdav_fd_table_t *fdt = webdav_get_fd_table(r->connection);
        if (fdt != NULL) {
            webdav_fd_table_evict(fdt, dst_path);
        }
    }

    r->headers_out.status           = dst_existed ? NGX_HTTP_NO_CONTENT
                                                   : NGX_HTTP_CREATED;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}
