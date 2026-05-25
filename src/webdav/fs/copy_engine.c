/*
 * WHAT: Confined filesystem copy helpers for WebDAV COPY operations on local files
 * (not HTTP-TPC remote transfers). Provides zero-copy optimization via Linux
 * copy_file_range(2) with pread/write fallback, extended attribute preservation
 * (XRootD fattr), and recursive directory traversal.
 *
 * WHY: WebDAV COPY/MOVE on local destinations requires atomic file-level copy with
 * metadata preservation. copy_file_range(2) enables kernel zero-copy transfer when
 * supported by the filesystem (avoiding userspace buffer churn); fallback ensures
 * portability across different filesystem types (NFS, CIFS, etc.) that don't support
 * the syscall. XRootD fattr extended attributes must be preserved to maintain file
 * identity across protocol boundaries (INVARIANT: consistent metadata regardless of
 * access path).
 *
 * HOW: Three-function architecture:
 *   xrootd_copy_range — shared zero-copy copy engine with Linux copy_file_range(2)
 *     and pread/pwrite fallback. INVARIANT #5 reference: never mix TLS memory-backed
 *     buffers with file-backed sendfile paths - this function uses pure file I/O.
 *   webdav_copy_xattrs — extended attribute enumeration (listxattr) filtering for
 *     XROOTD_FATTR_XKEY_PFX prefix, get/set xattr transfer per attribute name.
 *   webdav_copy_file — orchestration: confined open via xrootd_open_confined_canon (INVARIANT #4),
 *     copy_fds data transfer, close both fds, conditional xattrs preservation on success.
 *   webdav_copy_dir_recursive — traversal: opendir + readdir filtering (. and ..),
 *     lstat classification → mkdir for dirs + recursive call, file copy for regular files.
 */

#include "copy_engine.h"
#include "../../compat/copy_range.h"
#include "../../compat/namespace_ops.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

ngx_int_t
webdav_copy_file(ngx_log_t *log, const char *root_canon,
    const char *src, const char *dst)
{
    int          src_fd;
    int          dst_fd;
    struct stat  sb;
    ngx_int_t    rc;

    if (stat(src, &sb) != 0) {
        return NGX_ERROR;
    }

    src_fd = xrootd_open_confined_canon(log, root_canon, src,
                                        O_RDONLY | O_CLOEXEC, 0);
    if (src_fd < 0) {
        return NGX_ERROR;
    }

    dst_fd = xrootd_open_confined_canon(log, root_canon, dst,
                                        O_WRONLY | O_CREAT | O_TRUNC
                                            | O_CLOEXEC,
                                        sb.st_mode & 0777);
    if (dst_fd < 0) {
        (void) close(src_fd);
        return NGX_ERROR;
    }

    rc = xrootd_copy_range(log, src_fd, 0, dst_fd, 0, (size_t) sb.st_size,
                           src, dst);

    (void) close(src_fd);
    (void) close(dst_fd);

    if (rc == NGX_OK) {
        xrootd_ns_copy_fattrs(log, src, dst);
        webdav_dead_props_copy(log, src, dst);
    }

    return rc;
}

ngx_int_t
webdav_copy_dir_recursive(ngx_log_t *log, const char *root_canon,
    const char *src, const char *dst)
{
    DIR            *dp;
    struct dirent  *de;
    char            src_child[WEBDAV_MAX_PATH];
    char            dst_child[WEBDAV_MAX_PATH];
    struct stat     sb;
    ngx_int_t       rc;

    rc = NGX_OK;
    dp = opendir(src);
    if (dp == NULL) {
        xrootd_log_safe_path(log, NGX_LOG_ERR, errno,
            "xrootd_webdav COPY: opendir failed for: \"%s\"", src);
        return NGX_ERROR;
    }

    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.' && (de->d_name[1] == '\0'
            || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
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

            webdav_dead_props_copy(log, src_child, dst_child);
            xrootd_ns_copy_fattrs(log, src_child, dst_child);

            if (webdav_copy_dir_recursive(log, root_canon, src_child,
                                          dst_child) != NGX_OK)
            {
                rc = NGX_ERROR;
                break;
            }

        } else if (S_ISREG(sb.st_mode)) {
            if (webdav_copy_file(log, root_canon, src_child, dst_child)
                != NGX_OK)
            {
                rc = NGX_ERROR;
                break;
            }
        }
    }

    closedir(dp);
    return rc;
}
