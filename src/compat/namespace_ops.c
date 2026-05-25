/*
 * namespace_ops.c — shared namespace mutation service.
 *
 * WHAT: Implements shared orchestration for filesystem mutations (mkdir, rename,
 *       delete, local copy) using the low-level confined primitives.
 * WHY: Protocol modules (native root, WebDAV, S3) repeat the same orchestration
 *      around missing-target semantics, recursive-vs-empty directory behavior,
 *      and errno mapping.
 * HOW: These helpers operate on already-resolved, confined paths. Protocol
 *      handlers are responsible for wire parsing, auth, and lock checks.
 */

#include "namespace_ops.h"
#include "../path/path.h"
#include "../fattr/ngx_xrootd_fattr.h"
#include "fs_walk.h"
#include "copy_range.h"
#include "staged_file.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>

static xrootd_ns_status_t
errno_to_ns_status(int err)
{
    switch (err) {
    case 0:         return XROOTD_NS_OK;
    case ENOENT:    return XROOTD_NS_NOT_FOUND;
    case EACCES:
    case EPERM:     return XROOTD_NS_DENIED;
    case EEXIST:    return XROOTD_NS_EXISTS;
    case ENOTEMPTY: return XROOTD_NS_NOT_EMPTY;
    case ENAMETOOLONG: return XROOTD_NS_TOO_LONG;
    case ENOSPC:    return XROOTD_NS_NO_SPACE;
    case EBUSY:
    case EINVAL:    return XROOTD_NS_CONFLICT;
    default:        return XROOTD_NS_IO_ERROR;
    }
}

void
xrootd_ns_copy_fattrs(ngx_log_t *log, const char *src, const char *dst)
{
    ssize_t  list_len, vlen;
    char    *list;
    char    *p;
    u_char   value[XROOTD_FATTR_MAX_VBUF];

    list_len = listxattr(src, NULL, 0);
    if (list_len <= 0) {
        return;
    }

    list = ngx_alloc((size_t) list_len, log);
    if (list == NULL) {
        return;
    }

    list_len = listxattr(src, list, (size_t) list_len);
    if (list_len <= 0) {
        ngx_free(list);
        return;
    }

    for (p = list; p < list + list_len; p += strlen(p) + 1) {
        if (strncmp(p, XROOTD_FATTR_XKEY_PFX,
                    XROOTD_FATTR_XKEY_PFX_LEN) != 0)
        {
            continue;
        }

        vlen = getxattr(src, p, value, sizeof(value));
        if (vlen >= 0) {
            (void) setxattr(dst, p, value, (size_t) vlen, 0);
        }
    }

    ngx_free(list);
}

xrootd_ns_result_t
xrootd_ns_delete(ngx_log_t *log, const char *root_canon, const char *path,
    const xrootd_ns_delete_opts_t *opts)
{
    xrootd_ns_result_t res;
    struct stat        sb;

    ngx_memzero(&res, sizeof(res));

    if (stat(path, &sb) != 0) {
        if (errno == ENOENT && opts->idempotent_missing) {
            res.status = XROOTD_NS_OK;
            return res;
        }
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        return res;
    }

    res.existed = 1;
    res.was_dir = S_ISDIR(sb.st_mode) ? 1 : 0;

    if (res.was_dir && opts->require_empty_dir) {
        ngx_flag_t is_empty;
        if (xrootd_fs_dir_is_empty(path, &is_empty) == NGX_OK && !is_empty) {
            res.status = XROOTD_NS_NOT_EMPTY;
            return res;
        }
    }

    if (opts->recursive && res.was_dir) {
        if (xrootd_fs_remove_tree_confined(log, root_canon, path) == NGX_OK) {
            res.status = XROOTD_NS_OK;
        } else {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
        }
    } else {
        if (xrootd_unlink_confined_canon(log, root_canon, path, res.was_dir) == 0) {
            res.status = XROOTD_NS_OK;
        } else {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
        }
    }

    return res;
}

xrootd_ns_result_t
xrootd_ns_mkdir(ngx_log_t *log, const char *root_canon, const char *path,
    mode_t mode, ngx_flag_t recursive)
{
    xrootd_ns_result_t res;
    ngx_memzero(&res, sizeof(res));

    if (recursive) {
        if (xrootd_mkdir_recursive_confined_canon(log, root_canon, path, mode,
                                                  NULL) == 0)
        {
            res.status  = XROOTD_NS_OK;
            res.created = 1;
        } else {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
        }
    } else {
        if (xrootd_mkdir_confined_canon(log, root_canon, path, mode) == 0) {
            res.status  = XROOTD_NS_OK;
            res.created = 1;
        } else {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
        }
    }

    return res;
}

xrootd_ns_result_t
xrootd_ns_rename(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, ngx_flag_t overwrite_dirs)
{
    xrootd_ns_result_t res;
    struct stat        sb;

    ngx_memzero(&res, sizeof(res));

    if (stat(dst, &sb) == 0) {
        res.existed = 1;
        if (S_ISDIR(sb.st_mode)) {
            res.was_dir = 1;
            if (overwrite_dirs) {
                /* WebDAV/S3 semantics: delete target directory tree before rename
                 * if overwrite is requested. rename(2) only replaces empty dirs. */
                if (xrootd_fs_remove_tree_confined(log, root_canon, dst) != NGX_OK) {
                    res.sys_errno = errno;
                    res.status    = errno_to_ns_status(errno);
                    return res;
                }
            } else {
                res.status = XROOTD_NS_EXISTS;
                return res;
            }
        }
    }

    if (xrootd_rename_confined_canon(log, root_canon, src, dst) == 0) {
        res.status = XROOTD_NS_OK;
    } else {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
    }

    return res;
}

xrootd_ns_result_t
xrootd_ns_local_copy(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, const xrootd_ns_copy_opts_t *opts)
{
    xrootd_ns_result_t   res;
    struct stat          ssb, dsb;
    int                  src_fd = -1, dst_fd = -1;
    xrootd_staged_file_t staged;
    ngx_flag_t           use_staging = 0;

    ngx_memzero(&res, sizeof(res));

    if (stat(src, &ssb) != 0) {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        return res;
    }

    if (S_ISDIR(ssb.st_mode)) {
        res.status = XROOTD_NS_CONFLICT; /* COPY on collection not yet shared */
        return res;
    }

    if (stat(dst, &dsb) == 0) {
        res.existed = 1;
        if (!opts->overwrite) {
            res.status = XROOTD_NS_EXISTS;
            return res;
        }
        if (S_ISDIR(dsb.st_mode)) {
            res.was_dir = 1;
            if (!opts->overwrite_dirs) {
                res.status = XROOTD_NS_EXISTS;
                return res;
            }
        }
    }

    src_fd = xrootd_open_confined_canon(log, root_canon, src, O_RDONLY, 0);
    if (src_fd < 0) {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        return res;
    }

    if (opts->staged_commit) {
        if (xrootd_staged_open(log, root_canon, dst,
                               O_WRONLY | O_CREAT | O_TRUNC,
                               ssb.st_mode, 16, &staged) != NGX_OK)
        {
            close(src_fd);
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
            return res;
        }
        dst_fd = staged.fd;
        use_staging = 1;
    } else {
        dst_fd = xrootd_open_confined_canon(log, root_canon, dst,
                                            O_WRONLY | O_CREAT | O_TRUNC,
                                            ssb.st_mode);
        if (dst_fd < 0) {
            close(src_fd);
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
            return res;
        }
    }

    if (xrootd_copy_range(log, src_fd, 0, dst_fd, 0, ssb.st_size, src,
                          use_staging ? staged.tmp_path : dst) != NGX_OK)
    {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        close(src_fd);
        if (use_staging) {
            xrootd_staged_abort(log, root_canon, &staged, 1);
        } else {
            close(dst_fd);
        }
        return res;
    }

    close(src_fd);

    if (use_staging) {
        if (xrootd_staged_commit(log, root_canon, &staged, dst) != NGX_OK) {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
            return res;
        }
    } else {
        close(dst_fd);
    }

    if (opts->preserve_xattrs) {
        xrootd_ns_copy_fattrs(log, src, dst);
    }

    res.status  = XROOTD_NS_OK;
    res.created = 1;
    return res;
}
