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
#include "../path/beneath.h"
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

/*
 * Confinement model for this file (Phase 8 — openat2 RESOLVE_BENEATH).
 *
 * Every path that reaches these helpers is a client-derived path under the
 * export root.  We no longer trust an upstream realpath() to have confined it:
 * each function opens a kernel-confinement rootfd on root_canon and routes ALL
 * filesystem touches (stat, open, unlink, mkdir, rename) through the beneath
 * API, so escape is blocked atomically by the kernel even if the caller passed
 * a non-canonicalised path.  ns_open_rel() centralises the rootfd-open +
 * within-root strip; a NULL rel means the path is not under root_canon and the
 * operation is refused (EXDEV) rather than falling through to a raw syscall.
 *
 * Where beneath is deliberately NOT used (see the inline notes below):
 *   - xrootd_copy_range(): operates on already-open file descriptors, not paths.
 *     Confinement happened when those fds were obtained via xrootd_open_beneath;
 *     a path-anchored RESOLVE_BENEATH check is meaningless on an fd.
 *   - xrootd_ns_copy_fattrs()/listxattr/getxattr/setxattr: the xattr syscalls are
 *     name+path based and have no openat2/RESOLVE_BENEATH-equivalent that takes a
 *     dirfd.  They run on src/dst paths that the immediately-preceding beneath
 *     open already proved resident under the root, so no new escape surface is
 *     introduced; switching them to an fd-based fsetxattr/fgetxattr is a possible
 *     future hardening but is not a confinement gap today.
 */

/*
 * ns_rel — open a confinement rootfd on root_canon and return the within-root
 * relative tail of abspath.  *rootfd_out receives the fd (caller closes it);
 * returns NULL with *rootfd_out=-1 and errno set when the rootfd cannot be
 * opened or abspath escapes root_canon.
 */
static const char *
ns_rel(const char *root_canon, const char *abspath, int *rootfd_out)
{
    const char *rel;
    int         fd;

    *rootfd_out = -1;

    rel = xrootd_beneath_strip_root(root_canon, abspath);
    if (rel == NULL) {
        errno = EXDEV;            /* path is not under the export root */
        return NULL;
    }

    fd = xrootd_beneath_open_root(root_canon);
    if (fd < 0) {
        return NULL;             /* errno from open() */
    }

    *rootfd_out = fd;
    return rel;
}

static xrootd_ns_status_t
errno_to_ns_status(int err)
{
    switch (err) {
    case 0:         return XROOTD_NS_OK;
    case ENOENT:    return XROOTD_NS_NOT_FOUND;
    case EACCES:
    case EPERM:
    case EXDEV:     /* openat2 RESOLVE_BENEATH ".." escape (mkdir/rm/rename/copy) */
    case ELOOP:     /* RESOLVE_BENEATH/NO_MAGICLINKS escaping-symlink rejection */
                    return XROOTD_NS_DENIED;
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
xrootd_xattr_copy_by_prefix(ngx_log_t *log,
    const char *src, const char *dst,
    const char *prefix, size_t prefix_len,
    size_t value_max)
{
    ssize_t  list_len, vlen;
    char    *list;
    char    *p;
    u_char  *value;

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

    value = ngx_alloc(value_max, log);
    if (value == NULL) {
        ngx_free(list);
        return;
    }

    for (p = list; p < list + list_len; p += strlen(p) + 1) {
        if (strncmp(p, prefix, prefix_len) != 0) {
            continue;
        }
        vlen = getxattr(src, p, value, value_max);
        if (vlen >= 0) {
            (void) setxattr(dst, p, value, (size_t) vlen, 0);
        }
    }

    ngx_free(value);
    ngx_free(list);
}

void
xrootd_ns_copy_fattrs(ngx_log_t *log, const char *src, const char *dst)
{
    xrootd_xattr_copy_by_prefix(log, src, dst,
        XROOTD_FATTR_XKEY_PFX, XROOTD_FATTR_XKEY_PFX_LEN,
        XROOTD_FATTR_MAX_VBUF);
}

xrootd_ns_result_t
xrootd_ns_delete(ngx_log_t *log, const char *root_canon, const char *path,
    const xrootd_ns_delete_opts_t *opts)
{
    xrootd_ns_result_t res;
    struct stat        sb;
    int                rootfd;
    const char        *rel;

    ngx_memzero(&res, sizeof(res));

    rel = ns_rel(root_canon, path, &rootfd);
    if (rel == NULL) {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        return res;
    }

    if (xrootd_stat_beneath(rootfd, rel, &sb) != 0) {
        if (errno == ENOENT && opts->idempotent_missing) {
            res.status = XROOTD_NS_OK;
            close(rootfd);
            return res;
        }
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        close(rootfd);
        return res;
    }

    res.existed = 1;
    res.was_dir = S_ISDIR(sb.st_mode) ? 1 : 0;

    /* kXR_rmdir is directory-only: reject regular files with ENOTDIR rather
     * than silently unlinking them (matches rmdir(2) semantics). */
    if (opts->require_directory && !res.was_dir) {
        res.sys_errno = ENOTDIR;
        res.status    = errno_to_ns_status(ENOTDIR);
        close(rootfd);
        return res;
    }

    if (res.was_dir && opts->require_empty_dir) {
        /* dir_is_empty() opens `path` directly; it is reached only after the
         * stat_beneath above proved the target resident under the root, so the
         * emptiness probe cannot itself be steered out of the export tree. */
        ngx_flag_t is_empty;
        if (xrootd_fs_dir_is_empty(path, &is_empty) == NGX_OK && !is_empty) {
            res.status = XROOTD_NS_NOT_EMPTY;
            close(rootfd);
            return res;
        }
    }

    if (opts->recursive && res.was_dir) {
        /* Recursive tree removal is confined internally by fs_walk (it descends
         * with O_NOFOLLOW dir fds and unlinks via the beneath/confined API). */
        if (xrootd_fs_remove_tree_confined(log, root_canon, path) == NGX_OK) {
            res.status = XROOTD_NS_OK;
        } else {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
        }
    } else {
        if (xrootd_unlink_beneath(rootfd, rel, res.was_dir) == 0) {
            res.status = XROOTD_NS_OK;
        } else {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
        }
    }

    close(rootfd);
    return res;
}

xrootd_ns_result_t
xrootd_ns_mkdir(ngx_log_t *log, const char *root_canon, const char *path,
    mode_t mode, ngx_flag_t recursive)
{
    xrootd_ns_result_t res;
    int                rootfd;
    const char        *rel;

    ngx_memzero(&res, sizeof(res));

    rel = ns_rel(root_canon, path, &rootfd);
    if (rel == NULL) {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        return res;
    }

    if (recursive) {
        /* mkdir -p, confined: creates each missing component beneath rootfd.
         * This variant takes the absolute path + root_canon and strips
         * internally, so pass `path` (not the pre-stripped rel). */
        if (xrootd_mkdir_recursive_beneath(log, rootfd, root_canon, path,
                                           mode, NULL) == 0) {
            res.status  = XROOTD_NS_OK;
            res.created = 1;
        } else {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
        }
    } else {
        if (xrootd_mkdir_beneath(rootfd, rel, mode) == 0) {
            res.status  = XROOTD_NS_OK;
            res.created = 1;
        } else {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
        }
    }

    close(rootfd);
    return res;
}

xrootd_ns_result_t
xrootd_ns_rename(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, ngx_flag_t overwrite_dirs)
{
    xrootd_ns_result_t res;
    struct stat        sb;
    int                rootfd;
    const char        *src_rel, *dst_rel;

    ngx_memzero(&res, sizeof(res));

    /* Both src and dst must be within the SAME export root (renameat across
     * roots is refused).  Open one rootfd and confine both ends through it. */
    dst_rel = ns_rel(root_canon, dst, &rootfd);
    if (dst_rel == NULL) {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        return res;
    }
    src_rel = xrootd_beneath_strip_root(root_canon, src);
    if (src_rel == NULL) {
        close(rootfd);
        res.sys_errno = EXDEV;
        res.status    = errno_to_ns_status(EXDEV);
        return res;
    }

    if (xrootd_stat_beneath(rootfd, dst_rel, &sb) == 0) {
        res.existed = 1;
        if (S_ISDIR(sb.st_mode)) {
            res.was_dir = 1;
            if (overwrite_dirs) {
                /* WebDAV/S3 semantics: delete target directory tree before rename
                 * if overwrite is requested. rename(2) only replaces empty dirs. */
                if (xrootd_fs_remove_tree_confined(log, root_canon, dst) != NGX_OK) {
                    res.sys_errno = errno;
                    res.status    = errno_to_ns_status(errno);
                    close(rootfd);
                    return res;
                }
            } else {
                res.status = XROOTD_NS_EXISTS;
                close(rootfd);
                return res;
            }
        }
    }

    if (xrootd_rename_beneath(rootfd, src_rel, dst_rel) == 0) {
        res.status = XROOTD_NS_OK;
    } else {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
    }

    close(rootfd);
    return res;
}

xrootd_ns_result_t
xrootd_ns_local_copy(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, const xrootd_ns_copy_opts_t *opts)
{
    xrootd_ns_result_t   res;
    struct stat          ssb, dsb;
    int                  src_fd = -1, dst_fd = -1;
    int                  rootfd;
    const char          *src_rel, *dst_rel;
    xrootd_staged_file_t staged;
    ngx_flag_t           use_staging = 0;

    ngx_memzero(&res, sizeof(res));

    src_rel = ns_rel(root_canon, src, &rootfd);
    if (src_rel == NULL) {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        return res;
    }
    dst_rel = xrootd_beneath_strip_root(root_canon, dst);
    if (dst_rel == NULL) {
        close(rootfd);
        res.sys_errno = EXDEV;
        res.status    = errno_to_ns_status(EXDEV);
        return res;
    }

    if (xrootd_stat_beneath(rootfd, src_rel, &ssb) != 0) {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        close(rootfd);
        return res;
    }

    if (S_ISDIR(ssb.st_mode)) {
        res.status = XROOTD_NS_CONFLICT; /* COPY on collection not yet shared */
        close(rootfd);
        return res;
    }

    if (xrootd_stat_beneath(rootfd, dst_rel, &dsb) == 0) {
        res.existed = 1;
        if (!opts->overwrite) {
            res.status = XROOTD_NS_EXISTS;
            close(rootfd);
            return res;
        }
        if (S_ISDIR(dsb.st_mode)) {
            res.was_dir = 1;
            if (!opts->overwrite_dirs) {
                res.status = XROOTD_NS_EXISTS;
                close(rootfd);
                return res;
            }
        }
    }

    src_fd = xrootd_open_beneath(rootfd, src_rel, O_RDONLY, 0);
    if (src_fd < 0) {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
        close(rootfd);
        return res;
    }

    if (opts->staged_commit) {
        /* staged_file confines its own temp open/rename internally. */
        if (xrootd_staged_open(log, root_canon, dst,
                               O_WRONLY | O_CREAT | O_TRUNC,
                               ssb.st_mode, 16, &staged) != NGX_OK)
        {
            close(src_fd);
            close(rootfd);
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
            return res;
        }
        dst_fd = staged.fd;
        use_staging = 1;
    } else {
        dst_fd = xrootd_open_beneath(rootfd, dst_rel,
                                     O_WRONLY | O_CREAT | O_TRUNC,
                                     ssb.st_mode);
        if (dst_fd < 0) {
            close(src_fd);
            close(rootfd);
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
            return res;
        }
    }

    /*
     * NOT a beneath site: xrootd_copy_range operates on the two file
     * descriptors obtained above (src_fd, dst_fd).  Both fds were opened
     * through xrootd_open_beneath / staged_file, so confinement is already
     * established; copy_file_range(2)/pread/pwrite act on fds, not paths, and
     * have no RESOLVE_BENEATH concept.  Re-confining here is neither possible
     * nor meaningful.
     */
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
        close(rootfd);
        return res;
    }

    close(src_fd);

    if (use_staging) {
        if (xrootd_staged_commit(log, root_canon, &staged, dst) != NGX_OK) {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
            close(rootfd);
            return res;
        }
    } else {
        close(dst_fd);
    }

    /*
     * NOT a beneath site: xattr copy is name+path based (listxattr/getxattr/
     * setxattr on src/dst).  There is no openat2/RESOLVE_BENEATH-equivalent for
     * extended attributes that takes a dirfd, and src/dst were just proven
     * resident under the root by the beneath opens above, so this introduces no
     * new escape surface.  (A future hardening could switch to fd-based
     * fgetxattr/fsetxattr; tracked, not a confinement gap.)
     */
    if (opts->preserve_xattrs) {
        xrootd_ns_copy_fattrs(log, src, dst);
    }

    close(rootfd);
    res.status  = XROOTD_NS_OK;
    res.created = 1;
    return res;
}
