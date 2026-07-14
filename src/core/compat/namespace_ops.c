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
#include "namespace_ops_internal.h"   /* cross-file: ns_rel / ns_set_err (namespace_ops_copy.c) */
#include "fs/path/path.h"
#include "fs/path/beneath.h"
#include "fs_walk.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
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
 * a non-canonicalised path.  ns_rel() centralises the rootfd-open +
 * within-root strip; a NULL rel means the path is not under root_canon and the
 * operation is refused (EXDEV) rather than falling through to a raw syscall.
 *
 * The single-file local-copy path (which additionally reasons about fd-based and
 * xattr-based confinement) lives in namespace_ops_copy.c; it reuses ns_rel() and
 * ns_set_err() from this file through namespace_ops_internal.h.
 */

/*
 * ns_rel — open a confinement rootfd on root_canon and return the within-root
 * relative tail of abspath.  *rootfd_out receives the fd (caller closes it);
 * returns NULL with *rootfd_out=-1 and errno set when the rootfd cannot be
 * opened or abspath escapes root_canon.
 */
const char *
ns_rel(const char *root_canon, const char *abspath, int *rootfd_out)
{
    const char *rel;
    int         fd;

    *rootfd_out = -1;

    rel = brix_beneath_strip_root(root_canon, abspath);
    if (rel == NULL) {
        errno = EXDEV;            /* path is not under the export root */
        return NULL;
    }

    fd = brix_beneath_open_root(root_canon);
    if (fd < 0) {
        return NULL;             /* errno from open() */
    }

    *rootfd_out = fd;
    return rel;
}

static brix_ns_status_t
errno_to_ns_status(int err)
{
    switch (err) {
    case 0:         return BRIX_NS_OK;
    case ENOENT:    return BRIX_NS_NOT_FOUND;
    case EACCES:
    case EPERM:
    case EXDEV:     /* openat2 RESOLVE_BENEATH ".." escape (mkdir/rm/rename/copy) */
    case ELOOP:     /* RESOLVE_BENEATH/NO_MAGICLINKS escaping-symlink rejection */
                    return BRIX_NS_DENIED;
    case EEXIST:    return BRIX_NS_EXISTS;
    case ENOTEMPTY: return BRIX_NS_NOT_EMPTY;
    case ENAMETOOLONG: return BRIX_NS_TOO_LONG;
    case ENOSPC:    return BRIX_NS_NO_SPACE;
    case EBUSY:
    case EINVAL:    return BRIX_NS_CONFLICT;
    default:        return BRIX_NS_IO_ERROR;
    }
}

/*
 * ns_set_err — record a failed syscall's errno on the result.
 *
 * WHAT: Stores err in res->sys_errno and the mapped BRIX_NS_* code in
 *       res->status.  Returns nothing.
 * WHY: Every error path in these orchestrators sets exactly this pair; one
 *      helper keeps the mapping in a single place and shortens each error return
 *      to one call while preserving the original two-field assignment behavior.
 * HOW: 1. Copy err into sys_errno.  2. Translate err via errno_to_ns_status().
 */
void
ns_set_err(brix_ns_result_t *res, int err)
{
    res->sys_errno = err;
    res->status    = errno_to_ns_status(err);
}

/*
 * ns_delete_probe — lstat the delete target and classify it.
 *
 * WHAT: Confines an lstat on rel beneath rootfd, sets res->existed/was_dir on
 *       success, and enforces the require_directory gate.  Returns 1 when the
 *       caller must return res immediately (missing-idempotent success, stat
 *       error, or ENOTDIR rejection), 0 when removal should proceed.
 * WHY: Splits the classify/reject decision out of the delete orchestrator so the
 *      orchestrator stays a flat sequence and each half stays under the
 *      complexity cap, without changing any syscall or errno mapping.
 * HOW: 1. lstat_beneath; on failure honor idempotent_missing for ENOENT else
 *      record the errno.  2. Mark existed and derive was_dir from the mode.
 *      3. Reject a non-directory when require_directory is set (ENOTDIR).
 */
static ngx_flag_t
ns_delete_probe(int rootfd, const char *rel,
    const brix_ns_delete_opts_t *opts, brix_ns_result_t *res)
{
    struct stat  sb;

    /* LSTAT, not stat: delete must operate on the final component itself and must
     * never dereference a trailing symlink (POSIX unlink/rm semantics). Following it
     * would (a) misclassify a symlink-to-dir as a directory and (b) fail outright when
     * the link's stored target is an absolute logical path, which RESOLVE_BENEATH
     * rejects — leaving the link un-removable. brix_unlink_beneath() likewise unlinks
     * the name in its parent without following it, so the two agree. */
    if (brix_lstat_beneath(rootfd, rel, &sb) != 0) {
        if (errno == ENOENT && opts->idempotent_missing) {
            res->status = BRIX_NS_OK;
            return 1;
        }
        ns_set_err(res, errno);
        return 1;
    }

    res->existed = 1;
    res->was_dir = S_ISDIR(sb.st_mode) ? 1 : 0;   /* a symlink is never a dir → unlink */

    /* kXR_rmdir is directory-only: reject regular files with ENOTDIR rather
     * than silently unlinking them (matches rmdir(2) semantics). */
    if (opts->require_directory && !res->was_dir) {
        ns_set_err(res, ENOTDIR);
        return 1;
    }

    return 0;
}

/*
 * ns_delete_remove — enforce the emptiness gate and perform the removal.
 *
 * WHAT: For an already-classified target, optionally rejects a non-empty
 *       directory (require_empty_dir), then removes it via a confined recursive
 *       tree walk (recursive dir) or a single confined unlink, filling res.
 * WHY: Isolates the removal decision tree from the orchestrator so both stay
 *      simple; the confinement primitives and their ordering are unchanged.
 * HOW: 1. If a directory must be empty, probe emptiness and stop with
 *      BRIX_NS_NOT_EMPTY when it is not.  2. Recursive directory → confined
 *      remove_tree; otherwise → confined unlink.  3. Map any errno onto res.
 */
static void
ns_delete_remove(ngx_log_t *log, const char *root_canon, const char *path,
    int rootfd, const char *rel, const brix_ns_delete_opts_t *opts,
    brix_ns_result_t *res)
{
    if (res->was_dir && opts->require_empty_dir) {
        /* dir_is_empty() opens `path` directly; it is reached only after the
         * stat_beneath above proved the target resident under the root, so the
         * emptiness probe cannot itself be steered out of the export tree. */
        ngx_flag_t is_empty;
        if (brix_fs_dir_is_empty(path, &is_empty) == NGX_OK && !is_empty) {
            res->status = BRIX_NS_NOT_EMPTY;
            return;
        }
    }

    if (opts->recursive && res->was_dir) {
        /* Recursive tree removal is confined internally by fs_walk (it descends
         * with O_NOFOLLOW dir fds and unlinks via the beneath/confined API). */
        if (brix_fs_remove_tree_confined(log, root_canon, path) == NGX_OK) {
            res->status = BRIX_NS_OK;
        } else {
            ns_set_err(res, errno);
        }
    } else {
        if (brix_unlink_beneath(rootfd, rel, res->was_dir) == 0) {
            res->status = BRIX_NS_OK;
        } else {
            ns_set_err(res, errno);
        }
    }
}

brix_ns_result_t
brix_ns_delete(ngx_log_t *log, const char *root_canon, const char *path,
    const brix_ns_delete_opts_t *opts)
{
    brix_ns_result_t  res;
    int               rootfd;
    const char       *rel;

    ngx_memzero(&res, sizeof(res));

    rel = ns_rel(root_canon, path, &rootfd);
    if (rel == NULL) {
        ns_set_err(&res, errno);
        return res;
    }

    if (ns_delete_probe(rootfd, rel, opts, &res)) {
        close(rootfd);
        return res;
    }

    ns_delete_remove(log, root_canon, path, rootfd, rel, opts, &res);

    close(rootfd);
    return res;
}

brix_ns_result_t
brix_ns_mkdir(ngx_log_t *log, const char *root_canon, const char *path,
    mode_t mode, ngx_flag_t recursive)
{
    brix_ns_result_t res;
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
        if (brix_mkdir_recursive_beneath(log, rootfd, root_canon, path,
                                           mode, NULL) == 0) {
            res.status  = BRIX_NS_OK;
            res.created = 1;
        } else {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
        }
    } else {
        if (brix_mkdir_beneath(rootfd, rel, mode) == 0) {
            res.status  = BRIX_NS_OK;
            res.created = 1;
        } else {
            res.sys_errno = errno;
            res.status    = errno_to_ns_status(errno);
        }
    }

    close(rootfd);
    return res;
}

brix_ns_result_t
brix_ns_rename(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, ngx_flag_t overwrite_dirs)
{
    brix_ns_result_t res;
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
    src_rel = brix_beneath_strip_root(root_canon, src);
    if (src_rel == NULL) {
        close(rootfd);
        res.sys_errno = EXDEV;
        res.status    = errno_to_ns_status(EXDEV);
        return res;
    }

    if (brix_stat_beneath(rootfd, dst_rel, &sb) == 0) {
        res.existed = 1;
        if (S_ISDIR(sb.st_mode)) {
            res.was_dir = 1;
            if (overwrite_dirs) {
                /* WebDAV/S3 semantics: delete target directory tree before rename
                 * if overwrite is requested. rename(2) only replaces empty dirs. */
                if (brix_fs_remove_tree_confined(log, root_canon, dst) != NGX_OK) {
                    res.sys_errno = errno;
                    res.status    = errno_to_ns_status(errno);
                    close(rootfd);
                    return res;
                }
            } else {
                res.status = BRIX_NS_EXISTS;
                close(rootfd);
                return res;
            }
        }
    }

    if (brix_rename_beneath(rootfd, src_rel, dst_rel) == 0) {
        res.status = BRIX_NS_OK;
    } else {
        res.sys_errno = errno;
        res.status    = errno_to_ns_status(errno);
    }

    close(rootfd);
    return res;
}
