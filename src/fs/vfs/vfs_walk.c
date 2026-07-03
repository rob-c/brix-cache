/*
 * vfs_walk.c — VFS confined recursive walk (bulk / off-thread traversal).
 *
 * WHAT: Implements brix_vfs_walk(), a thread-safe, non-allocating, non-metered
 *       confined traversal of a rootfd-relative target. A regular-file target
 *       fires the caller's per-file callback once; a directory target recurses,
 *       firing the callback for each regular file it contains (to max_depth /
 *       max_files). Symlinks and special files are never followed or reported.
 *
 * WHY:  Bulk consumers — kXR_Qckscan (checksum scan), recursive copy/remove —
 *       run on a thread-pool worker (or at startup) and enumerate whole subtrees.
 *       The metered, pool-allocating handle API (brix_vfs_open/opendir) is
 *       neither thread-safe (it allocates on the request pool) nor appropriate
 *       (it would emit one OP_DIRLIST/OP_OPEN per visited node). This entry point
 *       keeps the confined open/opendir/fstatat INSIDE the VFS (so callers never
 *       reach for a confined-helper directly) while staying allocation- and
 *       metric-free, and books nothing — the enclosing protocol op accounts for
 *       the whole walk.
 *
 * HOW:  brix_vfs_walk() stats the target via the confined rootfd path
 *       (brix_stat_beneath): a regular file → open (when open_files) + one cb;
 *       a directory → vfs_walk_dir(). The recursion opens each directory with
 *       openat2 RESOLVE_BENEATH (brix_open_beneath O_DIRECTORY) + fdopendir,
 *       classifies each child by a dirfd-relative AT_SYMLINK_NOFOLLOW fstatat
 *       (immune to a concurrent rename), recurses into directories and opens +
 *       fires the callback for regular files. A per-entry open/stat failure
 *       SKIPS that entry (a raced unlink or an unreadable file does not abort the
 *       scan); only an opendir failure or a callback abort stops the walk. No
 *       goto (coding-standards): early-return + closedir on every exit.
 */
#include "vfs_internal.h"
#include "vfs_backend_registry.h"    /* backend resolve for driver-routed mkpath   */
#include "fs/path/beneath.h"
#include "fs/path/path.h"            /* confined-canon open/lstat/mkdir/opendir   */
#include "core/compat/fs_walk.h"
#include "core/compat/copy_range.h"    /* brix_copy_range (copyfile/copytree)     */
#include "core/compat/namespace_ops.h" /* brix_ns_copy_fattrs                     */

#include <dirent.h>
#include <limits.h>   /* PATH_MAX */

/* Join a parent logical path + child name into out (export-relative). Special-
 * cases parent=="/" so the root yields "/name", not "//name". Returns 0 (skip)
 * on truncation. */
static int
vfs_walk_join(const char *parent, const char *name, char *out, size_t outsz)
{
    int n;

    if (parent[0] == '/' && parent[1] == '\0') {
        n = snprintf(out, outsz, "/%s", name);
    } else {
        n = snprintf(out, outsz, "%s/%s", parent, name);
    }
    return (n > 0 && (size_t) n < outsz);
}

/* Open one regular file (when requested), fire the callback, close the fd.
 * Returns the callback's code, or NGX_OK when open_files and the open failed
 * (a per-entry open failure is a soft skip during a directory walk). */
static ngx_int_t
vfs_walk_emit_file(ngx_log_t *log, int rootfd, const char *logical,
    const struct stat *st, const brix_vfs_walk_opts_t *opts,
    brix_vfs_walk_file_cb cb, void *cookie, int soft_open_fail)
{
    brix_vfs_stat_t vst;
    ngx_int_t         rc;
    int               fd = -1;

    if (opts->open_files) {
        fd = brix_open_beneath(rootfd, logical, O_RDONLY, 0);
        if (fd < 0) {
            return soft_open_fail ? NGX_OK : NGX_ERROR;
        }
    }

    brix_vfs_fill_stat(st, &vst);
    rc = cb(cookie, logical, &vst, fd);

    if (fd >= 0) {
        (void) ngx_close_file(fd);
    }
    return rc;
}

/* Recursive directory body. Returns NGX_OK on success, NGX_ERROR on an opendir
 * failure (errmsg set), or a callback abort code. */
static ngx_int_t
vfs_walk_dir(ngx_log_t *log, int rootfd, const char *logical_dir,
    const brix_vfs_walk_opts_t *opts, brix_vfs_walk_file_cb cb, void *cookie,
    ngx_uint_t depth, ngx_uint_t *nfiles, char *errmsg, size_t errsz)
{
    DIR           *dh;
    struct dirent *de;
    int            dfd;

    if (depth > opts->max_depth) {
        return NGX_OK;   /* depth cap: prune, not an error */
    }

    /* RESOLVE_BENEATH O_DIRECTORY: refuses to escape the root or open a non-dir. */
    dfd = brix_open_beneath(rootfd, logical_dir, O_RDONLY | O_DIRECTORY, 0);
    if (dfd < 0) {
        if (errmsg != NULL && errsz > 0) {
            snprintf(errmsg, errsz, "opendir failed: %s", strerror(errno));
        }
        return NGX_ERROR;
    }

    /* fdopendir adopts dfd on success (closedir releases it); close it ourselves
     * only on the fdopendir failure path to avoid a leak and a double-close. */
    dh = fdopendir(dfd);
    if (dh == NULL) {
        (void) ngx_close_file(dfd);
        if (errmsg != NULL && errsz > 0) {
            snprintf(errmsg, errsz, "opendir failed: %s", strerror(errno));
        }
        return NGX_ERROR;
    }

    for ( ;; ) {
        char        child[BRIX_MAX_PATH + 1];
        struct stat st;
        ngx_int_t   rc;

        errno = 0;
        de = readdir(dh);
        if (de == NULL) {
            break;   /* end of stream (errno==0) or a readdir error — stop here */
        }

        if (brix_fs_is_dot_entry(de->d_name)) {
            continue;
        }
        if (!vfs_walk_join(logical_dir, de->d_name, child, sizeof(child))) {
            continue;   /* path too long — skip */
        }

        /* stat by (dirfd, name) — not full path — so we inspect the exact entry
         * readdir returned, immune to a concurrent rename. NOFOLLOW: a symlink
         * is neither S_ISDIR nor S_ISREG, so it is silently skipped (never
         * traversed or reported). */
        if (fstatat(dirfd(dh), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            rc = vfs_walk_dir(log, rootfd, child, opts, cb, cookie, depth + 1,
                              nfiles, errmsg, errsz);
            if (rc != NGX_OK) {
                (void) closedir(dh);
                return rc;
            }
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            continue;   /* symlink / special → skip */
        }

        /* Regular file: file cap counts every file reached (before any open), so
         * a skipped/unreadable file still consumes budget — bounding syscalls. */
        if (opts->max_files != 0 && *nfiles >= opts->max_files) {
            continue;
        }
        (*nfiles)++;

        rc = vfs_walk_emit_file(log, rootfd, child, &st, opts, cb, cookie,
                                1 /* soft open-fail: skip this entry */);
        if (rc != NGX_OK) {
            (void) closedir(dh);
            return rc;   /* callback abort */
        }
    }

    (void) closedir(dh);
    return NGX_OK;
}

/* Walk a confined rootfd-relative target. See vfs.h for the full contract. */
ngx_int_t
brix_vfs_walk(ngx_log_t *log, int rootfd, const char *logical,
    const brix_vfs_walk_opts_t *opts, brix_vfs_walk_file_cb cb, void *cookie,
    brix_vfs_walk_target_t *target_out, char *errmsg, size_t errsz)
{
    struct stat st;
    ngx_uint_t  nfiles = 0;

    if (target_out != NULL) {
        *target_out = BRIX_VFS_WALK_NONE;
    }
    if (opts == NULL || cb == NULL || logical == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (brix_stat_beneath(rootfd, logical, &st) != 0) {
        return NGX_DECLINED;   /* target not found */
    }

    if (S_ISREG(st.st_mode)) {
        if (target_out != NULL) {
            *target_out = BRIX_VFS_WALK_FILE;
        }
        /* Single-file target: an open failure here IS an error (not a skip). */
        return vfs_walk_emit_file(log, rootfd, logical, &st, opts, cb, cookie,
                                  0 /* hard open-fail */);
    }

    if (S_ISDIR(st.st_mode)) {
        if (target_out != NULL) {
            *target_out = BRIX_VFS_WALK_DIR;
        }
        return vfs_walk_dir(log, rootfd, logical, opts, cb, cookie, 0, &nfiles,
                            errmsg, errsz);
    }

    if (target_out != NULL) {
        *target_out = BRIX_VFS_WALK_OTHER;
    }
    return NGX_OK;   /* not a file or directory — caller inspects *target_out */
}

/* Confined open beneath root_canon returning a raw fd (thread-safe: no pool
 * alloc/metric). Takes raw O_* `flags` (so callers needing O_NOFOLLOW/O_DIRECTORY
 * etc. that the BRIX_VFS_O_* set does not model can pass them through);
 * O_CLOEXEC is always added. Impersonation-aware. fd or -1 with errno set. */
int
brix_vfs_open_fd(ngx_log_t *log, const char *root_canon, const char *logical,
    int flags, mode_t mode)
{
    return brix_open_confined_canon(log, root_canon, logical,
                                      flags | O_CLOEXEC, mode);
}

/* Confined open beneath a persistent O_PATH rootfd (raw O_* flags passthrough),
 * thread-safe. The fd lands in the session handle table as before. */
int
brix_vfs_open_fd_at(int rootfd, const char *logical, int flags, mode_t mode)
{
    return brix_open_beneath(rootfd, logical, flags, mode);
}

/* Confined unlink of a regular file (thread-safe: no pool alloc/metric). */
int
brix_vfs_unlink_path(ngx_log_t *log, const char *root_canon,
    const char *logical)
{
    return brix_unlink_confined_canon(log, root_canon, logical, 0 /* not dir */);
}

/* Confined remove beneath a persistent O_PATH rootfd (is_dir → rmdir), thread-safe. */
int
brix_vfs_unlink_at(int rootfd, const char *logical, int is_dir)
{
    return brix_unlink_beneath(rootfd, logical, is_dir);
}

/* Confined mkdir of a single directory (thread-safe: no pool alloc/metric). */
int
brix_vfs_mkdir_path(ngx_log_t *log, const char *root_canon,
    const char *logical, mode_t mode)
{
    return brix_mkdir_confined_canon(log, root_canon, logical, mode);
}

/*
 * brix_vfs_backend_mkpath — recursively create `logical` (export-relative,
 * leading-slash) and every missing parent through a NON-default backend driver's
 * mkdir slot, tolerating EEXIST. The driver namespace is inherently confined to
 * the export, so no rootfd anchoring is needed. Returns NGX_DECLINED for the
 * default POSIX export (resolve == NULL) or a driver without a mkdir slot, so the
 * caller falls back to its own confined/group-policy mkpath; 0 on success;
 * -1 with errno set on a real failure.
 */
int
brix_vfs_backend_mkpath(const char *root_canon, const char *logical,
    mode_t mode, ngx_log_t *log)
{
    brix_sd_instance_t *sd = brix_vfs_backend_resolve(root_canon, log);
    char   acc[PATH_MAX];
    size_t i = 0, j = 0;

    if (sd == NULL || sd->driver == NULL || sd->driver->mkdir == NULL) {
        return NGX_DECLINED;
    }

    /* Create each prefix in turn: "/a/b/c" → "/a", "/a/b", "/a/b/c". */
    while (logical[i] != '\0') {
        if (logical[i] != '/') {
            i++;                          /* defensive: skip a leading non-slash */
            continue;
        }
        if (j + 1 >= sizeof(acc)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        acc[j++] = '/';
        i++;
        while (logical[i] != '\0' && logical[i] != '/') {
            if (j + 1 >= sizeof(acc)) {
                errno = ENAMETOOLONG;
                return -1;
            }
            acc[j++] = logical[i++];
        }
        acc[j] = '\0';
        if (j > 1                          /* skip the bare "/" root */
            && sd->driver->mkdir(sd, acc, mode) != NGX_OK
            && errno != EEXIST) {
            return -1;
        }
    }
    return 0;
}

/* Copy a single confined regular file src→dst (impersonation-aware via the
 * confined-canon helpers; thread-safe — no pool allocation). See vfs.h. */
ngx_int_t
brix_vfs_copyfile(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, int preserve_xattrs, brix_vfs_copy_meta_cb meta_cb,
    void *cookie)
{
    struct stat sb;
    int         src_fd;
    int         dst_fd;
    ngx_int_t   rc;

    /* stat as the mapped user (src may be a 0600 file under a 0700 parent the
     * worker cannot itself traverse); follow semantics (copy the link target). */
    if (brix_lstat_confined_canon(log, root_canon, src, &sb, 0) != 0) {
        return NGX_ERROR;
    }

    src_fd = brix_open_confined_canon(log, root_canon, src,
                                        O_RDONLY | O_CLOEXEC, 0);
    if (src_fd < 0) {
        return NGX_ERROR;
    }

    dst_fd = brix_open_confined_canon(log, root_canon, dst,
                                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                                        sb.st_mode & 0777);
    if (dst_fd < 0) {
        (void) ngx_close_file(src_fd);
        return NGX_ERROR;
    }

    rc = brix_copy_range(log, src_fd, 0, dst_fd, 0, (size_t) sb.st_size,
                           src, dst);

    (void) ngx_close_file(src_fd);
    (void) ngx_close_file(dst_fd);

    if (rc == NGX_OK) {
        if (preserve_xattrs) {
            brix_ns_copy_fattrs(log, src, dst);
        }
        if (meta_cb != NULL) {
            rc = meta_cb(cookie, src, dst, 0 /* is_dir */);
        }
    }
    return rc;
}

/* Recursively copy a confined directory tree src→dst. See vfs.h. */
ngx_int_t
brix_vfs_copytree(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, int preserve_xattrs, brix_vfs_copy_meta_cb meta_cb,
    void *cookie)
{
    DIR           *dp;
    struct dirent *de;
    char           src_child[BRIX_MAX_PATH];
    char           dst_child[BRIX_MAX_PATH];
    struct stat    sb;
    ngx_int_t      rc = NGX_OK;

    /* Enumerate as the mapped user (a 0700 user-private collection would EACCES
     * a bare worker opendir). */
    dp = brix_opendir_confined_canon(log, root_canon, src);
    if (dp == NULL) {
        return NGX_ERROR;
    }

    while ((de = readdir(dp)) != NULL) {
        if (brix_fs_is_dot_entry(de->d_name)) {
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

        /* lstat nofollow: never resolve a symlink out of the export. */
        if (brix_lstat_confined_canon(log, root_canon, src_child, &sb, 1) != 0)
        {
            continue;   /* vanished/unreadable child — skip */
        }

        if (S_ISDIR(sb.st_mode)) {
            if (brix_mkdir_confined_canon(log, root_canon, dst_child,
                                            sb.st_mode & 0777) != 0
                && errno != EEXIST)
            {
                rc = NGX_ERROR;
                break;
            }
            if (preserve_xattrs) {
                brix_ns_copy_fattrs(log, src_child, dst_child);
            }
            if (meta_cb != NULL
                && meta_cb(cookie, src_child, dst_child, 1 /* is_dir */)
                       != NGX_OK)
            {
                rc = NGX_ERROR;
                break;
            }
            if (brix_vfs_copytree(log, root_canon, src_child, dst_child,
                                    preserve_xattrs, meta_cb, cookie) != NGX_OK)
            {
                rc = NGX_ERROR;
                break;
            }
        } else if (S_ISREG(sb.st_mode)) {
            if (brix_vfs_copyfile(log, root_canon, src_child, dst_child,
                                    preserve_xattrs, meta_cb, cookie) != NGX_OK)
            {
                rc = NGX_ERROR;
                break;
            }
        }
    }

    (void) closedir(dp);
    return rc;
}
