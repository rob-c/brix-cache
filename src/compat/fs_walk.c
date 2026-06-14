/*
 * fs_walk.c - shared directory traversal helpers.
 *
 * WHAT: Provides dot-entry detection, path joining, empty-directory check, recursive
 *       directory walk with callback, and confined tree removal. All functions share
 *       a common pattern of opendir/readdir/lstat with dot-filtering.
 *
 * WHY: XRootD dirlist, WebDAV PROPFIND on collections, S3 ListObjects all need
 *      directory traversal. remove-tree is used by DEL/MOVE/COPY on collections.
 *      Single shared implementation avoids duplication between modules.
 *
 * HOW: opendir → readdir loop skipping "." and "..", lstat for each entry,
 *      recursive callback walk with depth limit, confined unlink via
 *      xrootd_unlink_confined_canon() for tree removal.
 */

#include "fs_walk.h"
#include "../path/path.h"
#include "../path/beneath.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

/*
 * xrootd_fs_is_dot_entry - check if a directory entry name is "." or "..".
 *
 * WHAT: Returns NGX_TRUE if name is exactly "." (length 1) or ".." (length 2),
 *       NGX_FALSE otherwise. Handles NULL input safely.
 *
 * WHY: All directory traversal loops skip dot entries per POSIX convention. This
 *      shared check ensures consistency across dirlist, walk, and remove-tree paths.
 *
 * HOW: name[0] == '.' && (name[1]=='\0' || (name[1]=='.' && name[2]=='\0')).
 */

ngx_flag_t
xrootd_fs_is_dot_entry(const char *name)
{
    return name != NULL
           && name[0] == '.'
           && (name[1] == '\0'
               || (name[1] == '.' && name[2] == '\0'));
}

/*
 * xrootd_fs_join_path - concatenate dir + '/' + name into out buffer.
 *
 * WHAT: Formats "dir/name" into out[0..outsz-1] via snprintf. Returns NGX_OK if
 *       the result fits, NGX_ERROR on NULL inputs or truncation.
 *
 * WHY: Directory traversal builds child paths by joining parent directory with entry
 *      name. This function handles buffer bounds checking uniformly.
 *
 * HOW: snprintf(out, outsz, "%s/%s", dir, name). Checks return value < outsz.
 */

ngx_int_t
xrootd_fs_join_path(const char *dir, const char *name, char *out, size_t outsz)
{
    int n;

    if (dir == NULL || name == NULL || out == NULL || outsz == 0) {
        return NGX_ERROR;
    }

    n = snprintf(out, outsz, "%s/%s", dir, name);
    return (n >= 0 && (size_t) n < outsz) ? NGX_OK : NGX_ERROR;
}

/*
 * xrootd_fs_dir_is_empty - check whether a directory contains non-dot entries.
 *
 * WHAT: Opens path via opendir(), iterates readdir entries, skips dots, and sets
 *       *is_empty = 1 if no non-dot entries found (or empty dir), 0 otherwise.
 *
 * WHY: XRootD stat on collection returns whether it is empty. WebDAV MKCOL checks
 *      target directory emptiness. Single shared check avoids duplication.
 *
 * HOW: opendir → readdir loop, skip xrootd_fs_is_dot_entry(), set flag on first
 *      non-dot entry found. closedir always called. Returns NGX_OK or NGX_ERROR.
 */

ngx_int_t
xrootd_fs_dir_is_empty(const char *path, ngx_flag_t *is_empty)
{
    DIR           *dp;
    struct dirent *de;

    if (is_empty == NULL) {
        return NGX_ERROR;
    }

    *is_empty = 1;
    dp = opendir(path);
    if (dp == NULL) {
        return NGX_ERROR;
    }

    while ((de = readdir(dp)) != NULL) {
        if (xrootd_fs_is_dot_entry(de->d_name)) {
            continue;
        }
        *is_empty = 0;
        break;
    }

    closedir(dp);
    return NGX_OK;
}

/*
 * xrootd_fs_walk_dir - recursive directory walk with callback, depth tracking.
 *
 * WHAT: Opens dir via opendir(), iterates entries (skip dots, skip hidden if opts),
 *       lstat each child, builds entry struct (path/name/st/depth), calls cb(entry,
 *       data). Recursively descends into subdirectories respecting max_depth and
 *       stay_on_device options.
 *
 * WHY: The recursive engine behind xrootd_fs_walk(). Used by dirlist handlers, PROPFIND
 *      collection walks, and tree removal. Options control filtering (hidden dirs,
 *      files vs dirs only, depth limit, cross-device skip).
 *
 * HOW: opendir → readdir loop per entry: join path via xrootd_fs_join_path(), lstat,
 *      apply opts filters, build entry struct, call cb(). If is_dir and within max_depth,
 *      recurse with depth+1. closedir on exit.
 */

static ngx_int_t
xrootd_fs_walk_dir(ngx_log_t *log, const char *dir,
    const xrootd_fs_walk_options_t *opts, xrootd_fs_walk_pt cb, void *data,
    ngx_uint_t depth)
{
    DIR           *dp;
    struct dirent *de;
    ngx_int_t      rc;

    dp = opendir(dir);
    if (dp == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "xrootd: cannot open directory \"%s\"", dir);
        return NGX_ERROR;
    }

    rc = NGX_OK;

    while ((de = readdir(dp)) != NULL) {
        char                     child[PATH_MAX];
        struct stat              st;
        xrootd_fs_walk_entry_t   entry;
        ngx_flag_t               is_dir;

        if (xrootd_fs_is_dot_entry(de->d_name)) {
            continue;
        }

        if (opts != NULL && opts->skip_hidden && de->d_name[0] == '.') {
            continue;
        }

        if (xrootd_fs_join_path(dir, de->d_name, child, sizeof(child))
            != NGX_OK)
        {
            rc = NGX_ERROR;
            continue;
        }

        if (lstat(child, &st) != 0) {
            if (errno != ENOENT) {
                ngx_log_error(NGX_LOG_WARN, log, errno,
                              "xrootd: lstat failed \"%s\"", child);
                rc = NGX_ERROR;
            }
            continue;
        }

        if (opts != NULL && opts->stay_on_device && st.st_dev != opts->root_dev) {
            continue;
        }

        is_dir = S_ISDIR(st.st_mode);
        if (cb != NULL
            && ((is_dir && (opts == NULL || opts->include_dirs))
                || (!is_dir && (opts == NULL || opts->include_files))))
        {
            entry.path = child;
            entry.name = de->d_name;
            entry.st = &st;
            entry.depth = depth;

            if (cb(&entry, data) != NGX_OK) {
                rc = NGX_ERROR;
                break;
            }
        }

        if (is_dir
            && (opts == NULL || opts->max_depth == 0
                || depth < opts->max_depth))
        {
            if (xrootd_fs_walk_dir(log, child, opts, cb, data, depth + 1)
                != NGX_OK)
            {
                rc = NGX_ERROR;
            }
        }
    }

    closedir(dp);
    return rc;
}

/*
 * xrootd_fs_walk - top-level recursive directory walk with callback and options.
 *
 * WHAT: Validates start_path, then delegates to xrootd_fs_walk_dir() starting at
 *       depth 1. Calls cb(entry, data) for each matching entry in the tree.
 *
 * WHY: Convenience entry point for callers that want a full directory tree walk
 *      without managing recursion themselves. Used by dirlist, PROPFIND, and metrics.
 *
 * HOW: Validates start_path non-NULL, calls xrootd_fs_walk_dir(log, start_path,
 *      opts, cb, data, 1). Returns NGX_OK or NGX_ERROR from recursive walk.
 */

ngx_int_t
xrootd_fs_walk(ngx_log_t *log, const char *start_path,
    const xrootd_fs_walk_options_t *opts, xrootd_fs_walk_pt cb, void *data)
{
    if (start_path == NULL) {
        return NGX_ERROR;
    }

    return xrootd_fs_walk_dir(log, start_path, opts, cb, data, 1);
}

/*
 * xrootd_fs_remove_tree_confined - recursively delete directory tree confined to root_canon.
 *
 * WHAT: Opens path via opendir(), iterates entries (skip dots), lstat each child,
 *       recurses into subdirectories, unlinks files via xrootd_unlink_confined_canon().
 *       After processing children, rmdir the directory itself. Returns NGX_OK on
 *       full removal or NGX_ERROR on any failure.
 *
 * WHY: XRootD DEL/MOVE/COPY on collections requires recursive child deletion. The
 *      confined check (root_canon) ensures no entry escapes the root path boundary,
 *      preventing ../ traversal attacks.
 *
 * HOW: opendir → readdir loop per entry: join path, lstat. If dir → recurse.
 *      If file → xrootd_unlink_confined_canon(root_canon, child, 0). After all
 *      children processed → xrootd_unlink_confined_canon(root_canon, path, 1) (rmdir).
 */

ngx_int_t
xrootd_fs_remove_tree_confined(ngx_log_t *log, const char *root_canon,
    const char *path)
{
    DIR           *dp;
    struct dirent *de;
    ngx_int_t      rc;
    int            rootfd;
    const char    *path_rel;

    /*
     * The opendir/readdir/lstat iteration below is NOT a beneath site: it walks
     * by absolute child path built from single, kernel-supplied dirent names
     * (no client `..`), and lstat does not follow the final component, so a
     * dangling/outward symlink entry is seen as a symlink and unlinked as one
     * (its target is never opened or followed).  The actual mutations — every
     * unlink and the final rmdir — DO go through the beneath API, which is where
     * the export-root boundary is enforced.  A readdir-relative
     * openat(dirfd,...) walk would be a defence-in-depth refinement but is not a
     * confinement gap here.
     */
    rootfd = xrootd_beneath_open_root(root_canon);
    if (rootfd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: remove-tree cannot open root for \"%s\"", path);
        return NGX_ERROR;
    }
    path_rel = xrootd_beneath_strip_root(root_canon, path);
    if (path_rel == NULL) {
        close(rootfd);
        errno = EXDEV;
        return NGX_ERROR;
    }

    dp = opendir(path);
    if (dp == NULL) {
        close(rootfd);
        if (errno == ENOENT) {
            return NGX_OK;
        }
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: remove-tree opendir failed \"%s\"", path);
        return NGX_ERROR;
    }

    rc = NGX_OK;

    while ((de = readdir(dp)) != NULL) {
        char        child[PATH_MAX];
        struct stat st;

        if (xrootd_fs_is_dot_entry(de->d_name)) {
            continue;
        }

        if (xrootd_fs_join_path(path, de->d_name, child, sizeof(child))
            != NGX_OK)
        {
            rc = NGX_ERROR;
            break;
        }

        if (lstat(child, &st) != 0) {
            if (errno == ENOENT) {
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: remove-tree lstat failed \"%s\"", child);
            rc = NGX_ERROR;
            break;
        }

        if (S_ISDIR(st.st_mode)) {
            if (xrootd_fs_remove_tree_confined(log, root_canon, child)
                != NGX_OK)
            {
                rc = NGX_ERROR;
                break;
            }
        } else {
            const char *child_rel = xrootd_beneath_strip_root(root_canon,
                                                              child);
            if (child_rel == NULL) {
                errno = EXDEV;
                rc = NGX_ERROR;
                break;
            }
            if (xrootd_unlink_beneath(rootfd, child_rel, 0) != 0) {
                ngx_log_error(NGX_LOG_ERR, log, errno,
                              "xrootd: remove-tree unlink failed \"%s\"", child);
                rc = NGX_ERROR;
                break;
            }
        }
    }

    closedir(dp);

    if (rc == NGX_OK
        && xrootd_unlink_beneath(rootfd, path_rel, 1) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: remove-tree rmdir failed \"%s\"", path);
        rc = NGX_ERROR;
    }

    close(rootfd);
    return rc;
}
