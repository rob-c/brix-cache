/*
 * fs_walk.c - shared directory traversal helpers.
 *
 * WHAT: Provides dot-entry detection, path joining, empty-directory check, and
 *       recursive directory walk with callback. All functions share a common
 *       pattern of opendir/readdir/lstat with dot-filtering. Confined tree
 *       removal lives in the companion file fs_walk_remove.c.
 *
 * WHY: XRootD dirlist, WebDAV PROPFIND on collections, S3 ListObjects all need
 *      directory traversal. Single shared implementation avoids duplication
 *      between modules.
 *
 * HOW: opendir → readdir loop skipping "." and "..", lstat for each entry,
 *      recursive callback walk with depth limit.
 */

#include "fs_walk.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

/*
 * brix_fs_is_dot_entry - check if a directory entry name is "." or "..".
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
brix_fs_is_dot_entry(const char *name)
{
    return name != NULL
           && name[0] == '.'
           && (name[1] == '\0'
               || (name[1] == '.' && name[2] == '\0'));
}

/*
 * brix_fs_join_path - concatenate dir + '/' + name into out buffer.
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
brix_fs_join_path(const char *dir, const char *name, char *out, size_t outsz)
{
    int n;

    if (dir == NULL || name == NULL || out == NULL || outsz == 0) {
        return NGX_ERROR;
    }

    n = snprintf(out, outsz, "%s/%s", dir, name);
    return (n >= 0 && (size_t) n < outsz) ? NGX_OK : NGX_ERROR;
}

/*
 * brix_fs_dir_is_empty - check whether a directory contains non-dot entries.
 *
 * WHAT: Opens path via opendir(), iterates readdir entries, skips dots, and sets
 *       *is_empty = 1 if no non-dot entries found (or empty dir), 0 otherwise.
 *
 * WHY: XRootD stat on collection returns whether it is empty. WebDAV MKCOL checks
 *      target directory emptiness. Single shared check avoids duplication.
 *
 * HOW: opendir → readdir loop, skip brix_fs_is_dot_entry(), set flag on first
 *      non-dot entry found. closedir always called. Returns NGX_OK or NGX_ERROR.
 */

ngx_int_t
brix_fs_dir_is_empty(const char *path, ngx_flag_t *is_empty)
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
        if (brix_fs_is_dot_entry(de->d_name)) {
            continue;
        }
        *is_empty = 0;
        break;
    }

    closedir(dp);
    return NGX_OK;
}

/*
 * brix_fs_walk_action_e - per-entry disposition returned to the walk loop.
 *
 * WHAT: Encodes the three outcomes the walk loop must act on after processing a
 *       single directory entry: keep going cleanly, keep going but remember that
 *       an error occurred, or stop the loop and remember the error.
 *
 * WHY: Extracting the per-entry body into a helper (to cut cyclomatic complexity)
 *       means the helper cannot itself set the loop's rc or break; it returns an
 *       action code and the loop performs the control flow. This preserves the
 *       original behaviour exactly — a bad join/lstat marks rc but continues, a
 *       failed callback marks rc and breaks.
 *
 * HOW: The loop maps CONTINUE→next iteration, MARK_ERROR→rc=NGX_ERROR + continue,
 *       STOP→rc=NGX_ERROR + break.
 */

typedef enum {
    BRIX_FS_WALK_CONTINUE = 0,   /* skip this entry, no error */
    BRIX_FS_WALK_MARK_ERROR,     /* record error, keep walking */
    BRIX_FS_WALK_STOP            /* record error, stop the loop */
} brix_fs_walk_action_e;

/* Forward declaration: the per-entry handler recurses back into the walk. */
static ngx_int_t brix_fs_walk_dir(ngx_log_t *log, const char *dir,
    const brix_fs_walk_options_t *opts, brix_fs_walk_pt cb, void *data,
    ngx_uint_t depth);

/*
 * brix_fs_walk_skip_name - decide whether an entry name is filtered out.
 *
 * WHAT: Returns true when the entry must be skipped before any syscall: it is a
 *       dot entry ("." / ".."), or it is a hidden entry (leading '.') and opts
 *       requests skip_hidden. Returns false otherwise.
 *
 * WHY: The walk loop applies the same name filter every iteration; isolating it
 *      keeps the per-entry handler small and keeps the dot/hidden rule in one
 *      place. Matches the original inline checks byte for byte.
 *
 * HOW: brix_fs_is_dot_entry() first, then (opts && opts->skip_hidden &&
 *      name[0] == '.'). Pure, no side effects.
 */

static ngx_flag_t
brix_fs_walk_skip_name(const brix_fs_walk_options_t *opts, const char *name)
{
    if (brix_fs_is_dot_entry(name)) {
        return 1;
    }

    return opts != NULL && opts->skip_hidden && name[0] == '.';
}

/*
 * brix_fs_walk_cb_wants - decide whether the callback should fire for an entry.
 *
 * WHAT: Returns true when the entry's type matches the include filters: a
 *       directory when opts is NULL or include_dirs is set, a non-directory when
 *       opts is NULL or include_files is set.
 *
 * WHY: The include_files/include_dirs predicate is the densest boolean in the
 *      original loop. Naming it removes a compound condition from the handler and
 *      documents the intent (NULL opts means "emit everything").
 *
 * HOW: Branch on is_dir, then test the matching include flag (NULL opts ⇒ true).
 *      Equivalent to the original
 *      (is_dir && (opts==NULL||include_dirs)) || (!is_dir && (opts==NULL||include_files)).
 */

static ngx_flag_t
brix_fs_walk_cb_wants(const brix_fs_walk_options_t *opts, ngx_flag_t is_dir)
{
    if (is_dir) {
        return opts == NULL || opts->include_dirs;
    }

    return opts == NULL || opts->include_files;
}

/*
 * brix_fs_walk_should_recurse - decide whether to descend into an entry.
 *
 * WHAT: Returns true only for directories that are still within the depth budget:
 *       opts is NULL, or max_depth is 0 (unlimited), or the current depth is below
 *       max_depth. Non-directories never recurse.
 *
 * WHY: Keeps the depth-limit rule out of the handler body and documents that a
 *      max_depth of 0 means unlimited. Matches the original recurse guard exactly.
 *
 * HOW: Early-return false for non-dirs, then evaluate the depth predicate.
 */

static ngx_flag_t
brix_fs_walk_should_recurse(const brix_fs_walk_options_t *opts,
    ngx_flag_t is_dir, ngx_uint_t depth)
{
    if (!is_dir) {
        return 0;
    }

    return opts == NULL || opts->max_depth == 0 || depth < opts->max_depth;
}

/*
 * brix_fs_walk_handle_entry - process one directory entry for the walk.
 *
 * WHAT: Applies the name filter, joins the child path, lstats it, applies the
 *       stay_on_device filter, fires the callback for matching entries, and
 *       recurses into subdirectories within the depth budget. Returns a
 *       brix_fs_walk_action_e telling the loop what to do next.
 *
 * WHY: This is the body extracted from brix_fs_walk_dir()'s readdir loop so the
 *      loop stays trivial and each concern (filter, syscall, callback, recursion)
 *      is a single early-return step. Behaviour is identical to the original:
 *      dot/hidden/cross-device/ENOENT entries are skipped silently; a truncated
 *      join or a non-ENOENT lstat marks an error and continues; a callback that
 *      rejects the entry stops the walk; a failed recursion marks an error and
 *      continues.
 *
 * HOW: Sequence of guarded early returns. child[PATH_MAX] and st live on this
 *      frame; entry borrows pointers to them and to de->d_name for the callback.
 */

static brix_fs_walk_action_e
brix_fs_walk_handle_entry(ngx_log_t *log, const char *dir,
    const brix_fs_walk_options_t *opts, brix_fs_walk_pt cb, void *data,
    ngx_uint_t depth, const struct dirent *de)
{
    char                  child[PATH_MAX];
    struct stat           st;
    brix_fs_walk_entry_t  entry;
    ngx_flag_t            is_dir;

    if (brix_fs_walk_skip_name(opts, de->d_name)) {
        return BRIX_FS_WALK_CONTINUE;
    }

    if (brix_fs_join_path(dir, de->d_name, child, sizeof(child)) != NGX_OK) {
        return BRIX_FS_WALK_MARK_ERROR;
    }

    if (lstat(child, &st) != 0) {
        if (errno != ENOENT) {
            ngx_log_error(NGX_LOG_WARN, log, errno,
                          "brix: lstat failed \"%s\"", child);
            return BRIX_FS_WALK_MARK_ERROR;
        }
        return BRIX_FS_WALK_CONTINUE;
    }

    if (opts != NULL && opts->stay_on_device && st.st_dev != opts->root_dev) {
        return BRIX_FS_WALK_CONTINUE;
    }

    is_dir = S_ISDIR(st.st_mode);

    if (cb != NULL && brix_fs_walk_cb_wants(opts, is_dir)) {
        entry.path = child;
        entry.name = de->d_name;
        entry.st = &st;
        entry.depth = depth;

        if (cb(&entry, data) != NGX_OK) {
            return BRIX_FS_WALK_STOP;
        }
    }

    if (brix_fs_walk_should_recurse(opts, is_dir, depth)
        && brix_fs_walk_dir(log, child, opts, cb, data, depth + 1) != NGX_OK)
    {
        return BRIX_FS_WALK_MARK_ERROR;
    }

    return BRIX_FS_WALK_CONTINUE;
}

/*
 * brix_fs_walk_dir - recursive directory walk with callback, depth tracking.
 *
 * WHAT: Opens dir via opendir(), iterates entries, and dispatches each to
 *       brix_fs_walk_handle_entry() which does the filtering, lstat, callback and
 *       recursion. Aggregates the per-entry action into the return code.
 *
 * WHY: The recursive engine behind brix_fs_walk(). Used by dirlist handlers,
 *      PROPFIND collection walks, and tree removal. Options control filtering
 *      (hidden dirs, files vs dirs only, depth limit, cross-device skip).
 *
 * HOW: opendir → readdir loop; the handler returns CONTINUE/MARK_ERROR/STOP and
 *      this function maps those to rc and loop control, then closedir on exit.
 *      Traversal order is readdir order, identical to the original.
 */

static ngx_int_t
brix_fs_walk_dir(ngx_log_t *log, const char *dir,
    const brix_fs_walk_options_t *opts, brix_fs_walk_pt cb, void *data,
    ngx_uint_t depth)
{
    DIR           *dp;
    struct dirent *de;
    ngx_int_t      rc;

    dp = opendir(dir);
    if (dp == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "brix: cannot open directory \"%s\"", dir);
        return NGX_ERROR;
    }

    rc = NGX_OK;

    while ((de = readdir(dp)) != NULL) {
        brix_fs_walk_action_e action;

        action = brix_fs_walk_handle_entry(log, dir, opts, cb, data, depth, de);

        if (action == BRIX_FS_WALK_STOP) {
            rc = NGX_ERROR;
            break;
        }

        if (action == BRIX_FS_WALK_MARK_ERROR) {
            rc = NGX_ERROR;
        }
    }

    closedir(dp);
    return rc;
}

/*
 * brix_fs_walk - top-level recursive directory walk with callback and options.
 *
 * WHAT: Validates start_path, then delegates to brix_fs_walk_dir() starting at
 *       depth 1. Calls cb(entry, data) for each matching entry in the tree.
 *
 * WHY: Convenience entry point for callers that want a full directory tree walk
 *      without managing recursion themselves. Used by dirlist, PROPFIND, and metrics.
 *
 * HOW: Validates start_path non-NULL, calls brix_fs_walk_dir(log, start_path,
 *      opts, cb, data, 1). Returns NGX_OK or NGX_ERROR from recursive walk.
 */

ngx_int_t
brix_fs_walk(ngx_log_t *log, const char *start_path,
    const brix_fs_walk_options_t *opts, brix_fs_walk_pt cb, void *data)
{
    if (start_path == NULL) {
        return NGX_ERROR;
    }

    return brix_fs_walk_dir(log, start_path, opts, cb, data, 1);
}
