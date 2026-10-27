/*
 * fs_walk_remove.c - confined recursive tree removal (split from fs_walk.c).
 *
 * WHAT: Recursively deletes a directory tree confined to an export root_canon.
 *       brix_fs_remove_tree_confined() drives the opendir/readdir loop and the
 *       final rmdir; brix_fs_remove_tree_entry() handles one child per iteration
 *       (recurse into subdirs, unlink files) through the beneath API.
 *
 * WHY: XRootD DEL/MOVE/COPY on collections and S3 AbortMultipartUpload cleanup
 *      need recursive child deletion. The confined check (root_canon) ensures no
 *      entry escapes the root path boundary, preventing ../ traversal attacks.
 *      Split from fs_walk.c to keep both halves under the file-size cap; the walk
 *      helpers (dot-entry / join-path / dir-is-empty / callback walk) stay there,
 *      the tree-removal cluster lives here. Pure code motion, no behaviour change.
 *
 * HOW: opendir → readdir loop per entry: join path, strip to the root-relative
 *      form, lstat via the beneath helper. If dir → recurse. If file →
 *      brix_unlink_beneath(). After all children processed → brix_unlink_beneath()
 *      with the rmdir flag on the directory itself. Reuses brix_fs_is_dot_entry()
 *      and brix_fs_join_path() from fs_walk.h (both public API).
 */

#include "core/compat/log_event.h"
#include "fs_walk.h"
#include "fs/path/path.h"
#include "fs/path/beneath.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

/*
 * brix_fs_remove_tree_entry - remove one child during a confined tree walk.
 *
 * WHAT: Handles a single directory entry of brix_fs_remove_tree_confined(): skips
 *       dot entries, joins and strips the child path, lstats it via the beneath
 *       helper, then recurses into subdirectories or unlinks files through the
 *       beneath API. Returns NGX_OK to keep iterating, NGX_ERROR to stop.
 *
 * WHY: Extracted from the readdir loop so the outer function stays under the
 *      complexity/length budget while every mutation still flows through the
 *      beneath API (the export-root boundary). Behaviour is identical to the
 *      original inline body: dot and ENOENT entries are skipped; any join/strip
 *      failure, non-ENOENT lstat, failed recursion, or failed unlink stops the
 *      walk and (for the syscall failures) logs and leaves errno set.
 *
 * HOW: Guarded early returns; on the strip-escape case errno is set to EXDEV to
 *      match the original, and NGX_ERROR signals the loop to break.
 */

typedef struct {
    ngx_log_t                *log;
    const char               *root_canon;
    brix_fs_remove_guard_pt   guard;
    void                     *guard_cookie;
} brix_fs_remove_ctx_t;

/* Depth-carrying recursive core; the public wrappers are depth-0 entries. */
static ngx_int_t brix_fs_remove_tree_at(const brix_fs_remove_ctx_t *ctx,
    const char *path, ngx_uint_t depth);

static ngx_int_t
brix_fs_remove_tree_entry(const brix_fs_remove_ctx_t *ctx, int rootfd,
    const char *path, const struct dirent *de, ngx_uint_t depth)
{
    char        child[PATH_MAX];
    struct stat st;
    const char *child_rel;
    ngx_int_t   guard_rc;

    if (brix_fs_is_dot_entry(de->d_name)) {
        return NGX_OK;
    }

    if (brix_fs_join_path(path, de->d_name, child, sizeof(child)) != NGX_OK) {
        return NGX_ERROR;
    }

    child_rel = brix_beneath_strip_root(ctx->root_canon, child);
    if (child_rel == NULL) {
        errno = EXDEV;
        return NGX_ERROR;
    }

    /* lstat via the beneath helper so it runs AS THE MAPPED USER under
     * impersonation (the raw lstat would fail EACCES inside a 0700 user-owned
     * staging dir); off impersonation it is the same local lstat. */
    if (brix_lstat_beneath(rootfd, child_rel, &st) != 0) {
        if (errno == ENOENT) {
            return NGX_OK;
        }
        BRIX_LOG(NGX_LOG_ERR, ctx->log, errno,
                      "brix: remove-tree lstat failed \"%s\"", child);
        return NGX_ERROR;
    }

    if (S_ISDIR(st.st_mode)) {
        return brix_fs_remove_tree_at(ctx, child, depth + 1);
    }

    if (ctx->guard != NULL) {
        guard_rc = ctx->guard(ctx->guard_cookie, child, 0 /* file */);
        if (guard_rc != NGX_OK) {
            return guard_rc;
        }
    }

    if (brix_unlink_beneath(rootfd, child_rel, 0) != 0) {
        BRIX_LOG(NGX_LOG_ERR, ctx->log, errno,
                      "brix: remove-tree unlink failed \"%s\"", child);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * brix_fs_remove_tree_confined - recursively delete directory tree confined to root_canon.
 *
 * WHAT: Opens path via opendir(), iterates entries (skip dots), lstat each child,
 *       recurses into subdirectories, unlinks files via brix_unlink_confined_canon().
 *       After processing children, rmdir the directory itself. Returns NGX_OK on
 *       full removal or NGX_ERROR on any failure.
 *
 * WHY: XRootD DEL/MOVE/COPY on collections requires recursive child deletion. The
 *      confined check (root_canon) ensures no entry escapes the root path boundary,
 *      preventing ../ traversal attacks.
 *
 * HOW: opendir → readdir loop per entry: join path, lstat. If dir → recurse.
 *      If file → brix_unlink_confined_canon(root_canon, child, 0). After all
 *      children processed → brix_unlink_confined_canon(root_canon, path, 1) (rmdir).
 */

static ngx_int_t
brix_fs_remove_tree_at(const brix_fs_remove_ctx_t *ctx, const char *path,
    ngx_uint_t depth)
{
    DIR           *dp;
    struct dirent *de;
    ngx_int_t      rc;
    int            rootfd;
    const char    *path_rel;

    /* D-6/T2: independent C-stack recursion — bound it so a hostile deep tree
     * aborts cleanly instead of overflowing the worker stack. */
    if (depth > BRIX_FS_TREE_MAX_DEPTH) {
        BRIX_LOG(NGX_LOG_ERR, ctx->log, 0,
                      "brix: remove-tree depth cap (%d) exceeded at \"%s\"",
                      BRIX_FS_TREE_MAX_DEPTH, path);
        errno = ELOOP;
        return NGX_ERROR;
    }

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
    if (ctx->guard != NULL) {
        rc = ctx->guard(ctx->guard_cookie, path, 1 /* directory */);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    rootfd = brix_beneath_open_root(ctx->root_canon);
    if (rootfd < 0) {
        BRIX_LOG(NGX_LOG_ERR, ctx->log, errno,
                      "brix: remove-tree cannot open root for \"%s\"", path);
        return NGX_ERROR;
    }
    path_rel = brix_beneath_strip_root(ctx->root_canon, path);
    if (path_rel == NULL) {
        close(rootfd);
        errno = EXDEV;
        return NGX_ERROR;
    }

    /* Open the dir AS THE MAPPED USER under impersonation (broker fd + fdopendir):
     * a multipart staging dir is owned 0700 by the mapped user, so a raw worker
     * opendir() here fails EACCES and breaks AbortMultipartUpload / the cleanup.
     * Off impersonation this is a plain opendir(). */
    dp = brix_opendir_confined_canon(ctx->log, ctx->root_canon, path);
    if (dp == NULL) {
        close(rootfd);
        if (errno == ENOENT) {
            return NGX_OK;
        }
        BRIX_LOG(NGX_LOG_ERR, ctx->log, errno,
                      "brix: remove-tree opendir failed \"%s\"", path);
        return NGX_ERROR;
    }

    rc = NGX_OK;

    while ((de = readdir(dp)) != NULL) {
        rc = brix_fs_remove_tree_entry(ctx, rootfd, path, de, depth);
        if (rc != NGX_OK) {
            break;
        }
    }

    closedir(dp);

    if (rc == NGX_OK
        && brix_unlink_beneath(rootfd, path_rel, 1) != 0)
    {
        BRIX_LOG(NGX_LOG_ERR, ctx->log, errno,
                      "brix: remove-tree rmdir failed \"%s\"", path);
        rc = NGX_ERROR;
    }

    close(rootfd);
    return rc;
}

/* See fs_walk.h — depth-0 entry into the recursive core. */
ngx_int_t
brix_fs_remove_tree_confined(ngx_log_t *log, const char *root_canon,
    const char *path)
{
    return brix_fs_remove_tree_confined_checked(log, root_canon, path,
                                                NULL, NULL);
}

/* ---- Guarded entry into confined recursive removal ----------------------
 *
 * WHAT: Removes a confined tree while invoking `guard` on every file and
 *       directory before that path is traversed or deleted. Returns NGX_OK,
 *       NGX_ERROR, or the guard's exact non-OK refusal.
 *
 * WHY: Caller-visible recursive replacement must authorize every resource it
 *      destroys; the ordinary helper remains available for service-owned temp
 *      cleanup that has no caller namespace authority.
 *
 * HOW: Build one immutable recursion context and enter the bounded walker at
 *      depth zero; the walker propagates guard refusals without translation.
 */
ngx_int_t
brix_fs_remove_tree_confined_checked(ngx_log_t *log, const char *root_canon,
    const char *path, brix_fs_remove_guard_pt guard, void *guard_cookie)
{
    brix_fs_remove_ctx_t ctx = {
        .log = log,
        .root_canon = root_canon,
        .guard = guard,
        .guard_cookie = guard_cookie,
    };

    return brix_fs_remove_tree_at(&ctx, path, 0);
}
