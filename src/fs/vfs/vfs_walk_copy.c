/*
 * vfs_walk_copy.c — VFS confined single-file + recursive tree copy.
 *
 * WHAT: Implements brix_vfs_copyfile() (one confined regular file src→dst) and
 *       brix_vfs_copytree() (a confined directory tree src→dst), both
 *       impersonation-aware via the confined-canon helpers and thread-safe (no
 *       pool allocation / metric emission).
 *
 * WHY:  Split verbatim out of vfs_walk.c to keep every translation unit under the
 *       600-line file-size gate. The copy family is a self-contained concept: its
 *       recursion helpers are file-local statics and it shares no callee with the
 *       walk / confined-path-op remainder of vfs_walk.c — only the two extern
 *       entry points (declared in vfs.h) are visible outside this unit.
 *
 * HOW:  brix_vfs_copyfile() stats+opens src and dst through the confined-canon
 *       helpers and byte-copies via brix_copy_range, optionally preserving xattrs
 *       and firing a per-entry meta callback. brix_vfs_copytree() is a depth-0
 *       wrapper over vfs_copytree_run(), whose loop classifies each readdir entry
 *       (lstat-nofollow) and dispatches to a subdir recursion or a file copy;
 *       BRIX_FS_TREE_MAX_DEPTH bounds the C-stack recursion.
 */
#include "vfs_internal.h"
#include "fs/path/path.h"            /* confined-canon open/lstat/mkdir/opendir   */
#include "core/compat/fs_walk.h"       /* brix_fs_is_dot_entry, TREE_MAX_DEPTH     */
#include "core/compat/copy_range.h"    /* brix_copy_range (copyfile/copytree)     */
#include "core/compat/namespace_ops.h" /* brix_ns_copy_fattrs                     */

#include <dirent.h>

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

/*
 * vfs_copy_ctx_t — the invariant state of a confined copytree recursion.
 *
 * WHAT: Bundles every parameter that stays constant across a whole tree copy
 *       (the log, the confinement root, the preserve-xattrs flag and the
 *       per-entry metadata callback + cookie). Only the moving src/dst paths are
 *       passed as explicit per-node arguments.
 * WHY:  The per-entry / per-subdir copytree helpers otherwise each carried a
 *       7–8 parameter list (log/root_canon/src/dst/preserve_xattrs/meta_cb/
 *       cookie), which is param-bloat (coding-standards §8). A file-local context
 *       makes the shared data flow one pointer and keeps the extracted helpers
 *       under the 5-param gate without disturbing the frozen extern
 *       brix_vfs_copytree() contract.
 * HOW:  brix_vfs_copytree() zero-initialises one ctx on its stack from its own
 *       arguments and passes &ctx (plus the moving src/dst) into the loop helper;
 *       the recursion re-enters brix_vfs_copytree(), which rebuilds an identical
 *       ctx for that subtree — so the context never outlives one frame.
 */
typedef struct {
    ngx_log_t                *log;
    const char               *root_canon;
    int                       preserve_xattrs;
    brix_vfs_copy_meta_cb     meta_cb;
    void                     *cookie;
} vfs_copy_ctx_t;

/* Depth-carrying recursive core; brix_vfs_copytree() is a depth-0 wrapper.  The
 * depth threads through the subdir/entry helpers (rather than resetting at the
 * public entry each level) so BRIX_FS_TREE_MAX_DEPTH actually bounds the C-stack
 * recursion (D-6/T2). */
static ngx_int_t vfs_copytree_run(const vfs_copy_ctx_t *ctx, const char *src,
    const char *dst, ngx_uint_t depth);

/* Recursively copy one confined child directory src_child→dst_child: mkdir the
 * dst (tolerating EEXIST), copy fattrs + run meta_cb when requested, then recurse
 * one level deeper. Factored out of the copytree loop to keep that loop's
 * per-entry dispatch flat. Returns NGX_OK on success, NGX_ERROR on any step. */
static ngx_int_t
vfs_copytree_subdir(const vfs_copy_ctx_t *ctx, const char *src_child,
    const char *dst_child, mode_t mode, ngx_uint_t depth)
{
    if (brix_mkdir_confined_canon(ctx->log, ctx->root_canon, dst_child,
                                  mode & 0777) != 0
        && errno != EEXIST)
    {
        return NGX_ERROR;
    }
    if (ctx->preserve_xattrs) {
        brix_ns_copy_fattrs(ctx->log, src_child, dst_child);
    }
    if (ctx->meta_cb != NULL
        && ctx->meta_cb(ctx->cookie, src_child, dst_child, 1 /* is_dir */)
               != NGX_OK)
    {
        return NGX_ERROR;
    }
    return vfs_copytree_run(ctx, src_child, dst_child, depth + 1);
}

/* Copy one readdir entry of a copytree walk. Builds the src/dst child paths,
 * lstat-nofollow classifies the entry (a vanished/unreadable child is a soft
 * skip), then dispatches to the subdir recursion or the file copy. Returns
 * NGX_OK to continue the enclosing loop (including on a skip), NGX_ERROR to
 * abort it. */
static ngx_int_t
vfs_copytree_entry(const vfs_copy_ctx_t *ctx, const char *src, const char *dst,
    const struct dirent *de, ngx_uint_t depth)
{
    char        src_child[BRIX_MAX_PATH];
    char        dst_child[BRIX_MAX_PATH];
    struct stat sb;

    if (brix_fs_is_dot_entry(de->d_name)) {
        return NGX_OK;
    }
    if ((size_t) snprintf(src_child, sizeof(src_child), "%s/%s",
                          src, de->d_name) >= sizeof(src_child)
        || (size_t) snprintf(dst_child, sizeof(dst_child), "%s/%s",
                             dst, de->d_name) >= sizeof(dst_child))
    {
        return NGX_ERROR;
    }

    /* lstat nofollow: never resolve a symlink out of the export. */
    if (brix_lstat_confined_canon(ctx->log, ctx->root_canon, src_child, &sb, 1)
        != 0)
    {
        return NGX_OK;   /* vanished/unreadable child — skip */
    }

    if (S_ISDIR(sb.st_mode)) {
        return vfs_copytree_subdir(ctx, src_child, dst_child, sb.st_mode, depth);
    }
    if (S_ISREG(sb.st_mode)) {
        return brix_vfs_copyfile(ctx->log, ctx->root_canon, src_child, dst_child,
                                 ctx->preserve_xattrs, ctx->meta_cb, ctx->cookie);
    }
    return NGX_OK;   /* symlink / special → skip */
}

/* Depth-carrying recursive core for brix_vfs_copytree(). */
static ngx_int_t
vfs_copytree_run(const vfs_copy_ctx_t *ctx, const char *src, const char *dst,
    ngx_uint_t depth)
{
    DIR           *dp;
    struct dirent *de;
    ngx_int_t      rc = NGX_OK;

    /* D-6/T2: bound the independent C-stack recursion so a hostile deep source
     * tree aborts cleanly instead of overflowing the worker stack. */
    if (depth > BRIX_FS_TREE_MAX_DEPTH) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "brix: copytree depth cap (%d) exceeded at \"%s\"",
                      BRIX_FS_TREE_MAX_DEPTH, src);
        errno = ELOOP;
        return NGX_ERROR;
    }

    /* Enumerate as the mapped user (a 0700 user-private collection would EACCES
     * a bare worker opendir). */
    dp = brix_opendir_confined_canon(ctx->log, ctx->root_canon, src);
    if (dp == NULL) {
        return NGX_ERROR;
    }

    while ((de = readdir(dp)) != NULL) {
        rc = vfs_copytree_entry(ctx, src, dst, de, depth);
        if (rc != NGX_OK) {
            break;
        }
    }

    (void) closedir(dp);
    return rc;
}

/* Recursively copy a confined directory tree src→dst. See vfs.h. */
ngx_int_t
brix_vfs_copytree(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, int preserve_xattrs, brix_vfs_copy_meta_cb meta_cb,
    void *cookie)
{
    vfs_copy_ctx_t ctx = { log, root_canon, preserve_xattrs, meta_cb, cookie };

    return vfs_copytree_run(&ctx, src, dst, 0);
}
