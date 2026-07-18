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

/*
 * vfs_walk_ctx_t — the invariant traversal state threaded through the confined
 * recursive walk.
 *
 * WHAT: Bundles every parameter that stays constant across the whole walk (the
 *       confinement root, the caller's callback + cookie, the filter options and
 *       the opendir-failure error sink) plus the single mutable counter shared by
 *       the recursion (nfiles). Only `depth` — which changes on every recursive
 *       descent — is passed as an explicit per-call argument.
 * WHY:  vfs_walk_dir()/vfs_walk_emit_file() each carried a 8–10 parameter list
 *       (log/rootfd/opts/cb/cookie/nfiles/errmsg/errsz), which is param-bloat
 *       (coding-standards §8) and forced every recursive call to re-thread the
 *       same eight values. Promoting a file-local context makes the data flow
 *       explicit (one pointer), keeps the helpers small and drops the signatures
 *       under the 5-param gate without touching the frozen extern brix_vfs_walk()
 *       contract.
 * HOW:  brix_vfs_walk() zero-initialises one ctx on its stack from its own
 *       arguments and passes &ctx (plus a starting depth) into vfs_walk_dir();
 *       the recursion carries the same &ctx unchanged and only advances depth.
 *       nfiles is a live counter inside the ctx (the file cap is process-wide for
 *       the walk), so it is written through the shared pointer, not copied.
 */
typedef struct {
    ngx_log_t                    *log;
    int                           rootfd;
    const brix_vfs_walk_opts_t   *opts;
    brix_vfs_walk_file_cb         cb;
    void                         *cookie;
    ngx_uint_t                    nfiles;   /* regular files reached so far      */
    char                         *errmsg;   /* opendir-failure sink (may be NULL) */
    size_t                        errsz;
} vfs_walk_ctx_t;

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
vfs_walk_emit_file(const vfs_walk_ctx_t *ctx, const char *logical,
    const struct stat *st, int soft_open_fail)
{
    brix_vfs_stat_t vst;
    ngx_int_t         rc;
    int               fd = -1;

    if (ctx->opts->open_files) {
        fd = brix_open_beneath(ctx->rootfd, logical, O_RDONLY, 0);
        if (fd < 0) {
            return soft_open_fail ? NGX_OK : NGX_ERROR;
        }
    }

    brix_vfs_fill_stat(st, &vst);
    rc = ctx->cb(ctx->cookie, logical, &vst, fd);

    if (fd >= 0) {
        (void) ngx_close_file(fd);
    }
    return rc;
}

static ngx_int_t vfs_walk_dir(vfs_walk_ctx_t *ctx, const char *logical_dir,
    ngx_uint_t depth);

/* Open one directory for a confined walk. On success returns an open DIR* (the
 * caller closedir()s it); on failure returns NULL and records the opendir-error
 * message in the ctx sink. RESOLVE_BENEATH O_DIRECTORY refuses to escape the
 * root or open a non-directory. fdopendir adopts the fd on success (closedir
 * releases it); we close it ourselves only on the fdopendir failure path to
 * avoid a leak and a double-close. */
static DIR *
vfs_walk_opendir(const vfs_walk_ctx_t *ctx, const char *logical_dir)
{
    DIR *dh;
    int  dfd;

    dfd = brix_open_beneath(ctx->rootfd, logical_dir, O_RDONLY | O_DIRECTORY, 0);
    if (dfd < 0) {
        if (ctx->errmsg != NULL && ctx->errsz > 0) {
            snprintf(ctx->errmsg, ctx->errsz, "opendir failed: %s",
                     strerror(errno));
        }
        return NULL;
    }

    dh = fdopendir(dfd);
    if (dh == NULL) {
        (void) ngx_close_file(dfd);
        if (ctx->errmsg != NULL && ctx->errsz > 0) {
            snprintf(ctx->errmsg, ctx->errsz, "opendir failed: %s",
                     strerror(errno));
        }
        return NULL;
    }
    return dh;
}

/* Per-entry disposition returned by vfs_walk_entry(): keep scanning the
 * directory, or stop the whole walk and propagate `code` to the caller. */
typedef struct {
    int       stop;   /* non-zero → abort the walk, returning `code`            */
    ngx_int_t code;   /* the abort code (a callback result or NGX_ERROR)        */
} vfs_walk_step_t;

/* Classify and handle one readdir entry. `dh` supplies the dirfd for a
 * rename-immune fstatat; on a directory it recurses, on a regular file it counts
 * against the file cap and fires the callback. Any per-entry open/stat failure is
 * a soft skip (returns {0}); only a recursion/callback abort sets stop=1. */
static vfs_walk_step_t
vfs_walk_entry(vfs_walk_ctx_t *ctx, DIR *dh, const char *logical_dir,
    const struct dirent *de, ngx_uint_t depth)
{
    vfs_walk_step_t step = { 0, NGX_OK };
    char            child[BRIX_MAX_PATH + 1];
    struct stat     st;
    int             dfd;

    if (brix_fs_is_dot_entry(de->d_name)) {
        return step;
    }
    if (!vfs_walk_join(logical_dir, de->d_name, child, sizeof(child))) {
        return step;   /* path too long — skip */
    }

    /* stat by (dirfd, name) — not full path — so we inspect the exact entry
     * readdir returned, immune to a concurrent rename. NOFOLLOW: a symlink is
     * neither S_ISDIR nor S_ISREG, so it is silently skipped (never traversed or
     * reported). */
    dfd = dirfd(dh);
    if (dfd < 0 || fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return step;   /* unstattable (or dirfd failure) — skip the entry */
    }

    if (S_ISDIR(st.st_mode)) {
        ngx_int_t rc = vfs_walk_dir(ctx, child, depth + 1);
        if (rc != NGX_OK) {
            step.stop = 1;
            step.code = rc;
        }
        return step;
    }

    if (!S_ISREG(st.st_mode)) {
        return step;   /* symlink / special → skip */
    }

    /* Regular file: the file cap counts every file reached (before any open), so
     * a skipped/unreadable file still consumes budget — bounding syscalls. */
    if (ctx->opts->max_files != 0 && ctx->nfiles >= ctx->opts->max_files) {
        return step;
    }
    ctx->nfiles++;

    {
        ngx_int_t rc = vfs_walk_emit_file(ctx, child, &st,
                                          1 /* soft open-fail: skip this entry */);
        if (rc != NGX_OK) {
            step.stop = 1;
            step.code = rc;   /* callback abort */
        }
    }
    return step;
}

/* Recursive directory body. Returns NGX_OK on success, NGX_ERROR on an opendir
 * failure (errmsg set), or a callback abort code. */
static ngx_int_t
vfs_walk_dir(vfs_walk_ctx_t *ctx, const char *logical_dir, ngx_uint_t depth)
{
    DIR           *dh;
    struct dirent *de;

    if (depth > ctx->opts->max_depth) {
        return NGX_OK;   /* depth cap: prune, not an error */
    }

    dh = vfs_walk_opendir(ctx, logical_dir);
    if (dh == NULL) {
        return NGX_ERROR;
    }

    for ( ;; ) {
        vfs_walk_step_t step;

        errno = 0;
        de = readdir(dh);
        if (de == NULL) {
            break;   /* end of stream (errno==0) or a readdir error — stop here */
        }

        step = vfs_walk_entry(ctx, dh, logical_dir, de, depth);
        if (step.stop) {
            (void) closedir(dh);
            return step.code;
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
    struct stat    st;
    vfs_walk_ctx_t ctx = { log, rootfd, opts, cb, cookie, 0, errmsg, errsz };

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
        return vfs_walk_emit_file(&ctx, logical, &st, 0 /* hard open-fail */);
    }

    if (S_ISDIR(st.st_mode)) {
        if (target_out != NULL) {
            *target_out = BRIX_VFS_WALK_DIR;
        }
        return vfs_walk_dir(&ctx, logical, 0);
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
        /* Not a real failure — the caller falls back to its own confined/
         * group-policy mkpath — but set errno for clarity to any caller that
         * inspects it before checking the NGX_DECLINED return. */
        errno = ENOSYS;
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
