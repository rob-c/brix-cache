/*
 * vfs_policy_export.c — policy-bearing wrappers over the raw export helpers
 * (phase-105 W3).
 *
 * WHAT: One thin, gated form for every confinement-only mutator in vfs_ops.h
 *       (open_fd, open_fd_at, unlink_path, unlink_at, rmdir_path, mkdir_path,
 *       backend_mkpath, rename_path, copyfile, copytree). Each takes a
 *       brix_vfs_export_op_ctx_t carrying the request's endpoint mutation
 *       policy, refuses with EROFS on a read-only endpoint, and otherwise
 *       delegates verbatim to the raw helper.
 *
 * WHY:  The raw helpers exist because bulk and off-thread consumers (multipart
 *       assembly, the async namespace queue, TPC, CMS forwarding, checkpoint
 *       recovery) cannot use the pool-allocating, metered handle API. They
 *       carry confinement but knew nothing about whether the endpoint may be
 *       written at all, which made them a complete alternate route around every
 *       gate the handle API applies. Rather than thread a boolean through ten
 *       signatures, the authority travels as one typed bundle, so a caller
 *       cannot accidentally pass the wrong argument in the right position.
 *
 * HOW:  Every wrapper is: gate, then delegate. The gate is the same
 *       brix_vfs_export_require_mutation() kernel the context forms use, so the
 *       decision, the errno, and the single denial observation are identical on
 *       and off the event loop. The int-returning helpers translate the
 *       kernel's NGX_ERROR into their own -1/errno contract; brix_vfs_open_fd's
 *       wrapper additionally classifies its raw O_* flags, so a read-only open
 *       through a raw helper stays legal on a read-only export.
 *
 * The un-gated originals stay in vfs_walk.c/vfs_read.c for VFS-internal and
 * explicitly service-owned domains (the cache store, the staging area, a
 * VFS-owned unpublished temporary). Protocol, TPC, CMS, and queue code calls
 * the forms in THIS file.
 */
#include "vfs_internal.h"
#include "vfs_policy.h"

/* ---- Gated confined open beneath an export root ----
 *
 * WHAT: Returns a raw confined fd, or -1 with errno set; -1/EROFS when the
 *       endpoint is read-only and `flags` describe a mutating open.
 *
 * WHY:  A raw open is the widest of the raw helpers: O_CREAT|O_TRUNC through it
 *       creates and empties an export object with no other gate in the way.
 *       Reads must stay free, so the flag word — not the caller — decides
 *       whether the kernel runs.
 *
 * HOW:  1. Classify the flags; 2. gate a mutating open as MUTATE_OPEN;
 *       3. delegate to brix_vfs_open_fd with the bundle's log and root.
 */
int
brix_vfs_export_open_fd(const brix_vfs_export_op_ctx_t *opctx,
    const char *logical, int flags, mode_t mode)
{
    if (opctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (brix_vfs_open_flags_mutate(flags)
        && brix_vfs_export_require_mutation(opctx, BRIX_VFS_MUTATE_OPEN)
           != NGX_OK)
    {
        return -1;
    }

    return brix_vfs_open_fd(opctx->log, opctx->root_canon, logical, flags,
                            mode);
}

/* ---- Gated confined open beneath a persistent O_PATH rootfd ----
 *
 * WHAT: Returns a raw confined fd, or -1 with errno set; -1/EROFS for a
 *       mutating open on a read-only endpoint.
 *
 * WHY:  The rootfd form is what the session handle table and the CMS forwarder
 *       use; without a gated twin those paths would have had to fall back to
 *       the path form purely to be policed.
 *
 * HOW:  1. Classify the flags; 2. gate as MUTATE_OPEN; 3. delegate to
 *       brix_vfs_open_fd_at with the caller's rootfd.
 */
int
brix_vfs_export_open_fd_at(const brix_vfs_export_op_ctx_t *opctx, int rootfd,
    const char *logical, int flags, mode_t mode)
{
    if (opctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (brix_vfs_open_flags_mutate(flags)
        && brix_vfs_export_require_mutation(opctx, BRIX_VFS_MUTATE_OPEN)
           != NGX_OK)
    {
        return -1;
    }

    return brix_vfs_open_fd_at(rootfd, logical, flags, mode);
}

/* ---- Gated confined unlink of a regular file ----
 *
 * WHAT: 0 on success, -1 with errno set; -1/EROFS on a read-only endpoint.
 *
 * WHY:  Namespace removal is the mutation an operator most expects a read-only
 *       export to refuse, and the raw form is reachable from the async queue
 *       drain and from TPC completion.
 *
 * HOW:  1. Gate as MUTATE_REMOVE; 2. delegate to brix_vfs_unlink_path.
 */
int
brix_vfs_export_unlink(const brix_vfs_export_op_ctx_t *opctx,
    const char *logical)
{
    if (brix_vfs_export_require_mutation(opctx, BRIX_VFS_MUTATE_REMOVE)
        != NGX_OK)
    {
        return -1;
    }

    return brix_vfs_unlink_path(opctx->log, opctx->root_canon, logical);
}

/* ---- Gated confined remove beneath a persistent O_PATH rootfd ----
 *
 * WHAT: 0 on success, -1 with errno set; -1/EROFS on a read-only endpoint.
 *       `is_dir` selects rmdir over unlink, exactly as the raw form does.
 *
 * WHY:  The CMS receive path removes by rootfd; it is export storage like any
 *       other and must answer to the same policy.
 *
 * HOW:  1. Gate as MUTATE_REMOVE; 2. delegate to brix_vfs_unlink_at.
 */
int
brix_vfs_export_unlink_at(const brix_vfs_export_op_ctx_t *opctx, int rootfd,
    const char *logical, int is_dir)
{
    if (brix_vfs_export_require_mutation(opctx, BRIX_VFS_MUTATE_REMOVE)
        != NGX_OK)
    {
        return -1;
    }

    return brix_vfs_unlink_at(rootfd, logical, is_dir);
}

/* ---- Gated confined rmdir of a single empty directory ----
 *
 * WHAT: 0 on success, -1 with errno set; -1/EROFS on a read-only endpoint.
 *
 * WHY:  The async namespace queue drains rmdir records off the event loop; the
 *       policy it captured at enqueue must still be the policy that decides.
 *
 * HOW:  1. Gate as MUTATE_REMOVE; 2. delegate to brix_vfs_rmdir_path.
 */
int
brix_vfs_export_rmdir(const brix_vfs_export_op_ctx_t *opctx,
    const char *logical)
{
    if (brix_vfs_export_require_mutation(opctx, BRIX_VFS_MUTATE_REMOVE)
        != NGX_OK)
    {
        return -1;
    }

    return brix_vfs_rmdir_path(opctx->log, opctx->root_canon, logical);
}

/* ---- Gated confined mkdir of a single directory ----
 *
 * WHAT: 0 on success, -1 with errno set (EEXIST when it already exists);
 *       -1/EROFS on a read-only endpoint.
 *
 * WHY:  A collection COPY builds its destination tree through this helper, one
 *       directory at a time, entirely below the handle API.
 *
 * HOW:  1. Gate as MUTATE_MKDIR; 2. delegate to brix_vfs_mkdir_path.
 */
int
brix_vfs_export_mkdir(const brix_vfs_export_op_ctx_t *opctx,
    const char *logical, mode_t mode)
{
    if (brix_vfs_export_require_mutation(opctx, BRIX_VFS_MUTATE_MKDIR)
        != NGX_OK)
    {
        return -1;
    }

    return brix_vfs_mkdir_path(opctx->log, opctx->root_canon, logical, mode);
}

/* ---- Gated recursive backend mkdir of a path and its parents ----
 *
 * WHAT: 0 on success, NGX_DECLINED for a default POSIX export (the caller uses
 *       its own confined mkpath), -1 with errno set otherwise; -1/EROFS on a
 *       read-only endpoint.
 *
 * WHY:  The NGX_DECLINED answer is the one a caller must still be able to get
 *       cheaply, but only after the policy question: probing which backend an
 *       export selected is exactly the capability disclosure §6 forbids ahead
 *       of the decision.
 *
 * HOW:  1. Gate as MUTATE_MKDIR; 2. delegate to brix_vfs_backend_mkpath.
 */
int
brix_vfs_export_mkpath(const brix_vfs_export_op_ctx_t *opctx,
    const char *logical, mode_t mode)
{
    char physical[PATH_MAX];

    if (brix_vfs_export_require_mutation(opctx, BRIX_VFS_MUTATE_MKDIR)
        != NGX_OK)
    {
        return -1;
    }

    if (brix_path_export_to_pfn(opctx->root_canon, opctx->n2n, logical,
                                physical, sizeof(physical)) != NGX_OK)
    {
        return -1;
    }
    return brix_vfs_backend_mkpath(opctx->root_canon, physical, mode,
                                   opctx->log);
}

/* ---- Gated thread-safe confined rename ----
 *
 * WHAT: NGX_OK, or NGX_ERROR with errno set; NGX_ERROR/EROFS on a read-only
 *       endpoint. *was_dir_out is untouched on a policy refusal.
 *
 * WHY:  Rename mutates two namespace entries at once, and the async queue
 *       drains it off-thread. Leaving was_dir_out untouched keeps a refusal
 *       from telling the caller anything about the destination.
 *
 * HOW:  1. Gate as MUTATE_RENAME; 2. delegate to brix_vfs_rename_path.
 */
ngx_int_t
brix_vfs_export_rename(const brix_vfs_export_op_ctx_t *opctx,
    brix_sd_instance_t *sd, const char *src, const char *dst,
    unsigned overwrite, int *was_dir_out)
{
    if (brix_vfs_export_require_mutation(opctx, BRIX_VFS_MUTATE_RENAME)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return brix_vfs_rename_path(sd, opctx->log, opctx->root_canon, opctx->n2n,
                                src, dst, overwrite, was_dir_out);
}

/* ---- Gated single-file confined copy ----
 *
 * WHAT: NGX_OK, or NGX_ERROR with errno set; NGX_ERROR/EROFS on a read-only
 *       endpoint.
 *
 * WHY:  A copy is a create at the destination however the bytes move; the
 *       WebDAV COPY engine reaches this helper on a thread-pool worker where no
 *       request context exists.
 *
 * HOW:  1. Gate as MUTATE_COPY; 2. delegate to brix_vfs_copyfile.
 */
ngx_int_t
brix_vfs_export_copyfile(const brix_vfs_export_op_ctx_t *opctx,
    const char *src, const char *dst, int preserve_xattrs,
    brix_vfs_copy_meta_cb meta_cb, void *cookie)
{
    if (brix_vfs_export_require_mutation(opctx, BRIX_VFS_MUTATE_COPY)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return brix_vfs_copyfile(opctx->log, opctx->root_canon, src, dst,
                             preserve_xattrs, meta_cb, cookie);
}

/* ---- Gated recursive confined tree copy ----
 *
 * WHAT: NGX_OK, or NGX_ERROR with errno set; NGX_ERROR/EROFS on a read-only
 *       endpoint.
 *
 * WHY:  A recursive copy is the case §9.3 names explicitly — the parent gate
 *       must cover every child, and it does here because the whole traversal is
 *       behind one refusal rather than per-child checks that a partial walk
 *       could outrun.
 *
 * HOW:  1. Gate as MUTATE_COPY; 2. delegate to brix_vfs_copytree.
 */
ngx_int_t
brix_vfs_export_copytree(const brix_vfs_export_op_ctx_t *opctx,
    const char *src, const char *dst, int preserve_xattrs,
    brix_vfs_copy_meta_cb meta_cb, void *cookie)
{
    if (brix_vfs_export_require_mutation(opctx, BRIX_VFS_MUTATE_COPY)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return brix_vfs_copytree(opctx->log, opctx->root_canon, src, dst,
                             preserve_xattrs, meta_cb, cookie);
}
