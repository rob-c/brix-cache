#ifndef BRIX_VFS_MUTATE_H
#define BRIX_VFS_MUTATE_H

/*
 * vfs_mutate.h — namespace/object MUTATION declarations (unlink / rmdir /
 * bulk delete / rename / mkdir / chmod / setattr / truncate / sync), split
 * (phase-107 W5 file-size burndown) out of the oversized vfs.h with zero
 * behaviour change, the same way phase-79 cut vfs_ops.h. Every entry point
 * here passes the typed policy kernel (vfs_policy.c) FIRST — EROFS before
 * any leaf/cred/temp/evict work (INVARIANT #12) — and the phase-107 waves
 * that extend the mutation surface (W6 recall/evict, W7 preconditions, W8
 * lock gate) land their declarations HERE, not in vfs.h. Included at the
 * END of vfs.h and DEPENDS on the types it defines (brix_vfs_ctx_t /
 * brix_vfs_file_t / brix_sd_setattr_t and the nginx includes). Do not
 * include directly — include "fs/vfs.h".
 */

/* Remove the resolved ctx path as a regular file (non-recursive). Write-gated
 * (requires a writable endpoint — EROFS otherwise) and a non-NULL root_canon;
 * metered as OP_DELETE. NGX_ERROR with errno set (mapped from the namespace
 * status). */
ngx_int_t brix_vfs_unlink(brix_vfs_ctx_t *ctx);
/* Remove the resolved ctx directory: recursively when `recursive`, otherwise
 * only if empty. Write-gated, confined; metered as OP_DELETE. NGX_ERROR with
 * errno set on failure (e.g. ENOTEMPTY for a non-empty dir when not recursive). */
ngx_int_t brix_vfs_rmdir(brix_vfs_ctx_t *ctx, unsigned recursive);
/* Delete a flat batch of up to BRIX_SD_BULK_DELETE_WINDOW already-confined
 * absolute paths (phase-107 C4, the S3 DeleteObjects entry) under ONE write
 * gate and ONE OP_DELETE observation carrying the key count. errs (caller-
 * allocated, n entries) receives 0 or a positive errno per key — ENOENT stays
 * ENOENT, the caller decides idempotency; every slot is pre-filled with
 * ECANCELED so an untried key never reads as deleted. *done = leading keys
 * actually attempted. NGX_OK = every key attempted (errs may still hold
 * per-key failures); NGX_ERROR = the batch itself failed (EROFS before any
 * key is examined on a read-only endpoint). */
ngx_int_t brix_vfs_delete_many(brix_vfs_ctx_t *ctx, const char *const *paths,
    size_t n, int *errs, size_t *done);
/* Move the resolved ctx (source) path to the already-resolved destination `dst`
 * (borrowed; must be is_confined with a non-empty resolved path). Write-gated;
 * both endpoints confined; metered as OP_RENAME. `overwrite_dirs` removes an
 * existing DIRECTORY destination first (WebDAV MOVE Overwrite:T; rename(2)
 * alone only replaces an empty dir); with it 0 an existing dir dest fails
 * with errno==EEXIST (kXR_mv semantics). NGX_ERROR with errno set. */
ngx_int_t brix_vfs_rename(brix_vfs_ctx_t *ctx,
    const brix_path_result_t *dst, unsigned overwrite_dirs);
/* Thread-safe confined rename of src→dst under root_canon (no pool alloc, no
 * metric — usable off the event loop / pool-less). `overwrite` replaces an
 * existing destination; otherwise an existing dst fails with errno==EEXIST.
 * *was_dir_out (optional) reports whether a conflicting destination was a
 * directory (kXR_mv maps EEXIST + was_dir → kXR_isDirectory vs kXR_ItExists).
 * NGX_OK, or NGX_ERROR with errno set (EEXIST/ENOTEMPTY/EACCES/ENOTDIR/ENOENT
 * from the namespace status). */
ngx_int_t brix_vfs_rename_path(brix_sd_instance_t *sd, ngx_log_t *log,
    const char *root_canon, const char *src, const char *dst,
    unsigned overwrite, int *was_dir_out);
/* Atomically exchange the resolved ctx path with the already-resolved name
 * `other` (phase-107 C6): renameat2(RENAME_EXCHANGE) on posix, one catalogue
 * transaction on pblock, the adapter swap + tape catch-up on frm — with NO
 * instant at which either name is missing. Write-gated as a rename-class
 * mutation; metered as OP_RENAME. errno: EXDEV for a cross-export pair,
 * ENOENT unless both names exist, ENOTSUP where the backend has no primitive
 * (NEVER emulated with two renames). */
ngx_int_t brix_vfs_exchange(brix_vfs_ctx_t *ctx,
    const brix_path_result_t *other);

/* Create the resolved ctx path as a directory with `mode`, creating missing
 * parent components when `parents`. Write-gated, confined; metered as OP_MKDIR.
 * NGX_ERROR with errno set (e.g. EEXIST when the target already exists). */
ngx_int_t brix_vfs_mkdir(brix_vfs_ctx_t *ctx, mode_t mode,
    unsigned parents);

/* Change the resolved ctx path's permission bits. Write-gated; impersonation-
 * aware (performed by the broker as the mapped user when impersonation is on, so
 * the file's real owner can chmod even though the worker is not the owner). NGX_OK
 * / NGX_ERROR with errno set. */
ngx_int_t brix_vfs_chmod(brix_vfs_ctx_t *ctx, mode_t mode);

/* Apply kXR_setattr (timestamps and/or owner) to the resolved ctx path through
 * the VFS seam. Write-gated; routes to the backend's setattr slot for a non-POSIX
 * export (no-op success when the backend has no mutable metadata) and to the
 * impersonation-aware confined utimensat/fchownat path for the default POSIX
 * export. NGX_OK / NGX_ERROR with errno set. */
ngx_int_t brix_vfs_setattr(brix_vfs_ctx_t *ctx,
    const brix_sd_setattr_t *attr);

/* ftruncate the open handle to `length` and update the cached fh->size so later
 * reads see the new length. Unmetered. NGX_ERROR with errno set on a bad handle,
 * negative length, or ftruncate failure. */
ngx_int_t brix_vfs_truncate(brix_vfs_file_t *fh, off_t length);
/* Path-based truncate of the resolved ctx path to `length` — write-gated. Uses a
 * backend path-native truncate (remote xroot / stage decorator) when available so
 * a remote resize needs no write-open (no staging self-collision); otherwise falls
 * back to open(O_WRITE)+ftruncate+close. Unmetered (the kXR_truncate handler logs
 * access). NGX_ERROR with errno set on failure (ENOENT for a missing path). */
ngx_int_t brix_vfs_truncate_path(brix_vfs_ctx_t *ctx, off_t length);
/* fsync the open handle to stable storage. Unmetered (the enclosing write op
 * records the metric). NGX_ERROR with errno set on a bad handle or fsync error. */
ngx_int_t brix_vfs_sync(brix_vfs_file_t *fh);

/* Prestage the resolved ctx path from its nearline tier (phase-107 C2, gated
 * MUTATE_STAGE — EROFS first). Descends any cache/stage decorators to the
 * CAP_NEARLINE tier, like brix_vfs_residency. NGX_OK (already online),
 * NGX_AGAIN (recall queued; reqid_out — optional, ≤39 chars + NUL — carries
 * the parking handle, "" when the driver has none), or NGX_ERROR with errno
 * set (ENOTSUP: no nearline tier — fall back to prepare_command). The stage
 * REGISTRY lifecycle (record before driver call, delete on failure) belongs to
 * the reqid-owning protocol caller, not here. */
ngx_int_t brix_vfs_recall(brix_vfs_ctx_t *ctx, char reqid_out[40]);
/* Drop the online copy the TOP of the driver chain holds (phase-107 C2, gated
 * MUTATE_EVICT — EROFS first; top-dispatching, never the descend walk: on a
 * cache-fronted export the cache store's copy is the one being dropped).
 * Idempotent: NGX_OK even when already absent, *bytes_out (optional) = bytes
 * reclaimed (0 when unknown). NGX_ERROR with errno set (ENOTSUP when the top
 * driver has no evict slot — its online copy is the only copy). */
ngx_int_t brix_vfs_evict(brix_vfs_ctx_t *ctx, uint64_t *bytes_out);

#endif /* BRIX_VFS_MUTATE_H */
