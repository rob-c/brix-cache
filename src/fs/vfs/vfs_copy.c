/*
 * vfs_copy.c — VFS single-file copy (server-side COPY / CopyObject).
 *
 * WHAT: Implements brix_vfs_copy() — copy the resolved ctx (source) regular
 *       file to a destination path within the same export root, the data-mover
 *       behind WebDAV COPY and S3 CopyObject.
 *
 * WHY:  The copy engines reached brix_ns_local_copy() (copy_file_range with a
 *       read/write fallback) directly, so the bytes moved were confined but
 *       unmetered. Routing through here books one BRIX_METRIC_OP_COPY metric +
 *       access-log line per copy, with the byte count taken from the resulting
 *       destination size, while still delegating the confined data move to the
 *       namespace layer.
 *
 * HOW:  brix_vfs_copy() write-gates (brix_vfs_require_write — a copy creates
 *       a new object), translates the public brix_vfs_copy_opts_t into an
 *       brix_ns_copy_opts_t, and calls brix_ns_local_copy(ctx->root_canon,
 *       src=ctx path, dst). The namespace status is mapped back to errno and
 *       observed as OP_COPY; bytes are best-effort from a post-copy lstat of the
 *       destination (0 if that stat fails — it never affects the return value).
 */
#include "vfs_internal.h"

/*
 * brix_vfs_copy_fail — book a failed OP_COPY observation and return NGX_ERROR.
 *
 * WHAT: Emit one BRIX_METRIC_OP_COPY error observation (zero bytes) for `src`
 *       with the caller-chosen errno, set errno to that value, and hand back
 *       NGX_ERROR so callers can `return brix_vfs_copy_fail(...)`.
 * WHY:  Every failure exit in brix_vfs_copy repeated the same errno-set +
 *       observe + return triad; centralising it keeps the mapping and the
 *       metric label identical across all error paths.
 * HOW:  Assign errno from `err`, forward it as the observed status errno with
 *       NGX_ERROR, and return NGX_ERROR.
 */
static ngx_int_t
brix_vfs_copy_fail(brix_vfs_ctx_t *ctx, const char *src, int err,
    uint64_t start)
{
    errno = err;
    brix_vfs_observe_ctx_op(ctx, src, BRIX_METRIC_OP_COPY, NULL, 0,
                              NGX_ERROR, err, start);
    return NGX_ERROR;
}

/*
 * brix_vfs_copy_driver — non-POSIX backend server-side copy path.
 *
 * WHAT: Copy the export-relative source `src` to `dst_resolved` through the
 *       driver's server-copy slot, enforcing the overwrite gate via a pre-stat
 *       and forwarding a per-open credential when the credential gate is armed.
 * WHY:  Object/S3-style backends replace bytes in-store, so the confined POSIX
 *       copy_file_range path does not apply; this branch dispatches on the leaf
 *       instance so *_maybe_cred forwarders reach the leaf driver's *_cred
 *       slots (decorators carry only plain relays).
 * HOW:  Re-fetch the leaf driver (non-NULL by the caller's guard), zero the
 *       cred (the gate fills only the active kind), resolve the credential,
 *       reject an existing destination when overwrite is unset, then call the
 *       server_copy slot (ENOTSUP when absent) and book the OP_COPY observation
 *       with the copied byte count.
 */
static ngx_int_t
brix_vfs_copy_driver(brix_vfs_ctx_t *ctx, const char *src,
    const char *dst_resolved, const brix_vfs_copy_opts_t *opts,
    uint64_t start)
{
    const brix_sd_driver_t *drv  = brix_vfs_ctx_driver(ctx);
    const char         *s    = brix_vfs_export_relative(ctx, src);
    const char         *d    = brix_vfs_export_relative(ctx, dst_resolved);
    brix_sd_instance_t *leaf = brix_vfs_ns_leaf(ctx->sd);
    brix_sd_ucred_t     store;
    brix_sd_cred_t      cred;
    brix_sd_stat_t      dst_st;
    off_t               copied = 0;
    ngx_int_t           rc;
    int                 saved_errno;
    int                 use_cred = 0, cred_err = 0;

    /* The sole caller checks the driver before dispatching here, but the
     * accessor legitimately returns NULL for the default POSIX driver — keep
     * the invariant local so a future caller cannot hand us a NULL vtable. */
    if (drv == NULL) {
        return brix_vfs_copy_fail(ctx, src, ENOTSUP, start);
    }

    /* Zero before the gate: it fills only the active credential kind; an
     * unzeroed cred hands a garbage inactive pointer to the driver's
     * cred slot (bearer PASSTHROUGH would leave x509_proxy dangling). */
    ngx_memzero(&cred, sizeof(cred));

    if (brix_vfs_cred_gate_active(ctx)) {
        if (brix_vfs_ns_cred(ctx, &store, &cred, &use_cred, &cred_err)
            != NGX_OK)
        {
            return brix_vfs_copy_fail(ctx, src, cred_err ? cred_err : EACCES,
                                        start);
        }
    }

    if (opts != NULL && !opts->overwrite && drv->stat != NULL
        && brix_sd_stat_maybe_cred(leaf, d, &dst_st,
               use_cred ? &cred : NULL) == NGX_OK)
    {
        brix_sd_ucred_wipe(&store);   /* secret consumed; erase (A-4/T4) */
        return brix_vfs_copy_fail(ctx, src, EEXIST, start);
    }

    rc = (drv->server_copy != NULL)
        ? brix_sd_server_copy_maybe_cred(leaf, s, d, &copied,
               use_cred ? &cred : NULL)
        : (errno = ENOTSUP, NGX_ERROR);
    brix_sd_ucred_wipe(&store);       /* secret consumed by copy; erase (A-4/T4) */
    saved_errno = (rc == NGX_OK) ? 0 : errno;
    brix_vfs_observe_ctx_op(ctx, src, BRIX_METRIC_OP_COPY, NULL,
                              rc == NGX_OK ? (size_t) copied : 0, rc,
                              saved_errno, start);
    return rc;
}

/*
 * brix_vfs_copy_ns_bytes — best-effort destination size for the metric.
 *
 * WHAT: Return the size in bytes of the just-copied regular file at
 *       `dst_resolved`, or 0 when it cannot be confined-stat'd or is not
 *       a regular file.
 * WHY:  The OP_COPY metric byte count is taken from the resulting destination;
 *       a stat failure here must never affect the copy's success return value.
 * HOW:  Confined lstat under root_canon; on success for a regular file, return
 *       st_size, else 0.
 */
static size_t
brix_vfs_copy_ns_bytes(brix_vfs_ctx_t *ctx, const char *dst_resolved)
{
    struct stat sb;

    if (brix_lstat_confined_canon(ctx->log, ctx->root_canon, dst_resolved,
                                    &sb, 1) == 0
        && S_ISREG(sb.st_mode))
    {
        return (size_t) sb.st_size;
    }
    return 0;
}

/*
 * brix_vfs_copy_ns — POSIX namespace copy path (copy_file_range + fallback).
 *
 * WHAT: Translate the public copy opts into brix_ns_copy_opts_t and run the
 *       confined brix_ns_local_copy (copy_file_range with a pread/pwrite
 *       fallback) from `src` to `dst_resolved`, booking OP_COPY on completion.
 * WHY:  This is the default POSIX-backend data mover; it must preserve the
 *       exact namespace status→errno mapping and the best-effort byte count.
 * HOW:  Zero-init and populate ns_opts, call brix_ns_local_copy, map a non-OK
 *       status to errno (sys_errno when set, else the status mapping) via the
 *       shared failure helper, and on success observe with the post-copy size.
 */
static ngx_int_t
brix_vfs_copy_ns(brix_vfs_ctx_t *ctx, const char *src,
    const char *dst_resolved, const brix_vfs_copy_opts_t *opts,
    uint64_t start)
{
    brix_ns_copy_opts_t ns_opts;
    brix_ns_result_t    res;
    size_t              bytes;

    ngx_memzero(&ns_opts, sizeof(ns_opts));
    if (opts != NULL) {
        ns_opts.recursive       = opts->recursive ? 1 : 0;
        ns_opts.overwrite       = opts->overwrite ? 1 : 0;
        ns_opts.overwrite_dirs  = opts->overwrite_dirs ? 1 : 0;
        ns_opts.preserve_xattrs = opts->preserve_xattrs ? 1 : 0;
        ns_opts.staged_commit   = opts->staged_commit ? 1 : 0;
    }

    res = brix_ns_local_copy(ctx->log, ctx->root_canon, src, dst_resolved,
                               &ns_opts);
    if (res.status != BRIX_NS_OK) {
        return brix_vfs_copy_fail(ctx, src,
                   res.sys_errno != 0 ? res.sys_errno
                                      : brix_vfs_ns_status_errno(res.status),
                   start);
    }

    /* Best-effort byte count for the metric; a stat failure here is non-fatal. */
    bytes = brix_vfs_copy_ns_bytes(ctx, dst_resolved);
    brix_vfs_observe_ctx_op(ctx, src, BRIX_METRIC_OP_COPY, NULL, bytes,
                              NGX_OK, 0, start);
    return NGX_OK;
}

/* Copy the resolved ctx source file to dst_resolved (both under ctx->root_canon).
 * Returns NGX_OK, or NGX_ERROR with errno set (mapped from the namespace status:
 * EEXIST when the destination exists and overwrite is unset, EXDEV on a confine-
 * ment escape, EISDIR/ECONFLICT on a directory source). Metered as OP_COPY. */
ngx_int_t
brix_vfs_copy(brix_vfs_ctx_t *ctx, const char *dst_resolved,
    const brix_vfs_copy_opts_t *opts)
{
    const char               *src = brix_vfs_ctx_path(ctx);
    uint64_t                  start = brix_vfs_now_ns();
    const brix_sd_driver_t *drv;

    if (brix_vfs_require_write(ctx) != NGX_OK) {
        return brix_vfs_copy_fail(ctx, src, errno, start);
    }

    if (ctx->root_canon == NULL || dst_resolved == NULL) {
        return brix_vfs_copy_fail(ctx, src, EINVAL, start);
    }

    /* Non-POSIX backend: copy through the driver's server-copy slot. */
    drv = brix_vfs_ctx_driver(ctx);
    if (drv != NULL) {
        return brix_vfs_copy_driver(ctx, src, dst_resolved, opts, start);
    }

    return brix_vfs_copy_ns(ctx, src, dst_resolved, opts, start);
}
