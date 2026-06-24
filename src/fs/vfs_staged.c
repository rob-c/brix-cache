/*
 * vfs_staged.c — VFS atomic staged-write lifecycle (open temp → commit/abort).
 *
 * WHAT: Implements the xrootd_vfs_staged_* family — a thin VFS-owned wrapper
 *       over the compat staged-file primitive used by every crash-safe upload
 *       (S3 PutObject, WebDAV PUT, multipart assembly): create a unique O_EXCL
 *       temp inside the export root, let the caller write the staged fd, then
 *       atomically publish it onto the final (resolved ctx) path, or abort.
 *
 * WHY:  The upload paths called xrootd_staged_open/commit/abort directly, so the
 *       publish of a finished object — a real namespace mutation — produced no
 *       metric or access-log line. Funnelling the lifecycle through here books
 *       one XROOTD_METRIC_OP_WRITE on commit (byte count = the committed object
 *       size) and inherits the write gate, while still delegating the temp-file
 *       and rename mechanics to compat/staged_file.
 *
 * HOW:  xrootd_vfs_staged_open() write-gates, allocates the handle on ctx->pool,
 *       and opens the temp via xrootd_staged_open() with the final path taken
 *       from the resolved ctx. Callers write through the raw fd accessor
 *       (xrootd_vfs_staged_fd) — the same fd they used before. commit publishes
 *       onto the ctx path (RENAME_NOREPLACE when excl) and meters OP_WRITE;
 *       abort closes and optionally unlinks the temp. The handle struct lives in
 *       vfs_internal.h; only the opaque type is exposed in vfs.h.
 */
#include "vfs_internal.h"

#include "../compat/staged_file.h"

/* Open a staged temp file for the resolved ctx (final) path. Write-gated.
 * `mode` is the final object's permission bits; `attempts` bounds the O_EXCL
 * unique-name retries. Returns a handle on ctx->pool, or NULL with the errno in
 * *err_out (if non-NULL). Release via xrootd_vfs_staged_commit/abort. */
xrootd_vfs_staged_t *
xrootd_vfs_staged_open(xrootd_vfs_ctx_t *ctx, mode_t mode, ngx_uint_t attempts,
    int *err_out)
{
    xrootd_vfs_staged_t *st;
    const char          *final_path = xrootd_vfs_ctx_path(ctx);

    if (xrootd_vfs_require_write(ctx) != NGX_OK) {
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }

    if (ctx->root_canon == NULL) {
        errno = EINVAL;
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }

    st = ngx_pcalloc(ctx->pool, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }

    st->ctx  = ctx;
    st->pool = ctx->pool;
    st->log  = ctx->log;
    st->staged.fd = NGX_INVALID_FILE;

    if (xrootd_staged_open(ctx->log, ctx->root_canon, final_path, O_WRONLY,
                           mode, attempts, &st->staged) != NGX_OK)
    {
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }

    return st;
}

/* The underlying staged temp fd (write to it directly), or NGX_INVALID_FILE for
 * a NULL/already-finished handle. */
ngx_fd_t
xrootd_vfs_staged_fd(const xrootd_vfs_staged_t *st)
{
    return (st != NULL) ? st->staged.fd : NGX_INVALID_FILE;
}

/* The staged temp path (for callers that must name it, e.g. a sidecar). Returns
 * "" (never NULL) for a NULL handle. */
const char *
xrootd_vfs_staged_tmp_path(const xrootd_vfs_staged_t *st)
{
    return (st != NULL) ? st->staged.tmp_path : "";
}

/* Atomically publish the staged temp onto the resolved ctx (final) path. When
 * `excl`, uses RENAME_NOREPLACE and fails with errno==EEXIST if the final path
 * already exists (caller maps to 412). Metered as OP_WRITE with the committed
 * object size. Returns NGX_OK or NGX_ERROR with errno set. */
ngx_int_t
xrootd_vfs_staged_commit(xrootd_vfs_staged_t *st, unsigned excl)
{
    const char *final_path;
    ngx_msec_t  start = ngx_current_msec;
    size_t      bytes = 0;
    struct stat sb;
    ngx_int_t   rc;
    int         saved_errno;

    if (st == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    final_path = xrootd_vfs_ctx_path(st->ctx);

    rc = excl
         ? xrootd_staged_commit_excl(st->log, st->ctx->root_canon, &st->staged,
                                     final_path)
         : xrootd_staged_commit(st->log, st->ctx->root_canon, &st->staged,
                                final_path);
    if (rc != NGX_OK) {
        saved_errno = errno;
        xrootd_vfs_observe_ctx_op(st->ctx, final_path, XROOTD_METRIC_OP_WRITE,
                                  NULL, 0, NGX_ERROR, saved_errno, start);
        return NGX_ERROR;
    }

    if (xrootd_lstat_confined_canon(st->log, st->ctx->root_canon, final_path,
                                    &sb, 1) == 0
        && S_ISREG(sb.st_mode))
    {
        bytes = (size_t) sb.st_size;
    }

    xrootd_vfs_observe_ctx_op(st->ctx, final_path, XROOTD_METRIC_OP_WRITE, NULL,
                              bytes, NGX_OK, 0, start);
    return NGX_OK;
}

/* Close the staged temp and, when `remove_tmp`, unlink it (the failure/cleanup
 * path). Idempotent; safe on a NULL handle. */
void
xrootd_vfs_staged_abort(xrootd_vfs_staged_t *st, unsigned remove_tmp)
{
    if (st == NULL) {
        return;
    }

    xrootd_staged_abort(st->log, st->ctx->root_canon, &st->staged,
                        remove_tmp ? 1 : 0);
}
