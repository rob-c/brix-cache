/*
 * vfs_staged.c — VFS atomic staged-write lifecycle (open temp → commit/abort).
 *
 * WHAT: Implements the brix_vfs_staged_* family — a thin VFS-owned wrapper
 *       over the compat staged-file primitive used by every crash-safe upload
 *       (S3 PutObject, WebDAV PUT, multipart assembly): create a unique O_EXCL
 *       temp inside the export root, let the caller write the staged fd, then
 *       atomically publish it onto the final (resolved ctx) path, or abort.
 *
 * WHY:  The upload paths called brix_staged_open/commit/abort directly, so the
 *       publish of a finished object — a real namespace mutation — produced no
 *       metric or access-log line. Funnelling the lifecycle through here books
 *       one BRIX_METRIC_OP_WRITE on commit (byte count = the committed object
 *       size) and inherits the write gate, while still delegating the temp-file
 *       and rename mechanics to compat/staged_file.
 *
 * HOW:  brix_vfs_staged_open() write-gates, allocates the handle on ctx->pool,
 *       and opens the temp via brix_staged_open() with the final path taken
 *       from the resolved ctx. Callers write through the raw fd accessor
 *       (brix_vfs_staged_fd) — the same fd they used before. commit publishes
 *       onto the ctx path (RENAME_NOREPLACE when excl) and meters OP_WRITE;
 *       abort closes and optionally unlinks the temp. The handle struct lives in
 *       vfs_internal.h; only the opaque type is exposed in vfs.h.
 */
#include "vfs_internal.h"

#include "core/compat/staged_file.h"
#include "fs/xfer/xfer.h"   /* unified transfer audit ledger (one line per publish) */

#include <unistd.h>      /* pread for the write-back promote read loop */

/* Duplicate a C string onto `pool` (NUL-terminated). Returns NULL on a NULL input
 * (with *lenp = 0) or on allocation failure — the caller distinguishes the two by
 * checking the input. Used to make a staged handle's ctx self-contained. */
static char *
staged_pool_strdup(ngx_pool_t *pool, const char *s, size_t *lenp)
{
    size_t  n;
    u_char *p;

    if (s == NULL) {
        if (lenp != NULL) {
            *lenp = 0;
        }
        return NULL;
    }
    n = ngx_strlen(s);
    p = ngx_pnalloc(pool, n + 1);
    if (p == NULL) {
        return NULL;
    }
    ngx_memcpy(p, s, n);
    p[n] = '\0';
    if (lenp != NULL) {
        *lenp = n;
    }
    return (char *) p;
}

/* Open a staged temp file for the resolved ctx (final) path. Write-gated.
 * `mode` is the final object's permission bits; `attempts` bounds the O_EXCL
 * unique-name retries. Returns a handle on ctx->pool, or NULL with the errno in
 * *err_out (if non-NULL). Release via brix_vfs_staged_commit/abort. */
brix_vfs_staged_t *
brix_vfs_staged_open(brix_vfs_ctx_t *ctx, mode_t mode, ngx_uint_t attempts,
    int *err_out)
{
    brix_vfs_staged_t *st;
    const char          *final_path = brix_vfs_ctx_path(ctx);

    if (brix_vfs_require_write(ctx) != NGX_OK) {
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

    /*
     * Self-contain the ctx. The staged handle outlives the caller's stack frame:
     * S3 and WebDAV PUT dispatch the body write to a thread pool and RETURN before
     * brix_vfs_staged_commit runs, so a ctx — and the resolved-path / root_canon
     * buffers it POINTS at (WebDAV's resolved path lives in a stack `char[]`) —
     * that was stack-allocated by the caller would be a use-after-free at commit.
     * Deep-copy the ctx struct and those two strings onto ctx->pool (the request
     * pool, which lives until the response completes) so the handle is stable
     * across the async hop regardless of how the caller allocated its ctx.
     */
    st->ctx = ngx_palloc(ctx->pool, sizeof(*st->ctx));
    if (st->ctx == NULL) {
        errno = ENOMEM;
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NULL;
    }
    *st->ctx = *ctx;
    {
        size_t      rlen = 0;
        const char *rpath = brix_vfs_ctx_path(ctx);
        char       *rpath_dup = staged_pool_strdup(ctx->pool, rpath, &rlen);
        char       *root_dup  = staged_pool_strdup(ctx->pool, ctx->root_canon, NULL);

        if ((rpath != NULL && rpath_dup == NULL)
            || (ctx->root_canon != NULL && root_dup == NULL))
        {
            errno = ENOMEM;
            if (err_out != NULL) {
                *err_out = errno;
            }
            return NULL;
        }
        if (rpath_dup != NULL) {
            st->ctx->resolved.resolved.data = (u_char *) rpath_dup;
            st->ctx->resolved.resolved.len  = rlen;
        }
        if (root_dup != NULL) {
            st->ctx->root_canon = root_dup;
        }
    }
    st->pool = ctx->pool;
    st->log  = ctx->log;
    st->staged.fd = NGX_INVALID_FILE;

    /* A non-POSIX backend owns the staged lifecycle: delegate straight to the
     * resolved instance's staged_open slot (Mode A). When staging is configured the
     * registry composes the sd_stage write-back DECORATOR (C-2/C-6) as that instance
     * — so a local-temp-then-promote upload is the decorator's staged_open, NOT a
     * second copy here. A bare source streams the body to the remote final path. */
    if (ctx->sd != NULL && ctx->sd->driver != brix_sd_default_driver()
        && ctx->sd->driver->staged_open != NULL)
    {
        int sderr = 0;

        st->driver_staged = ctx->sd->driver->staged_open(ctx->sd,
            brix_vfs_export_relative(ctx, final_path), mode, &sderr);
        if (st->driver_staged == NULL) {
            if (err_out != NULL) {
                *err_out = sderr;
            }
            errno = sderr;
            return NULL;
        }
        return st;
    }

    /* Pure-POSIX export: the local confined temp IS the storage. */
    if (brix_staged_open(ctx->log, ctx->root_canon, final_path, O_WRONLY,
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
brix_vfs_staged_fd(const brix_vfs_staged_t *st)
{
    if (st == NULL || st->driver_staged != NULL) {
        return NGX_INVALID_FILE;   /* driver-backed: no kernel fd */
    }
    return st->staged.fd;
}

ngx_uint_t
brix_vfs_staged_is_driver(const brix_vfs_staged_t *st)
{
    return (st != NULL && st->driver_staged != NULL) ? 1 : 0;
}

/* Backend-neutral staged write: POSIX → pwrite the temp fd; driver-backed →
 * driver->staged_write (tracking the high-water mark for the commit metric). */
ngx_int_t
brix_vfs_staged_write(brix_vfs_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    if (st == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (st->driver_staged != NULL) {
        ssize_t n = st->ctx->sd->driver->staged_write(st->driver_staged, buf,
                                                      len, off);
        if (n < 0 || (size_t) n != len) {
            if (n >= 0) {
                errno = EIO;
            }
            return NGX_ERROR;
        }
        if (off + (off_t) len > st->driver_total) {
            st->driver_total = off + (off_t) len;
        }
        return NGX_OK;
    }

    return brix_vfs_pwrite_full(st->staged.fd, buf, len, off);
}

/* The staged temp path (for callers that must name it, e.g. a sidecar). Returns
 * "" (never NULL) for a NULL handle. */
const char *
brix_vfs_staged_tmp_path(const brix_vfs_staged_t *st)
{
    return (st != NULL) ? st->staged.tmp_path : "";
}


/* Atomically publish the staged temp onto the resolved ctx (final) path. When
 * `excl`, uses RENAME_NOREPLACE and fails with errno==EEXIST if the final path
 * already exists (caller maps to 412). Metered as OP_WRITE with the committed
 * object size. Returns NGX_OK or NGX_ERROR with errno set. */
ngx_int_t
brix_vfs_staged_commit(brix_vfs_staged_t *st, unsigned excl)
{
    const char *final_path;
    uint64_t    start = brix_vfs_now_ns();
    size_t      bytes = 0;
    struct stat sb;
    ngx_int_t   rc;
    int         saved_errno;

    if (st == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    final_path = brix_vfs_ctx_path(st->ctx);

    /* Driver-backed: the driver publishes the object atomically. On success it
     * consumes its staged handle (NULL it out so abort is not double-applied);
     * on failure the handle stays valid for the caller's abort. The byte count
     * is the high-water mark tracked across staged writes. */
    if (st->driver_staged != NULL) {
        rc = st->ctx->sd->driver->staged_commit(st->driver_staged, excl);
        if (rc != NGX_OK) {
            saved_errno = errno;
            brix_vfs_observe_ctx_op(st->ctx, final_path,
                                      BRIX_METRIC_OP_WRITE, NULL, 0, NGX_ERROR,
                                      saved_errno, start);
            brix_xfer_finish(BRIX_XFER_STAGE, "in", final_path, NULL, 0,
                               BRIX_XFER_COMMIT_ERR, saved_errno, st->log);
            errno = saved_errno;
            return NGX_ERROR;
        }
        bytes = (size_t) st->driver_total;
        st->driver_staged = NULL;   /* consumed by a successful commit */
        brix_vfs_observe_ctx_op(st->ctx, final_path, BRIX_METRIC_OP_WRITE,
                                  NULL, bytes, NGX_OK, 0, start);
        brix_xfer_finish(BRIX_XFER_STAGE, "in", final_path, NULL, bytes,
                           BRIX_XFER_OK, 0, st->log);
        return NGX_OK;
    }

    rc = excl
         ? brix_staged_commit_excl(st->log, st->ctx->root_canon, &st->staged,
                                     final_path)
         : brix_staged_commit(st->log, st->ctx->root_canon, &st->staged,
                                final_path);
    if (rc != NGX_OK) {
        saved_errno = errno;
        brix_vfs_observe_ctx_op(st->ctx, final_path, BRIX_METRIC_OP_WRITE,
                                  NULL, 0, NGX_ERROR, saved_errno, start);
        brix_xfer_finish(BRIX_XFER_STAGE, "in", final_path, NULL, 0,
                           BRIX_XFER_COMMIT_ERR, saved_errno, st->log);
        errno = saved_errno;
        return NGX_ERROR;
    }

    if (brix_lstat_confined_canon(st->log, st->ctx->root_canon, final_path,
                                    &sb, 1) == 0
        && S_ISREG(sb.st_mode))
    {
        bytes = (size_t) sb.st_size;
    }

    brix_vfs_observe_ctx_op(st->ctx, final_path, BRIX_METRIC_OP_WRITE, NULL,
                              bytes, NGX_OK, 0, start);
    /* The publication record — the single place this committed object is
     * accounted for across all transfer kinds. */
    brix_xfer_finish(BRIX_XFER_STAGE, "in", final_path, NULL, bytes,
                       BRIX_XFER_OK, 0, st->log);
    return NGX_OK;
}

/* Close the staged temp and, when `remove_tmp`, unlink it (the failure/cleanup
 * path). Idempotent; safe on a NULL handle. */
void
brix_vfs_staged_abort(brix_vfs_staged_t *st, unsigned remove_tmp)
{
    if (st == NULL) {
        return;
    }

    brix_staged_abort(st->log, st->ctx->root_canon, &st->staged,
                        remove_tmp ? 1 : 0);
}
