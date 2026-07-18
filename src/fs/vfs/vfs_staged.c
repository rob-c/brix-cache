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

/*
 * Set *err_out (when non-NULL) to the current errno and return NULL. Single
 * exit convention for brix_vfs_staged_open's failure arms.
 *
 * WHAT: fold "publish errno + return NULL" into one call.
 * WHY:  every failure arm of the open path shares this shape; a helper keeps
 *       each arm to one early-return line and removes repeated branches.
 * HOW:  copies errno into *err_out if the caller supplied one, returns NULL.
 */
static brix_vfs_staged_t *
staged_open_fail(int *err_out)
{
    if (err_out != NULL) {
        *err_out = errno;
    }
    return NULL;
}

/*
 * Validate the write gate + root_canon and allocate a self-contained handle.
 *
 * WHAT: the entry stage of brix_vfs_staged_open — write-gate, require a
 *       root_canon, allocate the handle and its owned ctx copy, deep-copy the
 *       resolved-path and root_canon strings onto ctx->pool, and seed the
 *       handle's pool/log/fd fields.
 * WHY:  the staged handle outlives the caller's stack frame (S3/WebDAV PUT
 *       dispatch the body write to a thread pool and RETURN before commit), so
 *       a ctx pointing at stack buffers would be a use-after-free at commit;
 *       self-containing here keeps the handle stable across the async hop.
 * HOW:  on any failure sets errno and returns NULL via staged_open_fail so the
 *       caller propagates *err_out; on success returns a handle whose ctx and
 *       both strings live on ctx->pool (the request pool). No behavior change:
 *       identical checks, allocations and copies as the original inline body.
 */
static brix_vfs_staged_t *
staged_alloc_handle(brix_vfs_ctx_t *ctx, int *err_out)
{
    brix_vfs_staged_t *st;

    if (brix_vfs_require_write(ctx) != NGX_OK) {
        return staged_open_fail(err_out);
    }

    if (ctx->root_canon == NULL) {
        errno = EINVAL;
        return staged_open_fail(err_out);
    }

    st = ngx_pcalloc(ctx->pool, sizeof(*st));
    if (st == NULL) {
        errno = ENOMEM;
        return staged_open_fail(err_out);
    }

    /*
     * The staged handle outlives the caller's stack frame (S3/WebDAV PUT dispatch
     * the body write to a thread pool and RETURN before commit), so self-contain a
     * deep copy of the ctx — including the resolved-path / root_canon buffers it
     * points at (WebDAV's resolved path lives in a stack `char[]`) — on ctx->pool,
     * which lives until the response completes.
     */
    st->ctx = brix_vfs_ctx_pool_clone(ctx, ctx->pool);
    if (st->ctx == NULL) {
        return staged_open_fail(err_out);   /* errno set by the clone */
    }

    st->pool      = ctx->pool;
    st->log       = ctx->log;
    st->staged.fd = NGX_INVALID_FILE;
    return st;
}

/*
 * Open the staged temp via a non-POSIX backend driver (Mode A).
 *
 * WHAT: delegate the staged lifecycle to the resolved instance's staged_open
 *       slot, resolving the per-open backend credential first.
 * WHY:  when staging is configured the registry composes the sd_stage
 *       write-back DECORATOR as that instance, so a local-temp-then-promote
 *       upload is the decorator's staged_open, not a second copy here; a bare
 *       source streams the body to the remote final path.
 * HOW:  fetches the backend cred, calls brix_sd_staged_open_maybe_cred, and on
 *       failure sets *err_out + errno. Returns NGX_OK with st->driver_staged
 *       populated, or NGX_ERROR. Behavior-identical to the original inline arm.
 */
static ngx_int_t
staged_open_driver(brix_vfs_ctx_t *ctx, brix_vfs_staged_t *st,
    const char *final_path, mode_t mode, int *err_out)
{
    int              sderr = 0;
    brix_sd_ucred_t  ustore;
    brix_sd_cred_t   ucred;
    int              use_cred = 0;

    ngx_memzero(&ucred, sizeof(ucred));
    if (brix_vfs_backend_cred(ctx, &ustore, &ucred, &use_cred, err_out)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    st->driver_staged = brix_sd_staged_open_maybe_cred(ctx->sd,
        brix_vfs_export_relative(ctx, final_path), mode,
        use_cred ? &ucred : NULL, &sderr);
    /* Secret consumed by the staged-origin session; erase the stack copy
     * (A-4 / T4). */
    brix_sd_ucred_wipe(&ustore);
    if (st->driver_staged == NULL) {
        if (err_out != NULL) {
            *err_out = sderr;
        }
        errno = sderr;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * Open the confined local temp for a pure-POSIX export.
 *
 * WHAT: create the O_EXCL unique temp inside root_canon via brix_staged_open,
 *       storing the resulting staged descriptor on the handle.
 * WHY:  for a pure-POSIX export the local confined temp IS the storage; the
 *       confinement (root_canon) and O_EXCL unique-name retries are preserved
 *       exactly by delegating to brix_staged_open unchanged.
 * HOW:  the caller supplies the fully-built request (root_canon confinement +
 *       O_WRONLY + mode + O_EXCL attempts); this calls brix_staged_open and on
 *       failure sets *err_out to errno. Behavior-identical to the original arm.
 */
static ngx_int_t
staged_open_posix(brix_vfs_ctx_t *ctx, brix_vfs_staged_t *st,
    const brix_staged_open_req_t *oreq, int *err_out)
{
    if (brix_staged_open(ctx->log, oreq, &st->staged) != NGX_OK) {
        if (err_out != NULL) {
            *err_out = errno;
        }
        return NGX_ERROR;
    }
    return NGX_OK;
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
    const char        *final_path = brix_vfs_ctx_path(ctx);

    st = staged_alloc_handle(ctx, err_out);
    if (st == NULL) {
        return NULL;
    }

    /* A non-POSIX backend owns the staged lifecycle: delegate to its staged_open
     * slot (Mode A). Otherwise the pure-POSIX confined temp IS the storage. */
    if (ctx->sd != NULL && ctx->sd->driver != brix_sd_default_driver()
        && ctx->sd->driver->staged_open != NULL)
    {
        if (staged_open_driver(ctx, st, final_path, mode, err_out) != NGX_OK) {
            return NULL;
        }
        return st;
    }

    {
        brix_staged_open_req_t  oreq = {
            .root_canon = ctx->root_canon,
            .final_path = final_path,
            .open_flags = O_WRONLY,
            .mode       = mode,
            .attempts   = attempts,
        };
        if (staged_open_posix(ctx, st, &oreq, err_out) != NGX_OK) {
            return NULL;
        }
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
