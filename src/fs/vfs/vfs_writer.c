/*
 * vfs_writer.c — unified verified write session across every storage backend.
 *
 * WHAT: brix_vfs_writer_open/write/commit/abort — one write entry point a
 *       protocol path (GridFTP STOR) uses regardless of backend, with an
 *       optional self-computed read-back integrity check folded in.
 * WHY:  The write mechanics differ per backend — a random-write backend (the
 *       POSIX default export, pblock) is patched in place through an O_WRITE
 *       handle, while an object store (S3) has no seekable file and must be
 *       written as an atomic staged upload — and the verify-on-write logic
 *       (accumulate a CRC, re-read the persisted object, compare) was hand-rolled
 *       in the STOR path. Folding both behind one session gives every filesystem
 *       the same verified-write call and lets a single caller serve S3 too.
 * HOW:  writer_open resolves the backend's CAP_RANDOM_WRITE bit from ctx->sd
 *       (NULL ⇒ the POSIX default export ⇒ random-write): a random backend opens
 *       an in-place handle, an object backend opens a staged upload. Each write is
 *       routed through the driver (brix_vfs_file_pwrite / brix_vfs_staged_write)
 *       and, when verifying, folded into a brix_wverify accumulator. commit closes
 *       or atomically publishes, then — when verifying a non-empty object — drives
 *       brix_vfs_wverify_check over a fresh read-only handle and unlinks on any
 *       mismatch. No goto; early-return per coding-standards.
 */
#include "vfs_writer_internal.h"       /* session struct + spill (phase-107 C1) */
#include "core/compat/copy_range.h"   /* brix_copy_range — zero-copy fd ingest */

/* Does the backend behind `ctx` accept an in-place random-offset write? The
 * POSIX default export has no resolved sd instance (ctx->sd == NULL) and is
 * always random-write; any other backend must advertise CAP_RANDOM_WRITE. */
static int
writer_random_backend(const brix_vfs_ctx_t *ctx)
{
    if (ctx->sd == NULL) {
        return 1;
    }
    return (brix_sd_caps(ctx->sd) & BRIX_SD_CAP_RANDOM_WRITE) != 0;
}

/* Release the descriptor/temp a partially-constructed writer holds without
 * publishing anything (used on an open-time failure and by writer_abort). The
 * random path leaves any created object in place — a mid-STOR failure is
 * REST-resumable — while the staged path drops its unpublished temp. */
static void
writer_release(brix_vfs_writer_t *w)
{
    if (w->fh != NULL) {
        brix_vfs_close(w->fh, w->log);
        w->fh = NULL;
    }
    if (w->st != NULL) {
        brix_vfs_staged_abort(w->st, 1 /* remove temp */);
        w->st = NULL;
    }
    brix_vfs_writer_spill_discard(w);   /* unlink any spill scratch (C1 T3) */
    if (w->wv != NULL) {
        brix_wverify_free(w->wv);
        w->wv = NULL;
    }
}

/*
 * WHAT: Store a writer-open failure in the caller's optional errno output.
 * WHY:  Optional diagnostics should not add branches to each construction step.
 * HOW:  Assign the supplied error only when output storage is present.
 */
static void
writer_set_error(int *err_out, int err)
{
    if (err_out != NULL)
        *err_out = err;
}

brix_vfs_writer_t *
brix_vfs_writer_open(brix_vfs_ctx_t *ctx, unsigned flags, int verify,
    int *err_out)
{
    brix_vfs_writer_t *w;
    int                verr = 0;

    writer_set_error(err_out, 0);
    if (ctx == NULL) {
        writer_set_error(err_out, EINVAL);
        return NULL;
    }

    w = ngx_pcalloc(ctx->pool, sizeof(*w));
    if (w == NULL) {
        writer_set_error(err_out, ENOMEM);
        return NULL;
    }
    /* Self-contain a deep copy of ctx: a write session outlives the request that
     * opened it (the caller's cred ctx can be a stack frame), and commit re-derives
     * from w->ctx for the verify read-back + unlink-on-mismatch. */
    w->ctx = brix_vfs_ctx_pool_clone(ctx, ctx->pool);
    if (w->ctx == NULL) {
        writer_set_error(err_out, ENOMEM);
        return NULL;
    }
    w->pool            = ctx->pool;
    w->log             = ctx->log;
    w->verify          = verify ? 1 : 0;
    w->mutation_policy = ctx->mutation_policy;
    w->spill.fd        = NGX_INVALID_FILE;   /* pcalloc's 0 is a real fd */
    /* O_ATOMIC forces the staged temp+publish path even for a random-write backend
     * so a failed write leaves no partial at the final path (WebDAV/S3 PUT). */
    w->mode = ((flags & BRIX_VFS_O_ATOMIC) == 0 && writer_random_backend(w->ctx))
            ? BRIX_VFS_WRITER_RANDOM
            : BRIX_VFS_WRITER_SEQUENTIAL;

    if (w->mode == BRIX_VFS_WRITER_RANDOM) {
        unsigned oflags = BRIX_VFS_O_WRITE | BRIX_VFS_O_CREATE
                        | (flags & BRIX_VFS_O_TRUNC);
        w->fh = brix_vfs_open(w->ctx, oflags, &verr);
        if (w->fh == NULL) {
            writer_set_error(err_out, verr ? verr : EIO);
            return NULL;
        }
    } else {
        w->st = brix_vfs_staged_open(w->ctx, NGX_FILE_DEFAULT_ACCESS,
                                     16 /* excl-name attempts */, &verr);
        if (w->st == NULL) {
            writer_set_error(err_out, verr ? verr : EIO);
            return NULL;
        }
        /* BRIX_VFS_WRITER_O_UNORDERED (phase-107 C1): the caller declares the
         * extents may arrive out of order, so provision the spill now rather
         * than on the first violation. The MUTATE_OPEN gate has already fired
         * inside brix_vfs_staged_open, so a read-only endpoint never reaches
         * this line — the scratch is created strictly AFTER the gate. Failure
         * to provision is not fatal at open: a strictly in-order stream still
         * succeeds, and a real reorder re-attempts (and then errors). */
        if (flags & BRIX_VFS_WRITER_O_UNORDERED) {
            (void) brix_vfs_writer_spill_enter(w, 0, 0);
        }
    }

    if (w->verify) {
        w->wv = brix_wverify_begin();
        if (w->wv == NULL) {
            writer_release(w);
            writer_set_error(err_out, ENOMEM);
            return NULL;
        }
    }
    return w;
}

/* Push one extent onto the chosen backend path (no verify bookkeeping). */
static ngx_int_t
writer_put(brix_vfs_writer_t *w, const void *buf, size_t len, off_t off)
{
    switch (w->mode) {

    case BRIX_VFS_WRITER_RANDOM: {
        const u_char *p    = buf;
        size_t        left = len;

        while (left > 0) {
            ssize_t n = brix_vfs_file_pwrite(w->fh, p, left, off);
            if (n <= 0) {
                return NGX_ERROR;
            }
            p    += n;
            left -= (size_t) n;
            off  += n;
        }
        return NGX_OK;
    }

    case BRIX_VFS_WRITER_SPILL:
        return brix_vfs_writer_spill_put(w, buf, len, off);

    case BRIX_VFS_WRITER_FAILED:
        errno = ENOSPC;             /* scratch was exhausted; nothing recovers */
        return NGX_ERROR;

    case BRIX_VFS_WRITER_SEQUENTIAL:
        break;
    }

    /* Staged / object store: the upload is built sequentially into the
     * temp/upload, so a reordered extent cannot be patched in place. Phase-107
     * C1 replaced the old EINVAL refusal here with the one-way T1 promotion
     * into spill mode; a rewind below the already-staged prefix (or a missing
     * spill root) is still refused inside spill_enter. */
    if (off != w->staged_cursor) {
        if (brix_vfs_writer_spill_enter(w, off, len) != NGX_OK) {
            return NGX_ERROR;
        }
        return brix_vfs_writer_spill_put(w, buf, len, off);
    }
    if (brix_vfs_staged_write(w->st, buf, len, off) != NGX_OK) {
        return NGX_ERROR;
    }
    w->staged_cursor += (off_t) len;
    return NGX_OK;
}

ngx_int_t
brix_vfs_writer_write(brix_vfs_writer_t *w, const void *buf, size_t len,
    off_t off)
{
    if (w == NULL || w->finished || buf == NULL || off < 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (len == 0) {
        return NGX_OK;
    }
    if (brix_vfs_require_carried_mutation(w->mutation_policy,
            brix_vfs_metrics_proto(w->ctx), BRIX_VFS_MUTATE_WRITE) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (writer_put(w, buf, len, off) != NGX_OK) {
        return NGX_ERROR;
    }
    if (w->wv != NULL && brix_wverify_update(w->wv, buf, off, len) != 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    w->written += (off_t) len;
    return NGX_OK;
}

/* Read the source fd in 64 KiB chunks and push each through the normal write
 * engine, which dispatches random/staged and folds the verify CRC. Used whenever
 * the bytes must pass through userspace: verify is on, the destination is a
 * staged/object upload, or the random backend has no single seekable fd (pblock). */
static ngx_int_t
writer_ingest_bounce(brix_vfs_writer_t *w, int src_fd, off_t src_off, size_t len,
    off_t dst_off)
{
    off_t  s    = src_off;
    off_t  d    = dst_off;
    size_t left = len;

    while (left > 0) {
        u_char  chunk[65536];
        size_t  want = left < sizeof(chunk) ? left : sizeof(chunk);
        ssize_t n    = pread(src_fd, chunk, want, s);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NGX_ERROR;
        }
        if (n == 0) {           /* source shorter than the caller promised */
            errno = EIO;
            return NGX_ERROR;
        }
        if (brix_vfs_writer_write(w, chunk, (size_t) n, d) != NGX_OK) {
            return NGX_ERROR;
        }
        s    += n;
        d    += (off_t) n;
        left -= (size_t) n;
    }
    return NGX_OK;
}

ngx_int_t
brix_vfs_writer_write_fd(brix_vfs_writer_t *w, int src_fd, off_t src_off,
    size_t len, off_t dst_off)
{
    if (w == NULL || w->finished || src_fd < 0 || src_off < 0 || dst_off < 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (len == 0) {
        return NGX_OK;
    }
    if (brix_vfs_require_carried_mutation(w->mutation_policy,
            brix_vfs_metrics_proto(w->ctx), BRIX_VFS_MUTATE_WRITE) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Zero-copy fast path: a single-fd, sendfile-capable random backend with no
     * verify obligation can move the bytes kernel-side without a userspace bounce.
     * sendfile_fd() returns NGX_INVALID_FILE for an object/block backend (no single
     * seekable destination), which — like verify and the staged path — falls back
     * to the bounce so block routing / the CRC accumulator are not bypassed. */
    if (w->mode == BRIX_VFS_WRITER_RANDOM && !w->verify) {
        ngx_fd_t dfd = brix_vfs_file_sendfile_fd(w->fh);

        if (dfd != NGX_INVALID_FILE) {
            if (brix_copy_range(w->log, src_fd, src_off, dfd, dst_off,
                                len, NULL, NULL) != NGX_OK) {
                return NGX_ERROR;
            }
            w->written += (off_t) len;
            return NGX_OK;
        }
    }

    return writer_ingest_bounce(w, src_fd, src_off, len, dst_off);
}

off_t
brix_vfs_writer_expected_off(const brix_vfs_writer_t *w)
{
    if (w == NULL) {
        return -1;
    }
    /* Advisory only since phase-107 C1: the writer accepts any offset in RANDOM
     * and SPILL modes and self-promotes SEQUENTIAL -> SPILL on a reorder, so
     * callers must NOT pre-refuse on a mismatch — submit the write and let the
     * writer's errno decide (EINVAL = unservable order, ENOSPC = no scratch). */
    switch (w->mode) {
    case BRIX_VFS_WRITER_SEQUENTIAL:
        return w->staged_cursor;
    case BRIX_VFS_WRITER_SPILL:
        return w->spill.high_water;
    case BRIX_VFS_WRITER_RANDOM:
    case BRIX_VFS_WRITER_FAILED:
        break;
    }
    return w->written;
}

/* Re-open the just-committed object read-only and confirm the driver persisted
 * exactly the CRC-checked bytes. An empty object has no extents to expect and is
 * trivially complete, so it is not read back. */
static ngx_int_t
writer_verify(brix_vfs_writer_t *w)
{
    brix_vfs_file_t *rfh;
    int              verr = 0;
    ngx_int_t        rc;

    if (w->wv == NULL || w->written == 0) {
        return NGX_OK;
    }
    rfh = brix_vfs_open(w->ctx, BRIX_VFS_O_READ, &verr);
    if (rfh == NULL) {
        return NGX_ERROR;
    }
    rc = brix_vfs_wverify_check(w->wv, rfh);
    brix_vfs_close(rfh, w->log);
    return rc;
}

/* Free the read-back verifier state, if armed. */
static void
writer_wv_free(brix_vfs_writer_t *w)
{
    if (w->wv != NULL) {
        brix_wverify_free(w->wv);
        w->wv = NULL;
    }
}

/*
 * WHAT: The staged half of commit: drain a spill, publish the temp onto the
 *       final path, tear the staged session down.
 * WHY:  A staged commit failure must leave nothing published; `pre` rides to
 *       brix_vfs_staged_commit, whose errno (EEXIST/ECANCELED = precondition
 *       refused) must survive the teardown that follows.
 * HOW:  T4 (FAILED) refuses ENOSPC without publishing. T2: a spilled object is
 *       drained sequentially into the staged session first; a coverage hole
 *       refuses (EINVAL). The scratch is unlinked only AFTER the publish
 *       succeeds, so a crash mid-publish leaves the bytes recoverable (C1).
 */
static ngx_int_t
writer_commit_staged(brix_vfs_writer_t *w, brix_sd_precond_t *pre)
{
    ngx_int_t crc;
    int       ce;

    if (w->mode == BRIX_VFS_WRITER_FAILED) {
        /* T4 already aborted the staged session; nothing may publish. */
        writer_release(w);
        errno = ENOSPC;
        return NGX_ERROR;
    }
    if (w->mode == BRIX_VFS_WRITER_SPILL
        && brix_vfs_writer_spill_drain(w) != NGX_OK)
    {
        ce = errno;
        writer_release(w);
        errno = ce;
        return NGX_ERROR;
    }

    crc = brix_vfs_staged_commit(w->st, pre);
    ce  = errno;   /* preserve EEXIST/ECANCELED (precondition refused) */

    brix_vfs_staged_abort(w->st, 0 /* already published/closed */);
    w->st = NULL;
    brix_vfs_writer_spill_discard(w);
    if (crc != NGX_OK) {
        writer_wv_free(w);
        errno = ce;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_vfs_writer_commit_pre(brix_vfs_writer_t *w, brix_sd_precond_t *pre)
{
    if (w == NULL || w->finished) {
        return NGX_ERROR;
    }
    /* MUTATE_PUBLISH: commit is where the object becomes visible under its final
     * name — a distinct event from the body writes above, and reported as one
     * (see the same reasoning in brix_vfs_staged_commit). */
    if (brix_vfs_require_carried_mutation(w->mutation_policy,
            brix_vfs_metrics_proto(w->ctx), BRIX_VFS_MUTATE_PUBLISH) != NGX_OK)
    {
        return NGX_ERROR;
    }
    /* The in-place path cannot evaluate a publish precondition: the bytes
     * already landed on the final object when they were written. NONE and
     * ABSENT are legitimately settled earlier (ABSENT was the open's O_EXCL);
     * a MATCH_* here would be a silent pass, so it refuses (§3.5 — a refusal
     * over an emulation that lies). After the policy gate, so a read-only
     * endpoint still answers EROFS, never ENOTSUP. */
    if (w->mode == BRIX_VFS_WRITER_RANDOM
        && pre != NULL && pre->kind != BRIX_SD_PRECOND_NONE
        && pre->kind != BRIX_SD_PRECOND_ABSENT)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    w->finished = 1;

    /* Persist: fsync + close the in-place handle, or atomically publish the temp
     * onto the final path. A staged commit failure leaves nothing published.
     * `excl` uses RENAME_NOREPLACE on the staged path (S3 If-None-Match → EEXIST);
     * it is meaningless for the in-place random path (no separate publish). */
    if (w->mode == BRIX_VFS_WRITER_RANDOM) {
        (void) brix_vfs_sync(w->fh);
        brix_vfs_close(w->fh, w->log);
        w->fh = NULL;
    } else if (writer_commit_staged(w, pre) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Read-back integrity check; a mismatch must never leave a corrupt object. */
    if (writer_verify(w) != NGX_OK) {
        (void) brix_vfs_unlink(w->ctx);
        writer_wv_free(w);
        return NGX_ERROR;
    }
    writer_wv_free(w);
    return NGX_OK;
}

ngx_int_t
brix_vfs_writer_commit_ex(brix_vfs_writer_t *w, unsigned excl)
{
    brix_sd_precond_t pre = { .kind = BRIX_SD_PRECOND_ABSENT };

    return brix_vfs_writer_commit_pre(w, excl ? &pre : NULL);
}

ngx_int_t
brix_vfs_writer_commit(brix_vfs_writer_t *w)
{
    return brix_vfs_writer_commit_pre(w, NULL /* replace */);
}

void
brix_vfs_writer_abort(brix_vfs_writer_t *w)
{
    if (w == NULL || w->finished) {
        return;
    }
    w->finished = 1;
    writer_release(w);
}

ngx_fd_t
brix_vfs_writer_fd(const brix_vfs_writer_t *w)
{
    if (w == NULL) {
        return NGX_INVALID_FILE;
    }
    /* The random path patches the final file in place through its handle fd; the
     * staged path exposes the temp fd (NGX_INVALID_FILE for a driver-backed object
     * with no kernel fd — those bodies must go through brix_vfs_writer_write). */
    if (w->mode == BRIX_VFS_WRITER_RANDOM) {
        return brix_vfs_file_fd(w->fh);
    }
    /* Never the spill scratch: a raw write there would bypass the coverage set
     * and the byte accounting. Raw-fd consumers stream strictly in order, so a
     * writer they drive never leaves SEQUENTIAL. */
    if (w->mode != BRIX_VFS_WRITER_SEQUENTIAL) {
        return NGX_INVALID_FILE;
    }
    return brix_vfs_staged_fd(w->st);
}

brix_vfs_staged_t *
brix_vfs_writer_staged(const brix_vfs_writer_t *w)
{
    return (w != NULL && w->mode == BRIX_VFS_WRITER_SEQUENTIAL) ? w->st : NULL;
}
