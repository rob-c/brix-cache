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
#include "vfs_internal.h"
#include "core/compat/wverify.h"
#include "core/compat/copy_range.h"   /* brix_copy_range — zero-copy fd ingest */

struct brix_vfs_writer_s {
    brix_vfs_ctx_t    *ctx;            /* pool-owned deep clone (self-contained) */
    ngx_pool_t        *pool;
    ngx_log_t         *log;
    brix_vfs_file_t   *fh;             /* random-write path (else NULL)          */
    brix_vfs_staged_t *st;             /* staged-upload path (else NULL)         */
    brix_wverify_t    *wv;             /* verify accumulator (NULL when !verify) */
    off_t              staged_cursor;  /* next expected offset on the staged path*/
    off_t              written;        /* total bytes written                    */
    unsigned           random:1;       /* 1 = in-place handle, 0 = staged        */
    unsigned           verify:1;
    unsigned           finished:1;     /* commit or abort has run                */
};

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
    if (w->wv != NULL) {
        brix_wverify_free(w->wv);
        w->wv = NULL;
    }
}

brix_vfs_writer_t *
brix_vfs_writer_open(brix_vfs_ctx_t *ctx, unsigned flags, int verify,
    int *err_out)
{
    brix_vfs_writer_t *w;
    int                verr = 0;

    if (err_out != NULL) {
        *err_out = 0;
    }
    if (ctx == NULL) {
        if (err_out != NULL) {
            *err_out = EINVAL;
        }
        return NULL;
    }

    w = ngx_pcalloc(ctx->pool, sizeof(*w));
    if (w == NULL) {
        if (err_out != NULL) {
            *err_out = ENOMEM;
        }
        return NULL;
    }
    /* Self-contain a deep copy of ctx: a write session outlives the request that
     * opened it (the caller's cred ctx can be a stack frame), and commit re-derives
     * from w->ctx for the verify read-back + unlink-on-mismatch. */
    w->ctx = brix_vfs_ctx_pool_clone(ctx, ctx->pool);
    if (w->ctx == NULL) {
        if (err_out != NULL) {
            *err_out = ENOMEM;
        }
        return NULL;
    }
    w->pool   = ctx->pool;
    w->log    = ctx->log;
    w->verify = verify ? 1 : 0;
    /* O_ATOMIC forces the staged temp+publish path even for a random-write backend
     * so a failed write leaves no partial at the final path (WebDAV/S3 PUT). */
    w->random = (flags & BRIX_VFS_O_ATOMIC)
              ? 0
              : (writer_random_backend(w->ctx) ? 1 : 0);

    if (w->random) {
        unsigned oflags = BRIX_VFS_O_WRITE | BRIX_VFS_O_CREATE
                        | (flags & BRIX_VFS_O_TRUNC);
        w->fh = brix_vfs_open(w->ctx, oflags, &verr);
        if (w->fh == NULL) {
            if (err_out != NULL) {
                *err_out = verr ? verr : EIO;
            }
            return NULL;
        }
    } else {
        w->st = brix_vfs_staged_open(w->ctx, NGX_FILE_DEFAULT_ACCESS,
                                     16 /* excl-name attempts */, &verr);
        if (w->st == NULL) {
            if (err_out != NULL) {
                *err_out = verr ? verr : EIO;
            }
            return NULL;
        }
    }

    if (w->verify) {
        w->wv = brix_wverify_begin();
        if (w->wv == NULL) {
            writer_release(w);
            if (err_out != NULL) {
                *err_out = ENOMEM;
            }
            return NULL;
        }
    }
    return w;
}

/* Push one extent onto the chosen backend path (no verify bookkeeping). */
static ngx_int_t
writer_put(brix_vfs_writer_t *w, const void *buf, size_t len, off_t off)
{
    if (w->random) {
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

    /* Staged / object store: no in-place patching — extents must land in order
     * from offset 0 (the object is built sequentially into the temp/upload). */
    if (off != w->staged_cursor) {
        errno = EINVAL;
        return NGX_ERROR;
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

    /* Zero-copy fast path: a single-fd, sendfile-capable random backend with no
     * verify obligation can move the bytes kernel-side without a userspace bounce.
     * sendfile_fd() returns NGX_INVALID_FILE for an object/block backend (no single
     * seekable destination), which — like verify and the staged path — falls back
     * to the bounce so block routing / the CRC accumulator are not bypassed. */
    if (w->random && !w->verify) {
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
    /* Staged/object path: the next byte must land at the sequential cursor. The
     * random path has no ordering constraint; report the high-water byte count. */
    return w->random ? w->written : w->staged_cursor;
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

ngx_int_t
brix_vfs_writer_commit_ex(brix_vfs_writer_t *w, unsigned excl)
{
    if (w == NULL || w->finished) {
        return NGX_ERROR;
    }
    w->finished = 1;

    /* Persist: fsync + close the in-place handle, or atomically publish the temp
     * onto the final path. A staged commit failure leaves nothing published.
     * `excl` uses RENAME_NOREPLACE on the staged path (S3 If-None-Match → EEXIST);
     * it is meaningless for the in-place random path (no separate publish). */
    if (w->random) {
        (void) brix_vfs_sync(w->fh);
        brix_vfs_close(w->fh, w->log);
        w->fh = NULL;
    } else {
        ngx_int_t crc = brix_vfs_staged_commit(w->st, excl);
        int       ce  = errno;   /* preserve EEXIST (excl create lost the race) */

        brix_vfs_staged_abort(w->st, 0 /* already published/closed */);
        w->st = NULL;
        if (crc != NGX_OK) {
            if (w->wv != NULL) {
                brix_wverify_free(w->wv);
                w->wv = NULL;
            }
            errno = ce;
            return NGX_ERROR;
        }
    }

    /* Read-back integrity check; a mismatch must never leave a corrupt object. */
    if (writer_verify(w) != NGX_OK) {
        (void) brix_vfs_unlink(w->ctx);
        if (w->wv != NULL) {
            brix_wverify_free(w->wv);
            w->wv = NULL;
        }
        return NGX_ERROR;
    }
    if (w->wv != NULL) {
        brix_wverify_free(w->wv);
        w->wv = NULL;
    }
    return NGX_OK;
}

ngx_int_t
brix_vfs_writer_commit(brix_vfs_writer_t *w)
{
    return brix_vfs_writer_commit_ex(w, 0 /* replace */);
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
    if (w->random) {
        return brix_vfs_file_fd(w->fh);
    }
    return brix_vfs_staged_fd(w->st);
}

brix_vfs_staged_t *
brix_vfs_writer_staged(const brix_vfs_writer_t *w)
{
    return (w != NULL && !w->random) ? w->st : NULL;
}
