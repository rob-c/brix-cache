/*
 * vfs_writer_spill.c — SPILL mode of the unified write session (phase-107 C1).
 *
 * WHAT: brix_vfs_writer_spill_{enter,put,drain,discard} — a local reorder
 *       buffer that lets a staged-only backend (http, remote: the two of the
 *       twelve drivers with no CAP_RANDOM_WRITE) accept out-of-order extents:
 *       absorb any offset into a sparse POSIX temp under the configured spill
 *       root, then at commit drain it sequentially into the driver's staged
 *       upload.
 * WHY:  GridFTP mode E and XRootD clients reorder legitimately; before
 *       phase-107 three independent refusals (the writer's EINVAL, sd_http's
 *       ESPIPE, sd_s3's sequential checks) failed every reordered upload on
 *       exactly the two drivers most likely to sit under a WAN-facing export.
 *       Buffering ONCE in the VFS — not once per driver — is the honest
 *       version, and capacity is answered with ENOSPC at the earliest moment
 *       rather than with a slow path or a truncated object.
 * HOW:  One temp (named by brix_make_tmp_path, so the owned-temp reaper
 *       recognises an orphan) whose file offsets are object offsets minus
 *       spill.base — the already-staged prefix [0, base) stays in the driver
 *       session and the drain appends behind it. Coverage is tracked as a
 *       sorted, coalesced extent set: overlap is refused at the write (it
 *       would also poison the verify CRC) and a hole is refused at the drain,
 *       never zero-filled — the filesystem zero-fills sub-block holes
 *       silently, so SEEK_HOLE could not see them. No goto; early-return.
 */
#include "vfs_writer_internal.h"
#include "vfs_backend_registry.h"
#include "core/compat/tmp_path.h"

#define BRIX_VFS_SPILL_EXT_INIT   64
#define BRIX_VFS_SPILL_EXT_MAX  8192   /* matches the GridFTP EB range ceiling */
#define BRIX_VFS_SPILL_DRAIN_CHUNK  (256 * 1024)

/* T4 — the scratch cannot hold the object: abort the staged session (nothing
 * may be published), drop the scratch, park the session in FAILED, and account
 * the refusal. `err` 0 means "capacity" (ENOSPC). Always NGX_ERROR. */
static ngx_int_t
spill_fail(brix_vfs_writer_t *w, int err, const char *what)
{
    ngx_log_error(NGX_LOG_ERR, w->log, err,
                  "brix: vfs writer: spill failed (%s) — upload refused",
                  what);
    brix_metric_vfs_spill_refused(brix_vfs_metrics_proto(w->ctx));
    brix_vfs_writer_spill_discard(w);
    if (w->st != NULL) {
        brix_vfs_staged_abort(w->st, 1 /* remove temp */);
        w->st = NULL;
    }
    w->mode = BRIX_VFS_WRITER_FAILED;
    errno = err ? err : ENOSPC;
    return NGX_ERROR;
}

/* Binary search: index of the first entry with .start > start (== the
 * insertion slot that keeps the set sorted). */
static ngx_uint_t
spill_ext_slot(const brix_vfs_spill_t *sp, off_t start)
{
    ngx_uint_t lo = 0, hi = sp->n_ext;

    while (lo < hi) {
        ngx_uint_t mid = lo + (hi - lo) / 2;

        if (sp->ext[mid].start <= start) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

/* Double the coverage-set capacity (pool realloc — the pool frees the old
 * block with the request). NGX_OK, or NGX_ERROR with errno = ENOSPC at the
 * BRIX_VFS_SPILL_EXT_MAX ceiling, ENOMEM on allocation failure. */
static ngx_int_t
spill_ext_grow(brix_vfs_writer_t *w, brix_vfs_spill_t *sp)
{
    brix_vfs_spill_ext_t *grown;
    ngx_uint_t            ncap = sp->ext_cap ? sp->ext_cap * 2
                                             : BRIX_VFS_SPILL_EXT_INIT;

    if (sp->n_ext >= BRIX_VFS_SPILL_EXT_MAX) {
        errno = ENOSPC;
        return NGX_ERROR;
    }
    grown = ngx_palloc(w->pool, ncap * sizeof(sp->ext[0]));
    if (grown == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    if (sp->n_ext > 0) {
        ngx_memcpy(grown, sp->ext, sp->n_ext * sizeof(sp->ext[0]));
    }
    sp->ext     = grown;
    sp->ext_cap = ncap;
    return NGX_OK;
}

/* Record [start, end) in the sorted disjoint coverage set. NGX_OK, or
 * NGX_ERROR with errno = EINVAL on overlap, ENOMEM on allocation failure, and
 * ENOSPC when the set outgrows BRIX_VFS_SPILL_EXT_MAX. Exact-touch neighbours
 * coalesce, so in-order runs inside a reordered stream stay one entry. */
static ngx_int_t
spill_ext_add(brix_vfs_writer_t *w, off_t start, off_t end)
{
    brix_vfs_spill_t *sp = &w->spill;
    ngx_uint_t        pos = spill_ext_slot(sp, start);

    if ((pos > 0 && sp->ext[pos - 1].end > start)
        || (pos < sp->n_ext && end > sp->ext[pos].start))
    {
        errno = EINVAL;            /* overlaps bytes already landed */
        return NGX_ERROR;
    }
    if (pos > 0 && sp->ext[pos - 1].end == start) {
        sp->ext[pos - 1].end = end;
        if (pos < sp->n_ext && sp->ext[pos].start == end) {
            sp->ext[pos - 1].end = sp->ext[pos].end;   /* bridged two runs */
            ngx_memmove(&sp->ext[pos], &sp->ext[pos + 1],
                        (sp->n_ext - pos - 1) * sizeof(sp->ext[0]));
            sp->n_ext--;
        }
        return NGX_OK;
    }
    if (pos < sp->n_ext && sp->ext[pos].start == end) {
        sp->ext[pos].start = start;
        return NGX_OK;
    }

    if (sp->n_ext == sp->ext_cap && spill_ext_grow(w, sp) != NGX_OK) {
        return NGX_ERROR;
    }
    ngx_memmove(&sp->ext[pos + 1], &sp->ext[pos],
                (sp->n_ext - pos) * sizeof(sp->ext[0]));
    sp->ext[pos].start = start;
    sp->ext[pos].end   = end;
    sp->n_ext++;
    return NGX_OK;
}

/* Create the scratch temp under `root` with an exclusive owned-temp name, so
 * a crashed worker's orphan is recognised (and reclaimed) by
 * brix_tmp_reap_all() walking the registered spill root. */
static ngx_int_t
spill_create(brix_vfs_writer_t *w, const char *root)
{
    char  base[PATH_MAX];
    char  path[PATH_MAX];
    int   attempts;

    if ((size_t) snprintf(base, sizeof(base), "%s/spill", root)
        >= sizeof(base))
    {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    for (attempts = 0; attempts < 16; attempts++) {
        int fd;

        if (brix_make_tmp_path(base, path, sizeof(path)) != NGX_OK) {
            errno = ENAMETOOLONG;
            return NGX_ERROR;
        }
        fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600); /* vfs-seam-allow: DOMAIN_STAGE — spill scratch under the service spill root, never export storage */
        if (fd >= 0) {
            size_t plen = ngx_strlen(path);

            w->spill.path = ngx_pnalloc(w->pool, plen + 1);
            if (w->spill.path == NULL) {
                (void) close(fd);   /* vfs-seam-allow: DOMAIN_STAGE — spill scratch teardown */
                (void) unlink(path); /* vfs-seam-allow: DOMAIN_STAGE — spill scratch teardown */
                errno = ENOMEM;
                return NGX_ERROR;
            }
            ngx_memcpy(w->spill.path, path, plen + 1);
            w->spill.fd = fd;
            return NGX_OK;
        }
        if (errno != EEXIST) {
            return NGX_ERROR;
        }
    }
    errno = EEXIST;
    return NGX_ERROR;
}

ngx_int_t
brix_vfs_writer_spill_enter(brix_vfs_writer_t *w, off_t off, size_t len)
{
    const char  *root = NULL;
    off_t        max  = 0;
    int          ce;

    if (off < w->staged_cursor) {
        /* The bytes below the cursor already streamed into the driver's
         * staged session (heap PUT body, multipart part) and cannot be read
         * back or patched — no scratch can serve this write. Stay SEQUENTIAL:
         * an in-order continuation still succeeds. */
        ngx_log_error(NGX_LOG_ERR, w->log, 0,
            "brix: vfs writer: write at %O rewinds below the %O bytes "
            "already staged — a whole-object upload cannot be patched",
            off, w->staged_cursor);
        brix_metric_vfs_spill_refused(brix_vfs_metrics_proto(w->ctx));
        errno = EINVAL;
        return NGX_ERROR;
    }

    (void) brix_vfs_backend_spill(w->ctx->root_canon, &root, &max);
    if (root == NULL || root[0] == '\0') {
        ngx_log_error(NGX_LOG_ERR, w->log, 0,
            "brix: vfs writer: out-of-order write at %O (expected %O) on a "
            "staged-only backend and no spill scratch is configured — set "
            "brix_vfs_spill_path (or brix_stage_dir)",
            off, w->staged_cursor);
        brix_metric_vfs_spill_refused(brix_vfs_metrics_proto(w->ctx));
        errno = ENOSPC;
        return NGX_ERROR;                      /* stays SEQUENTIAL */
    }
    if (max > 0 && off + (off_t) len - w->staged_cursor > max) {
        /* §C1 "ceiling, stated up front": the triggering extent alone already
         * exceeds brix_vfs_spill_max — refuse before creating anything. */
        return spill_fail(w, ENOSPC, "brix_vfs_spill_max exceeded at entry");
    }
    if (spill_create(w, root) != NGX_OK) {
        ce = errno;
        ngx_log_error(NGX_LOG_ERR, w->log, ce,
            "brix: vfs writer: cannot create spill scratch under \"%s\"",
            root);
        brix_metric_vfs_spill_refused(brix_vfs_metrics_proto(w->ctx));
        errno = ENOSPC;    /* capacity answer for the client; ce is logged */
        return NGX_ERROR;                      /* stays SEQUENTIAL */
    }

    w->spill.base       = w->staged_cursor;
    w->spill.high_water = w->staged_cursor;
    w->spill.max        = max;
    w->mode             = BRIX_VFS_WRITER_SPILL;
    brix_metric_vfs_spill_active(1);
    ngx_log_error(NGX_LOG_INFO, w->log, 0,
        "brix: vfs writer: entering spill mode (write at %O, %O bytes "
        "already staged) — scratch \"%s\"",
        off, w->staged_cursor, w->spill.path);
    return NGX_OK;
}

ngx_int_t
brix_vfs_writer_spill_put(brix_vfs_writer_t *w, const void *buf, size_t len,
    off_t off)
{
    off_t  end = off + (off_t) len;

    if (off < w->spill.base) {
        ngx_log_error(NGX_LOG_ERR, w->log, 0,
            "brix: vfs writer: spill write at %O rewinds below the %O bytes "
            "already staged", off, w->spill.base);
        brix_metric_vfs_spill_refused(brix_vfs_metrics_proto(w->ctx));
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (w->spill.max > 0 && end - w->spill.base > w->spill.max) {
        return spill_fail(w, ENOSPC, "brix_vfs_spill_max exceeded");
    }
    if (spill_ext_add(w, off, end) != NGX_OK) {
        if (errno == EINVAL) {
            ngx_log_error(NGX_LOG_ERR, w->log, 0,
                "brix: vfs writer: spill extent [%O,%O) overlaps bytes "
                "already written — refused", off, end);
            brix_metric_vfs_spill_refused(brix_vfs_metrics_proto(w->ctx));
            return NGX_ERROR;                  /* stays SPILL; not capacity */
        }
        return spill_fail(w, errno, "spill extent set exhausted");
    }
    if (brix_vfs_pwrite_full(w->spill.fd, buf, len,
                             off - w->spill.base) != NGX_OK)
    {
        return spill_fail(w, errno, "spill scratch write");
    }
    if (end > w->spill.high_water) {
        w->spill.high_water = end;
    }
    w->spill.written += (off_t) len;
    brix_metric_vfs_spill_bytes(brix_vfs_metrics_proto(w->ctx), len);
    return NGX_OK;
}

ngx_int_t
brix_vfs_writer_spill_drain(brix_vfs_writer_t *w)
{
    off_t    size = w->spill.high_water - w->spill.base;
    off_t    done = 0;
    u_char  *chunk;

    if (size == 0) {
        return NGX_OK;
    }
    if (w->spill.n_ext != 1
        || w->spill.ext[0].start != w->spill.base
        || w->spill.ext[0].end != w->spill.high_water)
    {
        ngx_log_error(NGX_LOG_ERR, w->log, 0,
            "brix: vfs writer: spill covers %O of %O bytes in %ui runs — the "
            "client left holes; refusing to publish bytes it never sent",
            w->spill.written, size, w->spill.n_ext);
        brix_metric_vfs_spill_refused(brix_vfs_metrics_proto(w->ctx));
        errno = EINVAL;
        return NGX_ERROR;
    }

    chunk = ngx_palloc(w->pool, BRIX_VFS_SPILL_DRAIN_CHUNK);
    if (chunk == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    while (done < size) {
        size_t  want = (size - done) < BRIX_VFS_SPILL_DRAIN_CHUNK
                     ? (size_t) (size - done) : BRIX_VFS_SPILL_DRAIN_CHUNK;
        size_t  got  = 0;

        if (brix_vfs_pread_full(w->spill.fd, chunk, want, done, &got) != NGX_OK
            || got != want)
        {
            if (errno == 0) {
                errno = EIO;       /* scratch shorter than its own extents */
            }
            return NGX_ERROR;
        }
        if (brix_vfs_staged_write(w->st, chunk, want,
                                  w->spill.base + done) != NGX_OK)
        {
            return NGX_ERROR;
        }
        done += (off_t) want;
    }
    return NGX_OK;
}

void
brix_vfs_writer_spill_discard(brix_vfs_writer_t *w)
{
    if (w->spill.fd == NGX_INVALID_FILE) {
        return;
    }
    (void) close(w->spill.fd);          /* vfs-seam-allow: DOMAIN_STAGE — spill scratch teardown */
    w->spill.fd = NGX_INVALID_FILE;
    if (w->spill.path != NULL) {
        (void) unlink((const char *) w->spill.path); /* vfs-seam-allow: DOMAIN_STAGE — spill scratch teardown */
        w->spill.path = NULL;
    }
    brix_metric_vfs_spill_active(-1);
}
