/* client/lib/vfs_posix.c
 *
 * WHAT: POSIX storage backend for xrdc_vfs — the reference implementation.
 *       Handles local file I/O via pread/pwrite on plain fds, with optional
 *       io_uring overlap for read-ahead / write-behind, and atomic temp+rename
 *       commit for safe overwrites.
 * WHY:  copy.c currently hard-codes POSIX fds at the local endpoint.  This
 *       backend encapsulates that in the xrdc_vfs_backend vtable so any caller
 *       using xrdc_vfs_open() transparently gets atomic commits, io_uring,
 *       and the correct caps without touching copy.c.
 * HOW:  open() for READ opens the final path directly; open() for WRITE creates
 *       a sibling temp (make_posix_temp_path + open O_WRONLY|O_CREAT|O_TRUNC
 *       with O_EXCL|O_NOFOLLOW for symlink safety), honouring XRDC_VFS_FORCE
 *       against an existing final path.  An io_uring ring is optionally wrapped
 *       around the fd (AUTO → use if available, ON → require, OFF → plain fd).
 *       pread/pwrite route through the ring when present, else fall back to the
 *       plain POSIX calls.  commit() = fsync + rename(tmp, final).
 *       abort() = unlink(tmp).  close() frees the ring and fd.
 *       Self-registers via xrdc_vfs_posix_backend() on first use.
 *       ngx-free; no goto; functional/modular; one responsibility per function.
 */

#include "vfs.h"
#include "uring.h"
#include "xrdc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- Concrete per-handle struct ----------------------------------------- */

/*
 * vfs_posix_file — concrete file handle for the POSIX backend.
 *
 * WHAT: extends xrdc_vfs_file with the fd, optional ring, and temp/final
 *       paths needed for atomic temp+rename commit.
 * HOW:  base MUST be first (struct alias cast to xrdc_vfs_file *).
 *       final_path is the real destination; tmp_path is the sibling temp
 *       (NULL for READ handles, where commit/abort are no-ops).
 */
typedef struct {
    xrdc_vfs_file  base;          /* MUST be first — aliased by façade */
    int            fd;
    xrdc_disk_ring *ring;         /* NULL when io_uring is OFF or unavailable */
    char          *final_path;    /* heap-allocated final path (READ or WRITE) */
    char          *tmp_path;      /* heap-allocated temp path (WRITE only; NULL for READ) */
} vfs_posix_file;

/* ---- Temp-path helper ---------------------------------------------------- */

/*
 * make_posix_temp_path — allocate a sibling temp path for a WRITE destination.
 *
 * WHAT: returns a heap string "<dst>.xrdvfs-tmp.<pid>", or NULL on OOM/overflow.
 * WHY:  co-locates the temp on the same filesystem as the final so rename() is
 *       guaranteed atomic; the predictable suffix lets the caller open with O_EXCL.
 * HOW:  snprintf into a heap buffer; return NULL on overflow (path too long) or
 *       malloc failure.  Caller must free the result.
 */
static char *
make_posix_temp_path(const char *dst)
{
    size_t n = strlen(dst) + 32;   /* room for ".xrdvfs-tmp.<pid>" */
    char  *buf = malloc(n);
    if (buf == NULL) {
        return NULL;
    }
    if ((size_t) snprintf(buf, n, "%s.xrdvfs-tmp.%ld", dst, (long) getpid()) >= n) {
        free(buf);
        return NULL;
    }
    return buf;
}

/* ---- Ring selection ------------------------------------------------------- */

/*
 * posix_ring_select — attach an optional io_uring ring to an already-open fd.
 *
 * WHAT: implements the AUTO/ON/OFF tri-state.  OFF → *ring=NULL, return 0.
 *       ON with unavailable io_uring → *ring=NULL, return -1, st set.
 *       AUTO with unavailable io_uring → *ring=NULL, return 0 (silent fallback).
 *       Otherwise attempts xrdc_disk_ring_create; ON failure with ON mode → error.
 * WHY:  mirrors copy.c:local_ring_select so the same semantics apply.
 * HOW:  mode from opts->io_uring; guards xrdc_uring_available(); delegates to
 *       xrdc_disk_ring_create with a modest window (4 ops, 64 KiB each).
 */
static int
posix_ring_select(int fd, int mode, xrdc_disk_ring **ring, xrdc_status *st)
{
    *ring = NULL;

    if (mode == XRDC_IO_URING_OFF) {
        return 0;
    }

    if (!xrdc_uring_available()) {
        if (mode == XRDC_IO_URING_ON) {
            xrdc_status_set(st, XRDC_EUNSUPPORTED, 0,
                            "vfs posix: io_uring=on but io_uring is unavailable "
                            "on this host or this build lacks liburing");
            return -1;
        }
        return 0;   /* AUTO: classic path */
    }

    {
        xrdc_status tmp_st;
        xrdc_status_clear(&tmp_st);
        *ring = xrdc_disk_ring_create(fd, 4, 65536, 0, &tmp_st);
        if (*ring == NULL && mode == XRDC_IO_URING_ON) {
            if (st != NULL) {
                *st = tmp_st;
            }
            return -1;
        }
        /* AUTO: create failure leaves *ring NULL → classic pread/pwrite */
    }
    return 0;
}

/* ---- vtable operations --------------------------------------------------- */

/*
 * posix_pread — read n bytes at offset off into buf.
 *
 * WHAT: delegates to the ring (read-ahead path) when present; falls back to
 *       plain pread(2) otherwise.  Returns bytes read (≥0) or -1 with st set.
 * WHY:  single dispatch point — callers never see the ring vs. plain difference.
 * HOW:  ring path: xrdc_disk_ring_pread; plain path: pread(2) with EINTR retry.
 */
static ssize_t
posix_pread(xrdc_vfs_file *f, int64_t off, void *buf, size_t n, xrdc_status *st)
{
    vfs_posix_file *pf = (vfs_posix_file *) f;

    if (pf->ring != NULL) {
        return xrdc_disk_ring_pread(pf->ring, off, (uint8_t *) buf, n, st);
    }

    {
        ssize_t r;
        do {
            r = pread(pf->fd, buf, n, (off_t) off);
        } while (r < 0 && errno == EINTR);

        if (r < 0) {
            xrdc_status_set(st, XRDC_EIO, errno,
                            "vfs posix pread: %s", strerror(errno));
        }
        return r;
    }
}

/*
 * posix_pwrite — write n bytes from buf at offset off.
 *
 * WHAT: delegates to the ring (write-behind path) when present; falls back to
 *       plain pwrite(2) otherwise.  Returns 0 on success, -1 with st set.
 * WHY:  single dispatch point; ring path avoids blocking disk writes.
 * HOW:  ring path: split into ring-buffer-sized pieces and call
 *       xrdc_disk_ring_pwrite for each (xrdc_disk_ring_pwrite requires n <=
 *       bufsz; the caller may supply a chunk much larger than the ring's
 *       per-op buffer).  Plain path: pwrite(2) retry loop.
 */
static int
posix_pwrite(xrdc_vfs_file *f, int64_t off, const void *buf, size_t n,
             xrdc_status *st)
{
    vfs_posix_file *pf = (vfs_posix_file *) f;

    if (pf->ring != NULL) {
        const uint8_t *p   = (const uint8_t *) buf;
        size_t         rem = n;
        size_t         rsz = xrdc_disk_ring_bufsz(pf->ring);

        while (rem > 0) {
            size_t chunk = rem < rsz ? rem : rsz;
            if (xrdc_disk_ring_pwrite(pf->ring, off, p, chunk, st) != 0) {
                return -1;
            }
            p   += chunk;
            off += (int64_t) chunk;
            rem -= chunk;
        }
        return 0;
    }

    {
        size_t  written = 0;
        ssize_t w;

        while (written < n) {
            w = pwrite(pf->fd, (const char *) buf + written,
                       n - written, (off_t) off + (off_t) written);
            if (w < 0) {
                if (errno == EINTR) {
                    continue;
                }
                xrdc_status_set(st, XRDC_EIO, errno,
                                "vfs posix pwrite: %s", strerror(errno));
                return -1;
            }
            written += (size_t) w;
        }
        return 0;
    }
}

/*
 * posix_fstat — fill *out with size, mtime, is_dir, exists for the open handle.
 *
 * WHAT: calls fstat(2) on pf->fd; maps the struct stat fields to xrdc_vfs_stat.
 * WHY:  avoids a second path stat when the fd is already open (no TOCTOU).
 * HOW:  fstat; populate out; on failure set st and return -1.
 */
static int
posix_fstat(xrdc_vfs_file *f, xrdc_vfs_stat *out, xrdc_status *st)
{
    vfs_posix_file *pf = (vfs_posix_file *) f;
    struct stat     sb;

    if (fstat(pf->fd, &sb) != 0) {
        xrdc_status_set(st, XRDC_EIO, errno,
                        "vfs posix fstat: %s", strerror(errno));
        return -1;
    }

    out->size   = (int64_t) sb.st_size;
    out->mtime  = (int64_t) sb.st_mtime;
    out->is_dir = S_ISDIR(sb.st_mode) ? 1 : 0;
    out->exists = 1;
    return 0;
}

/*
 * posix_truncate — truncate the open file to size bytes.
 *
 * WHAT: calls ftruncate(2) on pf->fd.
 * WHY:  thin POSIX wrapper exposing the cap via the vtable.
 * HOW:  ftruncate; set st on failure.
 */
static int
posix_truncate(xrdc_vfs_file *f, int64_t size, xrdc_status *st)
{
    vfs_posix_file *pf = (vfs_posix_file *) f;

    if (ftruncate(pf->fd, (off_t) size) != 0) {
        xrdc_status_set(st, XRDC_EIO, errno,
                        "vfs posix ftruncate: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * posix_sync — flush dirty pages to durable storage.
 *
 * WHAT: drains any ring write-behind queue, then calls fsync(2) on pf->fd.
 * WHY:  ensures callers can rely on data being durable after sync() returns.
 * HOW:  xrdc_disk_ring_flush (no-op on NULL); fsync; set st on failure.
 */
static int
posix_sync(xrdc_vfs_file *f, xrdc_status *st)
{
    vfs_posix_file *pf = (vfs_posix_file *) f;

    if (pf->ring != NULL) {
        if (xrdc_disk_ring_flush(pf->ring, st) != 0) {
            return -1;
        }
    }

    if (fsync(pf->fd) != 0) {
        xrdc_status_set(st, XRDC_EIO, errno,
                        "vfs posix fsync: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * posix_commit — finalise a WRITE handle: fsync the temp then rename to final.
 *
 * WHAT: drains any ring queue, fsyncs the fd, then atomically renames the sibling
 *       temp to the final path.  For READ handles (no tmp_path) this is a no-op.
 * WHY:  atomic rename guarantees readers never see a partial file at the final path.
 * HOW:  ring flush → fsync → rename; on rename failure unlink the temp and return -1.
 */
static int
posix_commit(xrdc_vfs_file *f, xrdc_status *st)
{
    vfs_posix_file *pf = (vfs_posix_file *) f;

    if (pf->tmp_path == NULL) {
        return 0;   /* READ handle — nothing to commit */
    }

    if (pf->ring != NULL) {
        if (xrdc_disk_ring_flush(pf->ring, st) != 0) {
            return -1;
        }
    }

    if (fsync(pf->fd) != 0) {
        xrdc_status_set(st, XRDC_EIO, errno,
                        "vfs posix commit fsync: %s", strerror(errno));
        return -1;
    }

    if (rename(pf->tmp_path, pf->final_path) != 0) {
        xrdc_status_set(st, XRDC_EIO, errno,
                        "vfs posix commit rename %s -> %s: %s",
                        pf->tmp_path, pf->final_path, strerror(errno));
        unlink(pf->tmp_path);
        return -1;
    }
    return 0;
}

/*
 * posix_abort — discard a partial WRITE by unlinking the sibling temp.
 *
 * WHAT: removes the temp file; no-op for READ handles.
 * WHY:  callers abort() on transfer failure so the temp is never left behind.
 * HOW:  unlink(tmp_path) if present; ignore errors (best-effort cleanup).
 */
static void
posix_abort(xrdc_vfs_file *f)
{
    vfs_posix_file *pf = (vfs_posix_file *) f;

    if (pf->tmp_path != NULL) {
        unlink(pf->tmp_path);
    }
}

/*
 * posix_close — release the handle: drain ring, close fd, free all heap memory.
 *
 * WHAT: frees the ring (if any), closes the fd, frees path strings, and frees
 *       the handle struct.  Must be called after commit() or abort().
 * WHY:  owns all resources allocated by posix_open(); one release point.
 * HOW:  xrdc_disk_ring_destroy (safe on NULL); close(fd); free strings; free pf.
 */
static void
posix_close(xrdc_vfs_file *f)
{
    vfs_posix_file *pf = (vfs_posix_file *) f;

    xrdc_disk_ring_destroy(pf->ring);

    if (pf->fd >= 0) {
        close(pf->fd);
    }

    free(pf->final_path);
    free(pf->tmp_path);
    free(pf);
}

/* ---- vtable singleton ---------------------------------------------------- */

static const xrdc_vfs_ops s_posix_ops = {
    .pread    = posix_pread,
    .pwrite   = posix_pwrite,
    .fstat    = posix_fstat,
    .truncate = posix_truncate,
    .sync     = posix_sync,
    .commit   = posix_commit,
    .abort    = posix_abort,
    .close    = posix_close,
};

/* ---- Backend open + stat ------------------------------------------------- */

/*
 * posix_be_open — allocate a vfs_posix_file and open the underlying fd.
 *
 * WHAT: READ → open(path, O_RDONLY); WRITE → FORCE-check then open a sibling
 *       temp with O_WRONLY|O_CREAT|O_TRUNC (O_EXCL|O_NOFOLLOW for safety);
 *       both paths optionally wrap the fd in an io_uring ring.
 * WHY:  single open implementation; FORCE/EXCL/NOFOLLOW guard matches copy.c.
 * HOW:  allocate pf; check FORCE vs existing final; open fd; ring_select; set caps.
 *       Caller receives NULL *out on any failure; the handle is not half-initialised.
 */
static int
posix_be_open(const xrdc_vfs_backend *be, const char *path, int flags,
              const xrdc_vfs_open_opts *opts, xrdc_vfs_file **out,
              xrdc_status *st)
{
    vfs_posix_file *pf;
    int             fd = -1;
    char           *final_copy = NULL;
    char           *tmp_path = NULL;
    int             uring_mode;

    (void) be;

    *out = NULL;

    uring_mode = (opts != NULL) ? opts->io_uring : XRDC_IO_URING_AUTO;

    final_copy = strdup(path);
    if (final_copy == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "vfs posix open: out of memory");
        return -1;
    }

    if (flags & XRDC_VFS_WRITE) {
        /* FORCE guard: if final exists and FORCE is not set, reject. */
        if (!(flags & XRDC_VFS_FORCE) && access(path, F_OK) == 0) {
            xrdc_status_set(st, XRDC_EUSAGE, EEXIST,
                            "vfs posix open: destination exists (use "
                            "XRDC_VFS_FORCE to overwrite): %s", path);
            free(final_copy);
            return -1;
        }

        tmp_path = make_posix_temp_path(path);
        if (tmp_path == NULL) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "vfs posix open: destination path too long: %s",
                            path);
            free(final_copy);
            return -1;
        }

        /* O_EXCL refuses a pre-existing name; O_NOFOLLOW refuses a symlink. */
        fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL | O_NOFOLLOW,
                  0644);
        if (fd < 0) {
            xrdc_status_set(st, XRDC_EIO, errno,
                            "vfs posix open write temp %s: %s",
                            tmp_path, strerror(errno));
            free(final_copy);
            free(tmp_path);
            return -1;
        }
    } else {
        /* READ */
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            xrdc_status_set(st, XRDC_EIO, errno,
                            "vfs posix open read %s: %s",
                            path, strerror(errno));
            free(final_copy);
            return -1;
        }
    }

    pf = calloc(1, sizeof(*pf));
    if (pf == NULL) {
        xrdc_status_set(st, XRDC_EIO, ENOMEM,
                        "vfs posix open: out of memory");
        close(fd);
        free(final_copy);
        free(tmp_path);
        return -1;
    }

    pf->fd         = fd;
    pf->final_path = final_copy;
    pf->tmp_path   = tmp_path;   /* NULL for READ */
    pf->ring       = NULL;

    if (posix_ring_select(fd, uring_mode, &pf->ring, st) != 0) {
        close(fd);
        free(final_copy);
        free(tmp_path);
        free(pf);
        return -1;
    }

    pf->base.ops  = &s_posix_ops;
    pf->base.caps = (XRDC_VFS_CAP_RANDOM_WRITE | XRDC_VFS_CAP_TRUNCATE |
                     XRDC_VFS_CAP_ATOMIC_TEMP   | XRDC_VFS_CAP_FADVISE);

    *out = &pf->base;
    return 0;
}

/*
 * posix_be_stat — stat a path by name without opening a handle.
 *
 * WHAT: calls stat(2) on path; fills xrdc_vfs_stat; sets exists=0 on ENOENT.
 * WHY:  allows pre-transfer existence/size checks without a full open.
 * HOW:  stat(2); populate out; ENOENT → exists=0, return 0; other errors → -1, st.
 */
static int
posix_be_stat(const xrdc_vfs_backend *be, const char *path,
              xrdc_vfs_stat *out, xrdc_status *st)
{
    struct stat sb;

    (void) be;

    if (stat(path, &sb) != 0) {
        if (errno == ENOENT) {
            out->exists = 0;
            out->size   = 0;
            out->mtime  = 0;
            out->is_dir = 0;
            return 0;
        }
        xrdc_status_set(st, XRDC_EIO, errno,
                        "vfs posix stat %s: %s", path, strerror(errno));
        return -1;
    }

    out->size   = (int64_t) sb.st_size;
    out->mtime  = (int64_t) sb.st_mtime;
    out->is_dir = S_ISDIR(sb.st_mode) ? 1 : 0;
    out->exists = 1;
    return 0;
}

/* ---- Backend descriptor + self-registration ----------------------------- */

static const xrdc_vfs_backend s_posix_backend = {
    .scheme = "file",
    .caps   = (XRDC_VFS_CAP_RANDOM_WRITE | XRDC_VFS_CAP_TRUNCATE |
               XRDC_VFS_CAP_ATOMIC_TEMP   | XRDC_VFS_CAP_FADVISE),
    .open   = posix_be_open,
    .stat   = posix_be_stat,
};

/*
 * xrdc_vfs_posix_backend — pure factory: return the POSIX backend descriptor.
 *
 * WHAT: strong definition that overrides the weak stub in vfs.c; called once
 *       during vfs_init_backends() (pthread_once).  Returns the static
 *       descriptor; vfs.c's init owns the xrdc_vfs_register_backend() call.
 * WHY:  registration is the façade's responsibility — the accessor must not
 *       double-register (which would consume two of the 8 registry slots).
 * HOW:  return the static descriptor directly.
 */
const xrdc_vfs_backend *
xrdc_vfs_posix_backend(void)
{
    return &s_posix_backend;
}
