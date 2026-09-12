/*
 * vfs_open_handle.c — VFS handle lifecycle, close, and the brix_vfs_file_*
 * accessors.
 *
 * WHAT: Implements brix_vfs_close() and every read-only accessor over an open
 *       brix_vfs_file_t: fd / sd_obj / pread / sendfile-fd / can-sendfile /
 *       backend-name / path / size / mtime / from_cache / file_stat, plus the
 *       phase-71 memfd sendfile-proxy materialiser.
 *
 * WHY:  Once brix_vfs_open() (vfs_open.c) hands back a confined, already-fstat'd
 *       handle, everything else is pure handle-state access and teardown. Keeping
 *       it separate from the open cascade keeps both files under the size cap and
 *       isolates the "given a handle" surface from the "build a handle" surface.
 *
 * HOW:  Accessors read cached metadata captured at adopt time; brix_vfs_file_stat()
 *       answers from that cache on a read-only handle (stat_current) and otherwise
 *       re-stats through the backend's fstat slot. brix_vfs_file_sendfile_fd()
 *       delegates the zero-copy decision to the backend and, for a fd-less
 *       CAP_MEMFILE backend, materialises a handle-owned memfd once.
 *       brix_vfs_close() releases any memfd then the descriptor through the
 *       backend's close slot.
 */
#include "vfs_internal.h"
#include "vfs_backend_registry.h"
#include <sys/mman.h>
#include "cvmfs/platform/platform.h"  /* brix_plat_anon_fd (cross-platform memfd/O_TMPFILE) */
#include "core/compat/log_diag.h"

ngx_int_t
brix_vfs_close(brix_vfs_file_t *fh, ngx_log_t *log)
{
    if (fh == NULL) {
        return NGX_OK;
    }

    /* phase-71 step 2: release a materialised memfd sendfile proxy, if any. This
     * runs before the fd-based early-out below because a CAP_MEMFILE backend has
     * obj.fd == NGX_INVALID_FILE yet may still own a memfd. */
    if (fh->memfd != NGX_INVALID_FILE) {
        (void) ngx_close_file(fh->memfd);
        fh->memfd = NGX_INVALID_FILE;
    }

    /* A memory-served backend (xroot/pblock/ceph — CAP_MEMFILE, no kernel fd)
     * still owns per-open driver state: an origin connection holding a live
     * remote write handle, catalog state, a RADOS ioctx. Skipping the close
     * slot for fd == NGX_INVALID_FILE leaked all of it — on a root:// backend
     * the origin kept counting this session as an open writer, so the very
     * next read-open of the object was denied by single-writer semantics. */
    if (fh->obj.driver == NULL
        || (fh->obj.fd == NGX_INVALID_FILE && fh->obj.state == NULL))
    {
        return NGX_OK;
    }

    /* Release the descriptor through the backend's close slot; the driver
     * marks obj.fd invalid. The VFS keeps the error-log wrapper. */
    if (fh->obj.driver->close(&fh->obj) != NGX_OK) {
        BRIX_DIAG_ERR(log != NULL ? log : fh->log, ngx_errno,
            "xrootd[disk]: close failed for \"%s\"",
            "a deferred write error surfaced at close — typically the "
            "filesystem filled up (ENOSPC) or the device returned an I/O error",
            "check free space and dmesg for disk errors; the file may be "
            "incomplete, so the client's write should be treated as failed",
            fh->path != NULL ? fh->path : "-");
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_fd_t
brix_vfs_file_fd(const brix_vfs_file_t *fh)
{
    return fh != NULL ? fh->obj.fd : NGX_INVALID_FILE;
}

void
brix_vfs_file_sd_obj(const brix_vfs_file_t *fh, brix_sd_obj_t *out)
{
    brix_vfs_handle_sd_obj(fh, out);
}

/* Read up to `len` bytes at `off` through the handle's storage driver — the
 * backend-neutral read used to serve a backend that exposes no single sendfile
 * fd (e.g. an object backend whose bytes span multiple block files). Returns the
 * bytes read (0 = EOF), or -1 with errno. One driver pread; the caller loops. */
ssize_t
brix_vfs_file_pread(brix_vfs_file_t *fh, void *buf, size_t len, off_t off)
{
    if (fh == NULL || fh->obj.driver == NULL
        || fh->obj.driver->pread == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    return fh->obj.driver->pread(&fh->obj, buf, len, off);
}

/* Write up to `len` bytes at `off` through the handle's storage driver — the
 * backend-neutral write used when a raw-fd pwrite would bypass an object
 * backend's block routing and size bookkeeping (e.g. pblock, whose bytes span
 * multiple block files and whose catalog size is maintained by the driver's
 * pwrite slot, not by the kernel fd). Returns bytes written, or -1 with errno;
 * the caller loops on a short write. */
ssize_t
brix_vfs_file_pwrite(brix_vfs_file_t *fh, const void *buf, size_t len, off_t off)
{
    if (fh == NULL || fh->obj.driver == NULL
        || fh->obj.driver->pwrite == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    return fh->obj.driver->pwrite(&fh->obj, buf, len, off);
}

/* brix_vfs_memfile_materialize — phase-71 step 2 memfd sendfile proxy.
 *
 * WHAT: For a CAP_MEMFILE backend that exposes no kernel fd (obj.fd invalid,
 *       read_sendfile_fd declines), pread the whole object into an anonymous
 *       memfd ONCE and cache it on fh->memfd, so the VFS can hand every backend
 *       a uniform seekable fd for the sendfile / file-backed serve path.
 * WHY:  Removes the last backend-identity branch in the serve path: callers stop
 *       special-casing "no fd → build a memory buffer myself" and use one fd path.
 * HOW:  memfd_create, sized with ftruncate and filled through one mmap of
 *       itself, so the driver's worker-safe pread slot is asked for the whole
 *       remaining span at once rather than in 64 KiB steps (see
 *       brix_vfs_memfile_fill). The fd is owned by the handle and closed in
 *       brix_vfs_close. Returns the cached fd on repeat calls.
 *       NGX_INVALID_FILE on any failure (the caller then falls back to its
 *       legacy memory-backed path — no behaviour change). */

/* Fill `map` (the whole object, already sized) from the driver.
 *
 * The span asked for is always ALL THAT IS LEFT, never a fixed chunk, and that
 * is the point rather than a detail.  The previous loop read 64 KiB at a time
 * through a stack buffer, and on a driver whose pread opens a session per call
 * — gsiftp does, one USER/PASS/TYPE/REST/RETR per read — materialising a
 * 300 kB object cost FIVE logins and five transfers where one would do.
 * Asking for the remainder lets a conforming driver answer in a single call
 * and still lets a short-reading one finish; the memfd is mapped rather than
 * written through a buffer because it already holds the whole object, so the
 * mapping costs no memory the materialisation was not paying anyway. */
static int
brix_vfs_memfile_fill(brix_sd_obj_t *obj, u_char *map, off_t size)
{
    off_t off;

    for (off = 0; off < size; /* advanced below */) {
        ssize_t n = obj->driver->pread(obj, map + off,
                                       (size_t) (size - off), off);

        if (n <= 0) {
            return NGX_ERROR;
        }
        off += n;
    }
    return NGX_OK;
}


/* The memfd sized and filled, or NGX_INVALID_FILE with the fd already closed. */
static ngx_fd_t
brix_vfs_memfile_build(brix_sd_obj_t *obj, off_t size)
{
    ngx_fd_t  fd;
    void     *map;
    int       filled;

    /* Use platform abstraction for anonymous fd (memfd on Linux, O_TMPFILE/mkstemp on macOS) */
    fd = (ngx_fd_t) brix_plat_anon_fd("brix-vfs-memfile", NULL);
    if (fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }
    if (size == 0) {
        return fd;                     /* an empty object needs no transfer */
    }
    if (ftruncate(fd, size) != 0) {
        (void) ngx_close_file(fd);
        return NGX_INVALID_FILE;
    }

    map = mmap(NULL, (size_t) size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        (void) ngx_close_file(fd);
        return NGX_INVALID_FILE;
    }
    filled = brix_vfs_memfile_fill(obj, map, size);
    (void) munmap(map, (size_t) size);

    if (filled != NGX_OK || lseek(fd, 0, SEEK_SET) == (off_t) -1) {
        (void) ngx_close_file(fd);
        return NGX_INVALID_FILE;
    }
    return fd;
}


static ngx_fd_t
brix_vfs_memfile_materialize(brix_vfs_file_t *fh)
{
    brix_sd_obj_t obj;
    ngx_fd_t      fd;

    if (fh->memfd != NGX_INVALID_FILE) {
        return fh->memfd;              /* already materialised */
    }

    brix_vfs_handle_sd_obj(fh, &obj);
    if (obj.driver == NULL || obj.driver->pread == NULL
        || !(brix_sd_caps(obj.inst) & BRIX_SD_CAP_MEMFILE))
    {
        return NGX_INVALID_FILE;
    }

    fd = brix_vfs_memfile_build(&obj, fh->size);
    if (fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }

    fh->memfd = fd;
    return fd;
}

/* The fd only when the backend elects to back a zero-copy transfer of the whole
 * object, else NGX_INVALID_FILE. The decision is delegated to the backend's
 * read_sendfile_fd slot (want_zerocopy=1: the HTTP serve helper applies the
 * TLS/cleartext choice itself). For a fd-less CAP_MEMFILE backend the VFS
 * materialises a handle-owned memfd (phase-71 step 2) so the serve path is a
 * uniform seekable fd for every backend. The contract gate for callers that
 * build a sendfile / file-backed response. */
ngx_fd_t
brix_vfs_file_sendfile_fd(const brix_vfs_file_t *fh)
{
    return brix_vfs_file_sendfile_fd_window(fh, 0,
                                            fh != NULL ? fh->size : 0);
}

/* brix_vfs_file_sendfile_fd_window — the sendfile fd for the window a caller is
 * ABOUT TO SEND, rather than for the whole object.
 *
 * WHAT: identical to brix_vfs_file_sendfile_fd() for any backend that owns a
 *       real kernel fd; for a fd-less CAP_MEMFILE backend it materialises the
 *       memfd ONLY when [off, off+len) is the whole object.
 * WHY:  materialisation preads the ENTIRE object through the driver.  On a
 *       remote backend (gsiftp, http, xroot, s3, ceph) that is a network
 *       transfer of the whole file, and it was being paid for every ranged
 *       read: a 256-byte Range on a 384 kB file fetched all 384 kB in six
 *       round trips, and the same request against a 10 GB object would have
 *       fetched 10 GB.  Nothing was wrong with the response — the right bytes
 *       came back with the right Content-Range — so the cost was invisible from
 *       outside, and it silently cancelled every bounded-retrieve extension the
 *       drivers negotiate (GridFTP ERET P, HTTP Range, xroot kXR_read), which
 *       were all correctly asking the origin for a window and then being handed
 *       a whole-object request by the layer above.
 * HOW:  probe the backend first and unchanged — a driver that owns an fd is
 *       indifferent to the window, and narrowing what it is asked would change
 *       which offsets sd_block / sd_pblock accept.  Only the materialisation
 *       fallback is gated: a strict sub-window declines and the caller falls
 *       back to its memory-backed path, which reads exactly the window it
 *       needs.  A caller that will read NOTHING (a HEAD) passes len < 0, which
 *       can never equal a size and so never materialises.
 *
 *       Declining costs nothing here: the memfd is a full COPY of an object the
 *       backend cannot sendfile, so the "zero-copy" path had already paid for
 *       the whole object once before sending a byte. */
ngx_fd_t
brix_vfs_file_sendfile_fd_window(const brix_vfs_file_t *fh, off_t off,
    off_t len)
{
    ngx_fd_t fd;

    if (fh == NULL) {
        return NGX_INVALID_FILE;
    }
    fd = brix_vfs_handle_sendfile_fd(fh, 0, (size_t) fh->size, 1);
    if (fd != NGX_INVALID_FILE) {
        return fd;
    }
    if (off != 0 || len != fh->size) {
        return NGX_INVALID_FILE;
    }
    /* fh is const by contract, but the memfd cache is an internal materialisation
     * that does not change the observable file — safe to fill lazily here. */
    return brix_vfs_memfile_materialize((brix_vfs_file_t *) fh);
}

/* Predicate form: 1 iff the backend will provide a sendfile fd for this handle. */
ngx_uint_t
brix_vfs_file_can_sendfile(const brix_vfs_file_t *fh)
{
    return brix_vfs_file_sendfile_fd(fh) != NGX_INVALID_FILE ? 1 : 0;
}

/* The census name of the backend serving this handle: the bound instance's
 * driver name, or "posix" for the default instance / a NULL handle. Used for
 * per-backend byte attribution at serve time (the serve paths release the
 * handle before the bytes are counted, so callers capture this up front). */
const char *
brix_vfs_file_backend_name(const brix_vfs_file_t *fh)
{
    if (fh == NULL || fh->ctx == NULL || fh->ctx->sd == NULL) {
        return "posix";
    }
    return brix_sd_backend_name(fh->ctx->sd);
}

const char *
brix_vfs_file_path(const brix_vfs_file_t *fh)
{
    return (fh != NULL && fh->path != NULL) ? fh->path : "";
}

off_t
brix_vfs_file_size(const brix_vfs_file_t *fh)
{
    return fh != NULL ? fh->size : 0;
}

time_t
brix_vfs_file_mtime(const brix_vfs_file_t *fh)
{
    return fh != NULL ? fh->mtime : 0;
}

ngx_uint_t
brix_vfs_file_from_cache(const brix_vfs_file_t *fh)
{
    return (fh != NULL && fh->from_cache) ? 1 : 0;
}

ngx_int_t
brix_vfs_file_stat(const brix_vfs_file_t *fh, brix_vfs_stat_t *stat_out)
{
    brix_sd_stat_t st;
    brix_sd_obj_t  obj;

    if (fh == NULL || stat_out == NULL
        || (fh->obj.fd == NGX_INVALID_FILE && fh->obj.driver == NULL))
    {
        /* A driver-backed handle (object/remote backend) has no kernel fd; it
         * answers from cached metadata or the driver's fstat slot below. */
        errno = EINVAL;
        return NGX_ERROR;
    }

    /*
     * phase-45 W2/R1: when the metadata cached at adopt time is authoritative,
     * answer from it and skip a redundant fstat(2).  This is the common read
     * path (S3/WebDAV GET open the fd then immediately stat it).  stat_current is
     * set by adopt_fd only for read-only handles, whose file cannot change
     * through them; a writable handle has it clear and always takes a live fstat.
     */
    if (fh->stat_current) {
        ngx_memzero(stat_out, sizeof(*stat_out));
        stat_out->size = fh->size;
        stat_out->mtime = fh->mtime;
        stat_out->ctime = fh->ctime;
        stat_out->mode = (ngx_uint_t) fh->mode;
        stat_out->ino = fh->ino;
        stat_out->is_directory = S_ISDIR(fh->mode) ? 1 : 0;
        stat_out->is_regular = S_ISREG(fh->mode) ? 1 : 0;
        return NGX_OK;
    }

    /* Live re-stat through the backend's fstat slot (not a direct fstat(2)). */
    brix_vfs_handle_sd_obj(fh, &obj);
    if (obj.driver->fstat == NULL || obj.driver->fstat(&obj, &st) != NGX_OK) {
        return NGX_ERROR;
    }

    brix_vfs_sd_stat_fill(&st, stat_out);
    return NGX_OK;
}
