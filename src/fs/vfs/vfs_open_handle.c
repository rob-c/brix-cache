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
#include <sys/mman.h>   /* memfd_create (phase-71 step 2 memfd sendfile proxy) */
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

    if (fh->obj.driver == NULL || fh->obj.fd == NGX_INVALID_FILE) {
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

/* brix_vfs_memfile_materialize — phase-71 step 2 memfd sendfile proxy.
 *
 * WHAT: For a CAP_MEMFILE backend that exposes no kernel fd (obj.fd invalid,
 *       read_sendfile_fd declines), pread the whole object into an anonymous
 *       memfd ONCE and cache it on fh->memfd, so the VFS can hand every backend
 *       a uniform seekable fd for the sendfile / file-backed serve path.
 * WHY:  Removes the last backend-identity branch in the serve path: callers stop
 *       special-casing "no fd → build a memory buffer myself" and use one fd path.
 * HOW:  memfd_create + a pread→write loop through the driver's worker-safe pread
 *       slot; the fd is owned by the handle and closed in brix_vfs_close. Returns
 *       the cached fd on repeat calls. NGX_INVALID_FILE on any failure (the caller
 *       then falls back to its legacy memory-backed path — no behaviour change). */
static ngx_fd_t
brix_vfs_memfile_materialize(brix_vfs_file_t *fh)
{
    brix_sd_obj_t obj;
    ngx_fd_t      fd;
    off_t         off;
    u_char        buf[65536];

    if (fh->memfd != NGX_INVALID_FILE) {
        return fh->memfd;              /* already materialised */
    }

    brix_vfs_handle_sd_obj(fh, &obj);
    if (obj.driver == NULL || obj.driver->pread == NULL
        || !(brix_sd_caps(obj.inst) & BRIX_SD_CAP_MEMFILE))
    {
        return NGX_INVALID_FILE;
    }

    fd = (ngx_fd_t) memfd_create("brix-vfs-memfile", MFD_CLOEXEC);
    if (fd == NGX_INVALID_FILE) {
        return NGX_INVALID_FILE;
    }

    for (off = 0; off < fh->size; /* advanced below */) {
        size_t  want = (size_t) ngx_min((off_t) sizeof(buf), fh->size - off);
        ssize_t n = obj.driver->pread(&obj, buf, want, off);

        if (n <= 0) {
            (void) ngx_close_file(fd);
            return NGX_INVALID_FILE;
        }
        if (write(fd, buf, (size_t) n) != n) {
            (void) ngx_close_file(fd);
            return NGX_INVALID_FILE;
        }
        off += n;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t) -1) {
        (void) ngx_close_file(fd);
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
    ngx_fd_t fd;

    if (fh == NULL) {
        return NGX_INVALID_FILE;
    }
    fd = brix_vfs_handle_sendfile_fd(fh, 0, (size_t) fh->size, 1);
    if (fd != NGX_INVALID_FILE) {
        return fd;
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

    brix_vfs_sd_stat_to_vfs(&st, stat_out);
    return NGX_OK;
}
