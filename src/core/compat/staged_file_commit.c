/*
 * staged_file_commit.c — Cross-device / cross-backend staged-commit publish.
 *
 * WHAT: brix_commit_staged() and its helpers — publish a completed staged
 *       partial onto its final path when a plain rename(2) cannot: a
 *       cross-device fast-cache stage dir (EXDEV → copy + fsync + rename) or a
 *       non-POSIX final export (upload INTO the driver's staged write→commit
 *       state machine).
 *
 * WHY:  Split from staged_file.c (phase-79 file-size split). The same-filesystem
 *       rename lifecycle (open/commit/abort) stays in staged_file.c; this file
 *       owns the heavier byte-moving publish paths that reach the storage-driver
 *       (SD) seam and the per-export backend registry. Isolating them keeps each
 *       file single-concept and under the size budget.
 *
 * HOW:  brix_commit_staged() flushes+chmods the open fd (commit_flush_and_chmod),
 *       resolves the final export's backend, and dispatches: non-POSIX backend →
 *       commit_staged_to_backend (cstb_open_source + cstb_pump_and_commit);
 *       same-FS → rename(2); EXDEV → commit_cross_device. All byte I/O routes
 *       through the SD seam (brix_sd_posix_wrap / driver vtable), never raw
 *       pread/pwrite here. Zero behavior change from the pre-split code.
 */

#include "staged_file.h"
#include "tmp_path.h"
#include "fs/backend/sd.h"   /* Storage Driver seam: VFS↔VFS (backend↔backend) move */
#include "fs/xfer/xfer.h"    /* brix_xfer_pump_objects — the shared in-process mover */
#include "fs/vfs/vfs_backend_registry.h"  /* per-export backend for a non-POSIX commit */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* VFS↔VFS (backend↔backend) byte move: copy the whole source object into the
 * destination object by reading through the SOURCE object's storage driver and
 * writing through the DESTINATION object's driver. The two objects may live on
 * different backends — this is the cross-mount staging commit, so it is exactly
 * the place where one side could later be a block/object (S3) store while the
 * other stays POSIX.
 *
 * Today both ends are POSIX (brix_sd_posix_wrap over a kernel fd), so the only
 * raw pread/pwrite happen INSIDE the POSIX backend (src/fs/backend/sd_posix.c) —
 * never here. When a stage or final mount becomes a non-POSIX backend, only how
 * the object is obtained changes (that driver's open() instead of a bare-fd
 * wrap); this positional copy loop is unchanged. 0 / NGX_ERROR (errno set). */
static ngx_int_t
stage_move_objects(brix_sd_obj_t *src, brix_sd_obj_t *dst)
{
    /* The mover now lives in the transfer engine (src/fs/xfer/xfer_mover_pump.c)
     * as the canonical BRIX_XFER_MOVE_PUMP strategy; this thin wrapper keeps the
     * two staged-commit callsites unchanged. */
    return brix_xfer_pump_objects(src, dst);
}

/* commit_be_logical — the export-root-relative ("/sub/file", or "/" for the root)
 * key form a non-POSIX backend's namespace expects, matching
 * brix_vfs_export_relative_root used by every other driver-backed op. */
static const char *
commit_be_logical(const char *abs, const char *root)
{
    size_t rl = (root != NULL) ? strlen(root) : 0;

    if (rl > 0 && strncmp(abs, root, rl) == 0) {
        if (abs[rl] == '/')  { return abs + rl; }   /* "/sub/file" */
        if (abs[rl] == '\0') { return "/"; }        /* the export root itself */
    }
    return abs;
}

/*
 * WHAT: Resolve the read side of a backend commit — reuse the caller's still-open
 *       staged fd, or open the partial O_RDONLY, and report the mode to publish.
 *
 * WHY:  commit_staged_to_backend can be reached with the partial fd still held
 *       (synchronous close) or already closed (crash-recovery reap), and the
 *       ownership decision governs whether the read fd must be closed on exit. A
 *       single resolver keeps that decision out of the copy loop.
 *
 * HOW:  If fd is valid, borrow it (*owned=0); else open stage_path O_RDONLY
 *       (*owned=1). Derive the publish mode from fstat (default 0644). Returns the
 *       read fd, or NGX_INVALID_FILE with errno set on open failure.
 *
 * Parameters:
 *   fd — caller's staged fd, or NGX_INVALID_FILE
 *   stage_path — partial path to open when fd is closed
 *   owned — output: 1 if the returned fd must be closed by the caller
 *   mode — output: file mode to publish into the backend
 */
static ngx_fd_t
cstb_open_source(ngx_fd_t fd, const char *stage_path, int *owned, mode_t *mode)
{
    struct stat  sb;
    ngx_fd_t     rfd;

    *owned = 0;
    *mode = 0644;

    if (fd != NGX_INVALID_FILE) {
        rfd = fd;
    } else {
        rfd = open(stage_path, O_RDONLY | O_CLOEXEC);
        if (rfd < 0) {
            return NGX_INVALID_FILE;
        }
        *owned = 1;
    }

    if (fstat(rfd, &sb) == 0) {
        *mode = sb.st_mode & 07777;
    }
    return rfd;
}

/*
 * WHAT: Stream a POSIX-read partial (via the SD seam) into an open driver-staged
 *       blob, whole-object, and atomically publish it.
 *
 * WHY:  The read→write pump is the body of the cross-backend commit; isolating it
 *       keeps commit_staged_to_backend a flat acquire/pump/cleanup orchestrator
 *       and confines the per-chunk error handling to one place.
 *
 * HOW:  Wrap rfd as a POSIX source object, positional-read 64 KiB chunks, and
 *       staged_write each fully before advancing the offset. On any read/write
 *       error, or a failing staged_commit, abort the driver blob (releasing it)
 *       and return NGX_ERROR with the originating errno preserved. On success the
 *       blob is committed (partial NOT unlinked here — the caller owns that).
 *
 * Parameters:
 *   rfd — open read fd for the staged partial (positional reads)
 *   dst — destination backend instance (driver vtable)
 *   st — open driver-staged blob to fill and commit
 */
static ngx_int_t
cstb_pump_and_commit(ngx_fd_t rfd, brix_sd_instance_t *dst,
    brix_sd_staged_t *st)
{
    brix_sd_obj_t  src_obj;
    off_t          off = 0;

    brix_sd_posix_wrap(&src_obj, rfd);   /* read the partial via the SD seam */
    for ( ;; ) {
        char    buf[65536];
        ssize_t r = src_obj.driver->pread(&src_obj, buf, sizeof(buf), off);
        ssize_t w = 0;

        if (r < 0) {
            int e = errno;
            dst->driver->staged_abort(st);
            errno = e;
            return NGX_ERROR;
        }
        if (r == 0) {
            break;                          /* EOF: whole partial consumed */
        }
        while (w < r) {
            ssize_t k = dst->driver->staged_write(st, buf + w,
                                                  (size_t) (r - w), off + w);
            if (k <= 0) {
                int e = errno;
                dst->driver->staged_abort(st);
                errno = e ? e : EIO;
                return NGX_ERROR;
            }
            w += k;
        }
        off += r;
    }

    /* Atomic publish. On failure staged_commit leaves the handle valid, so abort
     * to release it; KEEP the POSIX partial so a resume retry can republish. */
    if (dst->driver->staged_commit(st, 0 /* replace allowed */) != NGX_OK) {
        int e = errno;
        dst->driver->staged_abort(st);
        errno = e ? e : EIO;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * commit_staged_to_backend — publish a POSIX-staged partial INTO a non-POSIX
 * storage backend (e.g. pblock) by streaming it through that driver's staged
 * write→commit state machine. This is the cross-FILESYSTEM atomic commit that
 * rename(2) cannot do: the partial lives on an independent POSIX staging mount
 * (brix_stage_dir) and the final export is a different, driver-owned namespace,
 * so we read the partial through the (POSIX) source backend and write it through
 * the destination driver's staged_write, then staged_commit (which publishes
 * atomically — for pblock, a single catalog row insert pointing at the freshly
 * written blocks). On success the POSIX partial is unlinked; on failure it is
 * KEPT (a resume client can retry the close) and the driver's staged blob is
 * aborted. Returns NGX_OK / NGX_ERROR (errno set).
 */
static ngx_int_t
commit_staged_to_backend(ngx_fd_t fd, const char *stage_path,
    const char *final_path, brix_sd_instance_t *dst, const char *root_canon,
    ngx_log_t *log)
{
    const char        *logical = commit_be_logical(final_path, root_canon);
    brix_sd_staged_t  *st;
    mode_t             mode = 0644;
    int                rfd, owned = 0, serr = 0;
    ngx_int_t          rc;

    (void) log;

    if (dst->driver->staged_open == NULL || dst->driver->staged_write == NULL
        || dst->driver->staged_commit == NULL
        || dst->driver->staged_abort == NULL)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }

    /* Source: the open staged partial if we still hold it, else open it O_RDONLY.
     * Reads are positional (pread), so the fd's file position is irrelevant. */
    rfd = cstb_open_source(fd, stage_path, &owned, &mode);
    if (rfd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    st = dst->driver->staged_open(dst, logical, mode, &serr);
    if (st == NULL) {
        if (owned) { (void) close(rfd); }
        errno = serr ? serr : EIO;
        return NGX_ERROR;
    }

    rc = cstb_pump_and_commit(rfd, dst, st);   /* aborts st itself on failure */
    if (owned) { (void) close(rfd); }
    if (rc != NGX_OK) {
        return NGX_ERROR;                       /* errno set by the pump */
    }

    (void) unlink(stage_path);              /* published → drop the partial */
    return NGX_OK;
}

/*
 * WHAT: Make the still-open staged fd durable and publish the caller's intended
 *       mode on it, just before any commit path reads it.
 *
 * WHY:  close() alone does not flush, and a crash / power loss / ENOSPC mid-write
 *       must not expose a torn object — so the data must be fsync'd BEFORE the
 *       commit publishes it. The temp is written 0600 (private); the final mode is
 *       restored here so every downstream commit path derives the object's mode
 *       from the fd.
 *
 * HOW:  Wrap fd as a POSIX object and fsync via the backend; a failing fsync means
 *       "not durable" → NGX_ERROR (do not publish). Then fchmod to final_mode when
 *       non-zero (0 means "leave the temp's current mode", e.g. root:// POSC temps
 *       that already carry the client's create mode). No-op for a closed fd.
 *
 * Parameters:
 *   fd — open staged fd, or NGX_INVALID_FILE (crash-recovery reap)
 *   final_mode — mode to publish, or 0 to keep the temp's mode
 */
static ngx_int_t
commit_flush_and_chmod(ngx_fd_t fd, mode_t final_mode)
{
    brix_sd_obj_t  sobj;

    if (fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    brix_sd_posix_wrap(&sobj, fd);   /* durability flush via the backend */
    if (sobj.driver->fsync(&sobj) != NGX_OK) {
        return NGX_ERROR;   /* not durable — do not publish */
    }
    /* SECURITY: publish the caller's intended mode on the still-open fd before any
     * commit path reads it. */
    if (final_mode != 0) {
        (void) fchmod(fd, final_mode);
    }
    return NGX_OK;
}

/*
 * WHAT: Cross-device commit — copy the staged partial to a temp ON THE FINAL
 *       filesystem, fsync it, atomically rename it onto the final path, and drop
 *       the staged copy.
 *
 * WHY:  When the staged partial sits on a configured fast-cache device different
 *       from the storage (e.g. CEPHFS), rename(2) returns EXDEV and cannot publish
 *       it, so the bytes must be moved before the (now same-FS) atomic rename.
 *
 * HOW:  Derive a temp adjacent to final_path, open the partial O_RDONLY, create
 *       the temp preserving the partial's mode, VFS↔VFS move + fsync, close, then
 *       rename temp→final and unlink the staged copy. Every error path unlinks the
 *       temp and restores the originating errno.
 *
 * Parameters:
 *   stage_path — the staged partial (cross-device source)
 *   final_path — destination path (drives the adjacent temp + final rename)
 */
static ngx_int_t
commit_cross_device(const char *stage_path, const char *final_path)
{
    char         tmp[PATH_MAX];
    int          rfd, dfd, e;
    struct stat  sb;
    mode_t       mode;

    if (brix_make_tmp_path(final_path, tmp, sizeof(tmp)) != NGX_OK) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    rfd = open(stage_path, O_RDONLY | O_CLOEXEC);
    if (rfd < 0) {
        return NGX_ERROR;
    }
    /* Preserve the staged file's mode on the committed object. */
    mode = (fstat(rfd, &sb) == 0) ? (sb.st_mode & 07777) : 0644;
    dfd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (dfd < 0) {
        e = errno; close(rfd); errno = e; return NGX_ERROR;
    }
    {
        /* VFS↔VFS move: stage object (source backend) → temp object (final
         * backend). Both POSIX today; the loop is driver-mediated so a non-POSIX
         * mount on either side needs no change here. */
        brix_sd_obj_t src_obj, dst_obj;
        brix_sd_posix_wrap(&src_obj, rfd);
        brix_sd_posix_wrap(&dst_obj, dfd);
        if (stage_move_objects(&src_obj, &dst_obj) != NGX_OK
            || dst_obj.driver->fsync(&dst_obj) != NGX_OK) {
            e = errno; close(rfd); close(dfd); (void) unlink(tmp); errno = e;
            return NGX_ERROR;
        }
    }
    close(rfd);
    if (close(dfd) != 0) {
        e = errno; (void) unlink(tmp); errno = e; return NGX_ERROR;
    }
    if (rename(tmp, final_path) != 0) {
        e = errno; (void) unlink(tmp); errno = e; return NGX_ERROR;
    }
    (void) unlink(stage_path);   /* drop the cache copy; commit succeeded */
    return NGX_OK;
}

/*
 * WHAT: Commit a staged file onto its final path — atomically and across
 *       filesystems.  When the final export uses a NON-POSIX storage backend
 *       (e.g. pblock), the partial is uploaded INTO that backend via the driver's
 *       staged write→commit state machine (commit_staged_to_backend).  Otherwise
 *       it tries rename(2) first (atomic, same-FS, the fast path); on
 *       EXDEV (the staged file is on a configured fast-cache device different from
 *       the storage, e.g. CEPHFS) it copies the data to a temp ON THE FINAL
 *       filesystem, fsync()s, atomically renames that temp onto the final path,
 *       and unlinks the staged copy.  Either way a concurrent reader sees only the
 *       old object or the complete new one — never a partial.
 *
 * WHY:  Upload staging on a fast device + final storage on a POSIX mount means the
 *       commit can be a cross-device move, which rename(2) cannot do.  Centralising
 *       this lets both root:// (close) and WebDAV (PUT) commit identically.
 *
 * fd: the open staged-file descriptor (for the durability fsync before commit), or
 *     NGX_INVALID_FILE if already closed.  Returns NGX_OK / NGX_ERROR (errno set).
 */
ngx_int_t
brix_commit_staged(ngx_fd_t fd, const char *stage_path, const char *final_path,
                     mode_t final_mode, ngx_log_t *log)
{
    const char          *be_root = NULL;
    brix_sd_instance_t  *dst;

    if (commit_flush_and_chmod(fd, final_mode) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Non-POSIX final export (e.g. pblock): the staged POSIX partial lives on an
     * independent staging mount and the final namespace is driver-owned, so
     * rename(2) cannot publish it. Upload the partial INTO the backend via its
     * staged write→commit state machine (a cross-filesystem atomic publish).
     * POSIX exports (the common case) skip this and take the rename path below. */
    dst = brix_vfs_backend_resolve_for_path(final_path, &be_root, log);
    if (dst != NULL && dst->driver != NULL
        && dst->driver != brix_sd_default_driver())
    {
        return commit_staged_to_backend(fd, stage_path, final_path, dst,
                                        be_root, log);
    }

    if (rename(stage_path, final_path) == 0) {
        return NGX_OK;          /* same filesystem: atomic, zero-copy */
    }
    if (errno != EXDEV) {
        return NGX_ERROR;
    }

    /* Cross-device commit: copy the staged data to a temp adjacent to (and on the
     * same filesystem as) the final path, then atomically rename it into place. */
    return commit_cross_device(stage_path, final_path);
}
