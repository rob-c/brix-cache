/*
 * staged_file.c — Shared temp-file open/commit/abort lifecycle.
 *
 * Atomic write pattern: create a unique temp file inside the confined root, write data to it,
 * then rename to the final path. On failure, abort (close + optionally unlink). Used by S3 PUT,
 * WebDAV PUT, and other operations that need crash-safe writes.
 */

#include "staged_file.h"
#include "tmp_path.h"
#include "fs/path/path.h"
#include "fs/path/beneath.h"
#include "fs/backend/sd.h"   /* Storage Driver seam: VFS↔VFS (backend↔backend) move */
#include "fs/xfer/xfer.h"    /* brix_xfer_pump_objects — the shared in-process mover */
#include "fs/vfs/vfs_backend_registry.h"  /* per-export backend for a non-POSIX commit */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Confinement (Phase 8): the temp file and its final destination always live
 * under root_canon (brix_make_tmp_path derives the temp name next to
 * final_path, which the caller already confined to the export root).  We open a
 * kernel-confinement rootfd on root_canon and route the temp create / rename /
 * unlink through the beneath API so the operation is bounded by the kernel
 * regardless of how the caller derived the path.  A path that does not strip
 * cleanly under root_canon is refused (EXDEV) rather than touched raw.
 */

/*
 * WHAT: Open a unique temporary file inside the confined root_canon for atomic write.
 *
 * WHY: S3 PUT, WebDAV PUT, and other operations need to write data safely without risking
 *      corruption of the final path if the process crashes mid-write. A temp file with O_EXCL
 *      guarantees atomicity — either the rename succeeds (final path appears) or it doesn't
 *      (temp file remains for cleanup).
 *
 * HOW: Generate a unique tmp_path via brix_make_tmp_path(). Open with
 *      open_flags | O_CREAT | O_EXCL inside root_canon via brix_open_confined_canon().
 *      Loop up to 'attempts' times (default 16) on EEXIST. On success: set staged->active=1,
 *      store fd and tmp_path, return NGX_OK. On non-EEXIST failure or exhaustion: errno set,
 *      return NGX_ERROR.
 *
 * Parameters:
 *   log — nginx log for error reporting
 *   req — request description: root_canon / final_path / open_flags / mode /
 *         attempts (see brix_staged_open_req_t)
 *   staged — output struct: fd, tmp_path, active flag populated on success
 */
ngx_int_t
brix_staged_open(ngx_log_t *log, const brix_staged_open_req_t *req,
    brix_staged_file_t *staged)
{
    ngx_uint_t  attempts;
    ngx_uint_t  i;
    int         rootfd;

    (void) log;

    if (staged == NULL || req == NULL || req->final_path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    ngx_memzero(staged, sizeof(*staged));
    staged->fd = NGX_INVALID_FILE;
    /* SECURITY: the temp is created PRIVATE (0600) so another mapped uid on a
     * shared filesystem cannot read an in-progress upload; the caller's intended
     * final mode is restored at commit (staged_commit_internal). */
    staged->final_mode = req->mode;

    attempts = req->attempts;
    if (attempts == 0) {
        attempts = 16;
    }

    rootfd = brix_beneath_open_root(req->root_canon);
    if (rootfd < 0) {
        return NGX_ERROR;
    }

    for (i = 0; i < attempts; i++) {
        const char *rel;

        if (brix_make_tmp_path(req->final_path, staged->tmp_path,
                                 sizeof(staged->tmp_path)) != NGX_OK)
        {
            errno = ENAMETOOLONG;
            close(rootfd);
            return NGX_ERROR;
        }

        rel = brix_beneath_strip_root(req->root_canon, staged->tmp_path);
        if (rel == NULL) {
            errno = EXDEV;
            close(rootfd);
            return NGX_ERROR;
        }

        staged->fd = brix_open_beneath(rootfd, rel,
                                         req->open_flags | O_CREAT | O_EXCL,
                                         0600);
        if (staged->fd != NGX_INVALID_FILE) {
            staged->active = 1;
            close(rootfd);
            return NGX_OK;
        }

        if (errno != EEXIST) {
            close(rootfd);
            return NGX_ERROR;
        }
    }

    close(rootfd);
    errno = EEXIST;
    return NGX_ERROR;
}

/*
 * WHAT: Open the DETERMINISTIC, identity-keyed upload-resume partial for a final
 *       path (confined inside root_canon), creating it if absent and PRESERVING
 *       any existing bytes (no O_TRUNC, no O_EXCL).  Reports the current partial
 *       size in *cur_size so the caller / client can resume at that offset.
 *
 * WHY:  WebDAV resumable PUT (Content-Range) needs a chunk to land at an absolute
 *       offset on a partial that survives across separate PUT requests and a
 *       server restart, then commit (rename) only when complete — the HTTP
 *       analogue of the root:// resume staging.  Reuses the same name scheme
 *       (brix_make_resume_path) and confinement (brix_open_beneath) as the
 *       random staged_open so security and glob-clean are identical.
 *
 * Returns NGX_OK with staged->active=1, or NGX_ERROR (errno set).
 *
 * Parameters:
 *   log — nginx log for error reporting
 *   req — request description: root_canon / final_path / principal / stage_dir /
 *         mode (see brix_staged_open_req_t)
 *   staged — output struct populated on success
 *   cur_size — output: current partial size (resume offset), 0 if fresh
 */
ngx_int_t
brix_staged_open_resume(ngx_log_t *log, const brix_staged_open_req_t *req,
    brix_staged_file_t *staged, off_t *cur_size)
{
    const char  *stage_dir;
    int          rootfd, fd;
    const char  *rel;
    struct stat  sb;

    (void) log;

    if (staged == NULL || req == NULL || req->final_path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    ngx_memzero(staged, sizeof(*staged));
    staged->fd = NGX_INVALID_FILE;
    /* SECURITY: the resume partial is created PRIVATE (0600) and stays private
     * across requests/restarts (it persists between range chunks); the intended
     * final mode is restored at commit. */
    staged->final_mode = req->mode;
    if (cur_size != NULL) {
        *cur_size = 0;
    }

    if (brix_make_resume_path(req->final_path, req->principal, req->stage_dir,
                                staged->tmp_path, sizeof(staged->tmp_path))
        != NGX_OK)
    {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    stage_dir = req->stage_dir;
    if (stage_dir != NULL && stage_dir[0] != '\0') {
        /* Partial lives on the configured fast device (outside root_canon).  The
         * basename is a server-generated hash inside the operator-trusted stage
         * dir, so a direct O_NOFOLLOW open is safe; commit moves it to storage. */
        fd = open(staged->tmp_path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                  0600);
        if (fd == NGX_INVALID_FILE) {
            return NGX_ERROR;
        }
    } else {
        rootfd = brix_beneath_open_root(req->root_canon);
        if (rootfd < 0) {
            return NGX_ERROR;
        }
        rel = brix_beneath_strip_root(req->root_canon, staged->tmp_path);
        if (rel == NULL) {
            close(rootfd);
            errno = EXDEV;
            return NGX_ERROR;
        }
        /* O_CREAT but NOT O_EXCL / O_TRUNC: create-or-resume, preserving bytes. */
        fd = brix_open_beneath(rootfd, rel, O_RDWR | O_CREAT, 0600);
        close(rootfd);
        if (fd == NGX_INVALID_FILE) {
            return NGX_ERROR;
        }
    }

    if (cur_size != NULL && fstat(fd, &sb) == 0) {
        *cur_size = sb.st_size;
    }
    staged->fd = fd;
    staged->active = 1;
    return NGX_OK;
}

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

/*
 * When an upload completes, the (complete) staged file must be moved from the
 * stage device to the final storage.  With a synchronous commit the client waits
 * for that move, but if the worker dies mid-move the COMPLETE file is left in the
 * cache with nothing recording where it should go.  A marker file
 * "<stage_partial>.commit" (content = the final absolute path) is written +
 * fsync'd just before the move and removed after it; if the move is interrupted
 * the marker survives, and brix_stage_reap_dir() finishes the move on the next
 * worker startup / periodic sweep — so complete-but-uncommitted files are tracked
 * across restarts and always reach storage.
 */
#define BRIX_STAGE_COMMIT_SUFFIX ".commit"
#define BRIX_STAGE_MAX_DIRS 32

static char       s_stage_dirs[BRIX_STAGE_MAX_DIRS][PATH_MAX];
static ngx_uint_t s_stage_dir_count;

void
brix_stage_dir_register(const char *canon)
{
    ngx_uint_t i;

    if (canon == NULL || canon[0] == '\0' || strlen(canon) >= PATH_MAX) {
        return;
    }
    for (i = 0; i < s_stage_dir_count; i++) {
        if (strcmp(s_stage_dirs[i], canon) == 0) {
            return;   /* already registered (dedup across server blocks) */
        }
    }
    if (s_stage_dir_count >= BRIX_STAGE_MAX_DIRS) {
        return;
    }
    ngx_memcpy(s_stage_dirs[s_stage_dir_count], canon, strlen(canon) + 1);
    s_stage_dir_count++;
}

ngx_uint_t
brix_stage_dir_count(void)
{
    return s_stage_dir_count;
}

ngx_int_t
brix_stage_mark_pending(const char *stage_partial, const char *final_path,
                          ngx_log_t *log)
{
    char    marker[PATH_MAX];
    int     fd, n;
    size_t  flen;

    (void) log;
    n = snprintf(marker, sizeof(marker), "%s%s", stage_partial,
                 BRIX_STAGE_COMMIT_SUFFIX);
    if (n < 0 || (size_t) n >= sizeof(marker)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return NGX_ERROR;
    }
    flen = strlen(final_path);
    if ((size_t) write(fd, final_path, flen) != flen || fsync(fd) != 0) {
        int e = errno; close(fd); (void) unlink(marker); errno = e;
        return NGX_ERROR;
    }
    close(fd);
    return NGX_OK;
}

void
brix_stage_unmark_pending(const char *stage_partial)
{
    char marker[PATH_MAX];
    int  n = snprintf(marker, sizeof(marker), "%s%s", stage_partial,
                      BRIX_STAGE_COMMIT_SUFFIX);
    if (n > 0 && (size_t) n < sizeof(marker)) {
        (void) unlink(marker);
    }
}

/* Maximum stage-out markers snapshotted per reap pass, and the per-basename cap. */
#define BRIX_STAGE_REAP_MAX_MARKERS  256
#define BRIX_STAGE_REAP_NAME_MAX     256

/*
 * WHAT: Snapshot the basenames of every ".commit" marker in stage_dir into names[]
 *       (returns the count captured, capped at max).
 *
 * WHY:  The reap loop unlinks markers while it works, which would make a live
 *       readdir skip entries — so the directory is scanned into a snapshot FIRST,
 *       then the snapshot is processed.
 *
 * HOW:  opendir + readdir, keeping only names that end in BRIX_STAGE_COMMIT_SUFFIX
 *       and fit the basename buffer; copy each (with its NUL) into names[]. A
 *       missing / unopenable dir yields 0.
 *
 * Parameters:
 *   stage_dir — directory to scan
 *   names — output array of NUL-terminated basenames
 *   max — capacity of names[] (entries beyond it are ignored)
 */
static ngx_uint_t
reap_collect_markers(const char *stage_dir,
    char names[][BRIX_STAGE_REAP_NAME_MAX], ngx_uint_t max)
{
    DIR           *d;
    struct dirent *de;
    size_t         slen = sizeof(BRIX_STAGE_COMMIT_SUFFIX) - 1;
    ngx_uint_t     ncount = 0;

    d = opendir(stage_dir);
    if (d == NULL) {
        return 0;
    }
    while ((de = readdir(d)) != NULL && ncount < max) {
        size_t nlen = strlen(de->d_name);
        if (nlen > slen && nlen < BRIX_STAGE_REAP_NAME_MAX
            && strcmp(de->d_name + nlen - slen, BRIX_STAGE_COMMIT_SUFFIX) == 0)
        {
            ngx_memcpy(names[ncount], de->d_name, nlen + 1);
            ncount++;
        }
    }
    closedir(d);
    return ncount;
}

/*
 * WHAT: Read a marker's recorded final path into *final (NUL-terminated, trailing
 *       whitespace trimmed), validating it is a sane absolute path.
 *
 * WHY:  A marker's content is the final absolute path to publish the partial to;
 *       an unreadable, empty, or non-absolute marker is corrupt and must not drive
 *       a commit.
 *
 * HOW:  open O_RDONLY|O_NOFOLLOW, read up to cap-1 bytes, trim trailing CR/LF/space,
 *       and require a leading '/'. Returns NGX_OK with *final populated, or
 *       NGX_ERROR (the caller drops the marker).
 *
 * Parameters:
 *   marker — absolute path to the ".commit" marker file
 *   final — output buffer for the recorded path
 *   cap — size of final
 */
static ngx_int_t
reap_read_marker_target(const char *marker, char *final, size_t cap)
{
    int      mfd;
    ssize_t  r;

    mfd = open(marker, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (mfd < 0) {
        return NGX_ERROR;
    }
    r = read(mfd, final, cap - 1);
    close(mfd);
    if (r <= 0) {
        return NGX_ERROR;
    }
    final[r] = '\0';
    while (r > 0 && (final[r - 1] == '\n' || final[r - 1] == '\r'
                     || final[r - 1] == ' ')) {
        final[--r] = '\0';
    }
    if (final[0] != '/') {                 /* sanity: must be absolute */
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: Reap one snapshotted marker basename — finish its pending stage-out and
 *       remove the marker. Returns 1 if a commit completed this call, else 0.
 *
 * WHY:  Isolating the per-marker decision (build paths, read target, check the
 *       partial still exists, commit) keeps brix_stage_reap_dir a flat scan+loop.
 *       Idempotent: a marker whose partial is gone (committed by a racing pass or
 *       a client retry) is just dropped.
 *
 * HOW:  Build the marker + partial paths under stage_dir; read the target; if the
 *       partial is missing drop the marker; else brix_commit_staged (no fd →
 *       final_mode unused, fchmod is fd-guarded, partial keeps its on-disk mode).
 *       On success unlink the marker + NOTICE-log; on failure WARN and keep it for
 *       retry.
 *
 * Parameters:
 *   stage_dir — directory holding the marker + partial
 *   name — ".commit" marker basename to reap
 *   log — nginx log for the NOTICE / WARN result line
 */
static ngx_uint_t
reap_one_marker(const char *stage_dir, const char *name, ngx_log_t *log)
{
    char         marker[PATH_MAX], partial[PATH_MAX], final[PATH_MAX];
    size_t       slen = sizeof(BRIX_STAGE_COMMIT_SUFFIX) - 1;
    size_t       nlen = strlen(name);
    int          n;
    struct stat  sb;

    n = snprintf(marker, sizeof(marker), "%s/%s", stage_dir, name);
    if (n < 0 || (size_t) n >= sizeof(marker)) { return 0; }
    n = snprintf(partial, sizeof(partial), "%s/%.*s", stage_dir,
                 (int) (nlen - slen), name);
    if (n < 0 || (size_t) n >= sizeof(partial)) { return 0; }

    if (reap_read_marker_target(marker, final, sizeof(final)) != NGX_OK) {
        (void) unlink(marker);
        return 0;
    }

    if (stat(partial, &sb) != 0) {
        /* Partial already gone (committed elsewhere) — drop the marker. */
        (void) unlink(marker);
        return 0;
    }
    /* Crash-recovery: no open fd, so final_mode is unused (fchmod is fd-guarded);
     * the recovered partial keeps its on-disk mode. */
    if (brix_commit_staged(NGX_INVALID_FILE, partial, final, 0, log) == NGX_OK) {
        (void) unlink(marker);
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "brix: completed pending stage-out \"%s\" -> \"%s\"",
            partial, final);
        return 1;
    }
    ngx_log_error(NGX_LOG_WARN, log, errno,
        "brix: pending stage-out \"%s\" -> \"%s\" failed; will retry",
        partial, final);
    return 0;
}

/* Finish every pending stage-out recorded in stage_dir.  Returns the count of
 * commits completed this pass.  Idempotent and crash-safe: a marker whose partial
 * is already gone (committed by a racing pass / a client retry) is just dropped. */
ngx_uint_t
brix_stage_reap_dir(const char *stage_dir, ngx_log_t *log)
{
    /* Snapshot marker basenames first — we unlink while iterating, which would
     * otherwise make readdir skip entries. */
    char        names[BRIX_STAGE_REAP_MAX_MARKERS][BRIX_STAGE_REAP_NAME_MAX];
    ngx_uint_t  done = 0, ncount, i;

    if (stage_dir == NULL || stage_dir[0] == '\0') {
        return 0;
    }
    ncount = reap_collect_markers(stage_dir, names,
                                  BRIX_STAGE_REAP_MAX_MARKERS);

    for (i = 0; i < ncount; i++) {
        done += reap_one_marker(stage_dir, names[i], log);
    }
    return done;
}

ngx_uint_t
brix_stage_reap_all(ngx_log_t *log)
{
    ngx_uint_t total = 0, i;
    for (i = 0; i < s_stage_dir_count; i++) {
        total += brix_stage_reap_dir(s_stage_dirs[i], log);
    }
    return total;
}

/*
 * WHAT: Atomically rename the temp file to its final path and clean up.
 *
 * WHY: After all data has been written to the staged temp file, commit makes it visible at
 *      the target location. The rename is atomic on POSIX filesystems — readers see either
 *      the old file or the new one, never a partial write.
 *
 * HOW: Close the fd if still open (data should be flushed). Rename tmp_path → final_path via
 *      brix_rename_confined_canon(). On rename failure: unlink the temp file as cleanup. Set
 *      staged->active=0 and clear tmp_path buffer. Return NGX_OK on success, NGX_ERROR on fail.
 *
 * Parameters:
 *   log — nginx log for error/cleanup reporting
 *   root_canon — canonical root for confined rename
 *   staged — the staged file struct (must be active)
 *   final_path — destination path to rename into
 */
static ngx_int_t
staged_commit_internal(ngx_log_t *log, const char *root_canon,
    brix_staged_file_t *staged, const char *final_path, int exclusive)
{
    if (staged == NULL || !staged->active) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    int         rootfd;
    int         rc;
    const char *tmp_rel, *final_rel;

    /* Open the confinement root first so the fsync-failure cleanup path (C1) can
     * unlink the temp without re-opening it. */
    rootfd = brix_beneath_open_root(root_canon);
    if (rootfd < 0) {
        if (staged->fd != NGX_INVALID_FILE) {
            ngx_close_file(staged->fd);
            staged->fd = NGX_INVALID_FILE;
        }
        staged->active = 0;
        return NGX_ERROR;
    }
    tmp_rel   = brix_beneath_strip_root(root_canon, staged->tmp_path);
    final_rel = brix_beneath_strip_root(root_canon, final_path);
    if (tmp_rel == NULL || final_rel == NULL) {
        if (staged->fd != NGX_INVALID_FILE) {
            ngx_close_file(staged->fd);
            staged->fd = NGX_INVALID_FILE;
        }
        close(rootfd);
        staged->active = 0;
        errno = EXDEV;
        return NGX_ERROR;
    }

    /*
     * Phase 51 (C1): flush the staged data to stable storage BEFORE the rename
     * publishes it, so a crash / power loss / ENOSPC mid-write cannot expose a
     * torn object.  A failed fsync means the data is NOT durable — fail the
     * commit (unlink the temp, leave the final path untouched) rather than
     * publish possibly-incomplete data.  (close() alone does not flush.)
     */
    if (staged->fd != NGX_INVALID_FILE) {
        if (fsync(staged->fd) != 0) {
            int e = errno;
            ngx_log_error(NGX_LOG_ERR, log, e,
                          "brix: staged commit fsync failed — not publishing "
                          "\"%s\"", final_path);
            ngx_close_file(staged->fd);
            staged->fd = NGX_INVALID_FILE;
            (void) brix_unlink_beneath(rootfd, tmp_rel, 0);
            close(rootfd);
            staged->active = 0;
            errno = e;
            return NGX_ERROR;
        }
        /* SECURITY: restore the caller's intended mode on the OPEN fd just before
         * the rename publishes it. The temp was written 0600 (private); rename
         * preserves the fd's mode, so the committed namespace object carries its
         * client-intended bits (e.g. 0644) with no world-readable in-flight
         * window. */
        (void) fchmod(staged->fd, staged->final_mode);
        ngx_close_file(staged->fd);
        staged->fd = NGX_INVALID_FILE;
    }

    rc = exclusive ? brix_rename_beneath_excl(rootfd, tmp_rel, final_rel)
                   : brix_rename_beneath(rootfd, tmp_rel, final_rel);
    if (rc != 0) {
        int e = errno;                       /* preserve EEXIST for the caller */
        (void) brix_unlink_beneath(rootfd, tmp_rel, 0);
        close(rootfd);
        staged->active = 0;
        errno = e;
        return NGX_ERROR;
    }

    /* C1: persist the directory entry so the rename itself survives a crash
     * (best-effort — the data is already durable above). */
    (void) fsync(rootfd);

    close(rootfd);
    staged->active = 0;
    staged->tmp_path[0] = '\0';
    return NGX_OK;
}

ngx_int_t
brix_staged_commit(ngx_log_t *log, const char *root_canon,
    brix_staged_file_t *staged, const char *final_path)
{
    return staged_commit_internal(log, root_canon, staged, final_path, 0);
}

ngx_int_t
brix_staged_commit_excl(ngx_log_t *log, const char *root_canon,
    brix_staged_file_t *staged, const char *final_path)
{
    return staged_commit_internal(log, root_canon, staged, final_path, 1);
}

/*
 * WHAT: Close the temp file fd and optionally unlink it from disk.
 *
 * WHY: On write failure or client disconnect, abort cleans up the staged temp file so it
 *      doesn't leak on disk. The caller decides whether to remove the temp file (remove_tmp=1)
 *      or leave it for later inspection (remove_tmp=0).
 *
 * HOW: Close fd if open and valid. If remove_tmp is set AND staged is active AND tmp_path is
 *      non-empty: unlink via brix_unlink_confined_canon(). Always set active=0 and clear
 *      tmp_path buffer.
 *
 * Parameters:
 *   log — nginx log for cleanup error reporting
 *   root_canon — canonical root for confined unlink
 *   staged — the staged file struct (NULL-safe)
 *   remove_tmp — 1 to delete temp file, 0 to leave it on disk
 */
void
brix_staged_abort(ngx_log_t *log, const char *root_canon,
    brix_staged_file_t *staged, ngx_flag_t remove_tmp)
{
    if (staged == NULL) {
        return;
    }

    (void) log;

    if (staged->fd != NGX_INVALID_FILE) {
        ngx_close_file(staged->fd);
        staged->fd = NGX_INVALID_FILE;
    }

    if (remove_tmp && staged->active && staged->tmp_path[0] != '\0') {
        int         rootfd = brix_beneath_open_root(root_canon);
        const char *tmp_rel;

        if (rootfd >= 0) {
            tmp_rel = brix_beneath_strip_root(root_canon, staged->tmp_path);
            if (tmp_rel != NULL) {
                (void) brix_unlink_beneath(rootfd, tmp_rel, 0);
            }
            close(rootfd);
        }
    }

    staged->active = 0;
    staged->tmp_path[0] = '\0';
}
