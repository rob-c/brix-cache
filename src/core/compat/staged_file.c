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
#include "fs/xfer/xfer.h"    /* xrootd_xfer_pump_objects — the shared in-process mover */
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
 * under root_canon (xrootd_make_tmp_path derives the temp name next to
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
 * HOW: Generate a unique tmp_path via xrootd_make_tmp_path(). Open with
 *      open_flags | O_CREAT | O_EXCL inside root_canon via xrootd_open_confined_canon().
 *      Loop up to 'attempts' times (default 16) on EEXIST. On success: set staged->active=1,
 *      store fd and tmp_path, return NGX_OK. On non-EEXIST failure or exhaustion: errno set,
 *      return NGX_ERROR.
 *
 * Parameters:
 *   log — nginx log for error reporting
 *   root_canon — canonical root directory the temp file must reside within
 *   final_path — destination path (used to derive tmp_path name prefix)
 *   open_flags — base open flags (O_WRONLY typically; O_EXCL is added internally)
 *   mode — file creation mode (e.g. 0644)
 *   attempts — max retry count on EEXIST (0 → defaults to 16)
 *   staged — output struct: fd, tmp_path, active flag populated on success
 */
ngx_int_t
xrootd_staged_open(ngx_log_t *log, const char *root_canon,
    const char *final_path, int open_flags, mode_t mode, ngx_uint_t attempts,
    xrootd_staged_file_t *staged)
{
    ngx_uint_t  i;
    int         rootfd;

    (void) log;

    if (staged == NULL || final_path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    ngx_memzero(staged, sizeof(*staged));
    staged->fd = NGX_INVALID_FILE;

    if (attempts == 0) {
        attempts = 16;
    }

    rootfd = xrootd_beneath_open_root(root_canon);
    if (rootfd < 0) {
        return NGX_ERROR;
    }

    for (i = 0; i < attempts; i++) {
        const char *rel;

        if (xrootd_make_tmp_path(final_path, staged->tmp_path,
                                 sizeof(staged->tmp_path)) != NGX_OK)
        {
            errno = ENAMETOOLONG;
            close(rootfd);
            return NGX_ERROR;
        }

        rel = xrootd_beneath_strip_root(root_canon, staged->tmp_path);
        if (rel == NULL) {
            errno = EXDEV;
            close(rootfd);
            return NGX_ERROR;
        }

        staged->fd = xrootd_open_beneath(rootfd, rel,
                                         open_flags | O_CREAT | O_EXCL, mode);
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
 *       (xrootd_make_resume_path) and confinement (xrootd_open_beneath) as the
 *       random staged_open so security and glob-clean are identical.
 *
 * Returns NGX_OK with staged->active=1, or NGX_ERROR (errno set).
 */
ngx_int_t
xrootd_staged_open_resume(ngx_log_t *log, const char *root_canon,
    const char *final_path, const char *principal, const char *stage_dir,
    mode_t mode, xrootd_staged_file_t *staged, off_t *cur_size)
{
    int          rootfd, fd;
    const char  *rel;
    struct stat  sb;

    (void) log;

    if (staged == NULL || final_path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    ngx_memzero(staged, sizeof(*staged));
    staged->fd = NGX_INVALID_FILE;
    if (cur_size != NULL) {
        *cur_size = 0;
    }

    if (xrootd_make_resume_path(final_path, principal, stage_dir,
                                staged->tmp_path, sizeof(staged->tmp_path))
        != NGX_OK)
    {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    if (stage_dir != NULL && stage_dir[0] != '\0') {
        /* Partial lives on the configured fast device (outside root_canon).  The
         * basename is a server-generated hash inside the operator-trusted stage
         * dir, so a direct O_NOFOLLOW open is safe; commit moves it to storage. */
        fd = open(staged->tmp_path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                  mode);
        if (fd == NGX_INVALID_FILE) {
            return NGX_ERROR;
        }
    } else {
        rootfd = xrootd_beneath_open_root(root_canon);
        if (rootfd < 0) {
            return NGX_ERROR;
        }
        rel = xrootd_beneath_strip_root(root_canon, staged->tmp_path);
        if (rel == NULL) {
            close(rootfd);
            errno = EXDEV;
            return NGX_ERROR;
        }
        /* O_CREAT but NOT O_EXCL / O_TRUNC: create-or-resume, preserving bytes. */
        fd = xrootd_open_beneath(rootfd, rel, O_RDWR | O_CREAT, mode);
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
 * Today both ends are POSIX (xrootd_sd_posix_wrap over a kernel fd), so the only
 * raw pread/pwrite happen INSIDE the POSIX backend (src/fs/backend/sd_posix.c) —
 * never here. When a stage or final mount becomes a non-POSIX backend, only how
 * the object is obtained changes (that driver's open() instead of a bare-fd
 * wrap); this positional copy loop is unchanged. 0 / NGX_ERROR (errno set). */
static ngx_int_t
stage_move_objects(xrootd_sd_obj_t *src, xrootd_sd_obj_t *dst)
{
    /* The mover now lives in the transfer engine (src/fs/xfer/xfer_mover_pump.c)
     * as the canonical XROOTD_XFER_MOVE_PUMP strategy; this thin wrapper keeps the
     * two staged-commit callsites unchanged. */
    return xrootd_xfer_pump_objects(src, dst);
}

/* commit_be_logical — the export-root-relative ("/sub/file", or "/" for the root)
 * key form a non-POSIX backend's namespace expects, matching
 * xrootd_vfs_export_relative_root used by every other driver-backed op. */
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
 * commit_staged_to_backend — publish a POSIX-staged partial INTO a non-POSIX
 * storage backend (e.g. pblock) by streaming it through that driver's staged
 * write→commit state machine. This is the cross-FILESYSTEM atomic commit that
 * rename(2) cannot do: the partial lives on an independent POSIX staging mount
 * (xrootd_stage_dir) and the final export is a different, driver-owned namespace,
 * so we read the partial through the (POSIX) source backend and write it through
 * the destination driver's staged_write, then staged_commit (which publishes
 * atomically — for pblock, a single catalog row insert pointing at the freshly
 * written blocks). On success the POSIX partial is unlinked; on failure it is
 * KEPT (a resume client can retry the close) and the driver's staged blob is
 * aborted. Returns NGX_OK / NGX_ERROR (errno set).
 */
static ngx_int_t
commit_staged_to_backend(ngx_fd_t fd, const char *stage_path,
    const char *final_path, xrootd_sd_instance_t *dst, const char *root_canon,
    ngx_log_t *log)
{
    const char         *logical = commit_be_logical(final_path, root_canon);
    xrootd_sd_obj_t     src_obj;
    xrootd_sd_staged_t *st;
    struct stat         sb;
    mode_t              mode;
    int                 rfd, owned = 0, serr = 0;
    off_t               off = 0;

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
    if (fd != NGX_INVALID_FILE) {
        rfd = fd;
    } else {
        rfd = open(stage_path, O_RDONLY | O_CLOEXEC);
        if (rfd < 0) {
            return NGX_ERROR;
        }
        owned = 1;
    }
    mode = (fstat(rfd, &sb) == 0) ? (sb.st_mode & 07777) : 0644;

    st = dst->driver->staged_open(dst, logical, mode, &serr);
    if (st == NULL) {
        if (owned) { (void) close(rfd); }
        errno = serr ? serr : EIO;
        return NGX_ERROR;
    }

    xrootd_sd_posix_wrap(&src_obj, rfd);   /* read the partial via the SD seam */
    for ( ;; ) {
        char    buf[65536];
        ssize_t r = src_obj.driver->pread(&src_obj, buf, sizeof(buf), off);
        ssize_t w = 0;

        if (r < 0) {
            int e = errno;
            dst->driver->staged_abort(st);
            if (owned) { (void) close(rfd); }
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
                if (owned) { (void) close(rfd); }
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
        if (owned) { (void) close(rfd); }
        errno = e ? e : EIO;
        return NGX_ERROR;
    }

    if (owned) { (void) close(rfd); }
    (void) unlink(stage_path);              /* published → drop the partial */
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
xrootd_commit_staged(ngx_fd_t fd, const char *stage_path, const char *final_path,
                     ngx_log_t *log)
{
    char         tmp[PATH_MAX];
    int          rfd, dfd, e;
    struct stat  sb;

    if (fd != NGX_INVALID_FILE) {
        xrootd_sd_obj_t sobj;
        xrootd_sd_posix_wrap(&sobj, fd);   /* durability flush via the backend */
        if (sobj.driver->fsync(&sobj) != NGX_OK) {
            return NGX_ERROR;   /* not durable — do not publish */
        }
    }

    /* Non-POSIX final export (e.g. pblock): the staged POSIX partial lives on an
     * independent staging mount and the final namespace is driver-owned, so
     * rename(2) cannot publish it. Upload the partial INTO the backend via its
     * staged write→commit state machine (a cross-filesystem atomic publish).
     * POSIX exports (the common case) skip this and take the rename path below. */
    {
        const char           *be_root = NULL;
        xrootd_sd_instance_t *dst =
            xrootd_vfs_backend_resolve_for_path(final_path, &be_root, log);

        if (dst != NULL && dst->driver != NULL
            && dst->driver != xrootd_sd_default_driver())
        {
            return commit_staged_to_backend(fd, stage_path, final_path, dst,
                                            be_root, log);
        }
    }

    if (rename(stage_path, final_path) == 0) {
        return NGX_OK;          /* same filesystem: atomic, zero-copy */
    }
    if (errno != EXDEV) {
        return NGX_ERROR;
    }

    /* Cross-device commit: copy the staged data to a temp adjacent to (and on the
     * same filesystem as) the final path, then atomically rename it into place. */
    if (xrootd_make_tmp_path(final_path, tmp, sizeof(tmp)) != NGX_OK) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    rfd = open(stage_path, O_RDONLY | O_CLOEXEC);
    if (rfd < 0) {
        return NGX_ERROR;
    }
    /* Preserve the staged file's mode on the committed object. */
    mode_t mode = (fstat(rfd, &sb) == 0) ? (sb.st_mode & 07777) : 0644;
    dfd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (dfd < 0) {
        e = errno; close(rfd); errno = e; return NGX_ERROR;
    }
    {
        /* VFS↔VFS move: stage object (source backend) → temp object (final
         * backend). Both POSIX today; the loop is driver-mediated so a non-POSIX
         * mount on either side needs no change here. */
        xrootd_sd_obj_t src_obj, dst_obj;
        xrootd_sd_posix_wrap(&src_obj, rfd);
        xrootd_sd_posix_wrap(&dst_obj, dfd);
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
 * When an upload completes, the (complete) staged file must be moved from the
 * stage device to the final storage.  With a synchronous commit the client waits
 * for that move, but if the worker dies mid-move the COMPLETE file is left in the
 * cache with nothing recording where it should go.  A marker file
 * "<stage_partial>.commit" (content = the final absolute path) is written +
 * fsync'd just before the move and removed after it; if the move is interrupted
 * the marker survives, and xrootd_stage_reap_dir() finishes the move on the next
 * worker startup / periodic sweep — so complete-but-uncommitted files are tracked
 * across restarts and always reach storage.
 */
#define XROOTD_STAGE_COMMIT_SUFFIX ".commit"
#define XROOTD_STAGE_MAX_DIRS 32

static char       s_stage_dirs[XROOTD_STAGE_MAX_DIRS][PATH_MAX];
static ngx_uint_t s_stage_dir_count;

void
xrootd_stage_dir_register(const char *canon)
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
    if (s_stage_dir_count >= XROOTD_STAGE_MAX_DIRS) {
        return;
    }
    ngx_memcpy(s_stage_dirs[s_stage_dir_count], canon, strlen(canon) + 1);
    s_stage_dir_count++;
}

ngx_uint_t
xrootd_stage_dir_count(void)
{
    return s_stage_dir_count;
}

ngx_int_t
xrootd_stage_mark_pending(const char *stage_partial, const char *final_path,
                          ngx_log_t *log)
{
    char    marker[PATH_MAX];
    int     fd, n;
    size_t  flen;

    (void) log;
    n = snprintf(marker, sizeof(marker), "%s%s", stage_partial,
                 XROOTD_STAGE_COMMIT_SUFFIX);
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
xrootd_stage_unmark_pending(const char *stage_partial)
{
    char marker[PATH_MAX];
    int  n = snprintf(marker, sizeof(marker), "%s%s", stage_partial,
                      XROOTD_STAGE_COMMIT_SUFFIX);
    if (n > 0 && (size_t) n < sizeof(marker)) {
        (void) unlink(marker);
    }
}

/* Finish every pending stage-out recorded in stage_dir.  Returns the count of
 * commits completed this pass.  Idempotent and crash-safe: a marker whose partial
 * is already gone (committed by a racing pass / a client retry) is just dropped. */
ngx_uint_t
xrootd_stage_reap_dir(const char *stage_dir, ngx_log_t *log)
{
    DIR           *d;
    struct dirent *de;
    ngx_uint_t     done = 0;
    size_t         slen = sizeof(XROOTD_STAGE_COMMIT_SUFFIX) - 1;
    /* Snapshot marker basenames first — we unlink while iterating, which would
     * otherwise make readdir skip entries. */
    char           names[256][256];
    ngx_uint_t     ncount = 0, i;

    if (stage_dir == NULL || stage_dir[0] == '\0') {
        return 0;
    }
    d = opendir(stage_dir);
    if (d == NULL) {
        return 0;
    }
    while ((de = readdir(d)) != NULL && ncount < 256) {
        size_t nlen = strlen(de->d_name);
        if (nlen > slen && nlen < sizeof(names[0])
            && strcmp(de->d_name + nlen - slen, XROOTD_STAGE_COMMIT_SUFFIX) == 0)
        {
            ngx_memcpy(names[ncount], de->d_name, nlen + 1);
            ncount++;
        }
    }
    closedir(d);

    for (i = 0; i < ncount; i++) {
        char        marker[PATH_MAX], partial[PATH_MAX], final[PATH_MAX];
        size_t      nlen = strlen(names[i]);
        int         mfd, n;
        ssize_t     r;
        struct stat sb;

        n = snprintf(marker, sizeof(marker), "%s/%s", stage_dir, names[i]);
        if (n < 0 || (size_t) n >= sizeof(marker)) { continue; }
        n = snprintf(partial, sizeof(partial), "%s/%.*s", stage_dir,
                     (int) (nlen - slen), names[i]);
        if (n < 0 || (size_t) n >= sizeof(partial)) { continue; }

        mfd = open(marker, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (mfd < 0) { continue; }
        r = read(mfd, final, sizeof(final) - 1);
        close(mfd);
        if (r <= 0) { (void) unlink(marker); continue; }
        final[r] = '\0';
        while (r > 0 && (final[r - 1] == '\n' || final[r - 1] == '\r'
                         || final[r - 1] == ' ')) {
            final[--r] = '\0';
        }
        if (final[0] != '/') { (void) unlink(marker); continue; }  /* sanity */

        if (stat(partial, &sb) != 0) {
            /* Partial already gone (committed elsewhere) — drop the marker. */
            (void) unlink(marker);
            continue;
        }
        if (xrootd_commit_staged(NGX_INVALID_FILE, partial, final, log)
            == NGX_OK)
        {
            (void) unlink(marker);
            done++;
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: completed pending stage-out \"%s\" -> \"%s\"",
                partial, final);
        } else {
            ngx_log_error(NGX_LOG_WARN, log, errno,
                "xrootd: pending stage-out \"%s\" -> \"%s\" failed; will retry",
                partial, final);
        }
    }
    return done;
}

ngx_uint_t
xrootd_stage_reap_all(ngx_log_t *log)
{
    ngx_uint_t total = 0, i;
    for (i = 0; i < s_stage_dir_count; i++) {
        total += xrootd_stage_reap_dir(s_stage_dirs[i], log);
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
 *      xrootd_rename_confined_canon(). On rename failure: unlink the temp file as cleanup. Set
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
    xrootd_staged_file_t *staged, const char *final_path, int exclusive)
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
    rootfd = xrootd_beneath_open_root(root_canon);
    if (rootfd < 0) {
        if (staged->fd != NGX_INVALID_FILE) {
            ngx_close_file(staged->fd);
            staged->fd = NGX_INVALID_FILE;
        }
        staged->active = 0;
        return NGX_ERROR;
    }
    tmp_rel   = xrootd_beneath_strip_root(root_canon, staged->tmp_path);
    final_rel = xrootd_beneath_strip_root(root_canon, final_path);
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
                          "xrootd: staged commit fsync failed — not publishing "
                          "\"%s\"", final_path);
            ngx_close_file(staged->fd);
            staged->fd = NGX_INVALID_FILE;
            (void) xrootd_unlink_beneath(rootfd, tmp_rel, 0);
            close(rootfd);
            staged->active = 0;
            errno = e;
            return NGX_ERROR;
        }
        ngx_close_file(staged->fd);
        staged->fd = NGX_INVALID_FILE;
    }

    rc = exclusive ? xrootd_rename_beneath_excl(rootfd, tmp_rel, final_rel)
                   : xrootd_rename_beneath(rootfd, tmp_rel, final_rel);
    if (rc != 0) {
        int e = errno;                       /* preserve EEXIST for the caller */
        (void) xrootd_unlink_beneath(rootfd, tmp_rel, 0);
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
xrootd_staged_commit(ngx_log_t *log, const char *root_canon,
    xrootd_staged_file_t *staged, const char *final_path)
{
    return staged_commit_internal(log, root_canon, staged, final_path, 0);
}

ngx_int_t
xrootd_staged_commit_excl(ngx_log_t *log, const char *root_canon,
    xrootd_staged_file_t *staged, const char *final_path)
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
 *      non-empty: unlink via xrootd_unlink_confined_canon(). Always set active=0 and clear
 *      tmp_path buffer.
 *
 * Parameters:
 *   log — nginx log for cleanup error reporting
 *   root_canon — canonical root for confined unlink
 *   staged — the staged file struct (NULL-safe)
 *   remove_tmp — 1 to delete temp file, 0 to leave it on disk
 */
void
xrootd_staged_abort(ngx_log_t *log, const char *root_canon,
    xrootd_staged_file_t *staged, ngx_flag_t remove_tmp)
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
        int         rootfd = xrootd_beneath_open_root(root_canon);
        const char *tmp_rel;

        if (rootfd >= 0) {
            tmp_rel = xrootd_beneath_strip_root(root_canon, staged->tmp_path);
            if (tmp_rel != NULL) {
                (void) xrootd_unlink_beneath(rootfd, tmp_rel, 0);
            }
            close(rootfd);
        }
    }

    staged->active = 0;
    staged->tmp_path[0] = '\0';
}
