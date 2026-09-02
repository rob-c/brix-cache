/*
 * staged_file.c — Shared temp-file open/commit/abort lifecycle.
 *
 * Atomic write pattern: create a unique temp file inside the confined root, write data to it,
 * then rename to the final path. On failure, abort (close + optionally unlink). Used by S3 PUT,
 * WebDAV PUT, and other operations that need crash-safe writes.
 */

#include "staged_file.h"
#include "tmp_path.h"
#include "lock_record.h"                    /* phase-107 C7: lock carry-over */
#include "fs/path/path.h"
#include "fs/path/beneath.h"
#include "auth/impersonate/impersonate.h"   /* brix_imp_client_active */
#include "fs/vfs/vfs_backend_registry.h"    /* brix_vfs_backend_durable */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
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


/*
 * staged_seal_temp — make the staged TEMP publishable: flush its data, restore
 * the caller's intended mode, close the fd.
 *
 * Phase 51 (C1): flush the staged data to stable storage BEFORE the rename
 * publishes it, so a crash / power loss / ENOSPC mid-write cannot expose a
 * torn object.  A failed fsync means the data is NOT durable — fail the
 * commit (unlink the temp, leave the final path untouched) rather than
 * publish possibly-incomplete data.  (close() alone does not flush.)
 *
 * SECURITY (mode restore): the temp was written 0600 (private); the committed
 * object carries its client-intended bits (e.g. 0644) with no world-readable
 * in-flight window.  Under impersonation the fd fchmod runs as the
 * unprivileged worker on the MAPPED USER's file and EPERMs (silently),
 * leaving the object 0600 and blocking group DAC on a shared/setgid-dir
 * upload — so re-apply the mode AS THE MAPPED USER via the broker
 * (path-based), which the fd fchmod cannot reach.
 *
 * A no-op when the fd is already closed.  On failure: fd closed, temp
 * unlinked, staged deactivated, errno set — the caller only closes rootfd.
 */
static ngx_int_t
staged_seal_temp(ngx_log_t *log, const char *root_canon,
    brix_staged_file_t *staged, int rootfd, const char *tmp_rel,
    const char *final_path)
{
    if (staged->fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }
    if (fsync(staged->fd) != 0) {
        int e = errno;
        ngx_log_error(NGX_LOG_ERR, log, e,
                      "brix: staged commit fsync failed — not publishing "
                      "\"%s\"", final_path);
        ngx_close_file(staged->fd);
        staged->fd = NGX_INVALID_FILE;
        (void) brix_unlink_beneath(rootfd, tmp_rel, 0);
        staged->active = 0;
        errno = e;
        return NGX_ERROR;
    }
    if (staged->final_mode != 0 && brix_imp_client_active()) {
        (void) brix_chmod_confined_canon(log, root_canon, staged->tmp_path,
                                           staged->final_mode);
    } else {
        (void) fchmod(staged->fd, staged->final_mode);
    }
    ngx_close_file(staged->fd);
    staged->fd = NGX_INVALID_FILE;
    return NGX_OK;
}

/*
 * WHAT: Carry a live WebDAV lock record across a replace-publish.
 *
 * WHY:  Phase-107 C7 — the lock record (BRIX_LOCK_XATTR_KEY) lives in an xattr
 *       ON the destination inode, and a rename publish REPLACES that inode. An
 *       ADMITTED write under a live lock (the owner presenting the If: token
 *       over WebDAV, or any write on an `advisory`-enforcement export) must
 *       not silently discharge the lock: RFC 4918 §7.4 — a write does not
 *       remove a lock. Only the lock STATE MACHINE (UNLOCK/expiry reap) may.
 *
 * HOW:  Quiet lgetxattr on the current destination; the absent class (ENOENT,
 *       ENODATA, ENOTSUP, an over-cap value) means nothing to carry (NGX_OK).
 *       A record found is copied VERBATIM onto the about-to-publish temp —
 *       expired records included: expiry is the gate's question, and the reap
 *       belongs to the WebDAV edge, never to a commit. A failed copy FAILS
 *       the commit (errno preserved): publishing would strip the lock.
 */
ngx_int_t
brix_staged_lock_carry(ngx_log_t *log, const char *final_path,
    const char *tmp_path)
{
    char     buf[BRIX_LOCK_XATTR_MAXLEN];
    ssize_t  n;

    n = lgetxattr(final_path, BRIX_LOCK_XATTR_KEY, buf, sizeof(buf));
    if (n <= 0) {
        return NGX_OK;              /* absent class: nothing to carry */
    }
    if (lsetxattr(tmp_path, BRIX_LOCK_XATTR_KEY, buf, (size_t) n, 0) != 0) {
        int e = errno;

        ngx_log_error(NGX_LOG_ERR, log, e,
                      "brix: staged publish could not carry the lock record "
                      "onto \"%s\" — refusing a lock-stripping publish",
                      tmp_path);
        errno = e;
        return NGX_ERROR;
    }
    return NGX_OK;
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
/* Open the confinement root and strip both paths to their root-relative
 * forms. Returns the rootfd, or -1 after full cleanup (temp fd closed,
 * staged deactivated; errno = EXDEV on a path that does not strip). Split
 * from staged_commit_internal to keep its decision count in budget. */
static int
staged_commit_confine(const char *root_canon, brix_staged_file_t *staged,
    const char *final_path, const char **tmp_rel, const char **final_rel)
{
    int  rootfd;

    /* Open the confinement root first so the fsync-failure cleanup path (C1) can
     * unlink the temp without re-opening it. */
    rootfd = brix_beneath_open_root(root_canon);
    if (rootfd < 0) {
        if (staged->fd != NGX_INVALID_FILE) {
            ngx_close_file(staged->fd);
            staged->fd = NGX_INVALID_FILE;
        }
        staged->active = 0;
        return -1;
    }
    *tmp_rel   = brix_beneath_strip_root(root_canon, staged->tmp_path);
    *final_rel = brix_beneath_strip_root(root_canon, final_path);
    if (*tmp_rel == NULL || *final_rel == NULL) {
        if (staged->fd != NGX_INVALID_FILE) {
            ngx_close_file(staged->fd);
            staged->fd = NGX_INVALID_FILE;
        }
        close(rootfd);
        staged->active = 0;
        errno = EXDEV;
        return -1;
    }
    return rootfd;
}

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

    rootfd = staged_commit_confine(root_canon, staged, final_path,
                                     &tmp_rel, &final_rel);
    if (rootfd < 0) {
        return NGX_ERROR;
    }

    if (staged_seal_temp(log, root_canon, staged, rootfd, tmp_rel,
                           final_path) != NGX_OK)
    {
        int e = errno;
        close(rootfd);
        errno = e;
        return NGX_ERROR;
    }

    /* Phase-107 C7: the replace-publish swaps the destination inode — carry a
     * live lock record onto the temp first so an ADMITTED write under a lock
     * does not discharge it (brix_staged_lock_carry). The exclusive commit
     * (RENAME_NOREPLACE) has no destination inode to carry from. */
    if (!exclusive
        && brix_staged_lock_carry(log, final_path, staged->tmp_path) != NGX_OK)
    {
        int e = errno;

        (void) brix_unlink_beneath(rootfd, tmp_rel, 0);
        close(rootfd);
        staged->active = 0;
        errno = e;
        return NGX_ERROR;
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

    /* Phase-107 C3: persist the DIRECTORY ENTRY so the rename itself survives
     * a crash. This replaces an inert (void) fsync(rootfd): rootfd is O_PATH
     * (fsync = EBADF, discarded) and the export ROOT is the wrong directory
     * anyway — the publish to a/b/c needs a/b flushed. A failed barrier FAILS
     * the commit: the name is already visible and cannot be un-renamed, but a
     * publish that reports success without durability is the exact bug this
     * barrier exists to remove (the caller sees EIO; dirsync logged at crit).
     * Gated per export by brix_durable_publish (absent/unregistered = on). */
    if (brix_vfs_backend_durable(root_canon)
        && brix_publish_dirsync(log, rootfd, root_canon, final_rel) != NGX_OK)
    {
        int e = errno ? errno : EIO;

        close(rootfd);
        staged->active = 0;
        staged->tmp_path[0] = '\0';   /* the temp was consumed by the rename */
        errno = e;
        return NGX_ERROR;
    }

    close(rootfd);
    staged->active = 0;
    staged->tmp_path[0] = '\0';
    return NGX_OK;
}


/*
 * brix_publish_dirsync — see staged_file.h.
 *
 * HOW: derive the parent as everything before the last '/' of the
 *      root-relative path ("." when the object sits directly under the root),
 *      open it beneath the anchor with O_RDONLY — the one flag combination an
 *      fsync accepts — and flush. The parent fd is derived from the SAME
 *      rootfd the rename used, so a symlink swapped in after the rename can
 *      redirect the flush only chroot-style within the export, never outside
 *      it (RESOLVE_IN_ROOT).
 */
ngx_int_t
brix_publish_dirsync(ngx_log_t *log, int rootfd, const char *root_canon,
    const char *final_path)
{
    char        parent[PATH_MAX];
    const char *rel, *slash;
    size_t      n;
    int         anchor = rootfd, dirfd, e;

    if (final_path == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    /* Accept both forms the callers hand in: an ABSOLUTE canonical path under
     * root_canon (vfs_rename's resolved dst), or a ROOT-RELATIVE tail — which
     * strip_root itself produces WITH its leading '/' kept (staged commit's
     * final_rel), so a failed strip on a '/'-path is not an escape, it is the
     * already-relative form. beneath_rel then drops the slashes either way;
     * RESOLVE_BENEATH keeps every interpretation confined. */
    rel = final_path;
    if (rel[0] == '/') {
        const char *stripped = brix_beneath_strip_root(root_canon, rel);

        if (stripped != NULL) {
            rel = stripped;
        }
    }
    rel = brix_beneath_rel(rel);
    slash = strrchr(rel, '/');
    if (slash == NULL) {
        parent[0] = '.'; parent[1] = '\0';
    } else {
        n = (size_t) (slash - rel);
        if (n == 0 || n >= sizeof(parent)) {
            errno = EINVAL;
            return NGX_ERROR;
        }
        memcpy(parent, rel, n);
        parent[n] = '\0';
    }

    if (anchor < 0) {
        anchor = brix_beneath_open_root(root_canon);
        if (anchor < 0) {
            return NGX_ERROR;
        }
    }
    dirfd = brix_open_beneath(anchor, parent,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    e = errno;
    if (anchor != rootfd) {
        close(anchor);
    }
    if (dirfd < 0) {
        errno = e;
        return NGX_ERROR;
    }
    if (fsync(dirfd) != 0) {
        e = errno;
        close(dirfd);
        ngx_log_error(NGX_LOG_CRIT, log, e,
                      "brix: durable publish: parent dirsync of \"%s\" "
                      "failed — the published name is NOT durable", final_path);
        errno = e ? e : EIO;
        return NGX_ERROR;
    }
    close(dirfd);
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
