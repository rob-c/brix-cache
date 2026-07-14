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

#include <errno.h>
#include <fcntl.h>
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
