/*
 * staged_file.c — Shared temp-file open/commit/abort lifecycle.
 *
 * Atomic write pattern: create a unique temp file inside the confined root, write data to it,
 * then rename to the final path. On failure, abort (close + optionally unlink). Used by S3 PUT,
 * WebDAV PUT, and other operations that need crash-safe writes.
 */

#include "staged_file.h"
#include "tmp_path.h"
#include "../path/path.h"
#include "../path/beneath.h"

#include <errno.h>
#include <fcntl.h>
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

    (void) log;

    if (staged->fd != NGX_INVALID_FILE) {
        ngx_close_file(staged->fd);
        staged->fd = NGX_INVALID_FILE;
    }

    rootfd = xrootd_beneath_open_root(root_canon);
    if (rootfd < 0) {
        staged->active = 0;
        return NGX_ERROR;
    }
    tmp_rel   = xrootd_beneath_strip_root(root_canon, staged->tmp_path);
    final_rel = xrootd_beneath_strip_root(root_canon, final_path);
    if (tmp_rel == NULL || final_rel == NULL) {
        close(rootfd);
        staged->active = 0;
        errno = EXDEV;
        return NGX_ERROR;
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
