/*
 * vfs_sync.c — VFS handle-level truncate and durability.
 *
 * WHAT: Implements xrootd_vfs_truncate() (resize an open handle to `length`) and
 *       xrootd_vfs_sync() (flush an open handle to stable storage).
 *
 * WHY:  kXR_truncate and the sync/commit step of writes (kXR_sync, WebDAV PUT
 *       finalisation) operate on an already-open handle rather than a path, so
 *       they live with the file-handle ops; truncate must also keep the handle's
 *       cached size in step with the file.
 *
 * HOW:  truncate validates the handle/fd and a non-negative length, calls
 *       ftruncate(2), and on success updates fh->size so later reads see the new
 *       length. sync validates the handle and calls fsync(2). Both are direct,
 *       unmetered handle operations (the surrounding write op records the
 *       metric) returning NGX_OK / NGX_ERROR with errno set.
 */
#include "vfs_internal.h"

/* Resize the open handle to `length` (ftruncate) and update the cached
 * fh->size. NGX_ERROR with errno set on a bad handle or negative length. */
ngx_int_t
xrootd_vfs_truncate(xrootd_vfs_file_t *fh, off_t length)
{
    if (fh == NULL || fh->fd == NGX_INVALID_FILE || length < 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (ftruncate(fh->fd, length) != 0) {
        return NGX_ERROR;
    }

    fh->size = length;
    return NGX_OK;
}

/* Flush the open handle to stable storage (fsync). NGX_ERROR with errno set on
 * a bad handle or fsync failure. */
ngx_int_t
xrootd_vfs_sync(xrootd_vfs_file_t *fh)
{
    if (fh == NULL || fh->fd == NGX_INVALID_FILE) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    return fsync(fh->fd) == 0 ? NGX_OK : NGX_ERROR;
}
