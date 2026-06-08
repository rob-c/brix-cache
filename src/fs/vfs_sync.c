#include "vfs_internal.h"

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

ngx_int_t
xrootd_vfs_sync(xrootd_vfs_file_t *fh)
{
    if (fh == NULL || fh->fd == NGX_INVALID_FILE) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    return fsync(fh->fd) == 0 ? NGX_OK : NGX_ERROR;
}
