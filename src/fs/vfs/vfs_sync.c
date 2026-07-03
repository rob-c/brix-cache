/*
 * vfs_sync.c — VFS handle-level truncate and durability.
 *
 * WHAT: Implements brix_vfs_truncate() (resize an open handle to `length`) and
 *       brix_vfs_sync() (flush an open handle to stable storage).
 *
 * WHY:  kXR_truncate and the sync/commit step of writes (kXR_sync, WebDAV PUT
 *       finalisation) operate on an already-open handle rather than a path, so
 *       they live with the file-handle ops; truncate must also keep the handle's
 *       cached size in step with the file.
 *
 * HOW:  truncate validates the handle/fd and a non-negative length, runs a VFS
 *       I/O-core TRUNCATE job, and on success updates fh->size so later reads
 *       see the new length. sync validates the handle and runs a VFS I/O-core
 *       SYNC job. Both are unmetered handle operations (the surrounding write
 *       op records the metric) returning NGX_OK / NGX_ERROR with errno set.
 */
#include "vfs_internal.h"
#include "vfs_io_core.h"

/* Resize the open handle to `length` (ftruncate) and update the cached
 * fh->size. NGX_ERROR with errno set on a bad handle or negative length. */
ngx_int_t
brix_vfs_truncate(brix_vfs_file_t *fh, off_t length)
{
    brix_vfs_job_t job;

    if (fh == NULL || fh->obj.fd == NGX_INVALID_FILE || length < 0) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    brix_vfs_job_truncate_init(&job, fh->obj.fd, length);
    brix_vfs_io_execute(&job);
    if (job.io_errno != 0) {
        errno = job.io_errno;
        return NGX_ERROR;
    }

    fh->size = length;
    return NGX_OK;
}

/* Flush the open handle to stable storage (fsync). NGX_ERROR with errno set on
 * a bad handle or fsync failure. */
ngx_int_t
brix_vfs_sync(brix_vfs_file_t *fh)
{
    brix_vfs_job_t job;

    if (fh == NULL || fh->obj.fd == NGX_INVALID_FILE) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    brix_vfs_job_sync_init(&job, fh->obj.fd);
    brix_vfs_io_execute(&job);
    if (job.io_errno != 0) {
        errno = job.io_errno;
        return NGX_ERROR;
    }

    return NGX_OK;
}
