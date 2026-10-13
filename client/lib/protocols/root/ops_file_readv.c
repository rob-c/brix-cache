/* Public kXR_readv wrappers around the shared frame/accumulation engine. */
#include "protocols/root/ops_internal.h"

static ssize_t
readv_guarded(brix_conn *connection, brix_file *file,
    brix_file *const *files, brix_readv_seg *segments, size_t count,
    unsigned *partial_frames, brix_status *status)
{
    ssize_t result;

    brix_io_stall_arm(&connection->io);
    result = brix_readv_frames(connection, file, files, segments, count,
        partial_frames, status);
    brix_io_stall_disarm(&connection->io);
    return result;
}

ssize_t
brix_file_readv(brix_conn *connection, brix_file *file,
    brix_readv_seg *segments, size_t count, brix_status *status)
{
    return readv_guarded(connection, file, NULL, segments, count, NULL,
        status);
}

ssize_t
brix_file_readv_profile(brix_conn *connection, brix_file *file,
    brix_readv_seg *segments, size_t count, unsigned *partial_frames,
    brix_status *status)
{
    return readv_guarded(connection, file, NULL, segments, count,
        partial_frames, status);
}

ssize_t
brix_file_readv_multi(brix_conn *connection, brix_file *const *files,
    brix_readv_seg *segments, size_t count, brix_status *status)
{
    return readv_guarded(connection, count > 0 ? files[0] : NULL, files,
        segments, count, NULL, status);
}
