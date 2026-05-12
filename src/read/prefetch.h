#ifndef XROOTD_READ_PREFETCH_H
#define XROOTD_READ_PREFETCH_H

#include "../ngx_xrootd_module.h"

#define XROOTD_READ_PREFETCH_MIN        (1024 * 1024)
#define XROOTD_READ_PREFETCH_WINDOW     (32 * 1024 * 1024)
#define XROOTD_READ_PREFETCH_LOW_WATER  (8 * 1024 * 1024)
#define XROOTD_READV_PREFETCH_GAP       (128 * 1024)
#define XROOTD_READV_PREFETCH_MAX       (16 * 1024 * 1024)

void xrootd_prefetch_fd_range(ngx_log_t *log, int fd, off_t offset,
    size_t length);
void xrootd_prefetch_read_file(ngx_log_t *log, xrootd_file_t *file,
    off_t offset, size_t length, off_t file_size);
void xrootd_prefetch_flush(ngx_log_t *log, int fd, off_t range_start,
    off_t range_end);
void xrootd_prefetch_readv_segments(xrootd_ctx_t *ctx, ngx_connection_t *c,
    readahead_list *segments, size_t segment_count);

#endif /* XROOTD_READ_PREFETCH_H */
