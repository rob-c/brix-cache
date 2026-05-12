#include "prefetch.h"
#include <string.h>

void
xrootd_prefetch_fd_range(ngx_log_t *log, int fd, off_t offset, size_t length)
{
#if defined(POSIX_FADV_WILLNEED)
    int rc;
    if (fd < 0 || offset < 0 || length < XROOTD_READ_PREFETCH_MIN) {
        return;
    }
    rc = posix_fadvise(fd, offset, (off_t) length, POSIX_FADV_WILLNEED);
    if (rc != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, rc,
                       "xrootd: POSIX_FADV_WILLNEED ignored: %s",
                       strerror(rc));
    }
#else
    (void) log;
    (void) fd;
    (void) offset;
    (void) length;
#endif
}

void
xrootd_prefetch_read_file(ngx_log_t *log, xrootd_file_t *file, off_t offset,
    size_t length, off_t file_size)
{
    off_t      end, hint_start, hint_end, low_water_end;
    ngx_flag_t sequential;

    if (file == NULL || file->fd < 0 || offset < 0
        || length < XROOTD_READ_PREFETCH_MIN)
    {
        return;
    }

    if ((off_t) length > NGX_MAX_OFF_T_VALUE - offset) {
        return;
    }

    end = offset + (off_t) length;
    if (file_size > 0 && end > file_size) {
        end = file_size;
    }
    if (end <= offset) {
        return;
    }

    sequential = (file->read_last_end < 0 || offset == file->read_last_end);
    if (!sequential) {
        file->read_ahead_end = 0;
    }

    if (sequential) {
        if (end > NGX_MAX_OFF_T_VALUE - XROOTD_READ_PREFETCH_LOW_WATER) {
            low_water_end = NGX_MAX_OFF_T_VALUE;
        } else {
            low_water_end = end + XROOTD_READ_PREFETCH_LOW_WATER;
        }

        if (file->read_ahead_end > low_water_end) {
            file->read_last_end = end;
            return;
        }

        hint_start = (file->read_ahead_end > offset)
                     ? file->read_ahead_end : offset;

        if (end > NGX_MAX_OFF_T_VALUE - XROOTD_READ_PREFETCH_WINDOW) {
            hint_end = NGX_MAX_OFF_T_VALUE;
        } else {
            hint_end = end + XROOTD_READ_PREFETCH_WINDOW;
        }
        if (file_size > 0 && hint_end > file_size) {
            hint_end = file_size;
        }

    } else {
        hint_start = offset;
        hint_end = end;
    }

    if (hint_end > hint_start) {
        xrootd_prefetch_fd_range(log, file->fd, hint_start,
                                 (size_t) (hint_end - hint_start));
        file->read_ahead_end = hint_end;
    }

    file->read_last_end = end;
}

void
xrootd_prefetch_flush(ngx_log_t *log, int fd, off_t range_start,
    off_t range_end)
{
    if (fd >= 0 && range_end > range_start) {
        xrootd_prefetch_fd_range(log, fd, range_start,
                                 (size_t) (range_end - range_start));
    }
}

void
xrootd_prefetch_readv_segments(xrootd_ctx_t *ctx, ngx_connection_t *c,
    readahead_list *segments, size_t segment_count)
{
    int     merged_fd = -1;
    off_t   merged_start = 0;
    off_t   merged_end = 0;
    size_t  i;

    for (i = 0; i < segment_count; i++) {
        int      handle_index;
        int      fd;
        int64_t  request_offset;
        uint32_t request_length;
        off_t    segment_start;
        off_t    segment_end;

        handle_index = (int) (unsigned char) segments[i].fhandle[0];
        if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES
            || ctx->files[handle_index].fd < 0)
        {
            continue;
        }

        request_length = (uint32_t) ntohl((uint32_t) segments[i].rlen);
        if (request_length > XROOTD_READ_MAX) {
            request_length = XROOTD_READ_MAX;
        }
        if (request_length == 0) {
            continue;
        }

        request_offset = (int64_t) be64toh((uint64_t) segments[i].offset);
        if (request_offset < 0
            || (off_t) request_length > NGX_MAX_OFF_T_VALUE - request_offset)
        {
            continue;
        }

        fd = ctx->files[handle_index].fd;
        segment_start = (off_t) request_offset;
        segment_end = segment_start + (off_t) request_length;
        if (segment_end <= segment_start) {
            continue;
        }

        /*
         * readv often arrives as nearby ranges against the same file.  Merge
         * those ranges before issuing posix_fadvise() so one vector request
         * does not turn into many tiny kernel hints.
         */
        if (merged_fd == fd
            && segment_start >= merged_start
            && segment_start <= merged_end + (off_t) XROOTD_READV_PREFETCH_GAP
            && segment_end - merged_start <= (off_t) XROOTD_READV_PREFETCH_MAX)
        {
            if (segment_end > merged_end) {
                merged_end = segment_end;
            }
            continue;
        }

        xrootd_prefetch_flush(c->log, merged_fd, merged_start, merged_end);
        merged_fd = fd;
        merged_start = segment_start;
        merged_end = segment_end;
    }

    xrootd_prefetch_flush(c->log, merged_fd, merged_start, merged_end);
}
