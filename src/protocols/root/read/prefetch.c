/*
 * prefetch.c — read-ahead hints (POSIX_FADV_WILLNEED) for the read paths.
 */

#include "prefetch.h"
#include "fs/backend/sd.h"   /* read-ahead hints go through the SD seam */
#include <string.h>

/* Issue a WILLNEED read-ahead hint for [offset, offset+length) on fd through
 * the Storage Driver seam (phase-56 B-2).  Best-effort; a no-op on bad args
 * or a driver without the read_advise slot. */
void
brix_prefetch_fd_range(ngx_log_t *log, int fd, off_t offset, size_t length)
{
    brix_sd_obj_t obj;

    if (fd < 0 || offset < 0 || length < BRIX_READ_PREFETCH_MIN) {
        return;
    }

    brix_sd_posix_wrap(&obj, fd);
    if (obj.driver->read_advise != NULL
        && obj.driver->read_advise(&obj, offset, length, BRIX_SD_ADV_WILLNEED)
           != NGX_OK)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, errno,
                       "brix: WILLNEED read-ahead hint ignored: %s",
                       strerror(errno));
    }
}

/* Issue a WILLNEED hint for [offset, offset+length) on a driver-backed object
 * (fd < 0 — e.g. a slice partial-cache handle, which turns the hint into a
 * background block prefetch).  Best-effort; a no-op on bad args or a driver
 * without the read_advise slot. */
void
brix_prefetch_obj_range(ngx_log_t *log, brix_sd_obj_t *obj, off_t offset,
    size_t length)
{
    if (obj == NULL || obj->driver == NULL || obj->driver->read_advise == NULL
        || offset < 0 || length < BRIX_READ_PREFETCH_MIN)
    {
        return;
    }
    if (obj->driver->read_advise(obj, offset, length, BRIX_SD_ADV_WILLNEED)
        != NGX_OK)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, errno,
                       "brix: driver WILLNEED hint ignored: %s",
                       strerror(errno));
    }
}

/* ---- Validate a read-file prefetch request and compute its clamped end ----
 *
 * WHAT: Applies the argument guards for brix_prefetch_read_file() and, when the
 * request is prefetchable, writes the clamped end offset [offset, end) to
 * *end_out and returns 1.  Returns 0 (with *end_out untouched) when the handle
 * is invalid, the read is too small, the offset+length would overflow off_t, or
 * the range collapses to nothing after clamping to file_size.
 *
 * WHY: Isolating the guard/clamp arithmetic keeps the offset/length math (an
 * overflow-safe hot-path calculation) in one small, reviewable place and lets
 * the orchestrator read as a flat sequence of steps without a nested guard
 * ladder.
 *
 * HOW:
 *   1. Reject a null handle, closed fd, negative offset, or sub-threshold read.
 *   2. Reject when offset + length would overflow NGX_MAX_OFF_T_VALUE.
 *   3. Compute end = offset + length, clamping down to file_size when known.
 *   4. Reject a range that clamped away to <= offset; otherwise publish end.
 */
static ngx_flag_t
brix_prefetch_read_end(brix_file_t *file, off_t offset, size_t length,
    off_t file_size, off_t *end_out)
{
    off_t end;

    /* A handle is prefetchable through its raw fd (POSIX fadvise) OR through
     * its driver object (read_advise — e.g. the partial-cache background
     * prefetch); reject only when it has neither. */
    if (file == NULL || (file->fd < 0 && file->sd_obj.driver == NULL)
        || offset < 0 || length < BRIX_READ_PREFETCH_MIN)
    {
        return 0;
    }

    if ((off_t) length > NGX_MAX_OFF_T_VALUE - offset) {
        return 0;
    }

    end = offset + (off_t) length;
    if (file_size > 0 && end > file_size) {
        end = file_size;
    }
    if (end <= offset) {
        return 0;
    }

    *end_out = end;
    return 1;
}

/* ---- Compute the windowed WILLNEED hint range for a sequential read ----
 *
 * WHAT: For a read that continues the handle's sequential stream, writes the
 * read-ahead hint range [*hint_start, *hint_end) that should be issued ahead of
 * end.  When the handle's existing read_ahead_end already extends past the
 * low-water mark (end + LOW_WATER), no new hint is needed and both outputs are
 * set equal (an empty range the caller skips).
 *
 * WHY: The sequential windowing — low-water suppression, start clamped to the
 * already-prefetched frontier, and end extended by the read-ahead window and
 * clamped to file_size — is the subtle part of the prefetch policy.  Extracting
 * it as a pure computation (state read from file, results returned by pointer,
 * no I/O) keeps the arithmetic exact and independently reviewable.
 *
 * HOW:
 *   1. Compute the low-water mark end + LOW_WATER (saturating at off_t max).
 *   2. If read_ahead_end is already past low-water, emit an empty range (skip).
 *   3. Start the hint at the further of read_ahead_end (the prefetched frontier)
 *      and offset.
 *   4. End the hint at end + WINDOW (saturating), clamped down to file_size.
 */
static void
brix_prefetch_seq_window(brix_file_t *file, off_t offset, off_t end,
    off_t file_size, off_t *hint_start, off_t *hint_end)
{
    off_t low_water_end;

    if (end > NGX_MAX_OFF_T_VALUE - BRIX_READ_PREFETCH_LOW_WATER) {
        low_water_end = NGX_MAX_OFF_T_VALUE;
    } else {
        low_water_end = end + BRIX_READ_PREFETCH_LOW_WATER;
    }

    if (file->read_ahead_end > low_water_end) {
        /* Already prefetched past the low-water mark; issue no new hint. */
        *hint_start = 0;
        *hint_end = 0;
        return;
    }

    *hint_start = (file->read_ahead_end > offset)
                  ? file->read_ahead_end : offset;

    if (end > NGX_MAX_OFF_T_VALUE - BRIX_READ_PREFETCH_WINDOW) {
        *hint_end = NGX_MAX_OFF_T_VALUE;
    } else {
        *hint_end = end + BRIX_READ_PREFETCH_WINDOW;
    }
    if (file_size > 0 && *hint_end > file_size) {
        *hint_end = file_size;
    }
}

/* Sequential-aware prefetch for a read handle: detect sequential access from the
 * handle's read_last_end / read-ahead window and issue a windowed WILLNEED hint
 * ahead of the current read.  No-op for random access. */
void
brix_prefetch_read_file(ngx_log_t *log, brix_file_t *file, off_t offset,
    size_t length, off_t file_size)
{
    off_t      end = 0, hint_start = 0, hint_end = 0;
    ngx_flag_t sequential;

    if (!brix_prefetch_read_end(file, offset, length, file_size, &end)) {
        return;
    }

    sequential = (file->read_last_end < 0 || offset == file->read_last_end);
    if (!sequential) {
        /* Random access resets the read-ahead frontier and hints exactly the
         * requested range — but only on a raw fd (a page-cache warm-up).  A
         * driver-backed handle gets NO hint on random access: the read itself
         * fills exactly what it needs, and a speculative background fill of
         * the same blocks would double the origin traffic (XrdPfc
         * disable-on-random parity). */
        file->read_ahead_end = 0;
        if (file->sd_obj.driver == NULL) {
            hint_start = offset;
            hint_end = end;
        }
    } else if (file->sd_obj.driver != NULL) {
        /* Driver-backed sequential stream: hint the full engine window off
         * the CURRENT read cursor on every read.  The engine-side
         * read_ahead_end frontier is wrong here — it assumes the whole hint
         * was honored, but the driver clamps to its own prefetch window,
         * which would starve a long stream after the first burst.  The
         * driver keeps a per-handle rolling frontier instead, so repeated
         * hints over already-queued or cached blocks cost one bitmap peek. */
        hint_start = end;
        hint_end = (end > NGX_MAX_OFF_T_VALUE - BRIX_READ_PREFETCH_WINDOW)
                   ? NGX_MAX_OFF_T_VALUE : end + BRIX_READ_PREFETCH_WINDOW;
        if (file_size > 0 && hint_end > file_size) {
            hint_end = file_size;
        }
    } else {
        brix_prefetch_seq_window(file, offset, end, file_size,
                                 &hint_start, &hint_end);
    }

    if (hint_end > hint_start) {
        if (file->sd_obj.driver != NULL) {
            brix_prefetch_obj_range(log, &file->sd_obj, hint_start,
                                      (size_t) (hint_end - hint_start));
        } else {
            brix_prefetch_fd_range(log, file->fd, hint_start,
                                     (size_t) (hint_end - hint_start));
        }
        file->read_ahead_end = hint_end;
    }

    file->read_last_end = end;
}

/* Emit the pending coalesced prefetch range as a single WILLNEED hint on fd. */
void
brix_prefetch_flush(ngx_log_t *log, int fd, off_t range_start,
    off_t range_end)
{
    if (fd >= 0 && range_end > range_start) {
        brix_prefetch_fd_range(log, fd, range_start,
                                 (size_t) (range_end - range_start));
    }
}

/* Issue read-ahead hints for the segments of a kXR_readv request. */
void
brix_prefetch_readv_segments(brix_ctx_t *ctx, ngx_connection_t *c,
    readahead_list *segments, size_t segment_count, size_t readv_seg_max)
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
        if (handle_index < 0 || handle_index >= BRIX_MAX_FILES
            || ctx->files[handle_index].fd < 0)
        {
            continue;
        }

        request_length = (uint32_t) ntohl((uint32_t) segments[i].rlen);
        if ((size_t) request_length > readv_seg_max) {
            request_length = (uint32_t) readv_seg_max;
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
         * those ranges before issuing the WILLNEED hint so one vector request
         * does not turn into many tiny kernel hints.
         */
        if (merged_fd == fd
            && segment_start >= merged_start
            && segment_start <= merged_end + (off_t) BRIX_READV_PREFETCH_GAP
            && segment_end - merged_start <= (off_t) BRIX_READV_PREFETCH_MAX)
        {
            if (segment_end > merged_end) {
                merged_end = segment_end;
            }
            continue;
        }

        brix_prefetch_flush(c->log, merged_fd, merged_start, merged_end);
        merged_fd = fd;
        merged_start = segment_start;
        merged_end = segment_end;
    }

    brix_prefetch_flush(c->log, merged_fd, merged_start, merged_end);
}
