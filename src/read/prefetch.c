/* ------------------------------------------------------------------ */
/* Read Prefetch — POSIX Fadvise Helpers                                    */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements three helper functions for read-ahead optimization using POSIX_FADV_WILLNEED fadvise(2) hints. xrootd_prefetch_fd_range() provides basic fd-level prefetch hinting with minimum length guard (XROOTD_READ_PREFETCH_MIN); xrootd_prefetch_read_file() provides intelligent sequential detection and windowed hinting based on read_last_end/read_ahead_end state tracking; xrootd_prefetch_flush() forces pending hints to kernel before merging new segments.
 *
 * WHY: Read-ahead prefetch hints reduce latency for sequential file reads by telling the filesystem cache that upcoming data will be accessed soon. Sequential detection (xrootd_prefetch_read_file) optimizes hinting when consecutive reads arrive at same offset as previous read end — enables extended windowed prefetching beyond single-read boundaries. Segment merging in xrootd_prefetch_readv_segments reduces kernel fadvise call count for readv requests by consolidating nearby segments into larger hints before issuing POSIX_FADV_WILLNEED, preventing excessive syscall overhead from many tiny hints.
 *
 * HOW: Three-phase hinting → xrootd_prefetch_fd_range(): fd/offset/length validation (fd<0 || offset<0 || length<XROOTD_READ_PREFETCH_MIN guard) — POSIX_FADV_WILLNEED call with debug logging on ENOSYS/EOPNOTSUPP; xrootd_prefetch_read_file(): sequential detection (read_last_end < 0 || offset == read_last_end), windowed extension (end + XROOTD_READ_PREFETCH_WINDOW or low-water end + XROOTD_READ_PREFETCH_LOW_WATER depending on sequential state), merged hint via xrootd_prefetch_fd_range(); xrootd_prefetch_flush(): range validation (fd>=0 && range_end > range_start) — forces pending hints to kernel; xrootd_prefetch_readv_segments(): segment iteration with merge logic (same fd + nearby offset + gap < XROOTD_READV_PREFETCH_GAP + total < XROOTD_READV_PREFETCH_MAX triggers merge, else flush previous merged range). */

/* ------------------------------------------------------------------ */
/* Section: Basic Fadvise Hinting                                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_prefetch_fd_range() provides basic fd-level prefetch hinting using POSIX_FADV_WILLNEED. Validates parameters (fd<0 || offset<0 || length<XROOTD_READ_PREFETCH_MIN guard) before calling fadvise(2). Returns silently on ENOSYS/EOPNOTSUPP — some filesystems or platforms do not support posix_fadvise and the hint is optional, not required for correct operation. Debug logging captures unsupported cases without elevating to error level since prefetch is best-effort optimization only.
 *
 * WHY: Best-effort prefetch provides performance improvement when supported but does not affect correctness — calls failing due to unsupported filesystem or platform are silently ignored rather than causing operational errors. XROOTD_READ_PREFETCH_MIN guard prevents tiny hints from excessive syscall overhead — small length ranges would generate many fadvise calls without meaningful benefit, wasting CPU cycles on kernel interface overhead. */

/* ------------------------------------------------------------------ */
/* Section: Sequential Detection and Windowed Hinting                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_prefetch_read_file() provides intelligent sequential detection and windowed hinting based on read_last_end/read_ahead_end state tracking in xrootd_file_t. Sequential detection (read_last_end < 0 || offset == read_last_end) determines whether consecutive reads arrive at same offset as previous read end — enables extended windowed prefetching beyond single-read boundaries when sequential pattern detected. Non-sequential reads reset read_ahead_end to 0 preventing stale hints from interfering with random access patterns.
 *
 * WHY: Sequential detection optimizes hinting for common read patterns (xrdcp streaming downloads, Python client chunked reads) where consecutive requests arrive at predictable offsets extending previous read end. Windowed extension (end + XROOTD_READ_PREFETCH_WINDOW or low-water end + XROOTD_READ_PREFETCH_LOW_WATER depending on sequential state) provides aggressive prefetch when sequential detected, conservative hinting for non-sequential patterns preventing wasted cache space from random access speculation. */

/* ------------------------------------------------------------------ */
/* Section: Segment Merging for Readv                                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_prefetch_readv_segments() provides segment merging and flush orchestration for kXR_readv scatter-gather requests. Iterates through segment list, merges nearby segments against same fd within XROOTD_READV_PREFETCH_GAP offset window and XROOTD_READV_PREFETCH_MAX total span before issuing fadvise(2) call — consolidating many tiny hints into fewer larger ones reducing syscall overhead from readv requests with many small segments. Flushes merged range at segment boundary changes via xrootd_prefetch_flush() ensuring pending hints reach kernel before new merge begins.
 *
 * WHY: Segment merging prevents excessive syscall overhead from readv requests where clients may request hundreds of tiny segments against same file — consolidating nearby segments into larger hints reduces fadvise(2) call count significantly while maintaining equivalent prefetch coverage. XROOTD_READV_PREFETCH_GAP window allows small gaps between segments to be merged (common in chunked uploads), preventing each gap from triggering separate flush cycle and syscall overhead. */

/* ---- Function: xrootd_prefetch_fd_range() ----
 *
 * WHAT: Provides basic fd-level prefetch hinting using POSIX_FADV_WILLNEED fadvise(2). Validates parameters (fd<0 || offset<0 || length<XROOTD_READ_PREFETCH_MIN guard) before calling fadvise(2). Returns silently on ENOSYS/EOPNOTSUPP — some filesystems or platforms do not support posix_fadvise and the hint is optional, not required for correct operation. Debug logging captures unsupported cases without elevating to error level since prefetch is best-effort optimization only. XROOTD_READ_PREFETCH_MIN guard prevents tiny hints from excessive syscall overhead.
 *
 * WHY: Best-effort prefetch provides performance improvement when supported but does not affect correctness — calls failing due to unsupported filesystem or platform are silently ignored rather than causing operational errors. XROOTD_READ_PREFETCH_MIN guard prevents tiny hints from excessive syscall overhead — small length ranges would generate many fadvise calls without meaningful benefit, wasting CPU cycles on kernel interface overhead.
 *
 * HOW: Parameter validation (fd<0 || offset<0 || length<XROOTD_READ_PREFETCH_MIN) — POSIX_FADV_WILLNEED call with debug logging on ENOSYS/EOPNOTSUPP — return silently on unsupported cases since prefetch is best-effort optimization only. */

/* ---- Function: xrootd_prefetch_read_file() ----
 *
 * WHAT: Provides intelligent sequential detection and windowed hinting based on read_last_end/read_ahead_end state tracking in xrootd_file_t. Sequential detection (read_last_end < 0 || offset == read_last_end) determines whether consecutive reads arrive at same offset as previous read end — enables extended windowed prefetching beyond single-read boundaries when sequential pattern detected. Non-sequential reads reset read_ahead_end to 0 preventing stale hints from interfering with random access patterns. Windowed extension (end + XROOTD_READ_PREFETCH_WINDOW or low-water end + XROOTD_READ_PREFETCH_LOW_WATER depending on sequential state) provides aggressive prefetch when sequential detected, conservative hinting for non-sequential patterns preventing wasted cache space from random access speculation.
 *
 * WHY: Sequential detection optimizes hinting for common read patterns (xrdcp streaming downloads, Python client chunked reads) where consecutive requests arrive at predictable offsets extending previous read end. Windowed extension provides aggressive prefetch when sequential detected, conservative hinting for non-sequential patterns preventing wasted cache space from random access speculation. Non-sequential pattern detection prevents stale hints from interfering with random access patterns by resetting read_ahead_end to 0.
 *
 * HOW: Parameter validation (file==NULL || fd<0 || offset<0 || length<XROOTD_READ_PREFETCH_MIN) — sequential detection (read_last_end < 0 || offset == read_last_end) — non-sequential resets read_ahead_end=0, sequential enables windowed extension — hint range calculation (end + XROOTD_READ_PREFETCH_WINDOW or low-water end + XROOTD_READ_PREFETCH_LOW_WATER depending on sequential state and overflow guard) — merged hint via xrootd_prefetch_fd_range() updating file->read_last_end and file->read_ahead_end. */

/* ---- Function: xrootd_prefetch_flush() ----
 *
 * WHAT: Forces pending fadvise hints to kernel before merging new segments. Validates range (fd>=0 && range_end > range_start) then calls xrootd_prefetch_fd_range() with accumulated offset/length pair — ensuring pending hints reach kernel before new merge begins in readv segment processing. Used by xrootd_prefetch_readv_segments() at segment boundary changes to flush previous merged range before starting new merge cycle.
 *
 * WHY: Ensures pending hints are delivered to filesystem cache before new hint ranges begin accumulating — prevents stale hints from being lost when merge boundaries change during readv segment iteration. Without explicit flush, accumulated hints could be discarded if merge begins new cycle without delivering previous accumulated range to kernel first.
 *
 * HOW: Range validation (fd>=0 && range_end > range_start) — calls xrootd_prefetch_fd_range() with accumulated offset/length pair ensuring pending hints reach kernel before new merge begins in readv segment processing. */

/* ---- Function: xrootd_prefetch_readv_segments() ----
 *
 * WHAT: Provides segment merging and flush orchestration for kXR_readv scatter-gather requests. Iterates through segment list, merges nearby segments against same fd within XROOTD_READV_PREFETCH_GAP offset window and XROOTD_READV_PREFETCH_MAX total span before issuing fadvise(2) call — consolidating many tiny hints into fewer larger ones reducing syscall overhead from readv requests with many small segments. Flushes merged range at segment boundary changes via xrootd_prefetch_flush() ensuring pending hints reach kernel before new merge begins.
 *
 * WHY: Segment merging prevents excessive syscall overhead from readv requests where clients may request hundreds of tiny segments against same file — consolidating nearby segments into larger hints reduces fadvise(2) call count significantly while maintaining equivalent prefetch coverage. XROOTD_READV_PREFETCH_GAP window allows small gaps between segments to be merged (common in chunked uploads), preventing each gap from triggering separate flush cycle and syscall overhead.
 *
 * HOW: Segment iteration with merge logic (same fd + nearby offset + gap < XROOTD_READV_PREFETCH_GAP + total < XROOTD_READV_PREFETCH_MAX triggers merge, else flush previous merged range via xrootd_prefetch_flush()) — accumulated merged_fd/merged_start/merged_end tracking across segments — final flush at iteration end ensuring all pending hints reach kernel. */

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
        if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES
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
