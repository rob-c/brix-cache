#ifndef XROOTD_READ_PREFETCH_H
#define XROOTD_READ_PREFETCH_H

/* ---- Module: Read Prefetch Helpers ----
 *
 * WHAT: Configuration constants and function declarations for POSIX_FADV_WILLNEED-based read-ahead prefetch optimization.
 *       Constants define minimum hint length, sequential window size, low-water mark, and readv segment merge thresholds.
 *       Functions provide fd-level hints, sequential detection with windowed extension, flush orchestration,
 *       and scatter-gather segment merging for kXR_readv requests.
 *
 * WHY: Prefetch reduces latency for sequential file reads by telling the filesystem cache that upcoming data will be accessed soon.
 *      Constants tuned for HEP data patterns: 1MB minimum prevents tiny hints overhead, 32MB window enables xrdcp streaming prefetch,
 *      8MB low-water conservatively extends non-sequential reads, readv merge gap/limits reduce syscall count on scatter-gather requests.
 */

/* ---- Constants: Prefetch Thresholds ----
 *
 * WHY: These values are tuned for HEP data transfer patterns (xrdcp streaming, Python client chunked reads):
 *      XROOTD_READ_PREFETCH_MIN(1MB) — prevents excessive syscall overhead from tiny hints below 1MB
 *      XROOTD_READ_PREFETCH_WINDOW(32MB) — aggressive prefetch window for detected sequential pattern
 *      XROOTD_READ_PREFETCH_LOW_WATER(8MB) — conservative extension for non-sequential reads
 *      XROOTD_READV_PREFETCH_GAP(128KB) — allows small gaps between readv segments to be merged
 *      XROOTD_READV_PREFETCH_MAX(16MB) — total span cap prevents merging very distant segments
 */

#include "../ngx_xrootd_module.h"

#define XROOTD_READ_PREFETCH_MIN        (1024 * 1024)
#define XROOTD_READ_PREFETCH_WINDOW     (32 * 1024 * 1024)
#define XROOTD_READ_PREFETCH_LOW_WATER  (8 * 1024 * 1024)
#define XROOTD_READV_PREFETCH_GAP       (128 * 1024)
#define XROOTD_READV_PREFETCH_MAX       (16 * 1024 * 1024)

/* ---- Function: xrootd_prefetch_fd_range() ----
 * Provides basic fd-level prefetch hinting using POSIX_FADV_WILLNEED.
 * Validates fd>=0, offset>=0, length>=XROOTD_READ_PREFETCH_MIN before calling fadvise(2).
 * Returns silently on ENOSYS/EOPNOTSUPP — best-effort optimization only.
 */
void xrootd_prefetch_fd_range(ngx_log_t *log, int fd, off_t offset,
    size_t length);

/* ---- Function: xrootd_prefetch_read_file() ----
 * Provides intelligent sequential detection and windowed hinting based on read_last_end/read_ahead_end state tracking.
 * Sequential pattern detected → extended prefetch window (end + XROOTD_READ_PREFETCH_WINDOW).
 * Non-sequential → conservative single-read hint with low-water extension.
 */
void xrootd_prefetch_read_file(ngx_log_t *log, xrootd_file_t *file,
    off_t offset, size_t length, off_t file_size);

/* ---- Function: xrootd_prefetch_flush() ----
 * Forces pending fadvise hints to kernel before merging new segments.
 * Validates fd>=0 && range_end > range_start then calls xrootd_prefetch_fd_range().
 */
void xrootd_prefetch_flush(ngx_log_t *log, int fd, off_t range_start,
    off_t range_end);

/* ---- Function: xrootd_prefetch_readv_segments() ----
 * Provides segment merging and flush orchestration for kXR_readv scatter-gather requests.
 * Merges nearby segments against same fd within XROOTD_READV_PREFETCH_GAP/XROOTD_READV_PREFETCH_MAX thresholds.
 * Flushes merged range at boundary changes via xrootd_prefetch_flush().
 */
void xrootd_prefetch_readv_segments(xrootd_ctx_t *ctx, ngx_connection_t *c,
    readahead_list *segments, size_t segment_count, size_t readv_seg_max);

#endif /* XROOTD_READ_PREFETCH_H */
