#ifndef BRIX_READ_PREFETCH_H
#define BRIX_READ_PREFETCH_H

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
 *      BRIX_READ_PREFETCH_MIN(1MB) — prevents excessive syscall overhead from tiny hints below 1MB
 *      BRIX_READ_PREFETCH_WINDOW(32MB) — aggressive prefetch window for detected sequential pattern
 *      BRIX_READ_PREFETCH_LOW_WATER(8MB) — conservative extension for non-sequential reads
 *      BRIX_READV_PREFETCH_GAP(128KB) — allows small gaps between readv segments to be merged
 *      BRIX_READV_PREFETCH_MAX(16MB) — total span cap prevents merging very distant segments
 */

#include "core/ngx_brix_module.h"

#define BRIX_READ_PREFETCH_MIN        (1024 * 1024)
#define BRIX_READ_PREFETCH_WINDOW     (32 * 1024 * 1024)
#define BRIX_READ_PREFETCH_LOW_WATER  (8 * 1024 * 1024)
#define BRIX_READV_PREFETCH_GAP       (128 * 1024)
#define BRIX_READV_PREFETCH_MAX       (16 * 1024 * 1024)

/* ---- Function: brix_prefetch_fd_range() ----
 * Provides basic fd-level prefetch hinting using POSIX_FADV_WILLNEED.
 * Validates fd>=0, offset>=0, length>=BRIX_READ_PREFETCH_MIN before calling fadvise(2).
 * Returns silently on ENOSYS/EOPNOTSUPP — best-effort optimization only.
 */
void brix_prefetch_fd_range(ngx_log_t *log, int fd, off_t offset,
    size_t length);

/* ---- Function: brix_prefetch_read_file() ----
 * Provides intelligent sequential detection and windowed hinting based on read_last_end/read_ahead_end state tracking.
 * Sequential pattern detected → extended prefetch window (end + BRIX_READ_PREFETCH_WINDOW).
 * Non-sequential → conservative single-read hint with low-water extension.
 */
void brix_prefetch_read_file(ngx_log_t *log, brix_file_t *file,
    off_t offset, size_t length, off_t file_size);

/* ---- Function: brix_prefetch_flush() ----
 * Forces pending fadvise hints to kernel before merging new segments.
 * Validates fd>=0 && range_end > range_start then calls brix_prefetch_fd_range().
 */
void brix_prefetch_flush(ngx_log_t *log, int fd, off_t range_start,
    off_t range_end);

/* ---- Function: brix_prefetch_readv_segments() ----
 * Provides segment merging and flush orchestration for kXR_readv scatter-gather requests.
 * Merges nearby segments against same fd within BRIX_READV_PREFETCH_GAP/BRIX_READV_PREFETCH_MAX thresholds.
 * Flushes merged range at boundary changes via brix_prefetch_flush().
 */
void brix_prefetch_readv_segments(brix_ctx_t *ctx, ngx_connection_t *c,
    readahead_list *segments, size_t segment_count, size_t readv_seg_max);

#endif /* BRIX_READ_PREFETCH_H */
