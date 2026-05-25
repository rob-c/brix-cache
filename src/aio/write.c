#include "ngx_xrootd_module.h"
#include "cache/writethrough_metrics.h"

/* ------------------------------------------------------------------ */
/* Async Write I/O — Thread-Pool Offload for Large File Writes            */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the nginx thread-pool offload layer for XRootD write operations. It enables non-blocking pwrite(2) syscalls by posting blocking disk I/O to worker threads, allowing the main event loop to continue processing incoming requests while writes proceed in parallel. Two function pairs exist: (1) xrootd_write_aio_thread + xrootd_write_aio_done for single-segment kXR_write operations, and (2) writev_write_aio_thread + writev_write_aio_done for multi-segment kXR_writev vector writes.
 *
 * WHY: Large file transfers via xrdcp can block the main event loop for extended periods if disk I/O happens synchronously. Thread-pool offload keeps blocking pwrite syscalls off the event-loop thread, enabling concurrent request processing while writes proceed in parallel worker threads. For multi-segment writev requests, each segment is written independently on a worker thread, reducing total transfer time by maximizing parallel throughput. If the client requests sync (kXR_write with sync flag), fsync(2) is called per unique file descriptor after all writes succeed to ensure data durability.
 *
 * HOW: Two-phase pattern — _thread function runs inside nginx worker thread performing blocking pwrite(2) syscall storing nwritten/io_errno in task struct; _done callback fires on main event loop via ngx_post_event mechanism once thread completes — frees detached payload buffer, guards against stale connection (ctx->destroyed check), handles three outcomes: (1) pwrite returned < 0 → kXR_IOError with errno message, (2) short write (nwritten < len) → kXR_IOError "disk full?", (3) success → update byte counters + log access + send kXR_ok (write) or pgwrite status packet. Always fires on main event loop so ctx/c touch is safe after destroyed check — connection cannot be torn down between check and callback because event loop is single-threaded per worker. */

/* ------------------------------------------------------------------ */
/* Section: Single-Segment Write (kXR_write)                              */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_write_aio_thread + xrootd_write_aio_done handles the common kXR_write operation — writing a single payload segment to an open file at a specified offset. The _thread function performs pwrite(2) on the worker thread storing nwritten/io_errno in the task struct; the _done callback fires on main event loop handling completion outcomes, freeing detached payload buffer, and sending appropriate response (kXR_ok for success or kXR_IOError for failures).
 *
 * WHY: Enables large single-segment writes without blocking the event loop. The payload buffer is detached from ctx->payload_buf during AIO posting so the main thread can safely begin reading the next request header while write happens elsewhere in the worker pool. */

/* ------------------------------------------------------------------ */
/* Section: Multi-Segment Write (kXR_writev)                              */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_writev_write_aio_thread + xrootd_writev_write_aio_done handles kXR_writev — scatter-gather write from a vector of (offset, data) segments. Each segment is written independently on a worker thread using pwrite(2), then the _done callback aggregates results and sends response containing success count or error status for each segment.
 *
 * WHY: Enables parallel multi-segment writes where multiple payload segments can be written simultaneously across different file descriptors or offsets, maximizing throughput for bulk data transfers like xrdcp chunked uploads. */

/* ---- Function: xrootd_write_aio_thread() ----
 *
 * WHAT: Thread-pool worker function for kXR_write / kXR_pgwrite operations. Runs inside an nginx worker thread and performs blocking pwrite(2) syscall with the payload pointer, file descriptor, length, and offset from the task struct. Stores nwritten result and io_errno on failure in the task struct — must not touch any nginx state since this function runs outside the main event loop context.
 *
 * WHY: Provides non-blocking write capability by moving blocking pwrite(2) syscalls off the main event-loop thread into worker threads. The worker thread performs the actual disk I/O while the main loop continues processing incoming requests, enabling concurrent request handling during large file writes. */

/* ---- Function: xrootd_write_aio_done() ----
 *
 * WHAT: Main-thread completion callback for kXR_write / kXR_pgwrite operations. Fires on the main event loop once the worker thread completes — frees detached payload buffer (t->payload_to_free), guards against stale connection, then handles three outcomes: (1) pwrite returned < 0 → sends kXR_IOError with errno message, (2) short write (nwritten < len) → sends kXR_IOError "disk full?", (3) success → updates byte counters + logs access + sends kXR_ok (write) or pgwrite status packet (pgwrite). Always fires on main event loop so ctx/c touch is safe after destroyed check — connection cannot be torn down between check and callback because event loop is single-threaded per worker.
 *
 * WHY: Provides completion handling for async write operations — ensures detached payload buffers are freed, stale connections are detected, and appropriate responses are sent based on write outcome. The three-outcome pattern handles failures gracefully (IOError messages) while tracking byte counters for access-log throughput calculation and metrics reporting. */

/*
 * Section: kXR_write / kXR_writev async I/O — multi-segment parallel write for large files.
 *
 * This file implements the thread-pool offload for xrdcp's segmented write mode,
 * where a single request is split into multiple segments and each segment is
 * written by pwrite(2) on a worker thread. If the client requests sync (kXR_write with
 * sync flag), fsync(2) is called per unique file descriptor after all writes succeed.
 *
 * Two function pairs: (1) write_aio_thread + write_aio_done for single-segment kXR_write,
 *   and (2) writev_write_aio_thread + writev_write_aio_done for multi-segment kXR_writev.
 */


/*
 * xrootd_write_aio_thread — thread-pool worker for kXR_write / kXR_pgwrite write operations.
 *
 * WHAT: Performs a single blocking pwrite(2) syscall on the nginx worker thread to write
 * file data at a specified offset. The payload buffer, file descriptor, length, and offset
 * are all pre-configured in the task struct by the main-thread request handler before posting.
 * Only writes nwritten bytes to fd at offset; stores result and errno on failure.
 *
 * WHY: Enables non-blocking write capability by moving blocking pwrite(2) syscalls off
 * the main event-loop thread into worker threads. The worker thread performs actual disk I/O
 * while the main loop continues processing incoming requests, enabling concurrent request handling
 * during large file writes. This function must never touch nginx state (connections, pools, ctx) —
 * all protocol work happens in xrootd_write_aio_done on the main thread after completion.
 *
 * HOW: Calls pwrite(fd, data, len, offset) and stores return value in t->nwritten. On failure
 * (< 0), captures errno into t->io_errno for error message generation by the done callback.
 * Must not touch any nginx state since this runs outside main event loop context.
 */
void
xrootd_write_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_write_aio_t *t = data;

    t->nwritten = pwrite(t->fd, t->data, t->len, t->offset);
    if (t->nwritten < 0) {
        t->io_errno = errno;
    }
}

/*
 * xrootd_write_aio_done — main-thread completion callback for kXR_write / kXR_pgwrite AIO.
 *
 * WHAT: Reconstructs XRootD response after the worker thread finishes pwrite(2) of file data.
 * The response is either a simple kXR_ok acknowledgment (for standard writes) or a pgwrite status
 * packet containing the next expected offset (for page-mode writes with CRC32c). Unlike read AIO,
 * write operations do not send data back to the client — they only confirm completion status.
 *
 * WHY: Provides completion handling for async write operations ensuring detached payload buffers
 * are freed, stale connections detected, and appropriate responses sent based on write outcome.
 * The three-outcome pattern handles failures gracefully (IOError with errno/disk-full message) while
 * tracking byte counters for access-log throughput calculation and metrics reporting. pgwrite mode
 * sends a status packet rather than kXR_ok — the client uses this offset to determine next page to write.
 *
 * HOW: 1) Free detached payload buffer (t->payload_to_free). 2) Restore request context via xrootd_aio_restore_request().
 *   3) Branch on nwritten: negative → send IOError with errno; short write → send "disk full?" error.
 *   4) On success: update ctx->files.bytes_written and session_bytes_written counters, log access event
 *      (offset+length detail), send kXR_ok for standard write or xrootd_send_pgwrite_status() for pgwrite mode,
 *      resume connection via xrootd_aio_resume().
 */
void
xrootd_write_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t            *task = ev->data;
    xrootd_write_aio_t           *t = task->ctx;
    xrootd_ctx_t                 *ctx = t->ctx;
    ngx_connection_t             *c = t->c;
    ngx_stream_xrootd_srv_conf_t *rconf;
    ngx_int_t                     op = XROOTD_OP_WRITE;

    if (t->payload_to_free) {
        ngx_free(t->payload_to_free);
        t->payload_to_free = NULL;
    }

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);

    if (t->nwritten < 0) {
        if (rconf->access_log_fd != NGX_INVALID_FILE) {
            char detail[64];
            snprintf(detail, sizeof(detail), "%lld+%zu",
                     (long long) t->req_offset, t->len);
            xrootd_log_access(ctx, c, "WRITE", t->path, detail,
                              0, kXR_IOError,
                              t->io_errno ? strerror(t->io_errno)
                                          : "async write error",
                              0);
        }
        XROOTD_OP_ERR(ctx, op);
        xrootd_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno)
                                      : "async write error");
        xrootd_aio_resume(c);
        return;
    }

    if ((size_t) t->nwritten < t->len) {
        if (rconf->access_log_fd != NGX_INVALID_FILE) {
            char detail[64];
            snprintf(detail, sizeof(detail), "%lld+%zu",
                     (long long) t->req_offset, t->len);
            xrootd_log_access(ctx, c, "WRITE", t->path, detail,
                              0, kXR_IOError, "short write (disk full?)", 0);
        }
        XROOTD_OP_ERR(ctx, op);
        xrootd_send_error(ctx, c, kXR_IOError, "short write (disk full?)");
        xrootd_aio_resume(c);
        return;
    }

    ctx->files[t->handle_idx].bytes_written += (size_t) t->nwritten;
    ctx->session_bytes_written += (size_t) t->nwritten;
    if (ctx->files[t->handle_idx].wt_enabled) {
        xrootd_wt_mark_dirty(ctx, t->handle_idx,
            t->req_offset + (int64_t) t->nwritten - 1,
            (size_t) t->nwritten);
    }

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];
        snprintf(detail, sizeof(detail), "%lld+%zu",
                 (long long) t->req_offset, t->len);
        xrootd_log_access(ctx, c, "WRITE", t->path, detail,
                          1, 0, NULL, (size_t) t->nwritten);
    }
    XROOTD_OP_OK(ctx, op);

    if (t->is_pgwrite) {
        xrootd_send_pgwrite_status(ctx, c, t->req_offset + (int64_t) t->nwritten);
    } else {
        xrootd_send_ok(ctx, c, NULL, 0);
    }

    xrootd_aio_resume(c);
}

/*
 * xrootd_writev_write_aio_thread — thread-pool worker for kXR_writev multi-segment write operations.
 *
 * WHAT: Performs pwrite(2) on each non-zero segment descriptor from the scatter-gather vector, writing
 * data to different file descriptors or offsets in parallel. Each segment has its own fd, offset, and
 * length (wlen). After all segments complete successfully, if t->do_sync is set, fsync(2) is called
 * for each unique file descriptor ensuring data durability — used when the client sends the kXR_write sync flag.
 *
 * WHY: Enables parallel multi-segment writes where multiple payload segments can be written simultaneously
 * across different file descriptors or offsets, maximizing throughput for bulk data transfers like xrdcp
 * chunked uploads. Each segment is written independently on a worker thread reducing total transfer time.
 * The io_error flag distinguishes between hard failures (pwrite returned < 0, code=1) and soft failures
 * (short write/expected disk-full condition, code=2) — enabling differentiated error messaging by the done callback.
 *
 * HOW: Iterates over t->segs[0..n_segs-1], skipping zero-length segments. For each segment calls pwrite(fd, data, wlen, offset).
 * On failure (< 0): sets io_error=1 with seg-specific error message; on short write: sets io_error=2 with seg index.
 * Accumulates bytes into t->bytes_total for success path. If do_sync enabled, calls fsync(2) per unique fd after all writes succeed.
 */
void
xrootd_writev_write_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_writev_aio_t *t = data;
    size_t               i;

    t->bytes_total = 0;
    t->io_error = 0;

    for (i = 0; i < t->n_segs; i++) {
        xrootd_writev_seg_desc_t *seg = &t->segs[i];
        ssize_t                   nw;

        if (seg->wlen == 0) {
            continue;
        }

        nw = pwrite(seg->fd, seg->data, (size_t) seg->wlen, seg->offset);
        if (nw < 0) {
            t->io_error = 1;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "writev I/O error at seg %d: %s", (int) i, strerror(errno));
            return;
        }
        if ((uint32_t) nw < seg->wlen) {
            t->io_error = 2;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "writev short write at seg %d", (int) i);
            return;
        }

        t->bytes_total += (size_t) nw;
    }

    if (t->do_sync) {
        for (i = 0; i < t->n_segs; i++) {
            if (t->segs[i].wlen > 0) {
                (void) fsync(t->segs[i].fd);
            }
        }
    }
}

/*
 * xrootd_writev_write_aio_done — main-thread completion callback for kXR_writev multi-segment write AIO.
 *
 * WHAT: Reconstructs XRootD response after the worker thread finishes writing all segments in a
 * scatter-gather vector write request. The response is a simple kXR_ok acknowledgment confirming
 * that N_segs were successfully written — unlike read operations, write completion does not send data back.
 * Each segment's byte count is accumulated into both per-handle bytes_written and session total counters.
 *
 * WHY: Provides completion handling for multi-segment write operations ensuring detached payload buffers
 * are freed, stale connections detected, and appropriate responses sent based on aggregate write outcome.
 * The two-outcome pattern handles failures (IOError with segment-specific error message) versus success
 * (per-handle byte accumulation + session-wide tracking). Access-log entry uses "N_segs" detail format
 * rather than individual offset+length entries — reflecting the atomic multi-segment nature of this operation.
 *
 * HOW: 1) Free detached payload buffer (t->payload_buf). 2) Restore request context via xrootd_aio_restore_request().
 *   3) Branch on io_error: non-zero → send IOError with t->err_msg, resume immediately.
 *   4) On success: iterate segments accumulating per-handle bytes_written and session_bytes_written totals,
 *      log "N_segs" access entry (detail format), send kXR_ok, resume connection via xrootd_aio_resume().
 */
void
xrootd_writev_write_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t            *task = ev->data;
    xrootd_writev_aio_t          *t = task->ctx;
    xrootd_ctx_t                 *ctx = t->ctx;
    ngx_connection_t             *c = t->c;
    ngx_stream_xrootd_srv_conf_t *rconf;
    size_t                        i;

    if (t->payload_buf) {
        ngx_free(t->payload_buf);
        t->payload_buf = NULL;
    }

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->io_error) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITEV);
        xrootd_send_error(ctx, c, kXR_IOError, t->err_msg);
        xrootd_aio_resume(c);
        return;
    }

    for (i = 0; i < t->n_segs; i++) {
        if (t->segs[i].wlen > 0) {
            xrootd_file_t *file = &ctx->files[t->segs[i].handle_idx];

            file->bytes_written += t->segs[i].wlen;
            if (file->wt_enabled) {
                xrootd_wt_mark_dirty(ctx, t->segs[i].handle_idx,
                    t->segs[i].offset + (off_t) t->segs[i].wlen - 1,
                    t->segs[i].wlen);
            }
        }
    }
    ctx->session_bytes_written += t->bytes_total;

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);
    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];
        snprintf(detail, sizeof(detail), "%zu_segs", t->n_segs);
        xrootd_log_access(ctx, c, "WRITEV", "-", detail, 1, 0, NULL,
                          t->bytes_total);
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_WRITEV);

    xrootd_send_ok(ctx, c, NULL, 0);
    xrootd_aio_resume(c);
}
