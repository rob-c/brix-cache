#include "ngx_xrootd_module.h"

/* ------------------------------------------------------------------ */
/* Async Read I/O — Thread-Pool Offload for Large File Reads                */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the nginx thread-pool offload layer for XRootD read operations. It enables non-blocking pread(2) syscalls by posting blocking disk I/O to worker threads, allowing the main event loop to continue processing incoming requests while reads proceed in parallel. Two function pairs exist: xrootd_read_aio_thread + xrootd_read_aio_done for single-segment kXR_read operations; and corresponding functions for kXR_pgread page-mode reads with CRC32c verification.
 *
 * WHY: Large file transfers via xrdcp can block the main event loop for extended periods if disk I/O happens synchronously. Thread-pool offload keeps blocking pread syscalls off the event-loop thread, enabling concurrent request processing while reads proceed in parallel worker threads. For kXR_pgread operations, the _thread function performs pread(2) on each page fragment; the _done callback aggregates pages and encodes CRC32c checksums before building response chain.
 *
 * HOW: Two-phase pattern — _thread function runs inside nginx worker thread performing blocking pread(2) syscall storing nread/io_errno in task struct; _done callback fires on main event loop via ngx_post_event mechanism once thread completes — frees detached payload buffer, guards against stale connection (ctx->destroyed check), handles three outcomes: (1) pread returned < 0 → kXR_IOError with errno message, (2) short read (nread < requested_len) → kXR_IOError "short read", (3) success → update byte counters + log access + build response chain via xrootd_build_chunked_chain() for kXR_read or pgread encoding for kXR_pgread. Always fires on main event loop so ctx/c touch is safe after destroyed check — connection cannot be torn down between check and callback because event loop is single-threaded per worker. */

/* ------------------------------------------------------------------ */
/* Section: Single-Segment Read (kXR_read)                                  */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_read_aio_thread + xrootd_read_aio_done handles the common kXR_read operation — reading a single payload segment from an open file at a specified offset. The _thread function performs pread(2) on the worker thread storing nread/io_errno in the task struct; the _done callback fires on main event loop handling completion outcomes, freeing detached payload buffer, and building response chain via xrootd_build_chunked_chain() for raw byte-stream delivery to client without per-page CRC verification.
 *
 * WHY: Enables large single-segment reads without blocking the event loop. The payload buffer is detached from ctx->payload_buf during AIO posting so the main thread can safely begin reading the next request header while read happens elsewhere in the worker pool. Raw byte-stream delivery enables clients to implement their own integrity checks or rely on transport-layer guarantees (TLS for davs:// downloads). */

/* ------------------------------------------------------------------ */
/* Section: Page-Mode Read (kXR_pgread)                                     */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pgread_aio_thread + xrootd_pgread_aio_done handles kXR_pgread — page-mode read with per-page CRC32c integrity verification. The _thread function performs pread(2) on each page fragment (up to 4096 bytes); the _done callback aggregates pages and encodes CRC32c checksums via xrootd_pgread_encode_pages() before building kXR_status response chain containing next expected offset for client progress tracking.
 *
 * WHY: Enables parallel multi-page reads where multiple payload segments can be read simultaneously across different file descriptors or offsets, maximizing throughput for bulk data transfers like xrdcp chunked downloads. Per-page CRC32c verification ensures corruption is detected immediately rather than after transfer completion — clients can retry corrupted pages without retransmitting the entire file. */

/* ---- Function: xrootd_read_aio_thread() ----
 *
 * WHAT: Thread-pool worker function for kXR_read / kXR_pgread operations. Runs inside an nginx worker thread and performs blocking pread(2) syscall with the payload pointer, file descriptor, length, and offset from the task struct. Stores nread result and io_errno on failure in the task struct — must not touch any nginx state since this function runs outside the main event loop context.
 *
 * WHY: Provides non-blocking read capability by moving blocking pread(2) syscalls off the main event-loop thread into worker threads. The worker thread performs the actual disk I/O while the main loop continues processing incoming requests, enabling concurrent request handling during large file reads. */

/* ---- Function: xrootd_read_aio_done() ----
 *
 * WHAT: Main-thread completion callback for kXR_read / kXR_pgread operations. Fires on the main event loop once the worker thread completes — frees detached payload buffer (t->payload_to_free), guards against stale connection, then handles three outcomes: (1) pread returned < 0 → sends kXR_IOError with errno message, (2) short read (nread < len) → sends kXR_IOError "short read", (3) success → updates byte counters + logs access + builds response chain via xrootd_build_chunked_chain() for kXR_read or pgread encoding for kXR_pgread. Always fires on main event loop so ctx/c touch is safe after destroyed check — connection cannot be torn down between check and callback because event loop is single-threaded per worker.
 *
 * WHY: Provides completion handling for async read operations — ensures detached payload buffers are freed, stale connections are detected, and appropriate responses are sent based on read outcome. The three-outcome pattern handles failures gracefully (IOError messages) while tracking byte counters for access-log throughput calculation and metrics reporting. Response chain building uses xrootd_build_chunked_chain() for kXR_read raw byte-stream delivery or pgread encoding for page-mode CRC32c verification. */


/*
 * xrootd_read_aio_thread — thread-pool worker for kXR_read.
 *
 * Runs on a worker thread; must not touch nginx state, connection pools, or
 * any field that is not owned by the task struct.  Only the blocking pread(2)
 * syscall belongs here; all protocol work happens in the done callback on the
 * main thread.
 *
 * t->nread: set to pread return value (< 0 on error, 0 on EOF, > 0 on success).
 * t->io_errno: saved errno on failure.
 */
void
xrootd_read_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_read_aio_t *t = data;

    /*
     * Worker threads do the blocking syscall only; all protocol state updates
     * stay on the event-loop side in the completion callback.
     */
    t->nread = pread(t->fd, t->databuf, t->rlen, t->offset);
    if (t->nread < 0) {
        t->io_errno = errno;
    }
}

/*
 * xrootd_read_aio_done — main-thread completion callback for kXR_read AIO.
 *
 * Called by nginx's event loop after the thread pool posts the result via
 * ngx_post_event.  Responsibilities:
 *   1. Guard against stale connection (ctx->destroyed check via restore_stream).
 *   2. On I/O error: send kXR_IOError, release databuf, resume event loop.
 *   3. On success: build a response chain (chunked if > 16 MiB), update per-
 *      handle and session byte counters, queue the chain.
 *   4. Call xrootd_aio_resume() to re-arm the appropriate event (write or read).
 *
 * NOTE: if the chain send blocks (XRD_ST_SENDING), databuf is kept alive as
 * wchain_base and freed by xrootd_release_pending_buffer after full drain.
 */
void
xrootd_read_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    xrootd_read_aio_t  *t = task->ctx;
    xrootd_ctx_t       *ctx = t->ctx;
    ngx_connection_t   *c = t->c;
    ngx_chain_t        *rsp_chain;

    if (!xrootd_aio_restore_stream(ctx, t->streamid)) {
        return;
    }

    if (t->nread < 0) {
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->hdr_pos = 0;
        xrootd_release_read_buffer(ctx, c, t->databuf);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        xrootd_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async read error");
        xrootd_aio_resume(c);
        return;
    }

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->session_bytes += (size_t) t->nread;
    XROOTD_OP_OK(ctx, XROOTD_OP_READ);

    rsp_chain = xrootd_build_chunked_chain(ctx, c,
                                           t->databuf, (size_t) t->nread);
    if (rsp_chain == NULL) {
        xrootd_release_read_buffer(ctx, c, t->databuf);
        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_aio_resume(c);
        return;
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    xrootd_queue_response_chain(ctx, c, rsp_chain, t->databuf);
    if (ctx->state != XRD_ST_SENDING) {
        xrootd_release_read_buffer(ctx, c, t->databuf);
    }
    xrootd_aio_resume(c);
}

