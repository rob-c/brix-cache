#include "core/ngx_xrootd_module.h"

/*
 * kXR_readv async I/O — multi-segment parallel read for large files.
 *
 * This file implements the thread-pool offload for xrdcp's segmented read mode,
 * where a single request is split into multiple segments and each segment is
 * fetched by the VFS I/O core on a worker thread. The response is assembled as:
 *   [segment header][segment payload] × N_segments
 *
 * Two functions: the _thread function does the blocking I/O; the _done callback
 * builds the response chain on the main event loop and resumes connection flow.
 */


/*
 * xrootd_readv_aio_thread — thread-pool worker for kXR_readv.
 *
 * The main nginx thread has already allocated the response buffer and computed
 * the segment layout (header + payload pointers per segment).  This worker
 * only executes the VFS READV job to fill each segment's payload region and records totals.
 *
 * The response layout is:
 *   For each segment i:
 *     [xrootd_readv_seg_header (XROOTD_READV_SEGSIZE bytes)]
 *     [up to read_length bytes of file data at payload_ptr]
 *
 * t->response_bytes = n_segments * XROOTD_READV_SEGSIZE + bytes_read_total.
 * Segments that pread to fewer bytes than requested are zero-padded by the
 * thread (the per-segment header's rlen is updated to reflect the actual bytes
 * read by xrootd_readv_read_segments).
 */
void
xrootd_readv_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_readv_aio_t *t = data;
    xrootd_vfs_job_t    job;

    t->bytes_read_total = 0;
    t->io_error = 0;
    t->response_bytes = 0;
    t->err_msg[0] = '\0';

    /*
     * The main nginx thread already built the response layout.  The worker
     * only fills payload pointers and records totals; it must not touch the
     * connection or request parser state.
     */
    ngx_memzero(&job, sizeof(job));
    job.op = XROOTD_VFS_IO_READV;
    job.segs = t->segments;
    job.nsegs = t->segment_count;
    job.err_msg = t->err_msg;
    job.err_msg_cap = sizeof(t->err_msg);

    xrootd_vfs_io_execute(&job);

    if (job.io_errno != 0) {
        t->io_error = 1;
        if (t->err_msg[0] == '\0') {
            snprintf(t->err_msg, sizeof(t->err_msg), "readv I/O error");
        }
        return;
    }

    t->bytes_read_total = (size_t) job.nio;
    t->response_bytes = job.out_size;
}

/*
 * xrootd_readv_aio_done — main-thread response builder for kXR_readv AIO completion.
 *
 * WHAT: Reconstructs the XRootD response chain after the worker thread finishes reading
 * all segments in a segmented read request. The response consists of multiple segment headers
 * (each containing segment size, handle index, offset) followed by their corresponding payload data.
 * Unlike standard kXR_read, each segment has its own header describing which file and offset
 * it corresponds to — enabling clients to reassemble fragments from potentially different sources.
 *
 * WHY: kXR_readv enables parallel multi-segment reads for large files where segments can be fetched
 * concurrently across different file descriptors or offsets. This callback must handle four distinct paths:
 * connection teardown (free segments + buffer), I/O error (send IOError message), success (build chain,
 * update counters), and allocation failure (release before resume). The segment array is dynamically allocated
 * by the main thread and freed here after all processing completes.
 *
 * HOW: 1) Restore request context via xrootd_aio_restore_request(). 2) Free segments on failure path.
 *   3) On I/O error: send kXR_IOError with t->err_msg, release buffers, resume.
 *   4) On success: update session_bytes and per-handle bytes_read for each segment, build chunked chain via
 *      xrootd_build_chunked_chain(), queue response, free segments array, resume connection events.
 */
void
xrootd_readv_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    xrootd_readv_aio_t  *t = task->ctx;
    xrootd_ctx_t        *ctx = t->ctx;
    ngx_connection_t    *c = t->c;
    ngx_chain_t         *rsp_chain;
    size_t               i;

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        ngx_free(t->segments);
        xrootd_release_read_buffer(ctx, c, t->response_buffer);
        return;
    }

    if (t->io_error) {
        ngx_free(t->segments);
        xrootd_release_read_buffer(ctx, c, t->response_buffer);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
        xrootd_send_error(ctx, c, kXR_IOError, t->err_msg);
        xrootd_aio_resume(c);
        return;
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_READV);
    ctx->session_bytes += t->bytes_read_total;
    for (i = 0; i < t->segment_count; i++) {
        ctx->files[t->segments[i].handle_index].bytes_read +=
            t->segments[i].read_length;
    }

    rsp_chain = xrootd_build_chunked_chain(ctx, c,
                                           t->response_buffer,
                                           t->response_bytes);
    if (rsp_chain == NULL) {
        ngx_free(t->segments);
        xrootd_release_read_buffer(ctx, c, t->response_buffer);
        xrootd_aio_resume(c);
        return;
    }

    ngx_free(t->segments);
    xrootd_queue_response_chain(ctx, c, rsp_chain, t->response_buffer);
    if (ctx->state != XRD_ST_SENDING) {
        xrootd_release_read_buffer(ctx, c, t->response_buffer);
    }
    xrootd_aio_resume(c);
}
