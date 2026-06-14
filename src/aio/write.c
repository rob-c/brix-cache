#include "ngx_xrootd_module.h"
#include "cache/writethrough_metrics.h"
#include "write/wrts_journal.h"

/*
 * xrootd_write_aio_thread — thread-pool worker for kXR_write / kXR_pgwrite.
 *
 * Runs on a worker thread; must not touch nginx state, connection pools, or
 * any field that is not owned by the task struct.
 */
void
xrootd_write_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_write_aio_t *t = data;

    /*
     * Off-loop blocking write.  Capture errno into the task struct immediately:
     * errno is thread-local and would be clobbered before the done callback runs
     * on the main thread.  No nginx state may be touched from here.
     */
    t->nwritten = pwrite(t->fd, t->data, t->len, t->offset);
    if (t->nwritten < 0) {
        t->io_errno = errno;
    }
}

/*
 * xrootd_write_aio_done — main-thread completion callback for kXR_write / kXR_pgwrite AIO.
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

    /*
     * Free the detached payload first, before the restore guard can bail out.
     * The worker copied the wire bytes into this heap buffer so the recv buffer
     * could be reused while the write was in flight; we own it regardless of
     * whether the connection still exists, so free it unconditionally to avoid
     * a leak on the early-return path below.
     */
    if (t->payload_to_free) {
        ngx_free(t->payload_to_free);
        t->payload_to_free = NULL;
    }

    /*
     * Re-entry / liveness guard.  This callback was posted from a worker thread
     * and may fire after the client disconnected (ctx torn down) or after the
     * stream was reassigned.  restore_request validates streamid still maps to
     * this request and re-arms the request context; if it returns false the
     * connection is gone and we must touch nothing further (ctx/c are stale).
     */
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

    /*
     * Short write: pwrite returned a non-negative count smaller than requested.
     * POSIX permits this (typically disk-full / quota), but the kXR_write
     * protocol has no partial-success reply, so we surface it as a hard
     * kXR_IOError rather than acknowledging fewer bytes than the client sent.
     */
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

    /* Success path: commit accounting and side effects on the main thread. */
    ctx->files[t->handle_idx].bytes_written += (size_t) t->nwritten;
    ctx->session_bytes_written += (size_t) t->nwritten;
    if (ctx->files[t->handle_idx].wt_enabled) {
        /*
         * Mark the write-through cache range dirty.  The dirty-mark API takes
         * the LAST byte offset of the range (inclusive), not the start, hence
         * req_offset + nwritten - 1.  req_offset is the file offset the client
         * requested (t->offset is the same value; req_offset is kept distinct
         * for logging the original request).
         */
        xrootd_wt_mark_dirty(ctx, t->handle_idx,
            t->req_offset + (int64_t) t->nwritten - 1,
            (size_t) t->nwritten);
    }

    /* Record the committed write in the recovery journal. */
    if (ctx->files[t->handle_idx].wrts_enabled) {
        xrootd_wrts_record(&ctx->files[t->handle_idx], t->req_offset,
                           (uint32_t) t->nwritten);
    }

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];
        snprintf(detail, sizeof(detail), "%lld+%zu",
                 (long long) t->req_offset, t->len);
        xrootd_log_access(ctx, c, "WRITE", t->path, detail,
                          1, 0, NULL, (size_t) t->nwritten);
    }
    XROOTD_OP_OK(ctx, op);

    /*
     * Reply framing differs by opcode: kXR_pgwrite expects a kXR_status response
     * carrying the next expected offset (offset just past the bytes committed),
     * whereas plain kXR_write expects a bare kXR_ok with no body.
     */
    if (t->is_pgwrite) {
        xrootd_send_pgwrite_status(ctx, c, t->req_offset + (int64_t) t->nwritten);
    } else {
        xrootd_send_ok(ctx, c, NULL, 0);
    }

    /* Re-arm the connection events and resume the recv loop for the next op. */
    xrootd_aio_resume(c);
}

/*
 * xrootd_writev_write_aio_thread — thread-pool worker for kXR_writev multi-segment write.
 *
 * Runs on a worker thread. io_error=1 on hard failure, io_error=2 on short write.
 * If do_sync is set, fsync(2) is called per unique fd after all segments succeed.
 */
void
xrootd_writev_write_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_writev_aio_t *t = data;
    size_t               i;

    t->bytes_total = 0;
    t->io_error = 0;

    /*
     * Write each segment to its own (fd, offset).  On the first failing segment
     * we record the error and return immediately — earlier segments may already
     * be on disk, but the protocol reply is all-or-nothing, so we do not attempt
     * to roll back or continue. io_error encodes the failure kind for the done
     * callback: 1 = hard pwrite error, 2 = short write.
     */
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

    /*
     * Optional durability barrier (kXR_writev with the sync flag).  Reached only
     * after every segment wrote successfully — the error paths above returned
     * early, so a failed writev never fsyncs partial data.  fsync is called once
     * per segment fd; if multiple segments share an fd this issues redundant but
     * harmless syncs, and the return value is intentionally ignored (best-effort
     * flush; a hard sync failure would surface on the next op).
     */
    if (t->do_sync) {
        for (i = 0; i < t->n_segs; i++) {
            if (t->segs[i].wlen > 0) {
                (void) fsync(t->segs[i].fd);
            }
        }
    }
}

/*
 * xrootd_writev_write_aio_done — completion callback for kXR_writev AIO.
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

    /*
     * Free the detached payload before the liveness guard: we own this heap
     * buffer (the worker wrote from it) and must release it even when the
     * connection has gone away on the early-return path below.
     */
    if (t->payload_buf) {
        ngx_free(t->payload_buf);
        t->payload_buf = NULL;
    }

    /*
     * Liveness guard — see xrootd_write_aio_done.  If the request can't be
     * restored the connection is dead; ctx/c are stale, so return now.
     */
    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->io_error) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITEV);
        xrootd_send_error(ctx, c, kXR_IOError, t->err_msg);
        xrootd_aio_resume(c);
        return;
    }

    /*
     * Success path: apply per-segment accounting, journal, and cache state on
     * the main thread (the worker only does I/O). Each segment may target a
     * different open file handle, so resolve ctx->files per segment.
     */
    for (i = 0; i < t->n_segs; i++) {
        if (t->segs[i].wlen > 0) {
            xrootd_file_t *file = &ctx->files[t->segs[i].handle_idx];

            file->bytes_written += t->segs[i].wlen;

            /* Record the committed write in the recovery journal. */
            if (file->wrts_enabled) {
                xrootd_wrts_record(file, (int64_t) t->segs[i].offset,
                                   t->segs[i].wlen);
            }

            if (file->wt_enabled) {
                /* Dirty range end is inclusive: offset + wlen - 1. */
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
