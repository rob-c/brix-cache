#include "ngx_xrootd_module.h"

#if (NGX_THREADS)

/*
 * xrootd_write_aio_thread — thread-pool worker for kXR_write / kXR_pgwrite.
 *
 * Calls pwrite(2) with the payload pointer and offset from the task struct.
 * Sets t->nwritten and t->io_errno.  Must not touch any nginx state.
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
 * xrootd_write_aio_done — main-thread completion callback for kXR_write /
 * kXR_pgwrite.
 *
 * Frees the detached payload buffer (t->payload_to_free), guards against stale
 * connection, then handles three outcomes:
 *   - pwrite returned < 0: sends kXR_IOError with errno message.
 *   - short write (nwritten < len): sends kXR_IOError "disk full?".
 *   - success: updates byte counters, logs access, sends kXR_ok (write) or
 *     the pgwrite status packet (pgwrite).
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
 * xrootd_writev_write_aio_thread — thread-pool worker for kXR_writev.
 *
 * Iterates over all segment descriptors and calls pwrite(2) for each non-zero
 * segment.  Sets t->io_error (1=pwrite error, 2=short write) and t->err_msg on
 * failure, t->bytes_total on success.
 *
 * If t->do_sync is set, fsync(2) is called for each unique file descriptor
 * after all writes succeed — used when the client sends the kXR_write sync flag.
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
 * xrootd_writev_write_aio_done — main-thread completion callback for kXR_writev.
 *
 * Frees the detached payload buffer, guards against stale connection, then:
 *   - On io_error: sends kXR_IOError with the error message string.
 *   - On success: accumulates per-handle and session byte totals, logs
 *     the "N_segs" access-log entry, sends kXR_ok.
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
            ctx->files[t->segs[i].handle_idx].bytes_written += t->segs[i].wlen;
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

#endif /* NGX_THREADS */
