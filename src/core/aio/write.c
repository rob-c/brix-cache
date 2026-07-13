#include "core/ngx_brix_module.h"
#include "fs/cache/writethrough_metrics.h"
#include "protocols/root/write/wrts_journal.h"
#include "protocols/root/connection/disconnect.h"     /* deferred-teardown guards */
#include "protocols/root/connection/event_sched.h"    /* brix_schedule_read_resume */

/*
 * brix_write_aio_thread — thread-pool worker for kXR_write / kXR_pgwrite.
 *
 * Runs on a worker thread; must not touch nginx state, connection pools, or
 * any field that is not owned by the task struct.
 */
void
brix_write_aio_thread(void *data, ngx_log_t *log)
{
    brix_write_aio_t *t = data;
    brix_vfs_job_t    job;

    /*
     * Off-loop blocking write.  Capture errno into the task struct immediately:
     * errno is thread-local and would be clobbered before the done callback runs
     * on the main thread.  No nginx state may be touched from here.
     */
    brix_vfs_job_write_init(&job, t->fd, t->offset, t->data, t->len);
    job.csi = t->csi;                    /* phase-59 W2: update tags in worker */
    brix_vfs_job_set_obj(&job, &t->obj); /* Layer 3: route via driver if bound */
    brix_vfs_io_execute(&job);

    t->nwritten = job.nio;
    t->io_errno = job.io_errno;
}

/*
 * Access-log outcome for one WRITE AIO completion.  Bundles the four
 * per-outcome fields so the shared logger stays within the parameter budget and
 * so success/error callsites name their arguments explicitly.
 */
typedef struct {
    int          ok;          /* 1 = success line, 0 = error line */
    int          xrd_error;   /* kXR error code on the error line, 0 otherwise */
    const char  *errmsg;      /* error detail string, NULL on success */
    size_t       nbytes;      /* bytes written on success, 0 on error */
} brix_write_aio_logrec_t;

/*
 * WHAT: Emit one WRITE access-log line for this AIO completion, gated on the
 *       access-log fd being open.
 * WHY:  Every outcome (error, short-write, success) in both the pipelined and
 *       serial paths logs the same "<req_offset>+<len>" detail through the same
 *       fd-open guard; centralizing the snprintf + guard keeps the log bytes and
 *       the gate identical across all six callsites (the tests grep these lines).
 * HOW:  Skip when access_log_fd is closed; otherwise format the fixed
 *       "%lld+%zu" detail from req_offset/len and forward every field of the
 *       outcome record verbatim to brix_log_access.  c is the live connection
 *       (callers run this only after the destroyed/restore guards).
 */
static void
brix_write_aio_log(brix_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_brix_srv_conf_t *rconf, brix_write_aio_t *t,
                   const brix_write_aio_logrec_t *rec)
{
    char detail[64];

    if (rconf->access_log_fd == NGX_INVALID_FILE) {
        return;
    }

    snprintf(detail, sizeof(detail), "%lld+%zu",
             (long long) t->req_offset, t->len);
    brix_log_access(ctx, c, "WRITE", t->path, detail,
                      rec->ok, rec->xrd_error, rec->errmsg, rec->nbytes);
}

/*
 * WHAT: Commit the success-path accounting and cache/journal side effects for a
 *       completed single-region write.
 * WHY:  The pipelined and serial success paths perform the identical
 *       bytes_written accounting, write-through dirty-marking, and recovery-journal
 *       record; sharing them keeps the two paths in lockstep so a fix to one can
 *       never drift from the other.
 * HOW:  Add nwritten to the per-handle and totals byte counters, then, when the
 *       handle has write-through enabled, mark the written range dirty (the API
 *       takes the LAST inclusive offset, hence req_offset + nwritten - 1) and,
 *       when journalling is enabled, record the committed write.  Pure accounting
 *       plus cache/journal calls — no wire I/O.
 */
static void
brix_write_aio_commit(brix_ctx_t *ctx, brix_write_aio_t *t)
{
    ctx->files[t->handle_idx].bytes_written += (size_t) t->nwritten;
    ctx->totals.bytes_written += (size_t) t->nwritten;

    if (ctx->files[t->handle_idx].wt_enabled) {
        brix_wt_mark_dirty(ctx, t->handle_idx,
            t->req_offset + (int64_t) t->nwritten - 1,
            (size_t) t->nwritten);
    }

    if (ctx->files[t->handle_idx].wrts_enabled) {
        brix_wrts_record(&ctx->files[t->handle_idx], t->req_offset,
                           (uint32_t) t->nwritten);
    }
}

/*
 * WHAT: Handle the pipelined plain-kXR_write completion (the !is_pgwrite path).
 * WHY:  A pipelined write must not disturb the recv loop, which has kept
 *       receiving and posting further writes while this one ran; we restore only
 *       the streamid for this ack's frame, reply asynchronously (parked in the
 *       out_ring, drained by the write event), then nudge the read side in case
 *       recv throttled on the pipeline depth.
 * HOW:  Restore the streamid (on failure the connection is dead — run any held
 *       deferred teardown and return).  Classify the outcome into errmsg
 *       (hard error / short write / NULL=success).  On error: log, count, and
 *       send kXR_IOError under resp_async, then schedule a read resume.  On
 *       success: commit accounting via brix_write_aio_commit, log, count, and
 *       send kXR_ok under resp_async, then schedule a read resume.  Never touches
 *       the recv state/hdr_pos.
 */
static void
brix_write_aio_done_pipelined(brix_ctx_t *ctx, ngx_connection_t *c,
                              ngx_stream_brix_srv_conf_t *rconf,
                              brix_write_aio_t *t, ngx_int_t op)
{
    const char *errmsg = NULL;

    if (!brix_aio_restore_stream(ctx, t->streamid)) {
        if (ctx->out.finalize_pending && ctx->out.wr_inflight == 0) {
            brix_run_deferred_teardown(ctx, c);
        }
        return;
    }

    if (t->nwritten < 0) {
        errmsg = t->io_errno ? strerror(t->io_errno) : "async write error";
    } else if ((size_t) t->nwritten < t->len) {
        errmsg = "short write (disk full?)";
    }

    if (errmsg != NULL) {
        brix_write_aio_logrec_t rec = { 0, kXR_IOError, errmsg, 0 };
        brix_write_aio_log(ctx, c, rconf, t, &rec);
        BRIX_OP_ERR(ctx, op);
        ctx->out.resp_async = 1;
        (void) brix_send_error(ctx, c, kXR_IOError, errmsg);
        ctx->out.resp_async = 0;
        (void) brix_schedule_read_resume(c);
        return;
    }

    brix_write_aio_commit(ctx, t);
    {
        brix_write_aio_logrec_t rec = { 1, 0, NULL, (size_t) t->nwritten };
        brix_write_aio_log(ctx, c, rconf, t, &rec);
    }
    BRIX_OP_OK(ctx, op);

    ctx->out.resp_async = 1;
    (void) brix_send_ok(ctx, c, NULL, 0);
    ctx->out.resp_async = 0;
    (void) brix_schedule_read_resume(c);
}

/*
 * WHAT: Send the success reply for a completed serial write and re-arm the
 *       connection.
 * WHY:  The serial reply framing differs by opcode: kXR_pgwrite expects a
 *       kXR_status response whose "info" offset echoes the REQUEST offset (where
 *       the data landed, matching the reference do_pgWrite — not offset+len,
 *       which diverged from stock in test_conf_pgio), and a page that failed
 *       CRC32c gets a CSE retransmit frame instead; plain kXR_write expects a
 *       bare kXR_ok.
 * HOW:  For pgwrite, send the CSE retransmit list when bad_page_count > 0 else a
 *       plain pgwrite status at req_offset; for plain write, send kXR_ok.  Then
 *       resume the recv loop for the next op.
 */
static void
brix_write_aio_serial_reply_ok(brix_ctx_t *ctx, ngx_connection_t *c,
                               brix_write_aio_t *t)
{
    if (t->is_pgwrite) {
        /* CSE: one or more pages failed CRC32c. The data is already on disk
         * (accept-then-correct); reply with the retransmit list so the client
         * resends those pages with kXR_pgRetry. */
        if (t->bad_page_count > 0) {
            brix_send_pgwrite_cse(ctx, c, t->req_offset,
                                    t->bad_pages, t->bad_page_count);
        } else {
            brix_send_pgwrite_status(ctx, c, t->req_offset);
        }
    } else {
        brix_send_ok(ctx, c, NULL, 0);
    }

    brix_aio_resume(c);
}

/*
 * WHAT: Handle the serial kXR_pgwrite / non-pipelined kXR_write completion.
 * WHY:  pgwrite is not pipelined, so the recv loop is suspended in XRD_ST_AIO; it
 *       is safe to restore the FULL request context (state + hdr_pos) and drive
 *       the response + resume synchronously.
 * HOW:  Restore the request (on failure the connection is dead — return).  On a
 *       hard error (nwritten < 0) or a short write (nwritten < len) — which the
 *       kXR_write protocol cannot acknowledge partially — log, count, send
 *       kXR_IOError, and resume.  Otherwise commit accounting via
 *       brix_write_aio_commit, log the success, count it, and send the
 *       opcode-appropriate success reply.
 */
static void
brix_write_aio_done_serial(brix_ctx_t *ctx, ngx_connection_t *c,
                           ngx_stream_brix_srv_conf_t *rconf,
                           brix_write_aio_t *t, ngx_int_t op)
{
    if (!brix_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->nwritten < 0) {
        const char *errmsg = t->io_errno ? strerror(t->io_errno)
                                         : "async write error";
        brix_write_aio_logrec_t rec = { 0, kXR_IOError, errmsg, 0 };
        brix_write_aio_log(ctx, c, rconf, t, &rec);
        BRIX_OP_ERR(ctx, op);
        brix_send_error(ctx, c, kXR_IOError, errmsg);
        brix_aio_resume(c);
        return;
    }

    /*
     * Short write: pwrite returned a non-negative count smaller than requested.
     * POSIX permits this (typically disk-full / quota), but the kXR_write
     * protocol has no partial-success reply, so we surface it as a hard
     * kXR_IOError rather than acknowledging fewer bytes than the client sent.
     */
    if ((size_t) t->nwritten < t->len) {
        brix_write_aio_logrec_t rec = { 0, kXR_IOError,
                                        "short write (disk full?)", 0 };
        brix_write_aio_log(ctx, c, rconf, t, &rec);
        BRIX_OP_ERR(ctx, op);
        brix_send_error(ctx, c, kXR_IOError, "short write (disk full?)");
        brix_aio_resume(c);
        return;
    }

    brix_write_aio_commit(ctx, t);
    {
        brix_write_aio_logrec_t rec = { 1, 0, NULL, (size_t) t->nwritten };
        brix_write_aio_log(ctx, c, rconf, t, &rec);
    }
    BRIX_OP_OK(ctx, op);

    brix_write_aio_serial_reply_ok(ctx, c, t);
}

/*
 * brix_write_aio_done — main-thread completion callback for kXR_write / kXR_pgwrite AIO.
 *
 * WHAT: Bridge the thread-pool write worker back to the event loop: free the
 *       detached payload, keep the pipelining counter honest, run any deferred
 *       teardown on a torn-down connection, then dispatch to the pipelined or
 *       serial completion handler.
 * WHY:  The two reply disciplines are structurally different (async out-ring vs
 *       synchronous restore/resume) and each has its own liveness guard; splitting
 *       them keeps this callback a flat guard-then-dispatch sequence.
 * HOW:  Free payload_to_free unconditionally (we own it regardless of liveness);
 *       decrement wr_inflight for a plain write BEFORE the liveness check so a
 *       deferred teardown fires on the LAST completion; on ctx->destroyed run the
 *       held teardown (last pipelined completion only) and return; otherwise fetch
 *       rconf and call the pipelined or serial handler.
 */
void
brix_write_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t            *task = ev->data;
    brix_write_aio_t           *t = task->ctx;
    brix_ctx_t                 *ctx = t->ctx;
    ngx_connection_t             *c = t->c;
    ngx_stream_brix_srv_conf_t *rconf;
    ngx_int_t                     op = BRIX_OP_WRITE;
    ngx_flag_t                    pipelined = !t->is_pgwrite;

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
     * Write pipelining: a plain kXR_write is no longer in flight.  Decrement
     * BEFORE the liveness check so a deferred teardown (client disconnected while
     * writes were still running) fires on the LAST completion, once no pwrite
     * references ctx/fds.
     */
    if (pipelined && ctx->out.wr_inflight > 0) {
        ctx->out.wr_inflight--;
    }

    if (ctx->destroyed) {
        /*
         * Connection torn down — or a disconnect/timeout was deferred because
         * writes were in flight.  Touch nothing further except, on the last
         * pipelined completion, running the teardown that was held off.
         */
        if (pipelined && ctx->out.finalize_pending && ctx->out.wr_inflight == 0) {
            brix_run_deferred_teardown(ctx, c);   /* frees ctx — return now */
        }
        return;
    }

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

    if (pipelined) {
        brix_write_aio_done_pipelined(ctx, c, rconf, t, op);
        return;
    }

    brix_write_aio_done_serial(ctx, c, rconf, t, op);
}

/*
 * brix_writev_write_aio_thread — thread-pool worker for kXR_writev multi-segment write.
 *
 * Runs on a worker thread. io_error=1 on hard failure, io_error=2 on short write.
 * If do_sync is set, fsync(2) is called per unique fd after all segments succeed.
 */
void
brix_writev_write_aio_thread(void *data, ngx_log_t *log)
{
    brix_writev_aio_t *t = data;
    brix_vfs_job_t     job;

    t->bytes_total = 0;
    t->io_error = 0;
    t->err_msg[0] = '\0';

    /*
     * Write each segment to its own (fd, offset).  On the first failing segment
     * we record the error and return immediately — earlier segments may already
     * be on disk, but the protocol reply is all-or-nothing, so we do not attempt
     * to roll back or continue. io_error encodes the failure kind for the done
     * callback: 1 = hard pwrite error, 2 = short write.
     */
    ngx_memzero(&job, sizeof(job));
    job.op = BRIX_VFS_IO_WRITEV;
    job.segs = t->segs;
    job.nsegs = t->n_segs;
    job.do_sync = t->do_sync ? 1 : 0;
    job.err_msg = t->err_msg;
    job.err_msg_cap = sizeof(t->err_msg);

    brix_vfs_io_execute(&job);

    t->bytes_total = job.out_size;
    if (job.io_errno != 0) {
        t->io_error = job.short_io ? 2 : 1;
        if (t->err_msg[0] == '\0') {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "writev I/O error: %s", strerror(job.io_errno));
        }
    }
}

/*
 * brix_writev_write_aio_done — completion callback for kXR_writev AIO.
 */
void
brix_writev_write_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t            *task = ev->data;
    brix_writev_aio_t          *t = task->ctx;
    brix_ctx_t                 *ctx = t->ctx;
    ngx_connection_t             *c = t->c;
    ngx_stream_brix_srv_conf_t *rconf;
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
     * Liveness guard — see brix_write_aio_done.  If the request can't be
     * restored the connection is dead; ctx/c are stale, so return now.
     */
    if (!brix_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->io_error) {
        BRIX_OP_ERR(ctx, BRIX_OP_WRITEV);
        brix_send_error(ctx, c, kXR_IOError, t->err_msg);
        brix_aio_resume(c);
        return;
    }

    /*
     * Success path: apply per-segment accounting, journal, and cache state on
     * the main thread (the worker only does I/O). Each segment may target a
     * different open file handle, so resolve ctx->files per segment.
     */
    for (i = 0; i < t->n_segs; i++) {
        if (t->segs[i].wlen > 0) {
            brix_file_t *file = &ctx->files[t->segs[i].handle_idx];

            file->bytes_written += t->segs[i].wlen;

            /* Record the committed write in the recovery journal. */
            if (file->wrts_enabled) {
                brix_wrts_record(file, (int64_t) t->segs[i].offset,
                                   t->segs[i].wlen);
            }

            if (file->wt_enabled) {
                /* Dirty range end is inclusive: offset + wlen - 1. */
                brix_wt_mark_dirty(ctx, t->segs[i].handle_idx,
                    t->segs[i].offset + (off_t) t->segs[i].wlen - 1,
                    t->segs[i].wlen);
            }
        }
    }
    ctx->totals.bytes_written += t->bytes_total;

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_brix_module);
    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];
        snprintf(detail, sizeof(detail), "%zu_segs", t->n_segs);
        brix_log_access(ctx, c, "WRITEV", "-", detail, 1, 0, NULL,
                          t->bytes_total);
    }
    BRIX_OP_OK(ctx, BRIX_OP_WRITEV);

    brix_send_ok(ctx, c, NULL, 0);
    brix_aio_resume(c);
}
