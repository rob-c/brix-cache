#include "core/ngx_brix_module.h"
#include "protocols/root/connection/budget.h"
#include "protocols/root/connection/disconnect.h"  /* run_deferred_teardown (WS3) */
#include "protocols/root/read/read.h"

/*
 * reads.c — thread-pool offload for the stream kXR_read / kXR_pgread opcodes.
 *
 * WHAT: The worker-thread half and every completion half of the read-AIO
 *       family: brix_read_aio_thread (the blocking VFS read) and
 *       brix_read_aio_done, which routes a completion to the single-shot
 *       deliver path or to the windowed train (whose forward drive — pump,
 *       per-window post, round-12 double-buffered read-ahead — lives in
 *       reads_window.c).  pgread AIO, which interleaves a per-page CRC32C
 *       into the wire output, lives in pgreads.c.
 *
 * WHY:  File I/O (and the pgread CRC32C loop) can block; running them on the
 *       nginx event-loop thread would stall every other connection on this
 *       worker. The thread pool absorbs the blocking syscall and CPU-bound
 *       checksum so the event loop stays responsive.
 *
 * HOW:  Each path splits into a *_thread half (runs on a worker thread, may
 *       only touch the task struct — never ctx/connection/pool) and a *_done
 *       half (runs back on the event loop, owns all protocol/state mutation
 *       and chain building). The two halves communicate only through the
 *       brix_{read,pgread}_aio_t task struct carried by ngx_thread_task_t.
 *       Every *_done first re-validates the connection via
 *       brix_aio_restore_stream/_request (the stream may have died while the
 *       task ran) and ends by calling brix_aio_resume() to re-arm events.
 */


/*
 * brix_read_io_failure_log — forensic detail for a failed buffered read.
 * One line per failure with everything the watch item needs: which path
 * failed, the fd and what it currently refers to, the request geometry, and
 * the worker-side errno (io_errno == 0 means the error arrived without one —
 * itself a finding).
 */
void
brix_read_io_failure_log(ngx_log_t *log, const char *who, int fd,
    off_t offset, size_t rlen, int io_errno)
{
    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "brix: %s read failed: fd=%d off=%O len=%uz io_errno=%d "
                  "(%s) fd_kind=%s",
                  who, fd, offset, rlen, io_errno,
                  io_errno ? strerror(io_errno) : "-", brix_fd_kind(fd));
}


/*
 * brix_read_aio_thread — thread-pool worker for kXR_read.
 *
 * Runs on a worker thread; must not touch nginx state, connection pools, or
 * any field that is not owned by the task struct.  Only the blocking VFS core
 * syscall belongs here; all protocol work happens in the done callback on the
 * main thread.
 *
 * t->nread: set to pread return value (< 0 on error, 0 on EOF, > 0 on success).
 * t->io_errno: saved errno on failure.
 */
void
brix_read_aio_thread(void *data, ngx_log_t *log)
{
    brix_read_aio_t *t = data;
    brix_vfs_job_t   job;

    /*
     * Worker threads execute the VFS-owned thread-safe core only; all protocol
     * state updates stay on the event-loop side in the completion callback.
     */
    brix_vfs_job_read_init(&job, t->fd, t->offset, t->rlen,
                             t->databuf, t->rlen, 0);
    if (t->pg) {
        job.op = BRIX_VFS_IO_PGREAD;     /* windowed pgread: in-place gapped
                                          * encode + per-page CRC32c */
    }
    job.csi = t->csi;                    /* phase-59 W2: verify in the worker */
    brix_vfs_job_set_obj(&job, &t->obj); /* Layer 3: route via driver if bound */
    brix_vfs_io_execute(&job);

    t->out_size = job.out_size;          /* pg only: encoded wire bytes */
    t->nread = job.nio;
    t->io_errno = job.io_errno;          /* CSI mismatch surfaces as EIO here */
}

/*
 * brix_read_aio_done — main-thread completion callback for kXR_read AIO.
 *
 * Called by nginx's event loop after the thread pool posts the result via
 * ngx_post_event.  Responsibilities:
 *   1. Guard against stale connection (ctx->destroyed check via restore_stream).
 *   2. On I/O error: send kXR_IOError, release databuf, resume event loop.
 *   3. On success: build a response chain (chunked if > 16 MiB), update per-
 *      handle and session byte counters, queue the chain.
 *   4. Call brix_aio_resume() to re-arm the appropriate event (write or read).
 *
 * NOTE: if the chain send blocks (XRD_ST_SENDING), databuf is kept alive as
 * wchain_base and freed by brix_release_pending_buffer after full drain.
 */
/*
 * The stream vanished while this read ran. On the last outstanding op (no
 * pwrite and no read still in flight) run the held teardown that
 * brix_defer_teardown_if_writing parked; otherwise touch nothing — another
 * completion still references ctx.
 */
static void
brix_read_aio_orphaned(brix_read_aio_t *t, brix_ctx_t *ctx,
    ngx_connection_t *c)
{
    if (t->counted && ctx->out.finalize_pending
        && ctx->out.wr_inflight == 0 && ctx->rd.aio_inflight == 0)
    {
        brix_run_deferred_teardown(ctx, c);   /* frees ctx — return now */
    }
}


/*
 * Phase 31 W2.1: this completion belongs to one window of a windowed read.
 * Emit its chunk, then take exactly one of three paths (no fall-through):
 *   a) chunk still draining (XRD_ST_SENDING): hand off; send.c re-enters the
 *      pump once the socket has flushed this window.
 *   b) chunk sent synchronously and more windows remain (win_active still set):
 *      drive the next window now.
 *   c) windowed read complete (win_active cleared by emit): resume the normal
 *      request event loop.
 */
static void
brix_read_aio_window_done(brix_read_aio_t *t, brix_ctx_t *ctx,
    ngx_connection_t *c)
{
    if (brix_read_window_emit_step(ctx, c, t->conf, t->nread, t->out_size,
                                     t->io_errno) == NGX_ERROR)
    {
        brix_read_window_park_or_resume(ctx, c);
        return;
    }
    /* phase-56 D-2, one sample per REQUEST: the emit clears win_active on the
     * final window, so this is the windowed read's single histogram sample.
     * It has to happen HERE — before the pump/resume below, either of which
     * may finish the request and retire ctx. */
    if (!ctx->rd.win_active) {
        brix_aio_metric_done(t->start_ns, BRIX_METRIC_OP_READ);
    }
    if (ctx->state == XRD_ST_SENDING) {
        return;                /* (a) send.c resumes the pump when it drains */
    }
    if (ctx->rd.win_active) {
        brix_read_window_pump(ctx, c, t->conf);   /* (b) sync-sent: next window */
        return;
    }
    brix_aio_resume(c);        /* (c) finished */
}


/*
 * Round 12: a read-ahead window finished on the worker.  If the train died
 * while it ran (an emit failed), discard the result — and if the pump parked
 * the connection on this very completion, restore the request loop.  Live
 * train: stash the result (win_ready) and let the previous frame's drain
 * (send.c → pump) emit it; if the drain already happened, emit now.
 */
static void
brix_read_window_prefetch_done(brix_read_aio_t *t, brix_ctx_t *ctx,
    ngx_connection_t *c)
{
    ctx->rd.win_prefetch = 0;

    if (!ctx->rd.win_active) {
        if (ctx->state == XRD_ST_AIO) {
            ctx->state = XRD_ST_REQ_HEADER;
            ctx->recv.hdr_pos = 0;
            brix_aio_resume(c);
        }
        return;
    }

    ctx->rd.win_ready = 1;
    ctx->rd.win_pf_nread = t->nread;
    ctx->rd.win_pf_osz = t->out_size;
    ctx->rd.win_pf_errno = t->io_errno;

    if (ctx->state == XRD_ST_SENDING) {
        return;   /* previous frame still draining; send.c re-enters the pump */
    }
    brix_read_window_pump(ctx, c, t->conf);
}


/* The read syscall itself failed: log it, release the buffer, and answer the
 * client with kXR_IOError before resuming the request loop. */
static void
brix_read_aio_failed(brix_read_aio_t *t, brix_ctx_t *ctx, ngx_connection_t *c)
{
    brix_read_io_failure_log(c->log, "read-aio", t->fd, t->offset,
                               t->rlen, t->io_errno);
    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;
    brix_release_read_buffer(ctx, c, t->databuf);
    BRIX_OP_ERR(ctx, BRIX_OP_READ);
    brix_send_error(ctx, c, kXR_IOError,
                      t->io_errno ? strerror(t->io_errno) : "async read error");
    brix_aio_resume(c);
}


/* Successful single-chunk read: account the bytes, frame the response and queue
 * it, then release or park the pool buffer depending on whether it drained. */
static void
brix_read_aio_deliver(brix_read_aio_t *t, brix_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_chain_t *rsp_chain;

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->totals.bytes += (size_t) t->nread;
    BRIX_OP_OK(ctx, BRIX_OP_READ);

    rsp_chain = brix_build_chunked_chain(ctx, c,
                                           t->databuf, (size_t) t->nread);
    if (rsp_chain == NULL) {
        brix_release_read_buffer(ctx, c, t->databuf);
        ctx->state = XRD_ST_REQ_HEADER;
        brix_aio_resume(c);
        return;
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;

    brix_queue_response_chain(ctx, c, rsp_chain, t->databuf);
    if (ctx->state != XRD_ST_SENDING) {
        brix_release_read_buffer(ctx, c, t->databuf);
    } else {
        /*
         * Parked and draining: the buffer is a per-in-flight rd_pool slot and the
         * header is per-slot, so this memory-backed read is SAFE to pipeline.
         * phase-32 WS3: recv no longer suspends on a cold read's AIO — after the
         * post it keeps receiving and issues the next read into a different pool
         * buffer with its own per-slot task (read_post_aio), so cold reads now
         * pipeline like the warm-cache inline path.  Single-chunk only (non-
         * windowed read <= BRIX_READ_WINDOW < CHUNK_MAX).
         */
        ctx->out.resp_pipelinable = 1;
    }
    brix_aio_resume(c);
}


void
brix_read_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    brix_read_aio_t  *t = task->ctx;
    brix_ctx_t       *ctx = t->ctx;
    ngx_connection_t   *c = t->c;

    /*
     * phase-32 WS3 (concurrent read-AIO): a counted single-shot read is no
     * longer in flight.  Decrement BEFORE the liveness guard so a deferred
     * teardown (the client vanished while pipelined reads were running) fires on
     * the LAST completion — once no worker thread references any rd_pool buffer.
     * Mirrors the wr_inflight discipline in brix_write_aio_done.
     */
    if (t->counted && ctx->rd.aio_inflight > 0) {
        ctx->rd.aio_inflight--;
    }

    if (!brix_aio_restore_stream(ctx, t->streamid)) {
        brix_read_aio_orphaned(t, ctx, c);
        return;
    }

    /* phase-56 D-2: file this completed read into the op-latency histogram.
     * The exporter's io_ops_total books ONE op per kXR_read REQUEST (the
     * legacy per-port fold), so a windowed read must sample ONCE too — the
     * windowed path files its own sample on the final window (inside
     * brix_read_aio_window_done / the pump's win_ready path, where ctx is
     * still alive), or the histogram count would exceed the op count and
     * break aio.h's "AIO-sampled subset of ops" contract.
     *
     * Round 12: windowed-family completions route on TASK IDENTITY, never on
     * win_active alone — a pipelined single-shot completion (per-slot task)
     * can land while a train is active and must take the classic path below.
     * Within the family, win_prefetch says whether this is a read-ahead. */
    if (task == ctx->rd.read_aio_task) {
        if (ctx->rd.win_prefetch) {
            brix_read_window_prefetch_done(t, ctx, c);
        } else if (ctx->rd.win_active) {
            brix_read_aio_window_done(t, ctx, c);
        } else {
            brix_aio_resume(c);   /* stale windowed completion — train gone */
        }
        return;
    }
    brix_aio_metric_done(t->start_ns, BRIX_METRIC_OP_READ);
    if (t->nread < 0) {
        brix_read_aio_failed(t, ctx, c);
        return;
    }
    brix_read_aio_deliver(t, ctx, c);
}
