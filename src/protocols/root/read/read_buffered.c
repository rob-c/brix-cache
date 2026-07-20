/*
 * read_buffered.c — kXR_read memory-path serve helpers (split from read.c):
 * windowed streaming plus the single-shot warm-probe / AIO / sync buffered
 * path.  See each function's docblock below.
 */

#include "read.h"
#include "fs/backend/sd.h"   /* phase-55: route raw fd I/O through the SD seam */
#include "fs/backend/csi_tagstore.h"  /* phase-59 W2: page-checksum verify */
#include "protocols/root/zip/zip_member.h"   /* phase-57 W2: ZIP member read dispatch */
#include "protocols/ssi/ssi.h"          /* §7: SSI handle read dispatch */

#include "core/ngx_brix_module.h"
#include "protocols/root/connection/budget.h"
#include "prefetch.h"

#include <sys/uio.h>   /* Phase 32 WS4: preadv2(RWF_NOWAIT) warm-cache probe */

#include "read_internal.h"

/*
 * read_clamped_total — bytes this memory-path read will actually deliver.
 *
 * WHAT: the request length clamped to what the file holds, for read-only
 * handles whose size was cached at open time.
 * WHY: Phase 31 W2.1 bounds resident heap for large memory-backed reads; the
 * windowed-vs-single-shot decision must be made on real bytes, not the
 * client's (possibly EOF-crossing) rlen.
 * HOW: read-only handles clamp against cached_size; writable handles (size
 * unknown) use rlen and let a short read at EOF terminate early.
 */
size_t
read_clamped_total(brix_ctx_t *ctx, const brix_read_io_t *io)
{
    size_t total = io->rlen;

    if (!ctx->files[io->idx].writable && ctx->files[io->idx].cached_size > 0) {
        off_t avail = ctx->files[io->idx].cached_size - (off_t) io->offset;
        total = (avail <= 0) ? 0
              : ((off_t) total > avail ? (size_t) avail : total);
    }

    return total;
}

/*
 * read_serve_windowed — stream a large memory-path read as kXR_oksofar chunks.
 *
 * WHAT: admits one window's worth of budget, arms the windowed-read state
 * machine in ctx->rd and kicks the pump.
 * WHY: a request bigger than one streaming window must not buffer whole in
 * heap — serve it as a sequence of window-sized kXR_oksofar chunks ending in
 * kXR_ok, holding only ~one window in read_scratch at a time.
 * HOW: budget-rejected requests get kXR_wait; otherwise the pump (and any
 * resumption after a partial flush) reads from rd_win_* rather than this
 * request's locals, so it survives across event-loop returns.
 */
ngx_int_t
read_serve_windowed(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_read_io_t *io,
    size_t total)
{
    /* Admit one window's worth — a windowed stream holds ~2 MiB, not
     * the full request, so many more fit under the budget. */
    if (!brix_budget_admit(ctx, rconf->memory_budget,
                             (size_t) BRIX_READ_WINDOW)) {
        return brix_send_wait(ctx, c, 1);
    }

    /*
     * Arm the windowed-read state machine: the pump below (and any
     * resumption after a partial flush) reads from rd_win_* rather than
     * this request's locals, so it survives across event-loop returns.
     * cur_streamid is snapshotted into rd_win_streamid because each
     * kXR_oksofar/kXR_ok chunk must echo the originating request's stream
     * id, but cur_streamid will be overwritten by the next inbound header
     * before this stream finishes draining.
     */
    ctx->rd.win_active = 1;
    ctx->rd.win_fd = io->fd;
    ctx->rd.win_idx = io->idx;
    ctx->rd.win_offset = (off_t) io->offset;
    ctx->rd.win_remaining = total;
    ctx->rd.win_streamid[0] = ctx->recv.cur_streamid[0];
    ctx->rd.win_streamid[1] = ctx->recv.cur_streamid[1];

    brix_prefetch_read_file(c->log, &ctx->files[io->idx], (off_t) io->offset,
                              total,
                              ctx->files[io->idx].writable
                                  ? 0 : ctx->files[io->idx].cached_size);

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char read_detail[64];
        snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                 (long long) io->offset, io->rlen);
        brix_log_access(ctx, c, "READ", ctx->files[io->idx].path,
                          read_detail, 1, 0, NULL, total);
    }

    brix_read_window_pump(ctx, c, rconf);
    return NGX_OK;
}

/*
 * read_prefetch_buffered — readahead hint for the single-shot memory path.
 *
 * WHAT: issues the prefetch hint for a regular-file buffered read, clamped to
 * the cached file size when known.
 * WHY: the buffered path bypasses the sendfile branch's clamp, so the hint
 * length must be recomputed here or readahead would be asked for bytes past
 * EOF.
 * HOW: read-only handles use the size cached at open; writable handles pass 0
 * (unknown) and hint the full rlen.
 */
static void
read_prefetch_buffered(brix_ctx_t *ctx, ngx_connection_t *c,
    const brix_read_io_t *io)
{
    off_t  file_size;
    size_t hint_len;

    if (!ctx->files[io->idx].is_regular) {
        return;
    }

    file_size = ctx->files[io->idx].writable ? 0
                                              : ctx->files[io->idx].cached_size;
    hint_len = io->rlen;

    if (file_size > 0) {
        if ((off_t) io->offset >= file_size) {
            hint_len = 0;
        } else if ((off_t) hint_len > file_size - (off_t) io->offset) {
            hint_len = (size_t) (file_size - (off_t) io->offset);
        }
    }

    brix_prefetch_read_file(c->log, &ctx->files[io->idx], (off_t) io->offset,
                              hint_len, file_size);
}

/*
 * read_try_warm — Phase 32 WS4 warm-cache fast path.
 *
 * WHAT: probes the page cache with a non-blocking preadv2(RWF_NOWAIT); on a
 * full hit, verifies CSI page checksums and attributes backend byte metrics.
 * WHY: if the whole request is resident it returns rlen bytes immediately and
 * completes inline — skipping the thread-pool round-trip (hundreds of µs)
 * that otherwise dominates a cache-hot read.
 * HOW: returns 1 on a full hit with *nread_out set (or -1 with errno=EIO on a
 * CSI mismatch); returns 0 on a (partial) miss so the caller falls through to
 * the AIO thread / synchronous pread, which reads the full data blocking off
 * the event loop.  Only attempted for regular files (RWF_NOWAIT is meaningful
 * against the page cache) with a thread pool configured, matching the paths
 * the probe would otherwise short-circuit.
 */
static ngx_flag_t
read_try_warm(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *rconf,
    const brix_read_io_t *io, ssize_t *nread_out)
{
    ssize_t warm = -1;
    ssize_t nread;

#if defined(RWF_NOWAIT)
    if (rconf->common.thread_pool != NULL && ctx->files[io->idx].is_regular) {
        struct iovec    iov;
        brix_sd_obj_t obj;
        iov.iov_base = io->databuf;
        iov.iov_len  = io->rlen;
        brix_sd_posix_wrap(&obj, io->fd);   /* phase-55: SD seam */
        warm = obj.driver->preadv2(&obj, &iov, 1,
                                              (off_t) io->offset, RWF_NOWAIT);
    }
#endif

    /*
     * Only an exact rlen match counts as a hit: a short warm result means
     * part of the range was not resident (or EOF), and re-issuing a blocking
     * read for the missing tail from the event loop would stall it — so any
     * non-exact result falls through to the thread pool / sync path, which
     * re-reads the full range from offset (the partial warm bytes are simply
     * overwritten).
     */
    if (warm != (ssize_t) io->rlen) {
        return 0;
    }

    nread = warm;   /* full page-cache hit — databuf is filled; complete inline */

    /* phase-59 W2: the warm fast path bypasses the VFS job, so verify
     * the page CRCs here too; a mismatch fails the read (EIO). */
    if (ctx->files[io->idx].csi != NULL && nread > 0
        && brix_csi_verify_read(
               (brix_csi_t *) ctx->files[io->idx].csi, io->databuf,
               (off_t) io->offset, (size_t) nread) == BRIX_CSI_MISMATCH)
    {
        nread = -1;
        errno = EIO;
    }

    /* The warm fast path bypasses brix_vfs_io_execute (where the other
     * read paths attribute), so charge the per-backend read total here. */
    if (nread > 0) {
        brix_metric_backend_bytes(
            ctx->files[io->idx].sd_obj.driver != NULL
                ? ctx->files[io->idx].sd_obj.driver->name : "posix",
            BRIX_METRIC_OP_READ, (size_t) nread);
    }

    *nread_out = nread;
    return 1;
}

/*
 * read_post_aio — post the buffered read to the thread pool.
 *
 * WHAT: allocates (once per session) or resets the reusable read AIO task,
 * fills the job fields and posts it to the configured thread pool.
 * WHY: the blocking pread must run off the event loop; the done-callback owns
 * databuf and finishes the response, so a successful post is the end of this
 * request's event-loop work.
 * HOW: one reusable task per session (ctx->rd.read_aio_task): allocate it the
 * first time, otherwise reset the two fields ngx reuse requires — unlink from
 * any prior queue (next) and clear the completion flag so the event loop will
 * fire the done-callback again.  Returns NGX_ERROR on allocation failure
 * (databuf already released); otherwise NGX_OK with *posted saying whether the
 * pool accepted the task (not posted => caller must read synchronously so the
 * read never silently drops).
 */
static ngx_int_t
read_post_aio(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_read_io_t *io,
    ngx_flag_t *posted)
{
    ngx_thread_task_t *task;
    brix_read_aio_t *t;

    task = ctx->rd.read_aio_task;
    if (task == NULL) {
        task = ngx_thread_task_alloc(c->pool, sizeof(brix_read_aio_t));
        if (task == NULL) {
            brix_release_read_buffer(ctx, c, io->databuf);
            return NGX_ERROR;
        }
        ctx->rd.read_aio_task = task;
    } else {
        task->next = NULL;
        task->event.complete = 0;
    }

    t = task->ctx;
    t->c = c;
    t->ctx = ctx;
    t->fd = io->fd;
    t->handle_idx = io->idx;
    t->offset = (off_t) io->offset;
    t->rlen = io->rlen;
    t->databuf = io->databuf;
    t->streamid[0] = ctx->recv.cur_streamid[0];
    t->streamid[1] = ctx->recv.cur_streamid[1];
    t->nread = 0;
    t->io_errno = 0;
    t->csi = ctx->files[io->idx].csi;   /* phase-59 W2: verify on read */
    t->obj = ctx->files[io->idx].sd_obj; /* Layer 3: driver obj (or zeroed) */

    brix_task_bind(task, brix_read_aio_thread, brix_read_aio_done);

    (void) brix_aio_post_task(ctx, c, rconf->common.thread_pool, task,
                                "brix: thread_task_post failed, sync read fallback",
                                posted);
    return NGX_OK;
}

/*
 * read_sync_fill — blocking buffered read via the VFS I/O seam.
 *
 * WHAT: fills io->databuf with up to rlen bytes from offset through
 * brix_vfs_io_execute, with CSI verification attached.
 * WHY: the fallback when no thread pool is configured or the pool rejected the
 * post — the read runs inline on the event loop rather than dropping.
 * HOW: returns the byte count (or -1 with errno set).  A CSI page-checksum
 * mismatch surfaces here as EIO (job.csi_mismatch set); the caller's nread<0
 * path fails the read so corrupt data is never served.
 */
static ssize_t
read_sync_fill(brix_ctx_t *ctx, const brix_read_io_t *io)
{
    brix_vfs_job_t job;

    brix_vfs_job_read_init(&job, io->fd, (off_t) io->offset, io->rlen,
                              io->databuf, io->rlen, 0);
    job.csi = ctx->files[io->idx].csi;   /* phase-59 W2: verify on read */
    brix_vfs_job_set_obj(&job, &ctx->files[io->idx].sd_obj);
    brix_vfs_io_execute(&job);
    if (job.io_errno != 0) {
        errno = job.io_errno;
    }
    return job.nio;
}

/*
 * read_finish_buffered — account, log and queue a completed memory-path read.
 *
 * WHAT: turns the (nread, databuf) result of the warm/sync buffered paths into
 * the wire response: error on nread<0, otherwise byte accounting, dashboard
 * slot update, access log, chunked chain build and queue.
 * WHY: the warm-hit and sync-fallback paths converge here so the response
 * assembly (and its ordering) exists exactly once — INVARIANT: this path
 * serves memory-backed buffers (TLS-safe), never sendfile.
 * HOW: on queue park (still SENDING) marks the response pipelinable —
 * per-in-flight buffer + per-slot header make this memory-backed read safe to
 * pipeline; on any other outcome the buffer is released back to the pool.
 */
static ngx_int_t
read_finish_buffered(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_read_io_t *io,
    ssize_t nread)
{
    size_t       data_total;
    ngx_chain_t *rsp_chain;
    u_char      *databuf = io->databuf;
    int          idx = io->idx;

    if (nread < 0) {
        brix_read_io_failure_log(c->log, "buffered", io->fd,
                                   (off_t) io->offset, io->rlen, errno);
        brix_release_read_buffer(ctx, c, databuf);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_READ, "READ",
                          ctx->files[idx].path, "-",
                          kXR_IOError, strerror(errno));
    }

    data_total = (size_t) nread;

    ctx->files[idx].bytes_read += data_total;
    ctx->totals.bytes += data_total;

    if (ctx->files[idx].dashboard_slot >= 0 &&
        ngx_brix_dashboard_shm_zone != NULL)
    {
        brix_transfer_slot_update(ngx_brix_dashboard_shm_zone->data,
                                    ctx->files[idx].dashboard_slot,
                                    (ngx_atomic_int_t) data_total,
                                    (int64_t) ngx_current_msec);
        brix_transfer_slot_count_op(ngx_brix_dashboard_shm_zone->data,
                                      ctx->files[idx].dashboard_slot, "read");
    }

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char read_detail[64];

        snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                 (long long) io->offset, io->rlen);
        brix_log_access(ctx, c, "READ", ctx->files[idx].path,
                          read_detail, 1, 0, NULL, data_total);
    }
    BRIX_OP_OK(ctx, BRIX_OP_READ);

    rsp_chain = brix_build_chunked_chain(ctx, c, databuf, data_total);
    if (rsp_chain == NULL) {
        brix_release_read_buffer(ctx, c, databuf);
        return NGX_ERROR;
    }

    {
        ngx_int_t rc = brix_queue_response_chain(ctx, c, rsp_chain, databuf);

        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            brix_release_read_buffer(ctx, c, databuf);
        } else {
            /*
             * Parked and draining: per-in-flight buffer + per-slot header make
             * this memory-backed (TLS) read safe to pipeline, so let the recv loop
             * queue the next read behind it instead of idling while it drains a
             * jittered socket.  (A single-chunk response only: the non-windowed
             * path is bounded by BRIX_READ_WINDOW < BRIX_READ_CHUNK_MAX.)
             */
            ctx->out.resp_pipelinable = 1;
        }
        return rc;
    }
}

/*
 * read_serve_buffered — single-shot memory-path read (<= one window).
 *
 * WHAT: admits the request against the memory budget, acquires a
 * per-in-flight buffer and fills it via the warm-cache probe, the AIO thread
 * pool, or a synchronous VFS read — then completes through
 * read_finish_buffered().
 * WHY: this is the memory path (TLS / non-regular file / CSI / driver-backed
 * handle) — INVARIANT: it serves memory-backed buffers only, never sendfile.
 * HOW: budget-rejected requests get kXR_wait.  Warm hit completes inline; a
 * miss posts to the thread pool when configured (a successful post returns
 * early — the done-callback owns databuf); a rejected post or no pool falls
 * back to read_sync_fill() so the read never silently drops.
 */
ngx_int_t
read_serve_buffered(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_read_io_t *io)
{
    ssize_t nread;

    if (!brix_budget_admit(ctx, rconf->memory_budget, io->rlen)) {
        return brix_send_wait(ctx, c, 1);
    }

    /*
     * Per-in-flight read buffer (read pipelining): each outstanding memory read
     * gets its OWN buffer from rd_pool rather than the single shared read_scratch,
     * so this response can keep draining the (possibly jittered) socket while the
     * recv loop already issues the next read into a different buffer.  Released
     * back to the pool when this response's out_ring slot drains.
     */
    io->databuf = brix_acquire_read_buffer(ctx, c, io->rlen);
    if (io->databuf == NULL) {
        return NGX_ERROR;
    }

    /* Charge the (possibly grown) read-pool footprint to the budget now so a
     * concurrent connection's admission check sees this allocation promptly. */
    brix_budget_sync(ctx);

    read_prefetch_buffered(ctx, c, io);

    if (!read_try_warm(ctx, rconf, io, &nread)) {
        if (rconf->common.thread_pool != NULL) {
            ngx_flag_t posted;

            if (read_post_aio(ctx, c, rconf, io, &posted) != NGX_OK) {
                return NGX_ERROR;
            }
            /*
             * Posted: the read now completes off-thread; the done-callback owns
             * databuf and finishes the response, so return early — nothing more to
             * do on the event loop.  Not posted (queue full / post error): fall
             * through to a blocking pread here so the read never silently drops.
             */
            if (posted) {
                return NGX_OK;
            }
        }

        /* No thread pool configured (or post rejected): read inline on the
         * event loop. */
        nread = read_sync_fill(ctx, io);
    }

    return read_finish_buffered(ctx, c, rconf, io, nread);
}
