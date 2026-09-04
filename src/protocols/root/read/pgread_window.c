/*
 * pgread_window.c — primary-path windowed kXR_pgread streaming.
 *
 * WHAT: Serves a pgread larger than one streaming window as a train of
 *       kXR_status frames (kXR_PartialResult ... kXR_FinalResult), each
 *       produced window-by-window into the single hot rd.read_scratch slot
 *       as [32-byte pgRead status header][gapped [CRC32c(4)][page] data].
 *
 * WHY: The monolithic path fills a request-sized rd_pool slot (8 MiB for an
 *      xrdcp-shaped pgread) before the first byte leaves; at streaming rates
 *      that destination never stays cache-resident and the page-cache-to-user
 *      copy dominates worker CPU.  A ~2 MiB window destination stays LLC-hot
 *      (30-40% cheaper per byte on this class of host), the stream holds one
 *      window of memory budget instead of the whole request, and the first
 *      frame reaches the wire after one window instead of the full request.
 *
 * HOW: Reuses the Phase 31 windowed-read state machine (ctx->rd.win_*,
 *      brix_read_window_pump in reads.c) with rd.win_pgread set.  The pump
 *      cuts every window on the absolute 4 KiB page grid (each partial frame
 *      carries whole [CRC][page] units — the same wire shape the §1.3
 *      chunked pool streamer sends), the worker thread runs the in-place
 *      encode+CRC (BRIX_VFS_IO_PGREAD), and brix_pgread_window_emit stamps
 *      the status header ahead of the encoded bytes and queues the
 *      contiguous frame.  The stream self-serializes: recv stays suspended
 *      in XRD_ST_AIO for the whole train and send.c re-enters the pump when
 *      a parked frame drains, so read_scratch is never overwritten while a
 *      frame still references it.
 */

#include "core/ngx_brix_module.h"
#include "protocols/root/connection/budget.h"
#include "protocols/root/connection/write_helpers.h"
#include "fs/backend/sd.h"       /* driver->preadv2 warm-probe capability */
#include "fs/vfs/vfs_io_core.h"  /* brix_vfs_effective_obj */

#include "read.h"
#include "read_internal.h"
#include "pgread_internal.h"
#include "prefetch.h"

/*
 * brix_pgread_window_want — data bytes for the next window.
 *
 * Cut on the absolute 4 KiB page grid (parity with brix_pgread_chunk_len in
 * the §1.3 streamer, at window scale): every window after the first then
 * starts page-aligned, so each frame carries whole [CRC][page] units and the
 * per-page CRC framing never splits a page across frames.
 */
size_t
brix_pgread_window_want(off_t cur, size_t left)
{
    off_t  grid_end;
    size_t wlen;

    grid_end = (off_t) (((uint64_t) cur + (uint64_t) BRIX_READ_WINDOW)
                        & ~((uint64_t) kXR_pgPageSZ - 1));
    wlen = (size_t) (grid_end - cur);
    return (wlen > left) ? left : wlen;
}

/*
 * brix_pgread_window_scratch — frame-buffer bytes for a window of `want` data
 * at offset `cur`: the 32-byte status header plus the gapped wire encoding
 * (one 4-byte CRC per page; offset alignment can split the first page — same
 * page-count math as brix_pgread_scratch_size).
 */
size_t
brix_pgread_window_scratch(off_t cur, size_t want)
{
    size_t n_pages;

    n_pages = ((size_t) (cur & (kXR_pgPageSZ - 1)) + want + kXR_pgPageSZ - 1)
              / kXR_pgPageSZ;
    if (n_pages == 0) {
        n_pages = 1;
    }
    return sizeof(ServerStatusResponse_pgRead) + want + n_pages * BRIX_PG_CKSZ;
}

/*
 * brix_pgread_window_try_warm — inline warm-cache probe for ONE window.
 *
 * WHAT: Attempts the window's read + in-place gapped encode + per-page CRC
 *       on the event loop via preadv2(RWF_NOWAIT) into `datap` (the byte
 *       after the frame headroom).  On a full hit sets *nread and *out_size,
 *       charges the backend byte metric, and returns 1; any miss returns 0
 *       with the outputs untouched.
 *
 * WHY: The windowed train self-serializes (recv suspended for its whole
 *      duration), so the pool buys no read/send overlap here — each window's
 *      thread-pool round-trip is pure handoff latency plus two scheduler
 *      wakeups (4 per xrdcp-shaped 8 MiB request; thousands per transfer),
 *      which is the drag when every core is busy.  A resident window served
 *      inline deletes that entirely.  Inline work stays bounded to one
 *      window (≤ BRIX_READ_WINDOW — the same inline budget the single-shot
 *      brix_pgread_try_warm accepts); a cold window posts to the pool as
 *      before, keeping the event loop off blocking disk reads.
 *
 * HOW: Mirrors brix_pgread_try_warm: pool configured + regular file +
 *      native preadv2 on the effective storage object; a hit means errno
 *      stayed 0 and every requested byte was delivered (a short window —
 *      EOF or partial residency — is a miss, and the blocking path re-reads
 *      it and owns the EOF framing).
 */
ngx_flag_t
brix_pgread_window_try_warm(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *rconf,
    u_char *datap, size_t want, ssize_t *nread, size_t *out_size)
{
    brix_pgread_io_t warm_io = { .nowait = 1, .nread = 0, .io_errno = 0 };
    size_t           warm_osz;
    brix_sd_obj_t    warm_scratch;
    brix_sd_obj_t   *warm_obj;

    if (rconf->common.thread_pool == NULL
        || !ctx->files[ctx->rd.win_idx].is_regular)
    {
        return 0;
    }

    warm_obj = brix_vfs_effective_obj(&ctx->files[ctx->rd.win_idx].sd_obj,
                                        ctx->rd.win_fd, &warm_scratch);
    if (warm_obj->driver->preadv2 == NULL) {
        return 0;
    }

    warm_osz = brix_pgread_read_encode_inplace(warm_obj, ctx->rd.win_offset,
                                                 want, datap, &warm_io);
    if (warm_io.io_errno != 0 || warm_io.nread != (ssize_t) want) {
        return 0;
    }

    /* The warm path bypasses brix_vfs_io_execute (where the posted and
     * inline-fallback windows attribute), so charge the per-backend read
     * total here. */
    brix_metric_backend_bytes(
        ctx->files[ctx->rd.win_idx].sd_obj.driver != NULL
            ? ctx->files[ctx->rd.win_idx].sd_obj.driver->name : "posix",
        BRIX_METRIC_OP_READ, (size_t) warm_io.nread);

    *nread = warm_io.nread;
    *out_size = warm_osz;
    return 1;
}

/*
 * brix_pgread_window_emit — frame + queue one completed window, advancing the
 * continuation state (the pgread twin of brix_read_window_emit; called via
 * the pump's dispatch).  The worker (or inline fallback) already encoded the
 * window into read_scratch + 32; this stamps the kXR_status header in the
 * headroom and queues the contiguous frame.  resptype is kXR_PartialResult
 * for every window except the last planned one or EOF, which sends
 * kXR_FinalResult (a zero-byte final frame is the wire EOF shape, matching
 * brix_pgread_done_eof).  Returns NGX_ERROR if the read or the queue failed
 * (the terminating error frame has been sent); otherwise NGX_OK with
 * ctx->state == XRD_ST_SENDING while the frame drains and rd.win_active
 * cleared when this was the final frame.
 */
ngx_int_t
brix_pgread_window_emit(brix_ctx_t *ctx, ngx_connection_t *c,
    ssize_t nread, size_t out_size, int io_errno)
{
    u_char  *frame = ctx->rd.read_scratch;
    int64_t  cur = (int64_t) ctx->rd.win_offset;
    size_t   got;
    u_char   resptype;

    if (nread < 0) {
        brix_read_io_failure_log(c->log, "pgread-windowed", ctx->rd.win_fd,
                                   ctx->rd.win_offset, ctx->rd.win_remaining,
                                   io_errno);
        ctx->rd.win_active = 0;
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->recv.hdr_pos = 0;
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        /* Partial frames may already be on the wire, so the terminating
         * kXR_error must carry the ORIGINAL request's streamid (§1.3
         * parity) — never cur_streamid, which the next inbound header
         * overwrites. */
        (void) brix_send_error_sid(ctx, c, ctx->rd.win_streamid, kXR_IOError,
                  io_errno ? strerror(io_errno) : "async pgread error");
        return NGX_ERROR;
    }

    got = (size_t) nread;
    ctx->files[ctx->rd.win_idx].bytes_read += got;
    ctx->totals.bytes += got;

    /* A short window is EOF and MUST end the train here: pgread framing
     * allows a partial page only in the FINAL frame, so emitting the short
     * window as kXR_PartialResult (and EOF as a later empty final) makes
     * the client reject the tail page as corrupt.  Only a full window with
     * bytes still owed continues the train. */
    if (got == brix_pgread_window_want((off_t) cur, ctx->rd.win_remaining)
        && got < ctx->rd.win_remaining)
    {
        ctx->rd.win_remaining -= got;
        ctx->rd.win_offset += (off_t) got;
    } else {
        ctx->rd.win_remaining = 0;
    }

    resptype = ctx->rd.win_remaining == 0
               ? (u_char) kXR_FinalResult : (u_char) kXR_PartialResult;

    brix_build_pgread_status_sid(ctx->rd.win_streamid, cur,
                                   (uint32_t) out_size, resptype,
                                   (ServerStatusResponse_pgRead *) frame);

    if (resptype == (u_char) kXR_FinalResult) {
        ctx->rd.win_active = 0;
        BRIX_OP_OK(ctx, BRIX_OP_PGREAD);
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;

    if (brix_queue_response_base(ctx, c, frame,
                                   sizeof(ServerStatusResponse_pgRead)
                                       + out_size, frame) != NGX_OK)
    {
        /* Hard send error: the socket is gone — stop pumping windows into
         * it (the caller resumes the event loop, which will observe the
         * dead connection). */
        ctx->rd.win_active = 0;
        return NGX_ERROR;
    }

    if (ctx->state != XRD_ST_SENDING) {
        brix_release_read_buffer(ctx, c, frame);   /* no-op scratch slot */
    }
    return NGX_OK;
}

/*
 * brix_pgread_serve_windowed — windowed-streaming entry for the pgread
 * handler (the pgread twin of read_serve_windowed): admits one window's
 * worth of budget, arms the shared windowed-read state machine with
 * win_pgread set, and kicks the pump.  cur_streamid is snapshotted into
 * win_streamid because every frame of the train must echo the originating
 * request's stream id.
 */
ngx_int_t
brix_pgread_serve_windowed(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_pgread_run_t *run)
{
    /* Admit one window's worth — the stream holds ~one encoded window in
     * read_scratch, not the full request, so many more fit under the
     * budget (parity with read_serve_windowed). */
    if (!brix_budget_admit(ctx, rconf->memory_budget,
            brix_pgread_window_scratch(0, (size_t) BRIX_READ_WINDOW))) {
        return brix_fsoverload_backoff(ctx, c, rconf);
    }

    ctx->rd.win_active = 1;
    ctx->rd.win_pgread = 1;
    ctx->rd.win_readv = 0;
    ctx->rd.win_prefetch = 0;   /* round-12: a fresh train starts with no
                                 * read-ahead in flight or stashed (the recv
                                 * defer barrier guarantees quiescence) */
    ctx->rd.win_ready = 0;
    ctx->rd.win_fd = run->fd;
    ctx->rd.win_idx = run->idx;
    ctx->rd.win_offset = (off_t) run->offset;
    ctx->rd.win_remaining = run->rlen;
    ctx->rd.win_streamid[0] = ctx->recv.cur_streamid[0];
    ctx->rd.win_streamid[1] = ctx->recv.cur_streamid[1];

    brix_prefetch_read_file(c->log, &ctx->files[run->idx],
                              (off_t) run->offset, run->rlen,
                              ctx->files[run->idx].writable
                                  ? 0 : ctx->files[run->idx].cached_size);

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];

        snprintf(detail, sizeof(detail), "%lld+%zu",
                 (long long) run->offset, run->rlen);
        brix_log_access(ctx, c, "PGREAD", ctx->files[run->idx].path,
                          detail, 1, 0, NULL, run->rlen);
    }

    brix_read_window_pump(ctx, c, rconf);
    return NGX_OK;
}
