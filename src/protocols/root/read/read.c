/*
 * read.c — kXR_read opcode.  See each function's docblock below.
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

/* Codec-vs-protocol drift guard: the wire codec (shared libxrdproto, deliberately
 * XProtocol-free) hard-codes the request body as XRDW_BODY_LEN bytes. This is the
 * one translation unit that sees both that constant and the real XProtocol
 * ClientRequestHdr, so it ties them together at compile time — if XRootD ever
 * resized the body region, every xrdw_*_unpack() call here would read the wrong
 * offsets, and this assert fails the build instead of corrupting requests. */
_Static_assert(sizeof(((ClientRequestHdr *) 0)->body) == XRDW_BODY_LEN,
    "wire codec body length must match XProtocol ClientRequestHdr.body");

/*
 * brix_read_io_t — decoded per-request read parameters, threaded through the
 * serve helpers below.
 *
 * WHAT: the validated (idx, fd, offset, rlen) tuple of one kXR_read plus the
 * per-in-flight memory buffer once the buffered path acquires it.
 * WHY: the read handler dispatches across several serve strategies (sendfile,
 * windowed, warm-probe, AIO, sync); passing one struct keeps every helper at a
 * small explicit signature instead of re-plumbing five scalars each time.
 * HOW: filled by read_validate_req(); databuf stays NULL until the buffered
 * path allocates it.  File-local only — never crosses the event loop (the
 * windowed/AIO state machines snapshot what they need into ctx as before).
 */
typedef struct {
    int       idx;      /* file-table slot */
    ngx_fd_t  fd;       /* backing fd for the slot */
    int64_t   offset;   /* requested file offset */
    size_t    rlen;     /* requested length, clamped to BRIX_READ_REQUEST_MAX */
    u_char   *databuf;  /* per-in-flight buffer (memory path only) */
} brix_read_io_t;

/*
 * brix_ktls_send_active — true when kernel-TLS transmit is active on this
 * connection (Phase 29 kTLS).
 *
 * Without kTLS, a TLS data stream must encrypt in userspace and therefore cannot
 * use sendfile(2) — the historical reason the read path gates the zero-copy
 * sendfile branch on !c->ssl.  When the kernel TLS ULP is negotiated for the send
 * side (OpenSSL SSL_OP_ENABLE_KTLS + a kTLS-offloadable cipher), the kernel does
 * the record encryption inside sendfile, so a file-backed chain is legal over TLS
 * and the read inherits the cleartext sendfile fast path (and its Phase-2
 * pipelining).  Returns 0 whenever kTLS is unavailable or not negotiated, so the
 * caller transparently falls back to the memory/window path — the relaxation is
 * always safe.
 */
static ngx_flag_t
brix_ktls_send_active(ngx_connection_t *c)
{
#ifdef BIO_get_ktls_send
    if (c->ssl != NULL && c->ssl->connection != NULL) {
        return BIO_get_ktls_send(SSL_get_wbio(c->ssl->connection)) > 0 ? 1 : 0;
    }
#endif
    return 0;
}

/* Zero-copy sendfile serve path for a regular-file cleartext (or kTLS) read:
 * clamps the chunk to EOF, charges bytes/bandwidth/dashboard + access log,
 * builds the sendfile chain and queues it.  Always completes the request --
 * the caller tail-calls this under the is_regular && (!ssl || kTLS) gate. */
static ngx_int_t
brix_read_serve_sendfile(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_read_io_t *io)
{
    size_t       data_total;
    u_char      *send_base = NULL;
    ngx_chain_t *rsp_chain;
    int          idx = io->idx;

    off_t file_size;
    off_t avail;

    /*
     * Read-only handles: file size is stable, use the value cached at open
     * time to skip the fstat(2) syscall on every chunk request.
     * Writable handles (kXR_open_updt): re-stat so a write on the same
     * session is visible to subsequent reads.
     */
    if (!ctx->files[idx].writable) {
        file_size = ctx->files[idx].cached_size;
    } else {
        struct stat st;
        if (fstat(io->fd, &st) != 0) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_READ, "READ",
                              ctx->files[idx].path, "-",
                              kXR_IOError, strerror(errno));
        }
        file_size = st.st_size;
    }

    /*
     * Clamp the chunk to bytes actually present: sendfile would otherwise be
     * asked for data past EOF.  offset at/after EOF yields a zero-length OK
     * (legal short read); otherwise serve min(rlen, remaining-to-EOF).  This
     * is also why data_total — not the client's requested rlen — drives every
     * accounting counter below.
     */
    if ((off_t) io->offset >= file_size) {
        data_total = 0;
    } else {
        avail = file_size - (off_t) io->offset;
        data_total = (avail < (off_t) io->rlen) ? (size_t) avail : io->rlen;
    }

    brix_prefetch_read_file(c->log, &ctx->files[idx], (off_t) io->offset,
                              data_total, file_size);

    ctx->files[idx].bytes_read += data_total;
    ctx->totals.bytes += data_total;
    brix_rl_charge_ctx(ctx, data_total);  /* Phase 25 bandwidth */

    /* Per-backend storage byte totals: this zero-copy branch never reaches
     * brix_vfs_io_execute (the kernel moves the bytes), so attribute here.
     * The branch gate (sd_obj.driver == NULL) means the backend is always the
     * default POSIX driver. Buffered/driver-backed reads attribute at the
     * io_execute seam instead — no double count. */
    brix_metric_backend_bytes("posix", BRIX_METRIC_OP_READ, data_total);

    if (ctx->files[idx].dashboard_slot >= 0 &&
        ngx_brix_dashboard_shm_zone != NULL)
    {
        brix_transfer_slot_update(ngx_brix_dashboard_shm_zone->data,
                                    ctx->files[idx].dashboard_slot,
                                    (ngx_atomic_int_t) data_total,
                                    (int64_t) ngx_current_msec);
        brix_transfer_slot_count_op(ngx_brix_dashboard_shm_zone->data,
                                      ctx->files[idx].dashboard_slot,
                                      "read");
    }

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char read_detail[64];

        snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                 (long long) io->offset, io->rlen);
        brix_log_access(ctx, c, "READ", ctx->files[idx].path,
                          read_detail, 1, 0, NULL, data_total);
    }
    BRIX_OP_OK(ctx, BRIX_OP_READ);

    rsp_chain = brix_build_sendfile_chain(ctx, c, io->fd,
                                            ctx->files[idx].path,
                                            (off_t) io->offset, data_total,
                                            &send_base);
    if (rsp_chain == NULL) {
        brix_release_read_buffer(ctx, c, send_base);
        return NGX_ERROR;
    }

    {
        ngx_int_t rc = brix_queue_response_chain(ctx, c, rsp_chain,
                                                   send_base);

        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            brix_release_read_buffer(ctx, c, send_base);
        }
        return rc;
    }
}

/*
 * read_validate_req — decode the wire request and run the early-return checks.
 *
 * WHAT: unpacks the kXR_read body into *io, validates the file handle, serves
 * the trivial rlen==0 case, clamps oversized requests and rejects negative
 * offsets.
 * WHY: every serve strategy needs the same validated (idx, fd, offset, rlen)
 * tuple; hoisting the checks keeps the dispatcher a pure strategy selector.
 * HOW: returns 1 when the request is valid and *io is filled (databuf NULL);
 * returns 0 when the request was fully handled here (ok/error response already
 * queued) with *rc set to the value the opcode handler must return.
 */
static ngx_flag_t
read_validate_req(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_read_io_t *io, ngx_int_t *rc)
{
    xrdw_read_req_t req;

    /*
     * The shared codec decodes the big-endian wire body into host order; the file
     * handle is a 4-byte blob but only byte 0 indexes our slot table
     * (BRIX_MAX_FILES <= 256); the (unsigned char) cast prevents sign-extension
     * of a high-bit handle byte into a negative idx.
     */
    xrdw_read_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    io->idx = (int) (unsigned char) req.fhandle[0];
    io->offset = req.offset;
    io->rlen = (size_t) (uint32_t) req.rlen;
    io->databuf = NULL;

    if (!brix_validate_read_handle(ctx, c, io->idx, "READ",
                                     BRIX_OP_READ, rc)) {
        return 0;
    }

    if (io->rlen == 0) {
        BRIX_OP_OK(ctx, BRIX_OP_READ);
        *rc = brix_send_ok(ctx, c, NULL, 0);
        return 0;
    }

    if (io->rlen > BRIX_READ_REQUEST_MAX) {
        io->rlen = BRIX_READ_REQUEST_MAX;
    }

    io->fd = ctx->files[io->idx].fd;

    if (io->offset < 0) {
        brix_log_access(ctx, c, "READ", ctx->files[io->idx].path, "-",
                          0, kXR_IOError, "negative read offset", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_READ);
        *rc = brix_send_error(ctx, c, kXR_IOError, "negative read offset");
        return 0;
    }

    return 1;
}

/*
 * read_sendfile_eligible — gate for the zero-copy sendfile fast path.
 *
 * WHAT: true when this handle/connection pair may serve the read via a
 * file-backed sendfile chain instead of the memory/window path.
 * WHY: INVARIANT — TLS serves memory-backed buffers and cleartext serves
 * file-backed + sendfile, never mixed; this predicate is the single place
 * that split is decided for kXR_read.
 * HOW: two conditions must both hold:
 *   - is_regular: sendfile(2) only works against a real file, not a pipe/dir.
 *   - !c->ssl OR kTLS active: a userspace-TLS stream cannot sendfile because
 *     nginx must encrypt each record in user memory (INVARIANT: TLS =>
 *     memory-backed buffers).  kTLS lifts that — the kernel encrypts inside
 *     sendfile — so a TLS connection with kTLS negotiated rejoins this branch.
 * Anything that fails the gate (TLS without kTLS, irregular file) drops to the
 * memory/window path.
 */
static ngx_flag_t
read_sendfile_eligible(brix_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    return ctx->files[idx].is_regular
        && (!c->ssl || brix_ktls_send_active(c))
        && ctx->files[idx].csi == NULL   /* phase-59 W2/ADR-6: CSI needs the
                                          * bytes in memory to verify, so an
                                          * integrity-checked handle takes the
                                          * buffered path, not zero-copy sendfile */
        && ctx->files[idx].sd_obj.driver == NULL; /* Layer 3: a driver-backed
                                          * handle's bare fd is only block 0 — a
                                          * sendfile over it cannot span striped
                                          * blocks, so serve via the buffered
                                          * io_core path (driver preadv) instead */
}

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
static size_t
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
static ngx_int_t
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
static ngx_int_t
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

/*
 * brix_handle_read — kXR_read dispatcher: validate, then pick a serve strategy.
 *
 * WHAT: routes a validated read to one of the serve paths — SSI/ZIP/codec
 * early dispatch, zero-copy sendfile, windowed streaming, or the buffered
 * memory path (warm-probe → AIO → synchronous fallback).
 * WHY: each strategy has its own invariants (TLS => memory-backed buffers,
 * cleartext/kTLS => sendfile; heap bounded by the streaming window); keeping
 * the handler a flat early-return ladder makes the strategy choice auditable.
 * HOW: read_validate_req() supplies the decoded request; every branch
 * tail-calls its serve helper.
 */
ngx_int_t
brix_handle_read(brix_ctx_t *ctx, ngx_connection_t *c)
{
    brix_read_io_t                io;
    ngx_stream_brix_srv_conf_t *rconf;
    ngx_int_t                     rc;

    if (!read_validate_req(ctx, c, &io, &rc)) {
        return rc;
    }

    rconf = ngx_stream_get_module_srv_conf(
                (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

    /* §7 XrdSsi: an SSI handle has no backing file — the first read dispatches the
     * accumulated request to the service and serves the response. Early dispatch
     * off the normal fd read path, like zip/slice below. */
    if (ctx->files[io.idx].ssi != NULL) {
        BRIX_OP_OK(ctx, BRIX_OP_READ);
        return brix_ssi_read(ctx, c, io.idx, (uint64_t) io.offset,
                             (uint32_t) io.rlen);
    }

    /* Phase-57 W2: ZIP member handles translate the read into the archive's
     * byte range (stored = offset add; deflate = stream inflate) — an early
     * dispatch off the normal fd read path. */
    if (ctx->files[io.idx].zip_mode) {
        return brix_zip_read(ctx, c, io.idx, io.offset, io.rlen);
    }

    /*
     * Phase-42 W4: inline read compression (opt-in, off by default).  Routed to
     * its own isolated synchronous handler so EVERYTHING below — the sendfile
     * fast path, windowed streaming and AIO pipeline — stays byte-identical for
     * the default (read_codec == 0 / BRIX_CODEC_IDENTITY) case.  pgread/readv
     * have their own handlers and never reach here, so their plaintext + CRC32c
     * invariant is preserved.
     */
    if (ctx->files[io.idx].read_codec != 0) {
        return brix_read_compressed(ctx, c, rconf, io.idx, (off_t) io.offset,
                                      io.rlen);
    }

    /*
     * Zero-copy sendfile fast path (gate in read_sendfile_eligible — the
     * TLS-vs-cleartext INVARIANT lives there).  Anything that fails the gate
     * drops to the memory/window path below.
     */
    if (read_sendfile_eligible(ctx, c, io.idx)) {
        return brix_read_serve_sendfile(ctx, c, rconf, &io);
    }

    /*
     * Phase 31 W2.1: bound resident heap for large memory-backed reads.  This
     * is the memory path (TLS / non-regular file) — unlike the cleartext
     * sendfile branch above it must buffer data in heap.  Clamp the request to
     * what the file actually holds (read-only handles have a cached size); if
     * that exceeds one streaming window, serve the read as a sequence of
     * window-sized kXR_oksofar chunks ending in kXR_ok, holding only ~one window
     * in read_scratch at a time instead of the whole request.  Writable handles
     * (size unknown) use rlen and let a short read at EOF terminate early.
     */
    {
        size_t total = read_clamped_total(ctx, &io);

        if (total > (size_t) BRIX_READ_WINDOW) {
            return read_serve_windowed(ctx, c, rconf, &io, total);
        }
    }

    /*
     * Small memory read (<= one window): single-shot.  Admit the full rlen and
     * buffer it in read_scratch — bounded by the window, so no streaming needed.
     */
    return read_serve_buffered(ctx, c, rconf, &io);
}
