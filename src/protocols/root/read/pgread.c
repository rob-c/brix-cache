/*
 * pgread.c — kXR_pgread opcode.  See each function's docblock below.
 */

#include "read.h"

#include "core/ngx_brix_module.h"
#include "fs/backend/sd.h"   /* phase-55: route preadv through the SD seam */
#include "fs/vfs/vfs_io_core.h"  /* brix_vfs_effective_obj — POSIX-wrap or driver obj */
#include "core/compat/pgio.h"     /* shared kXR page-mode encode (libxrdproto) */
#include "core/compat/crc32c.h"   /* brix_crc32c_value — in-place per-page CRC  */

#include <sys/uio.h>            /* preadv / struct iovec                        */

/* CRC32c word size per page unit ([CRC32c(4)][data]); == kXR_pgUnitSZ - page. */
#define BRIX_PG_CKSZ        ((size_t) (kXR_pgUnitSZ - kXR_pgPageSZ))
/* preadv scatter cap per syscall — mirrors kXR_readv (BRIX_READV_PREADV_MAXIOV). */
#define BRIX_PGREAD_MAXIOV  64

/*
 * brix_pgread_batch_t - one preadv scatter batch of gapped wire pages.
 *
 * WHAT: The per-batch page layout for the zero-copy paged read: the iovecs a
 *       single preadv/preadv2 call scatters into, plus each page's data
 *       pointer (just past its 4-byte CRC gap) and length, the page count,
 *       and the total file bytes the batch covers.
 *
 * WHY: Groups the parallel arrays the layout / read / CRC steps of
 *      brix_pgread_read_encode_inplace share, so each step can be a small
 *      single-purpose helper instead of one monolithic loop body.
 *
 * HOW: Filled by brix_pgread_layout_batch, read into by the driver's
 *      preadv/preadv2, checksummed by brix_pgread_crc_batch.
 */
typedef struct {
    struct iovec  iov[BRIX_PGREAD_MAXIOV];   /* scatter targets (page data)  */
    u_char       *data[BRIX_PGREAD_MAXIOV];  /* page data start (after CRC)  */
    size_t        dlen[BRIX_PGREAD_MAXIOV];  /* page data length             */
    int           k;                         /* pages in this batch          */
    size_t        bytes;                     /* total file bytes laid out    */
} brix_pgread_batch_t;

/*
 * brix_pgread_layout_batch - lay out one batch of gapped wire pages.
 *
 * WHAT: Fills `b` with up to BRIX_PGREAD_MAXIOV pages covering the next
 *       `remaining` file bytes of an rlen-byte read starting at `offset`,
 *       placing each page's data just after its 4-byte CRC gap in the wire
 *       buffer at cursor `o`.  Returns the advanced wire-buffer cursor.
 *
 * WHY: Pure gap-layout math, separated from the read syscall and the CRC
 *      pass so each stays independently reviewable (phase-72 decomposition).
 *
 * HOW: Page lengths use the in-page offset so the first fragment shortens on
 *      an unaligned read, exactly as xrdp_pg_encode does; the caller derives
 *      the batch's file offset from (rlen - remaining) the same way.
 */
static u_char *
brix_pgread_layout_batch(off_t offset, size_t rlen, size_t remaining,
    u_char *o, brix_pgread_batch_t *b)
{
    b->k = 0;
    b->bytes = 0;

    while (b->k < BRIX_PGREAD_MAXIOV && remaining > 0) {
        off_t  cur = offset + (off_t) (rlen - remaining);
        size_t in_off = (size_t) (cur & (off_t) (kXR_pgPageSZ - 1));
        size_t len = (size_t) kXR_pgPageSZ - in_off;

        if (len > remaining) {
            len = remaining;
        }
        b->data[b->k] = o + BRIX_PG_CKSZ;
        b->dlen[b->k] = len;
        b->iov[b->k].iov_base = b->data[b->k];
        b->iov[b->k].iov_len  = len;
        o           += BRIX_PG_CKSZ + len;
        b->bytes    += len;
        remaining   -= len;
        b->k++;
    }

    return o;
}

/*
 * brix_pgread_crc_batch - checksum the bytes one batch actually delivered.
 *
 * WHAT: Fuses the per-page CRC32c over exactly `got` bytes of batch `b`,
 *       writing each 4-byte big-endian checksum into the gap preceding its
 *       page data and adding the encoded bytes to *out_size.  Returns 1 when
 *       a short page ends the file (EOF), 0 otherwise.
 *
 * WHY: The CRC pass over delivered bytes is pure computation over the batch
 *      layout; splitting it from the read loop keeps the encode function
 *      under the complexity gate without touching the wire bytes.
 *
 * HOW: Walks the batch pages until the delivered bytes run out; a page that
 *      comes up short means EOF, so stop — no more data follows.
 */
static int
brix_pgread_crc_batch(brix_pgread_batch_t *b, size_t got, size_t *out_size)
{
    int i;

    for (i = 0; i < b->k; i++) {
        size_t   al = (got < b->dlen[i]) ? got : b->dlen[i];
        uint32_t crc_be;

        if (al == 0) {
            break;
        }
        crc_be = htonl(brix_crc32c_value(b->data[i], al));
        memcpy(b->data[i] - BRIX_PG_CKSZ, &crc_be, BRIX_PG_CKSZ);
        *out_size += BRIX_PG_CKSZ + al;
        got       -= al;
        if (al < b->dlen[i]) {
            return 1;   /* short page => short read; no more data follows */
        }
    }

    return 0;
}

/*
 * brix_pgread_read_encode_inplace - zero-copy paged read + in-place CRC.
 *
 * WHAT: Reads up to `rlen` bytes from `fd` at `offset` DIRECTLY into the final
 *       kXR page-mode wire buffer `out` (laid out as [CRC32c(4)][data] per page,
 *       file-offset aligned) and computes each page's CRC32c in place, writing
 *       the 4-byte big-endian checksum into the gap that precedes its data.
 *       Returns the encoded byte count; sets io->nread to bytes read (-1 on I/O
 *       error, with io->io_errno = errno). io->nowait selects the read mode.
 *
 * WHY: The previous path pread() the data into a flat buffer and then ran
 *      xrdp_pg_encode to COPY it into the interleaved wire buffer while
 *      checksumming. Flame-graph profiling showed that copy (a full extra pass
 *      over every byte — the dst-write memory stream) dominating read CPU, and a
 *      copy is memory-bandwidth-bound so the 3-way CRC barely helps it. Reading
 *      straight into the gapped wire buffer removes the copy entirely; the CRC
 *      then runs read-only (brix_crc32c_value, the latency-hiding 3-way path)
 *      over the data already in place. This mirrors the zero-copy preadv-into-
 *      final-buffer pattern kXR_readv already uses. Output is byte-identical to
 *      xrdp_pg_encode (Invariant #1): same page splitting, same CRC, same layout.
 *
 * HOW: Lay out one batch of <= BRIX_PGREAD_MAXIOV pages (data after each 4-byte
 *      CRC gap), preadv the batch's contiguous file region into those gapped
 *      positions, then fuse the per-page CRC over exactly the bytes the batch
 *      delivered — a short page or short batch means EOF, so stop. Page lengths
 *      use the in-page offset so the first fragment shortens on an unaligned
 *      read, exactly as xrdp_pg_encode does.
 */
size_t
brix_pgread_read_encode_inplace(brix_sd_obj_t *obj, off_t offset,
    size_t rlen, u_char *out, brix_pgread_io_t *io)
{
    u_char  *o = out;            /* write cursor in the gapped wire buffer */
    size_t   remaining = rlen;   /* file bytes not yet laid out into a batch */
    size_t          out_size = 0;       /* encoded bytes produced so far */
    ssize_t         total = 0;          /* file bytes actually read */
    int             eof = 0;

    io->nread = 0;
    io->io_errno = 0;

    /* The batched vectored read goes through the handle's storage driver (POSIX
     * or block-striped); the page layout / in-place CRC policy stays here. */

    while (remaining > 0 && !eof) {
        brix_pgread_batch_t batch;
        off_t   batch_off = offset + (off_t) (rlen - remaining);
        ssize_t n;

        /* Lay out a batch of pages: data lands after each 4-byte CRC gap. */
        o = brix_pgread_layout_batch(offset, rlen, remaining, o, &batch);
        remaining -= batch.bytes;

#if defined(RWF_NOWAIT)
        if (io->nowait) {
            /* Warm-cache probe: read only what is already resident. Any short
             * batch or EAGAIN means "not fully in page cache" — abort the whole
             * inline attempt so the caller offloads a blocking read (which also
             * re-detects true EOF correctly). A real error likewise aborts; the
             * blocking re-read surfaces it. Earlier full batches' work is
             * discarded by that re-read. */
            n = obj->driver->preadv2(obj, batch.iov, batch.k, batch_off,
                                               RWF_NOWAIT);
            if (n < 0 || (size_t) n < batch.bytes) {
                io->nread = 0;
                io->io_errno = (n < 0) ? errno : EAGAIN;
                return 0;
            }
        } else
#endif
        {
            /* Compat seam: drivers without a native preadv slot (remote/object
             * backends) fall back to per-iovec pread inside the helper. */
            n = brix_sd_obj_preadv(obj, batch.iov, batch.k, batch_off);
            if (n < 0) {
                io->nread = -1;
                io->io_errno = errno;
                return 0;
            }
        }
        total += n;

        /* Fuse the per-page CRC over exactly the bytes this batch delivered. */
        if (brix_pgread_crc_batch(&batch, (size_t) n, &out_size)) {
            eof = 1;
        }

        if ((size_t) n < batch.bytes) {
            eof = 1;       /* short batch overall => EOF */
        }
    }

    io->nread = total;
    return out_size;
}

/*
 * Encode raw file data into kXR page-mode [CRC32c(4)][data] units, file-offset
 * aligned (short first fragment on an unaligned read). Thin wrapper over the
 * shared page-mode encoder (libxrdproto) so the module and the native client
 * frame pages byte-identically.
 */
size_t
brix_pgread_encode_pages(const u_char *src, size_t len, off_t offset,
                           u_char *dst)
{
    return xrdp_pg_encode((const uint8_t *) src, len, (int64_t) offset,
                          (uint8_t *) dst);
}

/*
 * brix_pgread_run_t - per-request state threaded through the pgread steps.
 *
 * WHAT: The decoded request (handle index, fd, offset, capped length), the
 *       shared scratch buffer, and the produced output {out_buf, out_size,
 *       flat_buf} — filled by exactly one producer path (warm hit, AIO
 *       offload, or sync fallback).
 *
 * WHY: Makes the phase-72.A invariant structural: out_buf/flat_buf/out_size
 *      start NULL/0 (the handler zeroes the struct) and every producer sets
 *      all three through this one struct, so the pre-framing out_buf==NULL
 *      guard catches any path that failed to produce output.
 */
typedef struct {
    int       idx;        /* file-handle table index                        */
    int       fd;         /* resolved file descriptor                       */
    int64_t   offset;     /* requested file offset                          */
    size_t    rlen;       /* capped request length; sync path: bytes read   */
    u_char   *scratch;    /* gapped wire buffer (read_scratch slot)         */
    u_char   *out_buf;    /* encoded output start (NULL until produced)     */
    u_char   *flat_buf;   /* buffer to release after send (NULL until set)  */
    size_t    out_size;   /* encoded output bytes (0 until produced)        */
} brix_pgread_run_t;

/*
 * brix_pgread_parse_validate - decode the request and run all early checks.
 *
 * WHAT: Unpacks the kXR_pgread request into `run`, validates the handle,
 *       rejects negative offset/length, answers a zero-length read with an
 *       empty kXR_status frame, caps rlen, and resolves the fd.  Returns 1 to
 *       continue; 0 when the request was fully handled (*rc holds the
 *       handler's return value — error sent, empty response queued, or
 *       NGX_ERROR).
 *
 * WHY: All reject/short-circuit paths in one early-return helper keeps the
 *      handler a flat orchestrator (coding-standards §8).
 *
 * HOW: Mirrors brix_validate_read_handle's continue-flag + *rc convention
 *      so the caller propagates the exact wire response codes unchanged.
 */
static ngx_int_t
brix_pgread_parse_validate(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_pgread_run_t *run, ngx_int_t *rc)
{
    xrdw_pgread_req_t             req;
    ServerStatusResponse_pgRead  *hdr_buf;

    xrdw_pgread_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    run->idx = (int) (unsigned char) req.fhandle[0];
    run->offset = req.offset;
    run->rlen = (size_t) (uint32_t) req.rlen;

    if (!brix_validate_read_handle(ctx, c, run->idx, "PGREAD",
                                     BRIX_OP_PGREAD, rc)) {
        return 0;
    }

    if (run->offset < 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        *rc = brix_send_error(ctx, c, kXR_IOError,
                                "negative read offset");
        return 0;
    }

    /* The wire rlen is a signed 32-bit field; a negative request length is
     * invalid.  Read unsigned it would turn -1 into ~4 GiB (then capped),
     * silently succeeding where the reference rejects with kXR_ArgInvalid. */
    if (req.rlen < 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        *rc = brix_send_error(ctx, c, kXR_ArgInvalid,
                                "negative read length");
        return 0;
    }

    if (run->rlen == 0) {
        hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
        if (hdr_buf == NULL) {
            *rc = NGX_ERROR;
            return 0;
        }
        brix_build_pgread_status(ctx, run->offset, 0, hdr_buf);
        BRIX_OP_OK(ctx, BRIX_OP_PGREAD);
        *rc = brix_queue_response(ctx, c, (u_char *) hdr_buf,
                                    sizeof(*hdr_buf));
        return 0;
    }

    if (run->rlen > BRIX_READ_REQUEST_MAX) {
        run->rlen = BRIX_READ_REQUEST_MAX;
    }

    run->fd = ctx->files[run->idx].fd;
    return 1;
}

/*
 * brix_pgread_alloc_scratch - size and fetch the gapped wire buffer.
 *
 * WHAT: Computes the worst-case page count for the request and returns the
 *       per-connection read scratch slot grown to hold the interleaved
 *       [CRC32c(4)][data] wire output (NULL on allocation failure).
 *
 * WHY: The buffer-size math is pure and self-contained; isolating it keeps
 *      the page-count subtlety (alignment split) documented in one place.
 *
 * HOW: File-offset alignment can split an otherwise single-page read across
 *      two pages (short first fragment + remainder), so the page count is
 *      derived from the in-page offset, not just rlen — otherwise the
 *      scratch/out region would be one CRC short.
 */
static u_char *
brix_pgread_alloc_scratch(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_pgread_run_t *run)
{
    size_t  n_pages_max;
    size_t  scratch_size;

    n_pages_max = ((size_t) (run->offset & (kXR_pgPageSZ - 1)) + run->rlen
                   + kXR_pgPageSZ - 1) / kXR_pgPageSZ;
    if (n_pages_max == 0) {
        n_pages_max = 1;
    }
    /*
     * Single buffer holding the final interleaved [CRC32c(4)][data] wire
     * output (data is read straight into it — no separate flat copy region),
     * so it needs only the data bytes plus one 4-byte CRC per page.
     */
    scratch_size = run->rlen + n_pages_max * BRIX_PG_CKSZ;

    return BRIX_GET_SCRATCH(ctx, c, rd.read_scratch, rd.read_scratch_size,
                              scratch_size);
}

/*
 * brix_pgread_try_warm - inline warm-cache fast path.
 *
 * WHAT: Attempts the whole read + in-place CRC on the event loop via
 *       preadv2(RWF_NOWAIT).  On a full hit fills run->{out_buf, out_size,
 *       flat_buf}, charges the backend byte metric, and returns 1; on any
 *       miss returns 0 with the run output untouched.
 *
 * WHY: When the whole range is already page-cache resident, reading + CRCing
 *      inline skips the thread-pool handoff entirely — the handoff latency,
 *      not the copy, is the single-stream (n=1) cost. A miss (not resident /
 *      EOF / error) falls through to the blocking offload, which re-reads the
 *      full range. Only attempted with a pool configured (else the blocking
 *      path runs inline anyway) and for a regular file (RWF_NOWAIT is
 *      meaningful against the page cache). Mirrors the kXR_read Phase-32 probe.
 *
 * HOW: Delegates to brix_pgread_read_encode_inplace with nowait=1 against
 *      the handle's effective storage object; a hit means errno stayed 0 and
 *      every requested byte was delivered.
 */
static ngx_flag_t
brix_pgread_try_warm(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *rconf,
    brix_pgread_run_t *run)
{
    brix_pgread_io_t warm_io = { .nowait = 1, .nread = 0, .io_errno = 0 };
    size_t          warm_osz;
    brix_sd_obj_t warm_scratch;
    brix_sd_obj_t *warm_obj;

    if (rconf->common.thread_pool == NULL
        || !ctx->files[run->idx].is_regular)
    {
        return 0;
    }

    warm_obj = brix_vfs_effective_obj(&ctx->files[run->idx].sd_obj, run->fd,
                                        &warm_scratch);

    /* The RWF_NOWAIT probe needs the driver's native preadv2; drivers without
     * one (remote/object backends) have no page cache to probe — treat as a
     * miss so the read offloads to the blocking path. */
    if (warm_obj->driver->preadv2 == NULL) {
        return 0;
    }

    warm_osz = brix_pgread_read_encode_inplace(warm_obj, (off_t) run->offset,
                                                 run->rlen, run->scratch,
                                                 &warm_io);
    if (warm_io.io_errno != 0 || warm_io.nread != (ssize_t) run->rlen) {
        return 0;
    }

    run->out_size = warm_osz;
    run->flat_buf = run->scratch;
    run->out_buf  = run->scratch;      /* rlen already == bytes encoded */

    /* The warm fast path bypasses brix_vfs_io_execute (where the
     * cold pgread paths attribute), so charge the per-backend read
     * total here for the file bytes just read. */
    brix_metric_backend_bytes(
        ctx->files[run->idx].sd_obj.driver != NULL
            ? ctx->files[run->idx].sd_obj.driver->name : "posix",
        BRIX_METRIC_OP_READ, (size_t) warm_io.nread);

    return 1;
}

/*
 * brix_pgread_post_aio - offload the read to the thread pool.
 *
 * WHAT: Fills the connection's reusable pgread AIO task from `run` and posts
 *       it to the configured thread pool.  Returns NGX_OK when posted (the
 *       completion handler sends the response), NGX_DECLINED when the post
 *       failed (caller falls back to the sync path), NGX_ERROR on
 *       allocation failure.
 *
 * WHY: The task-population boilerplate is one nameable step of the handler;
 *      extracting it keeps the orchestrator flat (coding-standards §8).
 *
 * HOW: Reuses ctx->rd.pgread_aio_task across requests (allocating it once
 *      from the connection pool), binds the pgread worker/done pair, and
 *      lets brix_aio_post_task log the fallback warning on post failure.
 */
static ngx_int_t
brix_pgread_post_aio(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_pgread_run_t *run)
{
    ngx_thread_task_t   *task;
    brix_pgread_aio_t *t;
    ngx_flag_t           posted;

    task = ctx->rd.pgread_aio_task;
    if (task == NULL) {
        task = ngx_thread_task_alloc(c->pool,
                                     sizeof(brix_pgread_aio_t));
        if (task == NULL) {
            return NGX_ERROR;
        }
        ctx->rd.pgread_aio_task = task;
    } else {
        task->next = NULL;
        task->event.complete = 0;
    }

    t = task->ctx;
    t->c = c;
    t->ctx = ctx;
    t->fd = run->fd;
    t->handle_idx = run->idx;
    t->offset = (off_t) run->offset;
    t->rlen = run->rlen;
    t->scratch = run->scratch;
    t->out_size = 0;
    t->streamid[0] = ctx->recv.cur_streamid[0];
    t->streamid[1] = ctx->recv.cur_streamid[1];
    t->obj = ctx->files[run->idx].sd_obj; /* Layer 3: driver obj (or zeroed) */

    brix_task_bind(task, brix_pgread_aio_thread, brix_pgread_aio_done);

    (void) brix_aio_post_task(ctx, c, rconf->common.thread_pool, task,
                                "brix: thread_task_post failed, sync pgread fallback",
                                &posted);

    return posted ? NGX_OK : NGX_DECLINED;
}

/*
 * brix_pgread_sync_fill - blocking fallback read into the wire buffer.
 *
 * WHAT: Runs the pgread VFS job inline (read directly into the gapped wire
 *       buffer, CRC each page in place — no flat-buffer copy).  On success
 *       fills run->{out_buf, out_size, flat_buf}, updates run->rlen to the
 *       bytes actually read (accounting), and returns 0; on I/O error
 *       returns the job's errno for the caller's error triplet.
 *
 * WHY: Same code path as the AIO worker, kept as a pure produce-or-errno
 *      step so the handler owns the wire error response (side effects at
 *      the edges, coding-standards §8).
 *
 * HOW: Skipped by the caller when the warm-cache fast path already produced
 *      the encoding; runs when no thread pool is configured or the post
 *      failed.
 */
static int
brix_pgread_sync_fill(brix_ctx_t *ctx, brix_pgread_run_t *run)
{
    brix_vfs_job_t job;

    brix_vfs_job_read_init(&job, run->fd, (off_t) run->offset, run->rlen,
                              run->scratch, run->rlen, 0);
    job.op = BRIX_VFS_IO_PGREAD;
    brix_vfs_job_set_obj(&job, &ctx->files[run->idx].sd_obj);
    brix_vfs_io_execute(&job);

    if (job.io_errno != 0) {
        return job.io_errno;
    }

    run->out_size = job.out_size;
    run->flat_buf = run->scratch;
    run->out_buf  = run->scratch;      /* output starts at offset 0 now */
    run->rlen     = (size_t) job.nio;  /* actual bytes read (accounting) */
    return 0;
}

/*
 * brix_pgread_send_response - frame, account, log, and queue the reply.
 *
 * WHAT: Builds the kXR_status(4007) response chain over the produced output,
 *       charges the byte accounting / bandwidth limiter, writes the access
 *       log line, and queues the chain.  Returns the queue rc (NGX_ERROR on
 *       framing failure), releasing the read buffer on any non-send outcome.
 *
 * WHY: Response assembly is the handler's final nameable step; the order of
 *      framing → accounting → log → metric → queue is frozen (byte-identical
 *      wire output and log lines).
 *
 * HOW: run->rlen here is the actual byte count (the sync path overwrote it
 *      with job.nio; the warm path read exactly rlen).  The buffer is kept
 *      only while the send is in flight (state XRD_ST_SENDING).
 */
static ngx_int_t
brix_pgread_send_response(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_pgread_run_t *run)
{
    ngx_chain_t  *rsp_chain;
    char          detail[64];
    ngx_int_t     rc;

    rsp_chain = brix_build_pgread_chain(ctx, c, run->offset, run->out_buf,
                                          (uint32_t) run->out_size);
    if (rsp_chain == NULL) {
        brix_release_read_buffer(ctx, c, run->flat_buf);
        return NGX_ERROR;
    }

    ctx->files[run->idx].bytes_read += run->rlen;
    ctx->totals.bytes += run->rlen;
    brix_rl_charge_ctx(ctx, run->rlen);  /* Phase 25 bandwidth */

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        snprintf(detail, sizeof(detail), "%lld+%zu",
                 (long long) run->offset, run->rlen);
        brix_log_access(ctx, c, "PGREAD", ctx->files[run->idx].path,
                          detail, 1, 0, NULL, run->rlen);
    }
    BRIX_OP_OK(ctx, BRIX_OP_PGREAD);

    rc = brix_queue_response_chain(ctx, c, rsp_chain, run->flat_buf);
    if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
        brix_release_read_buffer(ctx, c, run->flat_buf);
    }
    return rc;
}

/*
 * brix_handle_pgread - kXR_pgread orchestrator.
 *
 * WHAT: Decodes and validates the request, sizes the wire buffer, then tries
 *       the producer paths in order — warm-cache inline, thread-pool offload,
 *       sync fallback — and frames whatever output was produced.
 *
 * WHY: Flat sequence of named steps per coding-standards §8; the complexity
 *      lives in the helpers above.
 *
 * HOW: run.{out_buf, flat_buf, out_size} start NULL/0 (phase-72.A) and are
 *      set only by a producer; the out_buf==NULL guard before framing makes
 *      the exactly-one-producer invariant enforceable.
 */
ngx_int_t
brix_handle_pgread(brix_ctx_t *ctx, ngx_connection_t *c)
{
    /* phase-42 W4 invariant: pgread is ALWAYS plaintext — it never consults
     * ctx->files[idx].read_codec.  Inline read compression is a kXR_read-only
     * handle property; pgread's kXR_status(4007) framing + per-page CRC32c must
     * stay byte-for-byte intact, so compression is deliberately not applied here. */
    brix_pgread_run_t             run;
    ngx_stream_brix_srv_conf_t *rconf;
    ngx_int_t                     rc;
    ngx_flag_t                    warm_hit;

    ngx_memzero(&run, sizeof(run));   /* out_buf/flat_buf NULL, out_size 0 */

    if (!brix_pgread_parse_validate(ctx, c, &run, &rc)) {
        return rc;
    }

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

    run.scratch = brix_pgread_alloc_scratch(ctx, c, &run);
    if (run.scratch == NULL) {
        return NGX_ERROR;
    }

    warm_hit = brix_pgread_try_warm(ctx, rconf, &run);

    if (!warm_hit && rconf->common.thread_pool != NULL) {
        rc = brix_pgread_post_aio(ctx, c, rconf, &run);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }
        if (rc == NGX_OK) {
            return NGX_OK;   /* posted; the AIO done handler responds */
        }
        /* NGX_DECLINED: post failed — fall through to the sync path. */
    }

    if (!warm_hit) {
        int io_errno = brix_pgread_sync_fill(ctx, &run);

        if (io_errno != 0) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_PGREAD, "PGREAD",
                              ctx->files[run.idx].path, "-",
                              kXR_IOError, strerror(io_errno));
        }
    }

    /* Invariant: exactly one of the producer paths (warm hit or sync
     * fallback) must have filled the output; the AIO path returned above. */
    if (run.out_buf == NULL) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_PGREAD, "PGREAD",
                          ctx->files[run.idx].path, "-",
                          kXR_ServerError, "pgread: no output produced");
    }

    return brix_pgread_send_response(ctx, c, rconf, &run);
}
