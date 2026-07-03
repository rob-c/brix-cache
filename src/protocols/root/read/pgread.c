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
 * brix_pgread_read_encode_inplace - zero-copy paged read + in-place CRC.
 *
 * WHAT: Reads up to `rlen` bytes from `fd` at `offset` DIRECTLY into the final
 *       kXR page-mode wire buffer `out` (laid out as [CRC32c(4)][data] per page,
 *       file-offset aligned) and computes each page's CRC32c in place, writing
 *       the 4-byte big-endian checksum into the gap that precedes its data.
 *       Returns the encoded byte count; sets *nread_out to bytes read (-1 on I/O
 *       error, with *io_errno_out = errno).
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
    size_t rlen, u_char *out, ssize_t *nread_out, int *io_errno_out, int nowait)
{
    u_char  *o = out;            /* write cursor in the gapped wire buffer */
    size_t   remaining = rlen;   /* file bytes not yet laid out into a batch */
    size_t          out_size = 0;       /* encoded bytes produced so far */
    ssize_t         total = 0;          /* file bytes actually read */
    int             eof = 0;

    *nread_out = 0;
    *io_errno_out = 0;

    /* The batched vectored read goes through the handle's storage driver (POSIX
     * or block-striped); the page layout / in-place CRC policy stays here. */

    while (remaining > 0 && !eof) {
        struct iovec iov[BRIX_PGREAD_MAXIOV];
        u_char      *data[BRIX_PGREAD_MAXIOV];
        size_t       dlen[BRIX_PGREAD_MAXIOV];
        off_t        batch_off = offset + (off_t) (rlen - remaining);
        size_t       batch_bytes = 0;
        ssize_t      n;
        size_t       got;
        int          k = 0;
        int          i;

        /* Lay out a batch of pages: data lands after each 4-byte CRC gap. */
        while (k < BRIX_PGREAD_MAXIOV && remaining > 0) {
            off_t  cur = offset + (off_t) (rlen - remaining);
            size_t in_off = (size_t) (cur & (off_t) (kXR_pgPageSZ - 1));
            size_t len = (size_t) kXR_pgPageSZ - in_off;

            if (len > remaining) {
                len = remaining;
            }
            data[k] = o + BRIX_PG_CKSZ;
            dlen[k] = len;
            iov[k].iov_base = data[k];
            iov[k].iov_len  = len;
            o           += BRIX_PG_CKSZ + len;
            batch_bytes += len;
            remaining   -= len;
            k++;
        }

#if defined(RWF_NOWAIT)
        if (nowait) {
            /* Warm-cache probe: read only what is already resident. Any short
             * batch or EAGAIN means "not fully in page cache" — abort the whole
             * inline attempt so the caller offloads a blocking read (which also
             * re-detects true EOF correctly). A real error likewise aborts; the
             * blocking re-read surfaces it. Earlier full batches' work is
             * discarded by that re-read. */
            n = obj->driver->preadv2(obj, iov, k, batch_off,
                                               RWF_NOWAIT);
            if (n < 0 || (size_t) n < batch_bytes) {
                *nread_out = 0;
                *io_errno_out = (n < 0) ? errno : EAGAIN;
                return 0;
            }
        } else
#endif
        {
            n = obj->driver->preadv(obj, iov, k, batch_off);
            if (n < 0) {
                *nread_out = -1;
                *io_errno_out = errno;
                return 0;
            }
        }
        total += n;

        /* Fuse the per-page CRC over exactly the bytes this batch delivered. */
        got = (size_t) n;
        for (i = 0; i < k; i++) {
            size_t   al = (got < dlen[i]) ? got : dlen[i];
            uint32_t crc_be;

            if (al == 0) {
                break;
            }
            crc_be = htonl(brix_crc32c_value(data[i], al));
            memcpy(data[i] - BRIX_PG_CKSZ, &crc_be, BRIX_PG_CKSZ);
            out_size += BRIX_PG_CKSZ + al;
            got      -= al;
            if (al < dlen[i]) {
                eof = 1;   /* short page => short read; no more data follows */
                break;
            }
        }

        if ((size_t) n < batch_bytes) {
            eof = 1;       /* short batch overall => EOF */
        }
    }

    *nread_out = total;
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

ngx_int_t
brix_handle_pgread(brix_ctx_t *ctx, ngx_connection_t *c)
{
    /* phase-42 W4 invariant: pgread is ALWAYS plaintext — it never consults
     * ctx->files[idx].read_codec.  Inline read compression is a kXR_read-only
     * handle property; pgread's kXR_status(4007) framing + per-page CRC32c must
     * stay byte-for-byte intact, so compression is deliberately not applied here. */
    xrdw_pgread_req_t             req;
    int                           idx;
    int64_t                       offset;
    size_t                        rlen;
    int                           fd;
    u_char                       *flat_buf;
    u_char                       *out_buf;
    size_t                        out_size;
    ServerStatusResponse_pgRead  *hdr_buf;
    ngx_chain_t                  *rsp_chain;
    ngx_stream_brix_srv_conf_t *rconf;
    char                          detail[64];
    ngx_int_t                     validate_rc;

    xrdw_pgread_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    idx = (int) (unsigned char) req.fhandle[0];
    offset = req.offset;
    rlen = (size_t) (uint32_t) req.rlen;

    if (!brix_validate_read_handle(ctx, c, idx, "PGREAD",
                                     BRIX_OP_PGREAD, &validate_rc)) {
        return validate_rc;
    }

    if (offset < 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        return brix_send_error(ctx, c, kXR_IOError,
                                 "negative read offset");
    }

    /* The wire rlen is a signed 32-bit field; a negative request length is
     * invalid.  Read unsigned it would turn -1 into ~4 GiB (then capped),
     * silently succeeding where the reference rejects with kXR_ArgInvalid. */
    if (req.rlen < 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        return brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "negative read length");
    }

    if (rlen == 0) {
        hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
        if (hdr_buf == NULL) {
            return NGX_ERROR;
        }
        brix_build_pgread_status(ctx, offset, 0, hdr_buf);
        BRIX_OP_OK(ctx, BRIX_OP_PGREAD);
        return brix_queue_response(ctx, c, (u_char *) hdr_buf,
                                     sizeof(*hdr_buf));
    }

    if (rlen > BRIX_READ_REQUEST_MAX) {
        rlen = BRIX_READ_REQUEST_MAX;
    }

    fd = ctx->files[idx].fd;

    {
        size_t     n_pages_max;
        size_t     scratch_size;
        u_char    *scratch;
        ngx_flag_t warm_hit = 0;

        rconf = ngx_stream_get_module_srv_conf(
            (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

        /*
         * File-offset alignment can split an otherwise single-page read across
         * two pages (short first fragment + remainder), so the page count is
         * derived from the in-page offset, not just rlen — otherwise the
         * scratch/out region would be one CRC short.
         */
        n_pages_max = ((size_t) (offset & (kXR_pgPageSZ - 1)) + rlen
                       + kXR_pgPageSZ - 1) / kXR_pgPageSZ;
        if (n_pages_max == 0) {
            n_pages_max = 1;
        }
        /*
         * Single buffer holding the final interleaved [CRC32c(4)][data] wire
         * output (data is read straight into it — no separate flat copy region),
         * so it needs only the data bytes plus one 4-byte CRC per page.
         */
        scratch_size = rlen + n_pages_max * BRIX_PG_CKSZ;

        scratch = BRIX_GET_SCRATCH(ctx, c, read_scratch, read_scratch_size,
                                     scratch_size);
        if (scratch == NULL) {
            return NGX_ERROR;
        }

        /*
         * Warm-cache fast path: when the whole range is already page-cache
         * resident, read + CRC it inline on the event loop via preadv2
         * (RWF_NOWAIT) and skip the thread-pool handoff entirely — the handoff
         * latency, not the copy, is the single-stream (n=1) cost. A miss
         * (not resident / EOF / error) sets no warm_hit and falls through to the
         * blocking offload below, which re-reads the full range. Only attempted
         * with a pool configured (else the blocking path runs inline anyway) and
         * for a regular file (RWF_NOWAIT is meaningful against the page cache).
         * Mirrors the kXR_read Phase-32 probe.
         */
        if (rconf->common.thread_pool != NULL && ctx->files[idx].is_regular) {
            ssize_t         warm_nread = 0;
            int             warm_errno = 0;
            size_t          warm_osz;
            brix_sd_obj_t warm_scratch;
            brix_sd_obj_t *warm_obj;

            warm_obj = brix_vfs_effective_obj(&ctx->files[idx].sd_obj, fd,
                                                &warm_scratch);
            warm_osz = brix_pgread_read_encode_inplace(warm_obj, (off_t) offset,
                                                         rlen, scratch,
                                                         &warm_nread,
                                                         &warm_errno, 1);
            if (warm_errno == 0 && warm_nread == (ssize_t) rlen) {
                out_size = warm_osz;
                flat_buf = scratch;
                out_buf  = scratch;
                warm_hit = 1;          /* rlen already == bytes encoded */

                /* The warm fast path bypasses brix_vfs_io_execute (where the
                 * cold pgread paths attribute), so charge the per-backend read
                 * total here for the file bytes just read. */
                brix_metric_backend_bytes(
                    ctx->files[idx].sd_obj.driver != NULL
                        ? ctx->files[idx].sd_obj.driver->name : "posix",
                    BRIX_METRIC_OP_READ, (size_t) warm_nread);
            }
        }

        if (!warm_hit && rconf->common.thread_pool != NULL) {
            ngx_thread_task_t   *task;
            brix_pgread_aio_t *t;
            ngx_flag_t           posted;

            task = ctx->pgread_aio_task;
            if (task == NULL) {
                task = ngx_thread_task_alloc(c->pool,
                                             sizeof(brix_pgread_aio_t));
                if (task == NULL) {
                    return NGX_ERROR;
                }
                ctx->pgread_aio_task = task;
            } else {
                task->next = NULL;
                task->event.complete = 0;
            }

            t = task->ctx;
            t->c = c;
            t->ctx = ctx;
            t->fd = fd;
            t->handle_idx = idx;
            t->offset = (off_t) offset;
            t->rlen = rlen;
            t->scratch = scratch;
            t->out_size = 0;
            t->streamid[0] = ctx->cur_streamid[0];
            t->streamid[1] = ctx->cur_streamid[1];
            t->obj = ctx->files[idx].sd_obj; /* Layer 3: driver obj (or zeroed) */

            brix_task_bind(task, brix_pgread_aio_thread, brix_pgread_aio_done);

            (void) brix_aio_post_task(ctx, c, rconf->common.thread_pool, task,
                                        "brix: thread_task_post failed, sync pgread fallback",
                                        &posted);
            if (posted) {
                return NGX_OK;
            }
        }

        /*
         * Sync fallback: read directly into the gapped wire buffer and CRC each
         * page in place (no flat-buffer copy). Same code path as the AIO worker.
         * Skipped when the warm-cache fast path already produced the encoding.
         */
        if (!warm_hit) {
            brix_vfs_job_t job;

            brix_vfs_job_read_init(&job, fd, (off_t) offset, rlen,
                                      scratch, rlen, 0);
            job.op = BRIX_VFS_IO_PGREAD;
            brix_vfs_job_set_obj(&job, &ctx->files[idx].sd_obj);
            brix_vfs_io_execute(&job);

            if (job.io_errno != 0) {
                BRIX_RETURN_ERR(ctx, c, BRIX_OP_PGREAD, "PGREAD",
                                  ctx->files[idx].path, "-",
                                  kXR_IOError, strerror(job.io_errno));
            }

            out_size = job.out_size;
            flat_buf = scratch;
            out_buf  = scratch;            /* output starts at offset 0 now */
            rlen     = (size_t) job.nio;   /* actual bytes read (accounting) */
        }
    }

    rsp_chain = brix_build_pgread_chain(ctx, c, offset, out_buf,
                                          (uint32_t) out_size);
    if (rsp_chain == NULL) {
        brix_release_read_buffer(ctx, c, flat_buf);
        return NGX_ERROR;
    }

    ctx->files[idx].bytes_read += rlen;
    ctx->session_bytes += rlen;
    brix_rl_charge_ctx(ctx, rlen);  /* Phase 25 bandwidth */

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        snprintf(detail, sizeof(detail), "%lld+%zu", (long long) offset, rlen);
        brix_log_access(ctx, c, "PGREAD", ctx->files[idx].path,
                          detail, 1, 0, NULL, rlen);
    }
    BRIX_OP_OK(ctx, BRIX_OP_PGREAD);

    {
        ngx_int_t rc = brix_queue_response_chain(ctx, c, rsp_chain, flat_buf);

        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            brix_release_read_buffer(ctx, c, flat_buf);
        }
        return rc;
    }
}
