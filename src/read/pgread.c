/* ------------------------------------------------------------------ */
/* Paged Read — kXR_pgread with CRC32c Integrity                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_pgread opcode — page-mode reads used by xrdcp v5 for high-integrity large-file transfers. Unlike single-segment kXR_read which returns raw bytes, pgread interleaves 4-byte CRC32c checksums between each page fragment (up to 4096 bytes per page) ensuring every byte read is verified against its checksum before returning to client. The response uses kXR_status framing with next expected offset — this allows clients to track read progress precisely through large transfers and retry corrupted pages without retransmitting the entire file.
 *
 * WHY: Page-mode reads provide byte-level integrity verification for large file downloads where single-segment kXR_read would offer no checksum protection. CRC32c per-page verification ensures data corruption is detected immediately rather than after transfer completion — clients can retry corrupted pages without retransmitting the entire file. The kXR_status response (next expected offset) enables precise progress tracking, critical for resumable downloads and monitoring large transfers in production deployments where network failures may interrupt mid-transfer reads.
 *
 * HOW: Two-phase encoding → xrootd_pgread_encode_pages(): iterate through source bytes splitting into pages (kXR_pgPageSZ=4096), compute CRC32c via xrootd_crc32c_copy() while simultaneously copying data to destination buffer, append 4-byte CRC after each page fragment — returns total encoded length; xrootd_handle_pgread(): validates read handle (xrootd_validate_read_handle for read-side validation) — reads from file using pread(2) (AIO thread-pool or inline fallback) — encodes pages via xrootd_pgread_encode_pages() — builds response chain with kXR_status framing containing next expected offset — queues response via xrootd_queue_response_chain(). */

/* ------------------------------------------------------------------ */
/* Section: Page Encoding with CRC Verification                             */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_pgread_encode_pages() encodes raw file data into page-mode format interleaving 4-byte CRC32c checksums between each page fragment. Iterates through source bytes splitting into pages (kXR_pgPageSZ=4096), computes CRC32c via xrootd_crc32c_copy() while simultaneously copying data to destination buffer, appends 4-byte CRC after each page fragment — returns total encoded length including both data and checksum bytes. First and last fragments may be shorter when read offset is unaligned or request ends mid-page.
 *
 * WHY: Single-pass CRC+copy fusion via xrootd_crc32c_copy() eliminates unnecessary memory reads by combining checksum computation with data extraction in one operation. For large transfers (10GB+ files), this reduction in memory bandwidth can significantly improve throughput on systems where cache pressure is a bottleneck. Per-page checksum verification ensures corruption is detected immediately rather than after transfer completion — clients can retry corrupted pages without retransmitting the entire file.
 *
 * HOW: Four-phase encoding → iterate through source bytes (remaining > 0 loop) — determine page_data size (min(remaining, kXR_pgPageSZ)) — compute CRC32c via xrootd_crc32c_copy() while simultaneously copying data to destination buffer — append 4-byte big-endian CRC after each page fragment — return total encoded length including both data and checksum bytes. */

/* ------------------------------------------------------------------ */
/* Section: Paged Read Handler                                              */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_handle_pgread() handles the kXR_pgread opcode — page-mode read with per-page CRC32c integrity verification. Supports two modes: handle-based (fhandle[4] identifies open slot, dlen==0) using fd already open on the slot; path-based (dlen>0 with payload containing path) resolves path via xrootd_resolve_path_write fallback to xrootd_resolve_path, opens O_RDONLY for pread(2), calls read then closes temporary fd. Offset is big-endian int64 representing start position in file; rlen is uint32_t representing requested byte count (capped at XROOTD_READ_REQUEST_MAX). Token scope read gate required for both paths ensuring only authenticated clients can access files. Returns kXR_status response containing next expected offset for client progress tracking.
 *
 * WHY: Page-mode reads provide byte-level integrity verification for large file downloads where single-segment kXR_read would offer no checksum protection. CRC32c per-page verification ensures data corruption is detected immediately rather than after transfer completion — clients can retry corrupted pages without retransmitting the entire file. The kXR_status response (next expected offset) enables precise progress tracking, critical for resumable downloads and monitoring large transfers in production deployments where network failures may interrupt mid-transfer reads.
 *
 * HOW: Two-phase read → validate read handle (xrootd_validate_read_handle for read-side validation) — parse offset/rlen from wire format (big-endian int64 + uint32_t) — cap rlen at XROOTD_READ_REQUEST_MAX if exceeds limit — pread(2) from file using AIO thread-pool or inline fallback — encode pages via xrootd_pgread_encode_pages() — build response chain with kXR_status framing containing next expected offset — queue response via xrootd_queue_response_chain(). */

/* ---- Function: xrootd_pgread_encode_pages() ----
 *
 * WHAT: Encodes raw file data into page-mode format interleaving 4-byte CRC32c checksums between each page fragment. Iterates through source bytes splitting into pages (kXR_pgPageSZ=4096), computes CRC32c via xrootd_crc32c_copy() while simultaneously copying data to destination buffer, appends 4-byte CRC after each page fragment — returns total encoded length including both data and checksum bytes. First and last fragments may be shorter when read offset is unaligned or request ends mid-page.
 *
 * WHY: Single-pass CRC+copy fusion via xrootd_crc32c_copy() eliminates unnecessary memory reads by combining checksum computation with data extraction in one operation. For large transfers (10GB+ files), this reduction in memory bandwidth can significantly improve throughput on systems where cache pressure is a bottleneck. Per-page checksum verification ensures corruption is detected immediately rather than after transfer completion — clients can retry corrupted pages without retransmitting the entire file.
 *
 * HOW: Four-phase encoding → iterate through source bytes (remaining > 0 loop) — determine page_data size (min(remaining, kXR_pgPageSZ)) — compute CRC32c via xrootd_crc32c_copy() while simultaneously copying data to destination buffer — append 4-byte big-endian CRC after each page fragment — return total encoded length including both data and checksum bytes. */

/* ---- Function: xrootd_handle_pgread() ----
 *
 * WHAT: Handles the kXR_pgread opcode — page-mode read with per-page CRC32c integrity verification supporting two modes: handle-based (fhandle[4] identifies open slot, dlen==0) using fd already open on the slot; path-based (dlen>0 with payload containing path) resolves via xrootd_resolve_path_write fallback to xrootd_resolve_path, opens O_RDONLY for pread(2), calls read then closes temporary fd. Offset is big-endian int64 representing start position in file; rlen is uint32_t representing requested byte count (capped at XROOTD_READ_REQUEST_MAX). Token scope read gate required for both paths ensuring only authenticated clients can access files. Returns kXR_status response containing next expected offset for client progress tracking.
 *
 * WHY: Page-mode reads provide byte-level integrity verification for large file downloads where single-segment kXR_read would offer no checksum protection. CRC32c per-page verification ensures data corruption is detected immediately rather than after transfer completion — clients can retry corrupted pages without retransmitting the entire file. The kXR_status response (next expected offset) enables precise progress tracking, critical for resumable downloads and monitoring large transfers in production deployments where network failures may interrupt mid-transfer reads.
 *
 * HOW: Two-phase read → validate read handle (xrootd_validate_read_handle for read-side validation) — parse offset/rlen from wire format (big-endian int64 + uint32_t) — cap rlen at XROOTD_READ_REQUEST_MAX if exceeds limit — pread(2) from file using AIO thread-pool or inline fallback — encode pages via xrootd_pgread_encode_pages() — build response chain with kXR_status framing containing next expected offset — queue response via xrootd_queue_response_chain(). */

#include "read.h"

#include "../ngx_xrootd_module.h"
#include "../fs/backend/sd.h"   /* phase-55: route preadv through the SD seam */
#include "../compat/pgio.h"     /* shared kXR page-mode encode (libxrdproto) */
#include "../compat/crc32c.h"   /* xrootd_crc32c_value — in-place per-page CRC  */

#include <sys/uio.h>            /* preadv / struct iovec                        */

/* CRC32c word size per page unit ([CRC32c(4)][data]); == kXR_pgUnitSZ - page. */
#define XROOTD_PG_CKSZ        ((size_t) (kXR_pgUnitSZ - kXR_pgPageSZ))
/* preadv scatter cap per syscall — mirrors kXR_readv (XROOTD_READV_PREADV_MAXIOV). */
#define XROOTD_PGREAD_MAXIOV  64

/*
 * xrootd_pgread_read_encode_inplace - zero-copy paged read + in-place CRC.
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
 *      then runs read-only (xrootd_crc32c_value, the latency-hiding 3-way path)
 *      over the data already in place. This mirrors the zero-copy preadv-into-
 *      final-buffer pattern kXR_readv already uses. Output is byte-identical to
 *      xrdp_pg_encode (Invariant #1): same page splitting, same CRC, same layout.
 *
 * HOW: Lay out one batch of <= XROOTD_PGREAD_MAXIOV pages (data after each 4-byte
 *      CRC gap), preadv the batch's contiguous file region into those gapped
 *      positions, then fuse the per-page CRC over exactly the bytes the batch
 *      delivered — a short page or short batch means EOF, so stop. Page lengths
 *      use the in-page offset so the first fragment shortens on an unaligned
 *      read, exactly as xrdp_pg_encode does.
 */
size_t
xrootd_pgread_read_encode_inplace(int fd, off_t offset, size_t rlen,
    u_char *out, ssize_t *nread_out, int *io_errno_out)
{
    u_char  *o = out;            /* write cursor in the gapped wire buffer */
    size_t   remaining = rlen;   /* file bytes not yet laid out into a batch */
    size_t          out_size = 0;       /* encoded bytes produced so far */
    ssize_t         total = 0;          /* file bytes actually read */
    int             eof = 0;
    xrootd_sd_obj_t obj;

    *nread_out = 0;
    *io_errno_out = 0;

    /* Route the batched vectored read through the Storage Driver seam
     * (phase-55); the page layout / in-place CRC policy stays here. */
    xrootd_sd_posix_wrap(&obj, fd);

    while (remaining > 0 && !eof) {
        struct iovec iov[XROOTD_PGREAD_MAXIOV];
        u_char      *data[XROOTD_PGREAD_MAXIOV];
        size_t       dlen[XROOTD_PGREAD_MAXIOV];
        off_t        batch_off = offset + (off_t) (rlen - remaining);
        size_t       batch_bytes = 0;
        ssize_t      n;
        size_t       got;
        int          k = 0;
        int          i;

        /* Lay out a batch of pages: data lands after each 4-byte CRC gap. */
        while (k < XROOTD_PGREAD_MAXIOV && remaining > 0) {
            off_t  cur = offset + (off_t) (rlen - remaining);
            size_t in_off = (size_t) (cur & (off_t) (kXR_pgPageSZ - 1));
            size_t len = (size_t) kXR_pgPageSZ - in_off;

            if (len > remaining) {
                len = remaining;
            }
            data[k] = o + XROOTD_PG_CKSZ;
            dlen[k] = len;
            iov[k].iov_base = data[k];
            iov[k].iov_len  = len;
            o           += XROOTD_PG_CKSZ + len;
            batch_bytes += len;
            remaining   -= len;
            k++;
        }

        n = xrootd_sd_posix_driver.preadv(&obj, iov, k, batch_off);
        if (n < 0) {
            *nread_out = -1;
            *io_errno_out = errno;
            return 0;
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
            crc_be = htonl(xrootd_crc32c_value(data[i], al));
            memcpy(data[i] - XROOTD_PG_CKSZ, &crc_be, XROOTD_PG_CKSZ);
            out_size += XROOTD_PG_CKSZ + al;
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
xrootd_pgread_encode_pages(const u_char *src, size_t len, off_t offset,
                           u_char *dst)
{
    return xrdp_pg_encode((const uint8_t *) src, len, (int64_t) offset,
                          (uint8_t *) dst);
}

ngx_int_t
xrootd_handle_pgread(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    /* phase-42 W4 invariant: pgread is ALWAYS plaintext — it never consults
     * ctx->files[idx].read_codec.  Inline read compression is a kXR_read-only
     * handle property; pgread's kXR_status(4007) framing + per-page CRC32c must
     * stay byte-for-byte intact, so compression is deliberately not applied here. */
    ClientPgReadRequest          *req = (ClientPgReadRequest *) ctx->hdr_buf;
    int                           idx;
    int64_t                       offset;
    size_t                        rlen;
    int                           fd;
    u_char                       *flat_buf;
    u_char                       *out_buf;
    size_t                        out_size;
    ServerStatusResponse_pgRead  *hdr_buf;
    ngx_chain_t                  *rsp_chain;
    ngx_stream_xrootd_srv_conf_t *rconf;
    char                          detail[64];
    ngx_int_t                     validate_rc;

    idx = (int) (unsigned char) req->fhandle[0];
    offset = (int64_t) be64toh((uint64_t) req->offset);
    rlen = (size_t) (uint32_t) ntohl((uint32_t) req->rlen);

    if (!xrootd_validate_read_handle(ctx, c, idx, "PGREAD",
                                     XROOTD_OP_PGREAD, &validate_rc)) {
        return validate_rc;
    }

    /*
     * Phase 26: a slice-mode handle parks its fd on /dev/null, so a raw pread
     * here would silently return an empty page-mode response instead of the
     * cached bytes.  Only kXR_read is wired into the slice serving path; reject
     * paged reads on such handles rather than returning wrong data.
     */
    if (ctx->files[idx].slice_mode) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_PGREAD);
        return xrootd_send_error(ctx, c, kXR_Unsupported,
                                 "pgread not supported on slice-cached handle");
    }

    if (offset < 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_PGREAD);
        return xrootd_send_error(ctx, c, kXR_IOError,
                                 "negative read offset");
    }

    /* The wire rlen is a signed 32-bit field; a negative request length is
     * invalid.  Read unsigned it would turn -1 into ~4 GiB (then capped),
     * silently succeeding where the reference rejects with kXR_ArgInvalid. */
    if ((int32_t) ntohl((uint32_t) req->rlen) < 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_PGREAD);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "negative read length");
    }

    if (rlen == 0) {
        hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
        if (hdr_buf == NULL) {
            return NGX_ERROR;
        }
        xrootd_build_pgread_status(ctx, offset, 0, hdr_buf);
        XROOTD_OP_OK(ctx, XROOTD_OP_PGREAD);
        return xrootd_queue_response(ctx, c, (u_char *) hdr_buf,
                                     sizeof(*hdr_buf));
    }

    if (rlen > XROOTD_READ_REQUEST_MAX) {
        rlen = XROOTD_READ_REQUEST_MAX;
    }

    fd = ctx->files[idx].fd;

    {
        size_t  n_pages_max;
        size_t  scratch_size;
        u_char *scratch;

        rconf = ngx_stream_get_module_srv_conf(
            (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);

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
        scratch_size = rlen + n_pages_max * XROOTD_PG_CKSZ;

        scratch = XROOTD_GET_SCRATCH(ctx, c, read_scratch, read_scratch_size,
                                     scratch_size);
        if (scratch == NULL) {
            return NGX_ERROR;
        }

        if (rconf->common.thread_pool != NULL) {
            ngx_thread_task_t   *task;
            xrootd_pgread_aio_t *t;
            ngx_flag_t           posted;

            task = ctx->pgread_aio_task;
            if (task == NULL) {
                task = ngx_thread_task_alloc(c->pool,
                                             sizeof(xrootd_pgread_aio_t));
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

            xrootd_task_bind(task, xrootd_pgread_aio_thread, xrootd_pgread_aio_done);

            (void) xrootd_aio_post_task(ctx, c, rconf->common.thread_pool, task,
                                        "xrootd: thread_task_post failed, sync pgread fallback",
                                        &posted);
            if (posted) {
                return NGX_OK;
            }
        }

        /*
         * Sync fallback: read directly into the gapped wire buffer and CRC each
         * page in place (no flat-buffer copy). Same code path as the AIO worker.
         */
        {
            xrootd_vfs_job_t job;

            xrootd_vfs_job_read_init(&job, fd, (off_t) offset, rlen,
                                      scratch, rlen, 0);
            job.op = XROOTD_VFS_IO_PGREAD;
            xrootd_vfs_io_execute(&job);

            if (job.io_errno != 0) {
                XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_PGREAD, "PGREAD",
                                  ctx->files[idx].path, "-",
                                  kXR_IOError, strerror(job.io_errno));
            }

            out_size = job.out_size;
            flat_buf = scratch;
            out_buf  = scratch;            /* output starts at offset 0 now */
            rlen     = (size_t) job.nio;   /* actual bytes read (accounting) */
        }
    }

    rsp_chain = xrootd_build_pgread_chain(ctx, c, offset, out_buf,
                                          (uint32_t) out_size);
    if (rsp_chain == NULL) {
        xrootd_release_read_buffer(ctx, c, flat_buf);
        return NGX_ERROR;
    }

    ctx->files[idx].bytes_read += rlen;
    ctx->session_bytes += rlen;
    xrootd_rl_charge_ctx(ctx, rlen);  /* Phase 25 bandwidth */

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        snprintf(detail, sizeof(detail), "%lld+%zu", (long long) offset, rlen);
        xrootd_log_access(ctx, c, "PGREAD", ctx->files[idx].path,
                          detail, 1, 0, NULL, rlen);
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_PGREAD);

    {
        ngx_int_t rc = xrootd_queue_response_chain(ctx, c, rsp_chain, flat_buf);

        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            xrootd_release_read_buffer(ctx, c, flat_buf);
        }
        return rc;
    }
}
