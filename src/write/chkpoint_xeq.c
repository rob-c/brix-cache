#include "chkpoint_xeq.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* WHAT: Writes one checkpoint payload range through the VFS I/O core and reports
 *      the byte count, errno, and short-write state to the caller.
 * WHY: ckpXeq sub-ops mutate the exported file, so they must share the same
 *      raw-I/O chokepoint as normal write/pgwrite/writev handlers.
 * HOW: Initialize a WRITE job, execute it inline, then normalize hard errors
 *      and partial writes into a single NGX_ERROR result. */

static ngx_int_t
ckp_xeq_vfs_write_full(ngx_fd_t fd, const u_char *data, size_t len,
    off_t offset, ssize_t *written, int *io_errno, ngx_flag_t *short_io)
{
    xrootd_vfs_job_t job;

    xrootd_vfs_job_write_init(&job, fd, offset, data, len);
    xrootd_vfs_io_execute(&job);

    if (written != NULL) {
        *written = job.nio;
    }
    if (io_errno != NULL) {
        *io_errno = 0;
    }
    if (short_io != NULL) {
        *short_io = 0;
    }

    if (job.io_errno != 0 || job.nio < 0) {
        if (io_errno != NULL) {
            *io_errno = job.io_errno != 0 ? job.io_errno : EIO;
        }
        if (short_io != NULL && job.short_io) {
            *short_io = 1;
        }
        return NGX_ERROR;
    }

    if ((size_t) job.nio < len) {
        if (io_errno != NULL) {
            *io_errno = EIO;
        }
        if (short_io != NULL) {
            *short_io = 1;
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* WHAT: Performs a single VFS-core write to the checkpointed file at the specified offset. Validates handle matches idx, writes sub_dlen bytes,
 *      updates byte counters and sends success response. Handles zero-length payloads (no-op).
 * WHY: ckpXeq write is the atomic transactional write operation — when executed under an active checkpoint, this write becomes "tentative" until commit/rollback.
 *      The handle mismatch check prevents cross-file corruption during checkpointed operations.
 * HOW: 1) Validate fhandle[0] == idx. 2) Handle zero-length payload as no-op. 3) Run a VFS WRITE job. 4) Update counters + send_ok. */

static ngx_int_t
ckp_xeq_write(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
    const u_char *sub_hdr, const u_char *sub_payload, uint32_t sub_dlen)
{
    xrdw_write_req_t    wreq;
    int64_t             offset;
    ssize_t             nw;
    char                detail[64];
    int                 err;
    ngx_flag_t          short_io;

    xrdw_write_req_unpack(((ClientRequestHdr *) sub_hdr)->body, &wreq);

    /* The sub-request names its own handle; it MUST be the one the checkpoint
     * was opened on (idx). Refusing a mismatch keeps a checkpointed op from
     * silently touching a different file than the one being protected. */
    if ((int)(unsigned char) wreq.fhandle[0] != idx) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq write: handle mismatch");
    }

    offset = wreq.offset;  /* host order from the shared codec */
    if (sub_dlen == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);  /* zero-length write: no-op */
    }

    if (ckp_xeq_vfs_write_full(ctx->files[idx].fd, sub_payload,
                               (size_t) sub_dlen, (off_t) offset, &nw, &err,
                               &short_io)
        != NGX_OK)
    {
        const char *msg = short_io ? "short write (disk full?)"
                                   : strerror(err);

        snprintf(detail, sizeof(detail), "xeq_write %lld+%u",
                 (long long) offset, (unsigned) sub_dlen);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT",
                          ctx->files[idx].path, detail, kXR_IOError, msg);
    }

    snprintf(detail, sizeof(detail), "xeq_write %lld+%u",
             (long long) offset, (unsigned) sub_dlen);

    ctx->files[idx].bytes_written += (size_t) nw;
    ctx->session_bytes_written    += (size_t) nw;
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* WHAT: Performs a page-write under checkpoint protection, decoding the pgwrite payload (per-page CRC32c framing) into flat data,
 *      then writing in XRD_PGWRITE_PAGESZ-sized chunks. Validates checksum integrity before committing writes.
 * WHY: kXR_pgwrite uses per-page CRC32c for data integrity verification — critical for large file transfers where partial corruption must be detected.
 *      Under ckpXeq, the pgwrite becomes tentative until commit; checksum mismatch rejection prevents corrupted data from entering the checkpoint.
 * HOW: 1) Validate handle + offset + payload size (> XRD_PGWRITE_CKSZ). 2) Decode payload via xrootd_pgwrite_decode_payload (CRC32c verification). 3) Write in PAGE-sized chunks through the VFS core. 4) Send pgwrite_status with final offset. */

static ngx_int_t
ckp_xeq_pgwrite(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
    const u_char *sub_hdr, const u_char *sub_payload, uint32_t sub_dlen)
{
    xrdw_pgwrite_req_t    preq;
    int64_t               offset;
    u_char               *flat;
    const u_char         *src;
    size_t                rem, page_data;
    size_t                flat_sz;
    int64_t               bad_offset;
    int64_t               write_offset;
    size_t                total_written = 0;
    char                  detail[64];
    ngx_int_t             rc;

    xrdw_pgwrite_req_unpack(((ClientRequestHdr *) sub_hdr)->body, &preq);
    if ((int)(unsigned char) preq.fhandle[0] != idx) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq pgwrite: handle mismatch");
    }

    /* Payload must hold at least one 4-byte CRC32c plus some data, so it has
     * to exceed XRD_PGWRITE_CKSZ; a negative offset is never valid. */
    offset = preq.offset;
    if (offset < 0 || sub_dlen <= XRD_PGWRITE_CKSZ) {
        snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%u",
                 (long long) offset, (unsigned) sub_dlen);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT",
                          ctx->files[idx].path, detail,
                          kXR_ArgInvalid, "invalid pgwrite payload");
    }

    /* Worst case the decoded (CRC-stripped) data is smaller than sub_dlen, so
     * sub_dlen is a safe upper bound for the flat buffer. Freed on every exit
     * path below (heap, not pool — must not leak on error returns). */
    flat = ngx_alloc((size_t) sub_dlen, c->log);
    if (flat == NULL) {
        return NGX_ERROR;
    }

    /* Verify every per-page CRC32c and copy the page bodies into flat[].
     * On checksum/format failure bad_offset is set to the offending file
     * offset so the error/log line can pinpoint the bad page. flat_sz returns
     * the contiguous byte count actually decoded. */
    bad_offset = offset;
    rc = xrootd_pgwrite_decode_payload(sub_payload, (size_t) sub_dlen, offset,
                                       flat, &flat_sz, &bad_offset);
    if (rc != NGX_OK) {
        /* NGX_DECLINED specifically means a CRC mismatch (-> kXR_ChkSumErr);
         * any other non-OK is a malformed/short payload (-> kXR_ArgInvalid). */
        uint16_t status = (rc == NGX_DECLINED) ? kXR_ChkSumErr
                                               : kXR_ArgInvalid;
        const char *msg = (rc == NGX_DECLINED) ? "pgwrite checksum mismatch"
                                               : "invalid pgwrite payload";

        snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%u",
                 (long long) bad_offset, (unsigned) sub_dlen);
        xrootd_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                          0, status, msg, 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
        ngx_free(flat);
        return xrootd_send_error(ctx, c, status, msg);
    }

    /* Drain the verified data to disk one page at a time, advancing the file
     * offset, source pointer, and remaining counter in lockstep. Writing in
     * page units keeps offsets page-aligned and bounds the amount that can be
     * lost/retried on a short write. */
    write_offset = offset;
    src          = flat;
    rem          = flat_sz;

    while (rem > 0) {
        ssize_t nw;
        int err;
        ngx_flag_t short_io;

        /* Final chunk may be a partial page. */
        page_data = (rem >= XRD_PGWRITE_PAGESZ) ? XRD_PGWRITE_PAGESZ : rem;

        if (ckp_xeq_vfs_write_full(ctx->files[idx].fd, src, page_data,
                                   (off_t) write_offset, &nw, &err, &short_io)
            != NGX_OK)
        {
            const char *msg = short_io ? "short write (disk full?)"
                                       : strerror(err);

            snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%zu",
                     (long long) offset, total_written);
            xrootd_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                              0, kXR_IOError, msg, 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
            ngx_free(flat);
            return xrootd_send_error(ctx, c, kXR_IOError, msg);
        }

        total_written += (size_t) nw;
        write_offset  += (int64_t) nw;
        src           += page_data;
        rem           -= page_data;
    }

    ctx->files[idx].bytes_written += total_written;
    ctx->session_bytes_written    += total_written;

    snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%zu",
             (long long) offset, total_written);
    xrootd_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                      1, kXR_ok, NULL, total_written);

    ngx_free(flat);

    return xrootd_send_pgwrite_status(ctx, c, write_offset);
}

/* WHAT: Truncates the checkpointed file to a specified length via the VFS I/O core. Always handle-based (path-based not supported in ckpXeq).
 * WHY: Transactional write semantics allow shrinking files as part of tentative operations; rollback restores original size from checkpoint.
 *      Handle mismatch check prevents cross-file corruption during truncated operations under checkpoint protection.
 * HOW: 1) Validate fhandle[0] == idx. 2) Decode offset as truncate length (be64toh). 3) Run a VFS TRUNCATE job. */

static ngx_int_t
ckp_xeq_truncate(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
    const u_char *sub_hdr)
{
    xrdw_truncate_req_t    treq;
    int64_t                length;
    xrootd_vfs_job_t       job;

    xrdw_truncate_req_unpack(((ClientRequestHdr *) sub_hdr)->body, &treq);
    if ((int)(unsigned char) treq.fhandle[0] != idx) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq truncate: handle mismatch");
    }

    /* ckpXeq truncate is always handle-based; path-based not supported here.
     * The wire reuses the request's offset field to carry the target length. */
    length = treq.offset;

    xrootd_vfs_job_truncate_init(&job, ctx->files[idx].fd, (off_t) length);
    xrootd_vfs_io_execute(&job);
    if (job.io_errno != 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT",
                          ctx->files[idx].path, "xeq_truncate",
                          kXR_IOError, strerror(job.io_errno));
    }

    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* WHAT: Performs a vectorized write under checkpoint protection, parsing multiple segments from the payload (each segment = fhandle+offset+wlen header + data),
 *      validating all segments target the checkpointed handle idx, then writing each segment sequentially through the VFS core. Enforces XROOTD_WRITEV_MAXSEGS limit.
 * WHY: kXR_writev enables efficient multi-offset writes in a single request — critical for sparse file operations and chunked transfers under checkpoint.
 *      Under ckpXeq all segments must target the same handle (idx); handle mismatch in any segment is rejected to prevent cross-file corruption.
 * HOW: 1) Parse payload header segments, validate total size matches sub_dlen. 2) Check each fhandle[0] == idx. 3) Skip zero-length segments. 4) Run one VFS WRITE job per data chunk. */

static ngx_int_t
ckp_xeq_writev(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
    const u_char *sub_payload, uint32_t sub_dlen)
{
    write_list       *wl;
    size_t            n_segs, i, total_wlen, max_segs;
    const u_char     *data_ptr;
    size_t            bytes_written_total = 0;

    if (sub_dlen < XROOTD_WRITEV_SEGSIZE) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "ckpXeq writev payload too short");
    }

    /* Same wire layout as plain kXR_writev: N back-to-back 16-byte descriptors
     * then concatenated data, with N recovered by size matching (see writev.c).
     * The extra rule here is that every segment must name the checkpointed
     * handle. */
    wl       = (write_list *) sub_payload;
    max_segs = sub_dlen / XROOTD_WRITEV_SEGSIZE;
    if (max_segs > XROOTD_WRITEV_MAXSEGS) {
        max_segs = XROOTD_WRITEV_MAXSEGS;
    }

    n_segs = 0; total_wlen = 0;
    for (i = 0; i < max_segs; i++) {
        uint32_t wlen = (uint32_t) ntohl((uint32_t) wl[i].wlen);

        /* ckpXeq writev: all segments must target the checkpointed handle so a
         * checkpoint can never be used to scatter writes across other files. */
        if ((int)(unsigned char) wl[i].fhandle[0] != idx) {
            return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                     "ckpXeq writev: handle mismatch in segment");
        }
        n_segs++;
        total_wlen += wlen;
        /* Exact fit pins down the real segment count. */
        if (n_segs * XROOTD_WRITEV_SEGSIZE + total_wlen == sub_dlen) {
            break;
        }
        /* Overshoot => descriptors inconsistent with byte count: reject. */
        if (n_segs * XROOTD_WRITEV_SEGSIZE + total_wlen > sub_dlen) {
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "ckpXeq writev: payload size mismatch");
        }
    }

    /* Hit the cap (or undershot) without an exact fit: malformed. */
    if (n_segs * XROOTD_WRITEV_SEGSIZE + total_wlen != sub_dlen) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "ckpXeq writev: payload size mismatch");
    }

    /* Data blocks begin right after the N descriptors. */
    data_ptr = sub_payload + n_segs * XROOTD_WRITEV_SEGSIZE;

    for (i = 0; i < n_segs; i++) {
        int64_t  offset = (int64_t) be64toh((uint64_t) wl[i].offset);
        uint32_t wlen   = (uint32_t) ntohl((uint32_t) wl[i].wlen);
        ssize_t  nw;
        int      err;
        ngx_flag_t short_io;

        if (wlen == 0) {
            continue;
        }

        if (ckp_xeq_vfs_write_full(ctx->files[idx].fd, data_ptr,
                                   (size_t) wlen, (off_t) offset, &nw, &err,
                                   &short_io)
            != NGX_OK)
        {
            const char *msg = short_io ? "short write (disk full?)"
                                       : strerror(err);

            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT",
                              ctx->files[idx].path, "xeq_writev",
                              kXR_IOError, msg);
        }
        ctx->files[idx].bytes_written += (size_t) nw;
        ctx->session_bytes_written    += (size_t) nw;
        bytes_written_total           += (size_t) nw;
        data_ptr                      += wlen;
    }

    xrootd_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path,
                      "xeq_writev", 1, kXR_ok, NULL, bytes_written_total);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* WHAT: Unwraps the embedded sub-request (a full 24-byte client request header plus
 *      its payload) carried in a kXR_ckpXeq body and routes it to the matching
 *      write/pgwrite/truncate/writev handler for the checkpointed handle idx.
 * WHY: kXR_ckpXeq tunnels an ordinary write op "inside" an active checkpoint so the op
 *      can be rolled back. Requiring an active checkpoint (ckp_path) and a complete
 *      sub-header guards against executing a tentative op with no rollback anchor.
 * HOW: 1) Require f->ckp_path (active checkpoint). 2) Require >= 24 body bytes (one
 *      full sub-header). 3) Read the embedded requestid (sub_hdr + 2). 4) Split header
 *      vs payload at the 24-byte boundary. 5) switch on requestid to the sub-handler. */
ngx_int_t
ckp_xeq(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_file_t *f = &ctx->files[idx];
    const u_char  *sub_hdr;
    const u_char  *sub_payload;
    uint32_t       sub_dlen;
    uint16_t       sub_reqid;

    /* A ckpXeq with no open checkpoint has nothing to make tentative — reject
     * so a write can never masquerade as checkpointed when it is not. */
    if (f->ckp_path == NULL) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "xeq",
                          kXR_InvalidRequest, "no active checkpoint");
    }

    /* The body must contain at least one complete client request header
     * (all client headers are exactly 24 bytes). */
    if (ctx->cur_dlen < 24 || ctx->payload == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
        return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                 "ckpXeq: missing sub-request header");
    }

    /* Wire layout of the ckpXeq body:
     *   [0 .. 24)        embedded ClientRequestHdr (the sub-request header)
     *   [24 .. cur_dlen) sub-request payload (write data, writev descriptors, ...)
     * The requestid lives at header offset 2 (right after the 2-byte streamid)
     * and is big-endian on the wire. */
    sub_hdr     = ctx->payload;
    sub_reqid   = (uint16_t) ntohs(*(uint16_t *)(sub_hdr + 2));
    sub_dlen    = ctx->cur_dlen - 24;
    sub_payload = ctx->payload + 24;

    switch (sub_reqid) {

    case kXR_write:
        return ckp_xeq_write(ctx, c, idx, sub_hdr, sub_payload, sub_dlen);

    case kXR_pgwrite:
        return ckp_xeq_pgwrite(ctx, c, idx, sub_hdr, sub_payload, sub_dlen);

    case kXR_truncate:
        return ckp_xeq_truncate(ctx, c, idx, sub_hdr);

    case kXR_writev:
        return ckp_xeq_writev(ctx, c, idx, sub_payload, sub_dlen);

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: ckpXeq unsupported sub-reqid=%d",
                       (int) sub_reqid);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq: unsupported sub-request type");
    }
}
