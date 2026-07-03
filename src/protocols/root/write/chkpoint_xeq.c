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
    brix_vfs_job_t job;

    brix_vfs_job_write_init(&job, fd, offset, data, len);
    brix_vfs_io_execute(&job);

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
ckp_xeq_write(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
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
        return brix_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq write: handle mismatch");
    }

    offset = wreq.offset;  /* host order from the shared codec */
    if (sub_dlen == 0) {
        return brix_send_ok(ctx, c, NULL, 0);  /* zero-length write: no-op */
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
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT",
                          ctx->files[idx].path, detail, kXR_IOError, msg);
    }

    snprintf(detail, sizeof(detail), "xeq_write %lld+%u",
             (long long) offset, (unsigned) sub_dlen);

    ctx->files[idx].bytes_written += (size_t) nw;
    ctx->session_bytes_written    += (size_t) nw;
    return brix_send_ok(ctx, c, NULL, 0);
}

/* WHAT: Performs a page-write under checkpoint protection, decoding the pgwrite payload (per-page CRC32c framing) into flat data,
 *      then writing in XRD_PGWRITE_PAGESZ-sized chunks. Validates checksum integrity before committing writes.
 * WHY: kXR_pgwrite uses per-page CRC32c for data integrity verification — critical for large file transfers where partial corruption must be detected.
 *      Under ckpXeq, the pgwrite becomes tentative until commit; checksum mismatch rejection prevents corrupted data from entering the checkpoint.
 * HOW: 1) Validate handle + offset + payload size (> XRD_PGWRITE_CKSZ). 2) Decode payload via brix_pgwrite_decode_payload (CRC32c verification). 3) Write in PAGE-sized chunks through the VFS core. 4) Send pgwrite_status with final offset. */

static ngx_int_t
ckp_xeq_pgwrite(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
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
        return brix_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq pgwrite: handle mismatch");
    }

    /* Payload must hold at least one 4-byte CRC32c plus some data, so it has
     * to exceed XRD_PGWRITE_CKSZ; a negative offset is never valid. */
    offset = preq.offset;
    if (offset < 0 || sub_dlen <= XRD_PGWRITE_CKSZ) {
        snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%u",
                 (long long) offset, (unsigned) sub_dlen);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT",
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
    rc = brix_pgwrite_decode_payload(sub_payload, (size_t) sub_dlen, offset,
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
        brix_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                          0, status, msg, 0);
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        ngx_free(flat);
        return brix_send_error(ctx, c, status, msg);
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
            brix_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                              0, kXR_IOError, msg, 0);
            BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
            ngx_free(flat);
            return brix_send_error(ctx, c, kXR_IOError, msg);
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
    brix_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                      1, kXR_ok, NULL, total_written);

    ngx_free(flat);

    return brix_send_pgwrite_status(ctx, c, write_offset);
}

/* WHAT: Truncates the checkpointed file to a specified length via the VFS I/O core. Always handle-based (path-based not supported in ckpXeq).
 * WHY: Transactional write semantics allow shrinking files as part of tentative operations; rollback restores original size from checkpoint.
 *      Handle mismatch check prevents cross-file corruption during truncated operations under checkpoint protection.
 * HOW: 1) Validate fhandle[0] == idx. 2) Decode offset as truncate length (be64toh). 3) Run a VFS TRUNCATE job. */

static ngx_int_t
ckp_xeq_truncate(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    const u_char *sub_hdr)
{
    xrdw_truncate_req_t    treq;
    int64_t                length;
    brix_vfs_job_t       job;

    xrdw_truncate_req_unpack(((ClientRequestHdr *) sub_hdr)->body, &treq);
    if ((int)(unsigned char) treq.fhandle[0] != idx) {
        return brix_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq truncate: handle mismatch");
    }

    /* ckpXeq truncate is always handle-based; path-based not supported here.
     * The wire reuses the request's offset field to carry the target length. */
    length = treq.offset;

    brix_vfs_job_truncate_init(&job, ctx->files[idx].fd, (off_t) length);
    brix_vfs_io_execute(&job);
    if (job.io_errno != 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT",
                          ctx->files[idx].path, "xeq_truncate",
                          kXR_IOError, strerror(job.io_errno));
    }

    return brix_send_ok(ctx, c, NULL, 0);
}

/* WHAT: Executes an embedded kXR_writev under checkpoint protection: validates
 *      the descriptor block under the STOCK wire contract (sub_dlen frames
 *      ONLY the N*16-byte write_list descriptors; data_len bytes of segment
 *      data were streamed after them), requires every data-bearing segment to
 *      target the checkpointed handle idx, then writes each segment through
 *      the VFS core.
 * WHY: kXR_ckpXeq tunnels the SAME wire layout as a standalone kXR_writev
 *      (see brix_handle_writev in writev.c): the embedded header's dlen
 *      counts descriptors only and the data rides behind — stock do_ChkPntXeq
 *      fetches the descriptor block, then hands off to do_WriteV, which
 *      streams the data.  Multi-file vectors are refused (stock: "multi-file
 *      chkpoint writev not supported") because the rollback anchor covers
 *      exactly one file.
 * HOW: 1) Validate sub_dlen non-zero, 16-aligned, <= BRIX_WRITEV_MAXSEGS
 *      segments — violations reject + drop the link like stock (once the
 *      descriptor framing is in doubt the trailing byte count is unknowable).
 *      2) Sum wlen; require data-bearing segments to name idx and the sum to
 *      equal data_len (defensive: the recv framing extended by exactly that).
 *      3) One VFS WRITE job per non-empty segment. */

static ngx_int_t
ckp_xeq_writev(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    const u_char *sub_payload, uint32_t sub_dlen, uint32_t data_len)
{
    write_list       *wl;
    size_t            n_segs, i;
    uint64_t          total_wlen;
    const u_char     *data_ptr;
    size_t            bytes_written_total = 0;

    /* Stock parity (do_WriteV, reached via do_ChkPntXeq): a sub_dlen that is
     * zero or not a whole number of descriptors is invalid — error + drop. */
    if (sub_dlen == 0 || sub_dlen % BRIX_WRITEV_SEGSIZE != 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "Write vector is invalid");
        return NGX_ERROR;
    }

    wl     = (write_list *) sub_payload;
    n_segs = sub_dlen / BRIX_WRITEV_SEGSIZE;

    if (n_segs > BRIX_WRITEV_MAXSEGS) {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgTooLong,
                                 "Write vector is too long");
        return NGX_ERROR;
    }

    total_wlen = 0;
    for (i = 0; i < n_segs; i++) {
        uint32_t wlen = (uint32_t) ntohl((uint32_t) wl[i].wlen);

        /* Every data-bearing segment must target the checkpointed handle so
         * a checkpoint can never scatter writes across other files (stock
         * ignores zero-length segments when it collects the vector, then
         * refuses a multi-file result). */
        if (wlen > 0 && (int)(unsigned char) wl[i].fhandle[0] != idx) {
            BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
            (void) brix_send_error(ctx, c, kXR_Unsupported,
                                 "multi-file chkpoint writev not supported");
            return NGX_ERROR;
        }
        total_wlen += wlen;
    }

    /* Defensive: the recv framing extended the body by exactly sum(wlen); a
     * mismatch means the extension never ran for this frame — the trailing
     * data was never read, so the link cannot be resynchronised. */
    if (total_wlen != (uint64_t) data_len) {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "ckpXeq writev: payload size mismatch");
        return NGX_ERROR;
    }

    /* Data blocks begin right after the N descriptors. */
    data_ptr = sub_payload + (size_t) sub_dlen;

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

            BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT",
                              ctx->files[idx].path, "xeq_writev",
                              kXR_IOError, msg);
        }
        ctx->files[idx].bytes_written += (size_t) nw;
        ctx->session_bytes_written    += (size_t) nw;
        bytes_written_total           += (size_t) nw;
        data_ptr                      += wlen;
    }

    brix_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path,
                      "xeq_writev", 1, kXR_ok, NULL, bytes_written_total);
    return brix_send_ok(ctx, c, NULL, 0);
}

/* brix_ckpxeq_body_extra — trailing sub-body length for kXR_ckpXeq
 * WHAT: Computes how many more bytes the client will stream after the ckpXeq
 * frame, staged on `have` (body bytes received so far).  have == 24: the
 * embedded sub-header just landed — the sub-request's own dlen bytes follow
 * (write/pgwrite data, or the writev descriptor block).  have == 24 +
 * sub_dlen: an embedded writev's descriptors landed — sum(wlen) data bytes
 * follow, delegated to brix_writev_body_extra (the SAME contract as a
 * standalone kXR_writev).  *final = 0 tells the recv framing to call again
 * after the current extension completes.
 * WHY: Stock wire contract (do_ChkPntXeq + XrdCl MessageUtils): the outer
 * chkpoint dlen frames ONLY the embedded 24-byte header; everything else is
 * raw body streamed behind the frame.  Shared by the recv framing so the
 * whole sub-request lands contiguously in payload_buf before dispatch.
 * HOW: Bound every stage by BRIX_MAX_WRITE_PAYLOAD (and the writev vector
 * cap) and return NGX_DECLINED on any violation — the framing then does NOT
 * extend, the auth gates still run, and ckp_xeq detects the un-read trailing
 * bytes (count mismatch) and drops the link. */
ngx_int_t
brix_ckpxeq_body_extra(const u_char *body, uint32_t have,
    uint32_t *extra, unsigned *final)
{
    uint16_t  sub_reqid;
    uint32_t  sub_dlen;

    *extra = 0;
    *final = 1;

    if (body == NULL || have < 24) {
        return NGX_DECLINED;
    }

    sub_reqid = (uint16_t) ntohs(*(const uint16_t *) (body + 2));
    sub_dlen  = (uint32_t) ntohl(*(const uint32_t *) (body + 20));

    if (have == 24) {
        if (sub_dlen == 0) {
            return NGX_OK;               /* nothing streams (e.g. truncate) */
        }

        switch (sub_reqid) {

        case kXR_write:
        case kXR_pgwrite:
            if (sub_dlen > BRIX_MAX_WRITE_PAYLOAD) {
                return NGX_DECLINED;
            }
            *extra = sub_dlen;
            return NGX_OK;

        case kXR_writev:
            /* Descriptor block first; the segment data extends in stage 2
             * once the descriptors can be summed. */
            if (sub_dlen % BRIX_WRITEV_SEGSIZE != 0
                || sub_dlen > BRIX_WRITEV_MAXSEGS * BRIX_WRITEV_SEGSIZE)
            {
                return NGX_DECLINED;
            }
            *extra = sub_dlen;
            *final = 0;
            return NGX_OK;

        default:
            /* Invalid embed (chkpoint-in-chkpoint, truncate with data, or
             * garbage) — no extension; ckp_xeq rejects and drops. */
            return NGX_DECLINED;
        }
    }

    /* Stage 2: the embedded writev descriptor block is in at body[24..). */
    if (sub_reqid == kXR_writev && have == 24 + sub_dlen) {
        return brix_writev_body_extra(body + 24, sub_dlen, extra);
    }

    return NGX_DECLINED;
}

/* WHAT: Unwraps the embedded sub-request carried by a kXR_ckpXeq frame and
 *      routes it to the matching write/pgwrite/truncate/writev handler for
 *      the checkpointed handle idx.
 * WHY: kXR_ckpXeq tunnels an ordinary write op "inside" an active checkpoint
 *      so the op can be rolled back.  Requiring an active checkpoint
 *      (ckp_path) guards against executing a tentative op with no rollback
 *      anchor.  Stock wire contract (do_ChkPntXeq): the frame's dlen is
 *      EXACTLY 24 — the embedded ClientRequestHdr — and the sub-request body
 *      (sub_dlen bytes per the embedded header; for writev, descriptors then
 *      data, see ckp_xeq_writev) streams after the frame.  The recv framing
 *      (brix_ckpxeq_body_extra) has already appended those streamed bytes
 *      to ctx->payload (ctx->cur_body_extra of them), so the sub-request is
 *      contiguous here.
 * HOW: Stock-parity validation, then dispatch: 1) embedded streamid must
 *      match the outer header's. 2) dlen must be 24. 3) An embedded chkpoint,
 *      or a truncate carrying data, is invalid.  All three reject + drop the
 *      link exactly like stock (do_ChkPntXeq returns -1) — for 1 and 3 the
 *      trailing bytes may not have been read, so no resync is possible.
 *      4) Per-type byte-count cross-check against cur_body_extra (defensive:
 *      detects a declined extension) — also error + drop.  5) Only then the
 *      checkpoint-active check (error, link kept: the sub-body is safely
 *      buffered by that point), and the switch to the sub-handler. */
ngx_int_t
ckp_xeq(brix_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    brix_file_t *f = &ctx->files[idx];
    const u_char  *sub_hdr;
    const u_char  *sub_payload;
    uint32_t       sub_dlen;
    uint16_t       sub_reqid;

    /* Stock parity: the embedded request must carry the outer streamid. */
    if (ctx->payload != NULL && ctx->cur_dlen >= 2
        && (ctx->payload[0] != ctx->cur_streamid[0]
            || ctx->payload[1] != ctx->cur_streamid[1]))
    {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "Request streamid mismatch");
        return NGX_ERROR;
    }

    /* Stock parity: the frame is EXACTLY the embedded 24-byte header — the
     * sub-request body streams after it.  This also rejects the legacy
     * private layout (header + body counted inside dlen) the way a stock
     * server does. */
    if (ctx->cur_dlen != 24 || ctx->payload == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "Request length invalid");
        return NGX_ERROR;
    }

    /* Wire layout as buffered by the recv framing:
     *   [0 .. 24)                 embedded ClientRequestHdr
     *   [24 .. 24+cur_body_extra) streamed sub-request body
     * requestid at header offset 2, dlen at offset 20, both big-endian. */
    sub_hdr     = ctx->payload;
    sub_reqid   = (uint16_t) ntohs(*(const uint16_t *) (sub_hdr + 2));
    sub_dlen    = (uint32_t) ntohl(*(const uint32_t *) (sub_hdr + 20));
    sub_payload = ctx->payload + 24;

    /* Stock parity: a chkpoint may not embed a chkpoint, and an embedded
     * truncate carries no data (its length rides in the offset field). */
    if (sub_reqid == kXR_chkpoint
        || (sub_reqid == kXR_truncate && sub_dlen != 0))
    {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "chkpoint request is invalid");
        return NGX_ERROR;
    }

    /* Defensive byte-count cross-check: the recv framing extended the body
     * by exactly sub_dlen (write/pgwrite data; writev descriptors).  A
     * shortfall means the extension was declined (oversized sub_dlen or a
     * malformed descriptor block) — the trailing bytes were never read, so
     * no resync is possible: error + drop.  Runs BEFORE the checkpoint-
     * active check so a framing violation always takes the link-drop path. */
    if (((sub_reqid == kXR_write || sub_reqid == kXR_pgwrite)
         && ctx->cur_body_extra != sub_dlen)
        || (sub_reqid == kXR_writev && ctx->cur_body_extra < sub_dlen))
    {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "ckpXeq: sub-request length invalid");
        return NGX_ERROR;
    }

    /* A ckpXeq with no open checkpoint has nothing to make tentative — reject
     * so a write can never masquerade as checkpointed when it is not.  Runs
     * AFTER the wire-shape checks above so a framing violation always takes
     * the link-drop path even when no checkpoint is open. */
    if (f->ckp_path == NULL) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT", f->path, "xeq",
                          kXR_InvalidRequest, "no active checkpoint");
    }

    switch (sub_reqid) {

    case kXR_write:
        return ckp_xeq_write(ctx, c, idx, sub_hdr, sub_payload, sub_dlen);

    case kXR_pgwrite:
        return ckp_xeq_pgwrite(ctx, c, idx, sub_hdr, sub_payload, sub_dlen);

    case kXR_truncate:
        return ckp_xeq_truncate(ctx, c, idx, sub_hdr);

    case kXR_writev:
        return ckp_xeq_writev(ctx, c, idx, sub_payload, sub_dlen,
                              ctx->cur_body_extra - sub_dlen);

    default:
        /* Stock parity: unknown embedded op — error, keep the link (stock's
         * second-pass default does not drop). */
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "brix: ckpXeq unsupported sub-reqid=%d",
                       (int) sub_reqid);
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        return brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "chkpoint request is invalid");
    }
}
