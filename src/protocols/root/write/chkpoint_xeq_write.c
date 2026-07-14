#include "chkpoint_xeq.h"
#include "chkpoint_xeq_internal.h"
#include "fs/backend/csi_tagstore.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* WHAT: Writes one checkpoint payload range through the VFS I/O core and reports
 *      the byte count, errno, and short-write state to the caller.
 * WHY: ckpXeq sub-ops mutate the exported file, so they must share the same
 *      raw-I/O chokepoint as normal write/pgwrite/writev handlers.
 * HOW: Initialize a WRITE job, execute it inline, then normalize hard errors
 *      and partial writes into a single NGX_ERROR result. */

/* WHAT: Out-parameters of one checkpoint VFS write: bytes written, the errno on
 *      failure, and whether the failure was a short (partial) write.
 * WHY: Bundling the three result slots collapses ckp_xeq_vfs_write_full's param
 *      list (which the callers all live in this file) below the ≤5 cap without
 *      changing any observed value — every field is written on every call.
 * HOW: The helper zero-inits all three, then overwrites on the error paths. */
typedef struct {
    ssize_t     written;
    int         io_errno;
    ngx_flag_t  short_io;
} ckp_write_result_t;

static ngx_int_t
ckp_xeq_vfs_write_full(ngx_fd_t fd, const u_char *data, size_t len,
    off_t offset, ckp_write_result_t *res)
{
    brix_vfs_job_t job;

    brix_vfs_job_write_init(&job, fd, offset, data, len);
    brix_vfs_io_execute(&job);

    res->written  = job.nio;
    res->io_errno = 0;
    res->short_io = 0;

    if (job.io_errno != 0 || job.nio < 0) {
        res->io_errno = job.io_errno != 0 ? job.io_errno : EIO;
        if (job.short_io) {
            res->short_io = 1;
        }
        return NGX_ERROR;
    }

    if ((size_t) job.nio < len) {
        res->io_errno = EIO;
        res->short_io = 1;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* WHAT: Performs a single VFS-core write to the checkpointed file at the specified offset. Validates handle matches idx, writes sub_dlen bytes,
 *      updates byte counters and sends success response. Handles zero-length payloads (no-op).
 * WHY: ckpXeq write is the atomic transactional write operation — when executed under an active checkpoint, this write becomes "tentative" until commit/rollback.
 *      The handle mismatch check prevents cross-file corruption during checkpointed operations.
 * HOW: 1) Validate fhandle[0] == idx. 2) Handle zero-length payload as no-op. 3) Run a VFS WRITE job. 4) Update counters + send_ok. */

ngx_int_t
ckp_xeq_write(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    const ckp_write_desc_t *d)
{
    xrdw_write_req_t     wreq;
    int64_t              offset;
    char                 detail[64];
    ckp_write_result_t   res;

    xrdw_write_req_unpack(((ClientRequestHdr *) d->sub_hdr)->body, &wreq);

    /* The sub-request names its own handle; it MUST be the one the checkpoint
     * was opened on (idx). Refusing a mismatch keeps a checkpointed op from
     * silently touching a different file than the one being protected. */
    if ((int)(unsigned char) wreq.fhandle[0] != idx) {
        return brix_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq write: handle mismatch");
    }

    offset = wreq.offset;  /* host order from the shared codec */
    if (d->sub_dlen == 0) {
        return brix_send_ok(ctx, c, NULL, 0);  /* zero-length write: no-op */
    }

    if (ckp_xeq_vfs_write_full(ctx->files[idx].fd, d->sub_payload,
                               (size_t) d->sub_dlen, (off_t) offset, &res)
        != NGX_OK)
    {
        const char *msg = res.short_io ? "short write (disk full?)"
                                       : strerror(res.io_errno);

        snprintf(detail, sizeof(detail), "xeq_write %lld+%u",
                 (long long) offset, (unsigned) d->sub_dlen);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT",
                          ctx->files[idx].path, detail, kXR_IOError, msg);
    }

    snprintf(detail, sizeof(detail), "xeq_write %lld+%u",
             (long long) offset, (unsigned) d->sub_dlen);

    /* Integrity: the write went straight through the VFS I/O core, bypassing the
     * normal write path's per-block CRC fold. Fold the bytes into the handle's
     * csi engine so it marks the touched extent dirty — otherwise a read of the
     * just-written region on this handle verifies the new data against the stale
     * pre-write on-disk CRC and fails with EIO (kXR_IOError). */
    if (ctx->files[idx].csi != NULL && res.written > 0) {
        (void) brix_csi_write_update((brix_csi_t *) ctx->files[idx].csi,
                                       d->sub_payload, (off_t) offset,
                                       (size_t) res.written);
    }

    ctx->files[idx].bytes_written += (size_t) res.written;
    ctx->totals.bytes_written    += (size_t) res.written;
    return brix_send_ok(ctx, c, NULL, 0);
}

/* WHAT: Performs a page-write under checkpoint protection, decoding the pgwrite payload (per-page CRC32c framing) into flat data,
 *      then writing in XRD_PGWRITE_PAGESZ-sized chunks. Validates checksum integrity before committing writes.
 * WHY: kXR_pgwrite uses per-page CRC32c for data integrity verification — critical for large file transfers where partial corruption must be detected.
 *      Under ckpXeq, the pgwrite becomes tentative until commit; checksum mismatch rejection prevents corrupted data from entering the checkpoint.
 * HOW: 1) Validate handle + offset + payload size (> XRD_PGWRITE_CKSZ). 2) Decode payload via brix_pgwrite_decode_payload (CRC32c verification). 3) Write in PAGE-sized chunks through the VFS core. 4) Send pgwrite_status with final offset. */

/* WHAT: In/out state for the pgwrite page-drain loop: the decoded flat buffer
 *      and its byte count plus the starting file offset (in), and the final
 *      file offset and total bytes written (out).
 * WHY: Passing one struct keeps ckp_xeq_pgwrite_drain at ≤5 params while the
 *      caller reads back both results after a successful drain.
 * HOW: ckp_xeq_pgwrite seeds flat/flat_sz/offset; the drain fills end_offset
 *      and total on success. */
typedef struct {
    const u_char  *flat;
    size_t         flat_sz;
    int64_t        offset;
    int64_t        end_offset;
    size_t         total;
} ckp_pgwrite_drain_t;

/* WHAT: Writes the verified pgwrite plaintext to disk one page at a time,
 *      advancing the file offset in lockstep, and reports the final offset and
 *      byte total (or emits the stock IO-error log + response on a failed page).
 * WHY: Page-unit writes keep offsets page-aligned and bound what a short write
 *      can lose; hoisting the loop out of ckp_xeq_pgwrite keeps that function
 *      under the length/CCN caps with byte-identical behaviour.
 * HOW: Loop over full-then-partial pages via ckp_xeq_vfs_write_full; on failure
 *      log + BRIX_OP_ERR + send kXR_IOError and return NGX_DONE (error already
 *      emitted — caller frees flat and returns brix_send_error's own NGX_OK);
 *      on success write st->end_offset / st->total and return NGX_OK. */
static ngx_int_t
ckp_xeq_pgwrite_drain(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    ckp_pgwrite_drain_t *st)
{
    const u_char  *src           = st->flat;
    size_t         rem           = st->flat_sz;
    int64_t        write_offset  = st->offset;
    size_t         total_written = 0;
    size_t         page_data;
    char           detail[64];

    while (rem > 0) {
        ckp_write_result_t res;

        /* Final chunk may be a partial page. */
        page_data = (rem >= XRD_PGWRITE_PAGESZ) ? XRD_PGWRITE_PAGESZ : rem;

        if (ckp_xeq_vfs_write_full(ctx->files[idx].fd, src, page_data,
                                   (off_t) write_offset, &res)
            != NGX_OK)
        {
            const char *msg = res.short_io ? "short write (disk full?)"
                                           : strerror(res.io_errno);

            snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%zu",
                     (long long) st->offset, total_written);
            brix_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                              0, kXR_IOError, msg, 0);
            BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
            (void) brix_send_error(ctx, c, kXR_IOError, msg);
            return NGX_DONE;
        }

        total_written += (size_t) res.written;
        write_offset  += (int64_t) res.written;
        src           += page_data;
        rem           -= page_data;
    }

    st->end_offset = write_offset;
    st->total      = total_written;
    return NGX_OK;
}

ngx_int_t
ckp_xeq_pgwrite(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    const ckp_write_desc_t *d)
{
    xrdw_pgwrite_req_t     preq;
    int64_t                offset;
    u_char                *flat;
    size_t                 flat_sz;
    int64_t                bad_offset;
    char                   detail[64];
    ngx_int_t              rc;
    ckp_pgwrite_drain_t    drain;

    xrdw_pgwrite_req_unpack(((ClientRequestHdr *) d->sub_hdr)->body, &preq);
    if ((int)(unsigned char) preq.fhandle[0] != idx) {
        return brix_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq pgwrite: handle mismatch");
    }

    /* Payload must hold at least one 4-byte CRC32c plus some data, so it has
     * to exceed XRD_PGWRITE_CKSZ; a negative offset is never valid. */
    offset = preq.offset;
    if (offset < 0 || d->sub_dlen <= XRD_PGWRITE_CKSZ) {
        snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%u",
                 (long long) offset, (unsigned) d->sub_dlen);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT",
                          ctx->files[idx].path, detail,
                          kXR_ArgInvalid, "invalid pgwrite payload");
    }

    /* Worst case the decoded (CRC-stripped) data is smaller than sub_dlen, so
     * sub_dlen is a safe upper bound for the flat buffer. Freed on every exit
     * path below (heap, not pool — must not leak on error returns). */
    flat = ngx_alloc((size_t) d->sub_dlen, c->log);
    if (flat == NULL) {
        return NGX_ERROR;
    }

    /* Verify every per-page CRC32c and copy the page bodies into flat[].
     * On checksum/format failure bad_offset is set to the offending file
     * offset so the error/log line can pinpoint the bad page. flat_sz returns
     * the contiguous byte count actually decoded. */
    bad_offset = offset;
    rc = brix_pgwrite_decode_payload(d->sub_payload, (size_t) d->sub_dlen,
                                       offset, flat, &flat_sz, &bad_offset);
    if (rc != NGX_OK) {
        /* NGX_DECLINED specifically means a CRC mismatch (-> kXR_ChkSumErr);
         * any other non-OK is a malformed/short payload (-> kXR_ArgInvalid). */
        uint16_t status = (rc == NGX_DECLINED) ? kXR_ChkSumErr
                                               : kXR_ArgInvalid;
        const char *msg = (rc == NGX_DECLINED) ? "pgwrite checksum mismatch"
                                               : "invalid pgwrite payload";

        snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%u",
                 (long long) bad_offset, (unsigned) d->sub_dlen);
        brix_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                          0, status, msg, 0);
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        ngx_free(flat);
        return brix_send_error(ctx, c, status, msg);
    }

    /* Drain the verified data to disk one page at a time.  On failure the
     * drain has already logged + sent the IO-error response; free and return. */
    drain.flat    = flat;
    drain.flat_sz = flat_sz;
    drain.offset  = offset;
    if (ckp_xeq_pgwrite_drain(ctx, c, idx, &drain) != NGX_OK) {
        /* NGX_DONE: the drain already logged + sent the IO-error response.
         * Return brix_send_error's own value (NGX_OK), matching the original
         * inline `return brix_send_error(...)`. */
        ngx_free(flat);
        return NGX_OK;
    }

    /* Integrity: same as ckp_xeq_write — the pages went straight through the
     * VFS I/O core, so fold the decoded plaintext into the csi engine to mark
     * the written extent dirty. Without this a read-back on this handle verifies
     * the new pages against the stale on-disk CRC and fails with EIO. */
    if (ctx->files[idx].csi != NULL && flat_sz > 0) {
        (void) brix_csi_write_update((brix_csi_t *) ctx->files[idx].csi,
                                       flat, (off_t) offset, flat_sz);
    }

    ctx->files[idx].bytes_written += drain.total;
    ctx->totals.bytes_written    += drain.total;

    snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%zu",
             (long long) offset, drain.total);
    brix_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                      1, kXR_ok, NULL, drain.total);

    ngx_free(flat);

    return brix_send_pgwrite_status(ctx, c, drain.end_offset);
}

/* WHAT: Truncates the checkpointed file to a specified length via the VFS I/O core. Always handle-based (path-based not supported in ckpXeq).
 * WHY: Transactional write semantics allow shrinking files as part of tentative operations; rollback restores original size from checkpoint.
 *      Handle mismatch check prevents cross-file corruption during truncated operations under checkpoint protection.
 * HOW: 1) Validate fhandle[0] == idx. 2) Decode offset as truncate length (be64toh). 3) Run a VFS TRUNCATE job. */

ngx_int_t
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

ngx_int_t
ckp_xeq_writev(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    const ckp_write_desc_t *d, uint32_t data_len)
{
    write_list       *wl;
    size_t            n_segs, i;
    uint64_t          total_wlen;
    const u_char     *data_ptr;
    size_t            bytes_written_total = 0;

    /* Stock parity (do_WriteV, reached via do_ChkPntXeq): a sub_dlen that is
     * zero or not a whole number of descriptors is invalid — error + drop. */
    if (d->sub_dlen == 0 || d->sub_dlen % BRIX_WRITEV_SEGSIZE != 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_CHKPOINT);
        (void) brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "Write vector is invalid");
        return NGX_ERROR;
    }

    wl     = (write_list *) d->sub_payload;
    n_segs = d->sub_dlen / BRIX_WRITEV_SEGSIZE;

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
    data_ptr = d->sub_payload + (size_t) d->sub_dlen;

    for (i = 0; i < n_segs; i++) {
        int64_t  offset = (int64_t) be64toh((uint64_t) wl[i].offset);
        uint32_t wlen   = (uint32_t) ntohl((uint32_t) wl[i].wlen);
        ckp_write_result_t res;

        if (wlen == 0) {
            continue;
        }

        if (ckp_xeq_vfs_write_full(ctx->files[idx].fd, data_ptr,
                                   (size_t) wlen, (off_t) offset, &res)
            != NGX_OK)
        {
            const char *msg = res.short_io ? "short write (disk full?)"
                                           : strerror(res.io_errno);

            BRIX_RETURN_ERR(ctx, c, BRIX_OP_CHKPOINT, "CHKPOINT",
                              ctx->files[idx].path, "xeq_writev",
                              kXR_IOError, msg);
        }
        ctx->files[idx].bytes_written += (size_t) res.written;
        ctx->totals.bytes_written    += (size_t) res.written;
        bytes_written_total           += (size_t) res.written;
        data_ptr                      += wlen;
    }

    brix_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path,
                      "xeq_writev", 1, kXR_ok, NULL, bytes_written_total);
    return brix_send_ok(ctx, c, NULL, 0);
}
