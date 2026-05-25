#include "chkpoint_xeq.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* ---- Function: ckp_xeq_write() — kXR_ckpXeq sub-op: write under checkpoint ---- */
/* WHAT: Performs a single pwrite to the checkpointed file at the specified offset. Validates handle matches idx, writes sub_dlen bytes via pwrite(),
 *      updates byte counters and sends success response. Handles zero-length payloads (no-op).
 * WHY: ckpXeq write is the atomic transactional write operation — when executed under an active checkpoint, this write becomes "tentative" until commit/rollback.
 *      The handle mismatch check prevents cross-file corruption during checkpointed operations.
 * HOW: 1) Validate fhandle[0] == idx. 2) Handle zero-length payload as no-op. 3) pwrite(sub_payload, sub_dlen, offset). 4) Update counters + send_ok. */

static ngx_int_t
ckp_xeq_write(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
    const u_char *sub_hdr, const u_char *sub_payload, uint32_t sub_dlen)
{
    ClientWriteRequest *wreq = (ClientWriteRequest *) sub_hdr;
    int64_t             offset;
    ssize_t             nw;
    char                detail[64];

    if ((int)(unsigned char) wreq->fhandle[0] != idx) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq write: handle mismatch");
    }

    offset = (int64_t) be64toh((uint64_t) wreq->offset);
    if (sub_dlen == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    nw = pwrite(ctx->files[idx].fd, sub_payload, (size_t) sub_dlen,
                (off_t) offset);
    snprintf(detail, sizeof(detail), "xeq_write %lld+%u",
             (long long) offset, (unsigned) sub_dlen);

    if (nw < 0 || (uint32_t) nw < sub_dlen) {
        const char *msg = nw < 0 ? strerror(errno) : "short write (disk full?)";
        xrootd_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                          0, kXR_IOError, msg, 0);
        return xrootd_send_error(ctx, c, kXR_IOError, msg);
    }

    ctx->files[idx].bytes_written += (size_t) nw;
    ctx->session_bytes_written    += (size_t) nw;
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* ---- Function: ckp_xeq_pgwrite() — kXR_ckpXeq sub-op: pgwrite with CRC32c verification ---- */
/* WHAT: Performs a page-write under checkpoint protection, decoding the pgwrite payload (per-page CRC32c framing) into flat data,
 *      then writing in XRD_PGWRITE_PAGESZ-sized chunks. Validates checksum integrity before committing writes.
 * WHY: kXR_pgwrite uses per-page CRC32c for data integrity verification — critical for large file transfers where partial corruption must be detected.
 *      Under ckpXeq, the pgwrite becomes tentative until commit; checksum mismatch rejection prevents corrupted data from entering the checkpoint.
 * HOW: 1) Validate handle + offset + payload size (> XRD_PGWRITE_CKSZ). 2) Decode payload via xrootd_pgwrite_decode_payload (CRC32c verification). 3) Write in PAGE-sized chunks loop. 4) Send pgwrite_status with final offset. */

static ngx_int_t
ckp_xeq_pgwrite(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
    const u_char *sub_hdr, const u_char *sub_payload, uint32_t sub_dlen)
{
    ClientPgWriteRequest *preq = (ClientPgWriteRequest *) sub_hdr;
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

    if ((int)(unsigned char) preq->fhandle[0] != idx) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq pgwrite: handle mismatch");
    }

    offset = (int64_t) be64toh((uint64_t) preq->offset);
    if (offset < 0 || sub_dlen <= XRD_PGWRITE_CKSZ) {
        snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%u",
                 (long long) offset, (unsigned) sub_dlen);
        xrootd_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                          0, kXR_ArgInvalid, "invalid pgwrite payload", 0);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid pgwrite payload");
    }

    flat = ngx_alloc((size_t) sub_dlen, c->log);
    if (flat == NULL) {
        return NGX_ERROR;
    }

    bad_offset = offset;
    rc = xrootd_pgwrite_decode_payload(sub_payload, (size_t) sub_dlen, offset,
                                       flat, &flat_sz, &bad_offset);
    if (rc != NGX_OK) {
        uint16_t status = (rc == NGX_DECLINED) ? kXR_ChkSumErr
                                               : kXR_ArgInvalid;
        const char *msg = (rc == NGX_DECLINED) ? "pgwrite checksum mismatch"
                                               : "invalid pgwrite payload";

        snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%u",
                 (long long) bad_offset, (unsigned) sub_dlen);
        xrootd_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                          0, status, msg, 0);
        ngx_free(flat);
        return xrootd_send_error(ctx, c, status, msg);
    }

    write_offset = offset;
    src          = flat;
    rem          = flat_sz;

    while (rem > 0) {
        ssize_t nw;

        page_data = (rem >= XRD_PGWRITE_PAGESZ) ? XRD_PGWRITE_PAGESZ : rem;

        nw = pwrite(ctx->files[idx].fd, src, page_data, (off_t) write_offset);
        if (nw < 0 || (size_t) nw < page_data) {
            const char *msg = nw < 0 ? strerror(errno) : "short write (disk full?)";
            snprintf(detail, sizeof(detail), "xeq_pgwrite %lld+%zu",
                     (long long) offset, total_written);
            xrootd_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path, detail,
                              0, kXR_IOError, msg, 0);
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

/* ---- Function: ckp_xeq_truncate() — kXR_ckpXeq sub-op: truncate under checkpoint ---- */
/* WHAT: Truncates the checkpointed file to a specified length via ftruncate(). Always handle-based (path-based not supported in ckpXeq).
 * WHY: Transactional write semantics allow shrinking files as part of tentative operations; rollback restores original size from checkpoint.
 *      Handle mismatch check prevents cross-file corruption during truncated operations under checkpoint protection.
 * HOW: 1) Validate fhandle[0] == idx. 2) Decode offset as truncate length (be64toh). 3) ftruncate() to target length. */

static ngx_int_t
ckp_xeq_truncate(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
    const u_char *sub_hdr)
{
    ClientTruncateRequest *treq = (ClientTruncateRequest *) sub_hdr;
    int64_t                length;

    if ((int)(unsigned char) treq->fhandle[0] != idx) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "ckpXeq truncate: handle mismatch");
    }

    /* ckpXeq truncate is always handle-based; path-based not supported here. */
    length = (int64_t) be64toh((uint64_t) treq->offset);

    if (ftruncate(ctx->files[idx].fd, (off_t) length) != 0) {
        xrootd_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path,
                          "xeq_truncate", 0, kXR_IOError, strerror(errno), 0);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* ---- Function: ckp_xeq_writev() — kXR_ckpXeq sub-op: vectorized multi-segment write ---- */
/* WHAT: Performs a vectorized write under checkpoint protection, parsing multiple segments from the payload (each segment = fhandle+offset+wlen header + data),
 *      validating all segments target the checkpointed handle idx, then pwriting each segment sequentially. Enforces XROOTD_WRITEV_MAXSEGS limit.
 * WHY: kXR_writev enables efficient multi-offset writes in a single request — critical for sparse file operations and chunked transfers under checkpoint.
 *      Under ckpXeq all segments must target the same handle (idx); handle mismatch in any segment is rejected to prevent cross-file corruption.
 * HOW: 1) Parse payload header segments, validate total size matches sub_dlen. 2) Check each fhandle[0] == idx. 3) Skip zero-length segments. 4) pwrite each data chunk sequentially. */

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

    wl       = (write_list *) sub_payload;
    max_segs = sub_dlen / XROOTD_WRITEV_SEGSIZE;
    if (max_segs > XROOTD_WRITEV_MAXSEGS) {
        max_segs = XROOTD_WRITEV_MAXSEGS;
    }

    n_segs = 0; total_wlen = 0;
    for (i = 0; i < max_segs; i++) {
        uint32_t wlen = (uint32_t) ntohl((uint32_t) wl[i].wlen);

        /* ckpXeq writev: all segments must target the checkpointed handle. */
        if ((int)(unsigned char) wl[i].fhandle[0] != idx) {
            return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                     "ckpXeq writev: handle mismatch in segment");
        }
        n_segs++;
        total_wlen += wlen;
        if (n_segs * XROOTD_WRITEV_SEGSIZE + total_wlen == sub_dlen) {
            break;
        }
        if (n_segs * XROOTD_WRITEV_SEGSIZE + total_wlen > sub_dlen) {
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "ckpXeq writev: payload size mismatch");
        }
    }

    if (n_segs * XROOTD_WRITEV_SEGSIZE + total_wlen != sub_dlen) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "ckpXeq writev: payload size mismatch");
    }

    data_ptr = sub_payload + n_segs * XROOTD_WRITEV_SEGSIZE;

    for (i = 0; i < n_segs; i++) {
        int64_t  offset = (int64_t) be64toh((uint64_t) wl[i].offset);
        uint32_t wlen   = (uint32_t) ntohl((uint32_t) wl[i].wlen);
        ssize_t  nw;

        if (wlen == 0) {
            continue;
        }

        nw = pwrite(ctx->files[idx].fd, data_ptr, (size_t) wlen, (off_t) offset);
        if (nw < 0 || (uint32_t) nw < wlen) {
            const char *msg = nw < 0 ? strerror(errno) : "short write (disk full?)";
            xrootd_log_access(ctx, c, "CHKPOINT", ctx->files[idx].path,
                              "xeq_writev", 0, kXR_IOError, msg, 0);
            return xrootd_send_error(ctx, c, kXR_IOError, msg);
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

ngx_int_t
ckp_xeq(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_file_t *f = &ctx->files[idx];
    const u_char  *sub_hdr;
    const u_char  *sub_payload;
    uint32_t       sub_dlen;
    uint16_t       sub_reqid;

    if (f->ckp_path == NULL) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "xeq",
                          kXR_InvalidRequest, "no active checkpoint");
    }

    if (ctx->cur_dlen < 24 || ctx->payload == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
        return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                 "ckpXeq: missing sub-request header");
    }

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
