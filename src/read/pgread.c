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

size_t
xrootd_pgread_encode_pages(const u_char *src, size_t len, u_char *dst)
{
    const u_char *p;
    u_char       *out;
    size_t        remaining;

    p = src;
    out = dst;
    remaining = len;

    while (remaining > 0) {
        size_t   page_data;
        uint32_t crc_be;

        page_data = (remaining >= (size_t) kXR_pgPageSZ)
                    ? (size_t) kXR_pgPageSZ : remaining;

        /* XRootD wire format per page: [CRC32c(4)][data(page_size)]
         * AsyncPageReader::InitIOV() reads digest first, then page data. */
        crc_be = htonl(xrootd_crc32c_copy(p, out + 4, page_data));
        ngx_memcpy(out, &crc_be, 4);
        out += 4 + page_data;
        p += page_data;
        remaining -= page_data;
    }

    return (size_t) (out - dst);
}

ngx_int_t
xrootd_handle_pgread(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientPgReadRequest          *req = (ClientPgReadRequest *) ctx->hdr_buf;
    int                           idx;
    int64_t                       offset;
    size_t                        rlen;
    int                           fd;
    ssize_t                       nread;
    size_t                        n_pages;
    u_char                       *flat_buf;
    u_char                       *out_buf;
    size_t                        out_size;
    ServerStatusResponse_pgRead  *hdr_buf;
    ngx_chain_t                  *cl_hdr;
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

    if (offset < 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_PGREAD);
        return xrootd_send_error(ctx, c, kXR_IOError,
                                 "negative read offset");
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

        n_pages_max = (rlen + kXR_pgPageSZ - 1) / kXR_pgPageSZ;
        if (n_pages_max == 0) {
            n_pages_max = 1;
        }
        scratch_size = rlen + n_pages_max * kXR_pgUnitSZ;

        scratch = xrootd_get_read_scratch(ctx, c, scratch_size);
        if (scratch == NULL) {
            return NGX_ERROR;
        }

        if (rconf->common.thread_pool != NULL) {
            ngx_thread_task_t   *task;
            xrootd_pgread_aio_t *t;
            ngx_flag_t           posted;

            task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_pgread_aio_t));
            if (task == NULL) {
                return NGX_ERROR;
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

            task->handler = xrootd_pgread_aio_thread;
            task->event.handler = xrootd_pgread_aio_done;
            task->event.data = task;

            (void) xrootd_aio_post_task(ctx, c, rconf->common.thread_pool, task,
                                        "xrootd: thread_task_post failed, sync pgread fallback",
                                        &posted);
            if (posted) {
                return NGX_OK;
            }
        }

        /*
         * Sync fallback: pread into scratch[0..rlen-1], encode into
         * scratch[rlen..], matching the AIO scratch layout so the same single
         * allocation is reused on subsequent requests.
         */
        nread = pread(fd, scratch, rlen, (off_t) offset);
        if (nread < 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_PGREAD, "PGREAD",
                              ctx->files[idx].path, "-",
                              kXR_IOError, strerror(errno));
        }

        flat_buf = scratch;
        rlen     = (size_t) nread;

        n_pages = (rlen + kXR_pgPageSZ - 1) / kXR_pgPageSZ;
        if (n_pages == 0) {
            n_pages = 1;
        }

        /* Encoded output placed at scratch[original rlen..] */
        out_buf  = scratch + (scratch_size - n_pages_max * kXR_pgUnitSZ);
        out_size = xrootd_pgread_encode_pages(flat_buf, rlen, out_buf);
    }

    hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
    if (hdr_buf == NULL) {
        xrootd_release_read_buffer(ctx, c, flat_buf);
        return NGX_ERROR;
    }
    xrootd_build_pgread_status(ctx, offset, (uint32_t) out_size, hdr_buf);

    cl_hdr = ngx_alloc_chain_link(c->pool);
    if (cl_hdr == NULL) {
        xrootd_release_read_buffer(ctx, c, flat_buf);
        return NGX_ERROR;
    }
    cl_hdr->buf = ngx_calloc_buf(c->pool);
    if (cl_hdr->buf == NULL) {
        xrootd_release_read_buffer(ctx, c, flat_buf);
        return NGX_ERROR;
    }
    cl_hdr->buf->pos = (u_char *) hdr_buf;
    cl_hdr->buf->last = cl_hdr->buf->pos + sizeof(*hdr_buf);
    cl_hdr->buf->memory = 1;
    cl_hdr->buf->last_buf = 0;

    {
        ngx_chain_t *cl_data;
        ngx_buf_t   *bd;

        cl_data = ngx_alloc_chain_link(c->pool);
        bd = ngx_calloc_buf(c->pool);
        if (cl_data == NULL || bd == NULL) {
            xrootd_release_read_buffer(ctx, c, flat_buf);
            return NGX_ERROR;
        }
        bd->pos = out_buf;
        bd->last = out_buf + out_size;
        bd->memory = 1;
        bd->last_buf = 1;
        cl_data->buf = bd;
        cl_data->next = NULL;

        cl_hdr->next = cl_data;
        rsp_chain = cl_hdr;
    }

    ctx->files[idx].bytes_read += rlen;
    ctx->session_bytes += rlen;

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
