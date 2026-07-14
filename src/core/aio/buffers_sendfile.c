#include "core/ngx_brix_module.h"
#include "core/aio/buffers_internal.h"   /* cross-file: chunk_geometry + chain_append_{mem,file} (buffers.c) */

/*
 * buffers_sendfile.c — file-backed (sendfile) response-chain builders plus the
 * pgread response chain.
 *
 * Split from buffers.c (phase-79 file-size cap): this file owns the zero-copy
 * sendfile path (single- and multi-chunk file-backed chains for cleartext,
 * non-TLS reads) and the page-mode kXR_pgread chain. The shared chunk-geometry
 * and link-append helpers it reuses stay in buffers.c and are reached via
 * buffers_internal.h; the memory-chain builders (single/window/chunked) also
 * stay in buffers.c.
 */

/*
 * brix_build_single_sendfile_chain — build a header+file chain for a single
 * chunk sendfile response (data_total <= BRIX_READ_CHUNK_MAX).
 *
 * WHAT: Constructs an nginx ngx_chain_t with two links where the second link is
 * a file-backed buffer (in_file=1) pointing to an open fd at offset..offset+data.
 * The header link contains ServerResponseHdr; the data link enables direct kernel
 * sendfile(2) — bypassing read()+write() and reducing CPU utilization on large reads.
 *
 * WHY: Non-TLS (cleartext) connections can leverage kernel-level zero-copy for superior
 * throughput. TLS connections automatically fall back to memory-backed chains because
 * nginx's SSL layer cannot wrap sendfile(2). This function handles the single-chunk
 * case; multi-chunk responses are built by brix_build_sendfile_chain via iteration.
 * Setting in_file=1 is critical: it tells nginx's output_filter to invoke sendfile()
 * syscall directly rather than reading into user space and writing back out.
 *
 * HOW: 1) Acquires rd.read_hdr_scratch for the header buffer (same as memory chain).
 *      2) Calls brix_build_resp_hdr() with ctx->recv.cur_streamid, kXR_ok, data_total.
 *      3) Memzeros fast structs including read_fast_file (ngx_file_t).
 *      4) Configures hdr_buf → hdr_chain (header memory-backed).
 *      5) If data_total==0 returns header-only; otherwise configures:
 *         - file.fd = fd, file.name = path
 *         - body_buf.file = &file, body_buf.in_file = 1
 *         - body_buf.file_pos = offset, body_buf.file_last = offset + data
 *      6) Links hdr_chain → body_chain; sets last_buf/last_in_chain on final buffer.
 *      7) If base_out is non-NULL, stores hdrbuf pointer for deferred free after send.
 */
static ngx_chain_t *
brix_build_single_sendfile_chain(brix_ctx_t *ctx, ngx_connection_t *c,
    int fd, const char *path, off_t offset, size_t data_total,
    u_char **base_out)
{
    brix_resp_slot_t *slot = &ctx->out.ring[ctx->out.tail];
    u_char *hdrbuf = slot->hdr_bytes;

    /*
     * Phase 29: write the 8-byte header into THIS slot's private header buffer
     * (not the shared rd.read_hdr_scratch), so pipelining the next read cannot
     * overwrite a still-draining read's header.  The header is owned by the slot
     * for its lifetime, so there is nothing to release — base_out stays NULL.
     */
    if (base_out != NULL) {
        *base_out = NULL;
    }

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok, (uint32_t) data_total,
                          (ServerResponseHdr *) hdrbuf);

    /* A single-chunk sendfile read is the one response the recv loop pipelines. */
    ctx->out.resp_pipelinable = 1;

    ngx_memzero(&slot->read_fast_hdr_chain, sizeof(slot->read_fast_hdr_chain));
    ngx_memzero(&slot->read_fast_body_chain, sizeof(slot->read_fast_body_chain));
    ngx_memzero(&slot->read_fast_hdr_buf, sizeof(slot->read_fast_hdr_buf));
    ngx_memzero(&slot->read_fast_body_buf, sizeof(slot->read_fast_body_buf));
    ngx_memzero(&slot->read_fast_file, sizeof(slot->read_fast_file));

    slot->read_fast_hdr_buf.pos = hdrbuf;
    slot->read_fast_hdr_buf.last = hdrbuf + XRD_RESPONSE_HDR_LEN;
    slot->read_fast_hdr_buf.memory = 1;
    slot->read_fast_hdr_buf.temporary = 1;

    slot->read_fast_hdr_chain.buf = &slot->read_fast_hdr_buf;
    slot->read_fast_hdr_chain.next = NULL;

    if (data_total == 0) {
        slot->read_fast_hdr_buf.last_buf = 1;
        slot->read_fast_hdr_buf.last_in_chain = 1;
        return &slot->read_fast_hdr_chain;
    }

    slot->read_fast_file.fd = fd;
    slot->read_fast_file.name.data = (u_char *) path;
    slot->read_fast_file.name.len = path ? ngx_strlen(path) : 0;
    slot->read_fast_file.log = c->log;

    slot->read_fast_body_buf.file = &slot->read_fast_file;
    slot->read_fast_body_buf.in_file = 1;
    slot->read_fast_body_buf.file_pos = offset;
    slot->read_fast_body_buf.file_last = offset + (off_t) data_total;
    slot->read_fast_body_buf.last_buf = 1;
    slot->read_fast_body_buf.last_in_chain = 1;

    slot->read_fast_body_chain.buf = &slot->read_fast_body_buf;
    slot->read_fast_body_chain.next = NULL;
    slot->read_fast_hdr_chain.next = &slot->read_fast_body_chain;

    return &slot->read_fast_hdr_chain;
}

/*
 * brix_build_sendfile_chain — build a multi-chunk sendfile chain for reads
 * from a kernel file descriptor (zero-copy path for non-TLS connections).
 *
 * WHAT: Constructs an nginx ngx_chain_t where each wire frame consists of:
 *   1. A header buffer (memory-backed, contains ServerResponseHdr)
 *   2. A file buffer (in_file=1, points to fd at offset+di .. offset+di+chunk)
 *
 * This enables nginx's send_chain to invoke sendfile(2) syscalls directly —
 * bypassing read()+write() round-trips and reducing CPU utilization on large
 * transfers. Zero-copy semantics are preserved: data never enters user space.
 *
 * WHY: Non-TLS connections can use the kernel-level zero-copy path for superior
 * throughput. TLS connections automatically fall back to read+write because
 * nginx's SSL layer cannot wrap sendfile — no explicit handling needed here.
 * Multi-chunk support handles reads exceeding BRIX_READ_CHUNK_MAX (16 MiB).
 *
 * HOW: Delegates to brix_build_single_sendfile_chain for small responses.
 * For large responses, iterates over n_chunks allocating one ngx_file_t per
 * data link (all referencing the same fd at successive offsets). hdrbuf is
 * packed contiguously like chunked memory chain; base_out tracks allocation
 * for deferred free after send completion.
 */
ngx_chain_t *
brix_build_sendfile_chain(brix_ctx_t *ctx, ngx_connection_t *c,
    int fd, const char *path, off_t offset, size_t data_total,
    u_char **base_out)
{
    size_t       n_chunks, last_size;
    u_char      *hdrbuf;
    ngx_chain_t *head = NULL, *tail = NULL;
    size_t       di = 0;
    size_t       chunk;

    if (base_out != NULL) {
        *base_out = NULL;
    }

    if (data_total <= BRIX_READ_CHUNK_MAX) {
        return brix_build_single_sendfile_chain(ctx, c, fd, path, offset,
                                                  data_total, base_out);
    }

    /* Same chunk-count math as brix_build_chunked_chain, via the shared
     * brix_chunk_geometry helper: ceil-divide, then remap a zero final remainder
     * back to a full CHUNK_MAX (the last frame must carry the trailing bytes,
     * never zero). */
    brix_chunk_geometry(data_total, &n_chunks, &last_size);

    /*
     * Phase 32 WS2: keep the per-chunk headers in THIS slot's private header
     * buffer (slot->hdr_bytes), not the shared rd.read_hdr_scratch, so a multi-chunk
     * sendfile read can pipeline — the next read built into another slot cannot
     * clobber these headers while this response is still draining.  rlen is
     * capped at BRIX_READ_REQUEST_MAX so n_chunks*8 <= BRIX_SLOT_HDR_MAX
     * always; the guard is defence-in-depth.  The data links are file-backed
     * (no heap) and the headers are slot-owned, so there is nothing to free —
     * base_out stays NULL.
     */
    if (n_chunks * XRD_RESPONSE_HDR_LEN > BRIX_SLOT_HDR_MAX) {
        return NULL;
    }
    hdrbuf = ctx->out.ring[ctx->out.tail].hdr_bytes;

    ctx->out.resp_pipelinable = 1;

    for (chunk = 0; chunk < n_chunks; chunk++) {
        size_t        chunk_data;
        uint16_t      status;
        u_char       *hptr;

        /* Same frame layout as the memory path: full CHUNK_MAX per chunk
         * except the last (last_size); kXR_oksofar on every frame but the
         * final kXR_ok, all sharing ctx->recv.cur_streamid. */
        chunk_data = (chunk < n_chunks - 1) ? BRIX_READ_CHUNK_MAX
                                            : last_size;
        status = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;
        hptr = hdrbuf + chunk * XRD_RESPONSE_HDR_LEN;

        brix_build_resp_hdr(ctx->recv.cur_streamid, status,
                              (uint32_t) chunk_data,
                              (ServerResponseHdr *) hptr);

        if (brix_chain_append_mem(c->pool, &head, &tail, hptr,
                                    hptr + XRD_RESPONSE_HDR_LEN) != NGX_OK)
        {
            return NULL;
        }

        if (chunk_data > 0) {
            /*
             * in_file=1 (set inside brix_chain_append_file) is what makes nginx
             * emit sendfile(2) for this link instead of read()+write().  Every
             * data link shares the SAME fd; di walks the byte offset so chunk k
             * covers fd bytes [offset+di .. offset+di+chunk_data) — successive
             * windows of one open file, no per-chunk seek or copy.
             */
            off_t file_pos = offset + (off_t) di;

            if (brix_chain_append_file(c->pool, c, &head, &tail, fd, path,
                                        file_pos,
                                        file_pos + (off_t) chunk_data) != NGX_OK)
            {
                return NULL;
            }
            di += chunk_data;
        }
    }

    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    return head;
}

/*
 * brix_build_pgread_chain — assemble the kXR_pgread response chain:
 *   [ServerStatusResponse_pgRead header] -> [encoded page data].
 *
 * `data` points at out_size bytes of already-CRC-encoded page-mode wire output
 * (the gapped [CRC32c][page]+ layout produced by the in-place encoder), and
 * carries its own per-page checksums — so it is sent verbatim, never through
 * brix_build_chunked_chain (which would prepend a kXR_ok framing wrong for
 * pgread). Both the synchronous handler (src/read/pgread.c) and the thread-pool
 * AIO completion (brix_pgread_aio_done) build exactly this chain, so it lives
 * here once. Returns the chain head, or NULL on a pool allocation failure — the
 * caller owns its scratch buffer and handles its own error/cleanup path.
 */
ngx_chain_t *
brix_build_pgread_chain(brix_ctx_t *ctx, ngx_connection_t *c,
    int64_t offset, u_char *data, uint32_t out_size)
{
    ServerStatusResponse_pgRead *hdr_buf;
    ngx_chain_t                 *cl_hdr, *cl_data;
    ngx_buf_t                   *bd;

    hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
    if (hdr_buf == NULL) {
        return NULL;
    }
    brix_build_pgread_status(ctx, offset, out_size, hdr_buf);

    cl_hdr = ngx_alloc_chain_link(c->pool);
    if (cl_hdr == NULL) {
        return NULL;
    }
    cl_hdr->buf = ngx_calloc_buf(c->pool);
    if (cl_hdr->buf == NULL) {
        return NULL;
    }
    cl_hdr->buf->pos = (u_char *) hdr_buf;
    cl_hdr->buf->last = cl_hdr->buf->pos + sizeof(*hdr_buf);
    cl_hdr->buf->memory = 1;
    cl_hdr->buf->last_buf = 0;

    cl_data = ngx_alloc_chain_link(c->pool);
    bd = ngx_calloc_buf(c->pool);
    if (cl_data == NULL || bd == NULL) {
        return NULL;
    }
    bd->pos = data;
    bd->last = data + out_size;
    bd->memory = 1;
    bd->last_buf = 1;
    cl_data->buf = bd;
    cl_data->next = NULL;

    cl_hdr->next = cl_data;
    return cl_hdr;
}
