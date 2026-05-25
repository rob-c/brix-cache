#include "ngx_xrootd_module.h"

/*
 * Response buffer and chain builders shared by synchronous read paths and
 * nginx thread-pool AIO completions.
 */

/*
 * xrootd_get_pool_scratch — return a reusable scratch buffer from the
 * connection pool, growing it only when the current allocation is too small.
 *
 * The caller owns one buffer slot (*slot / *slot_size) anchored in the
 * connection pool.  On first call *slot is NULL and ngx_palloc allocates it.
 * On subsequent calls, if *slot_size >= need, the existing buffer is returned
 * without a new allocation — critical for preventing unbounded pool growth
 * during long xrdcp sessions.
 *
 * When the buffer must grow, the old one is freed with ngx_pfree (which is a
 * no-op if the pool does not track the block, so it is always safe to call).
 *
 * NOTE: need==0 is clamped to 1 to satisfy ngx_palloc's precondition.
 */
static u_char *
xrootd_get_pool_scratch(ngx_pool_t *pool, u_char **slot, size_t *slot_size,
    size_t need)
{
    u_char *p;

    if (need == 0) {
        need = 1;
    }

    if (*slot != NULL && *slot_size >= need) {
        return *slot;
    }

    p = ngx_palloc(pool, need);
    if (p == NULL) {
        return NULL;
    }

    if (*slot != NULL) {
        (void) ngx_pfree(pool, *slot);
    }

    *slot = p;
    *slot_size = need;
    return p;
}

/*
 * xrootd_get_read_scratch — allocate or reuse the per-connection read data buffer.
 *
 * WHAT: Provides a scratch buffer for holding raw wire response data during
 * synchronous and AIO-read operations. The buffer is anchored in the connection
 * pool's lifetime so it persists across multiple requests on the same stream.
 *
 * WHY: xrdcp sessions may issue hundreds of read requests sequentially. Without
 * reuse, each request would allocate a new block — causing unbounded pool growth
 * and memory pressure on long-running transfers. This wrapper delegates to
 * xrootd_get_pool_scratch which grows the buffer only when needed.
 *
 * HOW: Returns xrootd_get_pool_scratch(c->pool, &ctx->read_scratch, ...) with
 * the ctx-level slot pointer. First call allocates; subsequent calls return the
 * existing buffer if size >= need.
 */
u_char *
xrootd_get_read_scratch(xrootd_ctx_t *ctx, ngx_connection_t *c, size_t need)
{
    return xrootd_get_pool_scratch(c->pool, &ctx->read_scratch,
                                   &ctx->read_scratch_size, need);
}

/*
 * xrootd_get_read_header_scratch — allocate or reuse the per-connection wire
 * response header buffer.
 *
 * WHAT: Provides a scratch buffer for writing ServerResponseHdr structures that
 * precede each data chunk in an XRootD response chain. These headers contain
 * streamid, status code (kXR_ok/kXR_oksofar), and data length fields.
 *
 * WHY: Each wire frame requires its own header block. For single-chunk responses
 * one allocation suffices; for chunked (>16 MiB) reads n_chunks headers are
 * packed contiguously into this buffer. Reuse prevents repeated pool allocations
 * during large transfers.
 *
 * HOW: Returns xrootd_get_pool_scratch(c->pool, &ctx->read_hdr_scratch, ...) with
 * the header-specific ctx slot pointer. Chunked chain builders pack multiple
 * headers sequentially into one allocation sized as n_chunks × XRD_RESPONSE_HDR_LEN.
 */
u_char *
xrootd_get_read_header_scratch(xrootd_ctx_t *ctx, ngx_connection_t *c,
    size_t need)
{
    return xrootd_get_pool_scratch(c->pool, &ctx->read_hdr_scratch,
                                   &ctx->read_hdr_scratch_size, need);
}

/*
 * xrootd_get_write_scratch — allocate or reuse the per-connection write data buffer.
 *
 * WHAT: Provides a scratch buffer for holding wire request payload during AIO-write
 * and synchronous write operations (pgwrite, kXR_write). The buffer accumulates
 * raw data from the client before being forwarded to xrootd upstream.
 *
 * WHY: Write requests may span multiple pages or contain large payloads. Without
 * per-connection reuse each request would trigger a fresh allocation — causing
 * pool fragmentation and unnecessary memory churn on repeated write operations.
 * This wrapper delegates to xrootd_get_pool_scratch for automatic grow-on-demand.
 *
 * HOW: Returns xrootd_get_pool_scratch(c->pool, &ctx->write_scratch, ...) with
 * the write-specific ctx slot pointer. First call allocates; subsequent calls
 * return the existing buffer if current size >= needed amount.
 */
u_char *
xrootd_get_write_scratch(xrootd_ctx_t *ctx, ngx_connection_t *c, size_t need)
{
    return xrootd_get_pool_scratch(c->pool, &ctx->write_scratch,
                                   &ctx->write_scratch_size, need);
}

/*
 * xrootd_release_read_buffer — return a response data buffer to the pool,
 * unless it is one of the reusable scratch slots.
 *
 * read_scratch and read_hdr_scratch are long-lived per-connection buffers that
 * must NOT be freed on every response.  Any other buffer (allocated via
 * ngx_palloc from c->pool for a single request) is returned with ngx_pfree.
 *
 * Called from xrootd_release_pending_buffer() in write_helpers.c.
 */
void
xrootd_release_read_buffer(xrootd_ctx_t *ctx, ngx_connection_t *c, u_char *buf)
{
    if (buf == NULL) {
        return;
    }

    if (buf == ctx->read_scratch || buf == ctx->read_hdr_scratch) {
        return;
    }

    (void) ngx_pfree(c->pool, buf);
}

/*
 * xrootd_build_single_memory_chain — build a two-link chain for a kXR_ok
 * response whose data fits in one wire chunk (data_total <= XROOTD_READ_CHUNK_MAX).
 *
 * WHAT: Constructs an nginx ngx_chain_t with exactly two links: a header buffer
 * containing the ServerResponseHdr (streamid, status=kXR_ok, length) followed by
 * a single data buffer pointing into databuf. Both buffers are memory-backed
 * (memory=1), enabling nginx to write via read()+write() rather than sendfile.
 *
 * WHY: The vast majority of xrdcp reads produce responses under 16 MiB that fit
 * in one wire chunk. Allocating fresh ngx_chain_t and ngx_buf_t structures on
 * every response would waste pool memory and CPU cycles. This function uses the
 * pre-allocated ctx->read_fast_* structs (hdr_chain, body_chain, hdr_buf, body_buf)
 * to avoid any pool allocation — zero-cost for the common case.
 *
 * HOW: 1) Acquires read_hdr_scratch via xrootd_get_read_header_scratch.
 *      2) Calls xrootd_build_resp_hdr() to populate ServerResponseHdr with
 *         ctx->cur_streamid, kXR_ok status, and data_total length.
 *      3) Memzeros the fast structs then configures hdr_buf → hdr_chain (header).
 *      4) If data_total==0 returns header-only chain; otherwise configures
 *         body_buf pointing into databuf → body_chain (data), linking them.
 *      5) Sets last_buf/last_in_chain on the final buffer to signal end-of-response.
 *
 * Precondition: data_total <= XROOTD_READ_CHUNK_MAX.
 */
static ngx_chain_t *
xrootd_build_single_memory_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t data_total)
{
    u_char *hdrbuf;

    hdrbuf = xrootd_get_read_header_scratch(ctx, c, XRD_RESPONSE_HDR_LEN);
    if (hdrbuf == NULL) {
        return NULL;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, (uint32_t) data_total,
                          (ServerResponseHdr *) hdrbuf);

    ngx_memzero(&ctx->read_fast_hdr_chain, sizeof(ctx->read_fast_hdr_chain));
    ngx_memzero(&ctx->read_fast_body_chain, sizeof(ctx->read_fast_body_chain));
    ngx_memzero(&ctx->read_fast_hdr_buf, sizeof(ctx->read_fast_hdr_buf));
    ngx_memzero(&ctx->read_fast_body_buf, sizeof(ctx->read_fast_body_buf));

    ctx->read_fast_hdr_buf.pos = hdrbuf;
    ctx->read_fast_hdr_buf.last = hdrbuf + XRD_RESPONSE_HDR_LEN;
    ctx->read_fast_hdr_buf.memory = 1;
    ctx->read_fast_hdr_buf.temporary = 1;

    ctx->read_fast_hdr_chain.buf = &ctx->read_fast_hdr_buf;
    ctx->read_fast_hdr_chain.next = NULL;

    if (data_total == 0) {
        ctx->read_fast_hdr_buf.last_buf = 1;
        ctx->read_fast_hdr_buf.last_in_chain = 1;
        return &ctx->read_fast_hdr_chain;
    }

    ctx->read_fast_body_buf.pos = databuf;
    ctx->read_fast_body_buf.last = databuf + data_total;
    ctx->read_fast_body_buf.memory = 1;
    ctx->read_fast_body_buf.temporary = 1;
    ctx->read_fast_body_buf.last_buf = 1;
    ctx->read_fast_body_buf.last_in_chain = 1;

    ctx->read_fast_body_chain.buf = &ctx->read_fast_body_buf;
    ctx->read_fast_body_chain.next = NULL;
    ctx->read_fast_hdr_chain.next = &ctx->read_fast_body_chain;

    return &ctx->read_fast_hdr_chain;
}

/*
 * xrootd_build_single_sendfile_chain — build a header+file chain for a single
 * chunk sendfile response (data_total <= XROOTD_READ_CHUNK_MAX).
 *
 * WHAT: Constructs an nginx ngx_chain_t with two links where the second link is
 * a file-backed buffer (in_file=1) pointing to an open fd at offset..offset+data.
 * The header link contains ServerResponseHdr; the data link enables direct kernel
 * sendfile(2) — bypassing read()+write() and reducing CPU utilization on large reads.
 *
 * WHY: Non-TLS (cleartext) connections can leverage kernel-level zero-copy for superior
 * throughput. TLS connections automatically fall back to memory-backed chains because
 * nginx's SSL layer cannot wrap sendfile(2). This function handles the single-chunk
 * case; multi-chunk responses are built by xrootd_build_sendfile_chain via iteration.
 * Setting in_file=1 is critical: it tells nginx's output_filter to invoke sendfile()
 * syscall directly rather than reading into user space and writing back out.
 *
 * HOW: 1) Acquires read_hdr_scratch for the header buffer (same as memory chain).
 *      2) Calls xrootd_build_resp_hdr() with ctx->cur_streamid, kXR_ok, data_total.
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
xrootd_build_single_sendfile_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int fd, const char *path, off_t offset, size_t data_total,
    u_char **base_out)
{
    u_char *hdrbuf;

    hdrbuf = xrootd_get_read_header_scratch(ctx, c, XRD_RESPONSE_HDR_LEN);
    if (hdrbuf == NULL) {
        return NULL;
    }
    if (base_out != NULL) {
        *base_out = hdrbuf;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, (uint32_t) data_total,
                          (ServerResponseHdr *) hdrbuf);

    ngx_memzero(&ctx->read_fast_hdr_chain, sizeof(ctx->read_fast_hdr_chain));
    ngx_memzero(&ctx->read_fast_body_chain, sizeof(ctx->read_fast_body_chain));
    ngx_memzero(&ctx->read_fast_hdr_buf, sizeof(ctx->read_fast_hdr_buf));
    ngx_memzero(&ctx->read_fast_body_buf, sizeof(ctx->read_fast_body_buf));
    ngx_memzero(&ctx->read_fast_file, sizeof(ctx->read_fast_file));

    ctx->read_fast_hdr_buf.pos = hdrbuf;
    ctx->read_fast_hdr_buf.last = hdrbuf + XRD_RESPONSE_HDR_LEN;
    ctx->read_fast_hdr_buf.memory = 1;
    ctx->read_fast_hdr_buf.temporary = 1;

    ctx->read_fast_hdr_chain.buf = &ctx->read_fast_hdr_buf;
    ctx->read_fast_hdr_chain.next = NULL;

    if (data_total == 0) {
        ctx->read_fast_hdr_buf.last_buf = 1;
        ctx->read_fast_hdr_buf.last_in_chain = 1;
        return &ctx->read_fast_hdr_chain;
    }

    ctx->read_fast_file.fd = fd;
    ctx->read_fast_file.name.data = (u_char *) path;
    ctx->read_fast_file.name.len = path ? ngx_strlen(path) : 0;
    ctx->read_fast_file.log = c->log;

    ctx->read_fast_body_buf.file = &ctx->read_fast_file;
    ctx->read_fast_body_buf.in_file = 1;
    ctx->read_fast_body_buf.file_pos = offset;
    ctx->read_fast_body_buf.file_last = offset + (off_t) data_total;
    ctx->read_fast_body_buf.last_buf = 1;
    ctx->read_fast_body_buf.last_in_chain = 1;

    ctx->read_fast_body_chain.buf = &ctx->read_fast_body_buf;
    ctx->read_fast_body_chain.next = NULL;
    ctx->read_fast_hdr_chain.next = &ctx->read_fast_body_chain;

    return &ctx->read_fast_hdr_chain;
}

/*
 * xrootd_build_chunked_chain — build a multi-chunk memory chain for large
 * reads (data_total > XROOTD_READ_CHUNK_MAX = 16 MiB).
 *
 * XRootD responses larger than 16 MiB must be split into multiple wire frames:
 *   [kXR_oksofar frame][data][kXR_oksofar frame][data]...[kXR_ok frame][data]
 *
 * Each header is written into a contiguous block in read_hdr_scratch (avoiding
 * N separate pool allocations).  Each data link points into databuf at the
 * corresponding offset — zero copy from the AIO receive buffer to the wire.
 *
 * Falls through to xrootd_build_single_memory_chain for data_total <= CHUNK_MAX.
 */
ngx_chain_t *
xrootd_build_chunked_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t data_total)
{
    size_t       n_chunks, last_size;
    u_char      *hdrbuf;
    ngx_chain_t *head = NULL, *tail = NULL;
    size_t       di = 0;
    size_t       chunk;

    if (data_total <= XROOTD_READ_CHUNK_MAX) {
        return xrootd_build_single_memory_chain(ctx, c, databuf, data_total);
    }

    n_chunks = (data_total + XROOTD_READ_CHUNK_MAX - 1)
               / XROOTD_READ_CHUNK_MAX;
    if (n_chunks == 0) {
        n_chunks = 1;
    }
    last_size = data_total % XROOTD_READ_CHUNK_MAX;
    if (last_size == 0 && data_total > 0) {
        last_size = XROOTD_READ_CHUNK_MAX;
    }

    hdrbuf = xrootd_get_read_header_scratch(ctx, c,
                                            n_chunks * XRD_RESPONSE_HDR_LEN);
    if (hdrbuf == NULL) {
        return NULL;
    }

    for (chunk = 0; chunk < n_chunks; chunk++) {
        size_t        chunk_data;
        uint16_t      status;
        ngx_chain_t  *clh;
        ngx_buf_t    *bh;
        u_char       *hptr;

        chunk_data = (chunk < n_chunks - 1) ? XROOTD_READ_CHUNK_MAX
                                            : last_size;
        status = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;
        hptr = hdrbuf + chunk * XRD_RESPONSE_HDR_LEN;

        xrootd_build_resp_hdr(ctx->cur_streamid, status,
                              (uint32_t) chunk_data,
                              (ServerResponseHdr *) hptr);

        clh = ngx_alloc_chain_link(c->pool);
        bh = ngx_calloc_buf(c->pool);
        if (clh == NULL || bh == NULL) {
            return NULL;
        }

        bh->pos = hptr;
        bh->last = hptr + XRD_RESPONSE_HDR_LEN;
        bh->memory = 1;
        bh->temporary = 1;
        clh->buf = bh;
        clh->next = NULL;

        if (head == NULL) {
            head = clh;
        } else {
            tail->next = clh;
        }
        tail = clh;

        if (chunk_data > 0) {
            ngx_chain_t *cld;
            ngx_buf_t   *bd;

            cld = ngx_alloc_chain_link(c->pool);
            bd = ngx_calloc_buf(c->pool);
            if (cld == NULL || bd == NULL) {
                return NULL;
            }

            bd->pos = databuf + di;
            bd->last = databuf + di + chunk_data;
            bd->memory = 1;
            bd->temporary = 1;
            cld->buf = bd;
            cld->next = NULL;

            tail->next = cld;
            tail = cld;
            di += chunk_data;
        }
    }

    if (tail != NULL) {
        tail->buf->last_buf = 1;
    }

    return head;
}

/*
 * xrootd_build_sendfile_chain — build a multi-chunk sendfile chain for reads
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
 * Multi-chunk support handles reads exceeding XROOTD_READ_CHUNK_MAX (16 MiB).
 *
 * HOW: Delegates to xrootd_build_single_sendfile_chain for small responses.
 * For large responses, iterates over n_chunks allocating one ngx_file_t per
 * data link (all referencing the same fd at successive offsets). hdrbuf is
 * packed contiguously like chunked memory chain; base_out tracks allocation
 * for deferred free after send completion.
 */
ngx_chain_t *
xrootd_build_sendfile_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
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

    if (data_total <= XROOTD_READ_CHUNK_MAX) {
        return xrootd_build_single_sendfile_chain(ctx, c, fd, path, offset,
                                                  data_total, base_out);
    }

    n_chunks = (data_total + XROOTD_READ_CHUNK_MAX - 1)
               / XROOTD_READ_CHUNK_MAX;
    if (n_chunks == 0) {
        n_chunks = 1;
    }
    last_size = data_total % XROOTD_READ_CHUNK_MAX;
    if (last_size == 0 && data_total > 0) {
        last_size = XROOTD_READ_CHUNK_MAX;
    }

    hdrbuf = xrootd_get_read_header_scratch(ctx, c,
                                            n_chunks * XRD_RESPONSE_HDR_LEN);
    if (hdrbuf == NULL) {
        return NULL;
    }
    if (base_out != NULL) {
        *base_out = hdrbuf;
    }

    for (chunk = 0; chunk < n_chunks; chunk++) {
        size_t        chunk_data;
        uint16_t      status;
        ngx_chain_t  *clh;
        ngx_buf_t    *bh;
        u_char       *hptr;

        chunk_data = (chunk < n_chunks - 1) ? XROOTD_READ_CHUNK_MAX
                                            : last_size;
        status = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;
        hptr = hdrbuf + chunk * XRD_RESPONSE_HDR_LEN;

        xrootd_build_resp_hdr(ctx->cur_streamid, status,
                              (uint32_t) chunk_data,
                              (ServerResponseHdr *) hptr);

        clh = ngx_alloc_chain_link(c->pool);
        bh = ngx_calloc_buf(c->pool);
        if (clh == NULL || bh == NULL) {
            return NULL;
        }

        bh->pos = hptr;
        bh->last = hptr + XRD_RESPONSE_HDR_LEN;
        bh->memory = 1;
        bh->temporary = 1;
        clh->buf = bh;
        clh->next = NULL;

        if (head == NULL) {
            head = clh;
        } else {
            tail->next = clh;
        }
        tail = clh;

        if (chunk_data > 0) {
            ngx_chain_t *clf;
            ngx_buf_t   *bf;
            ngx_file_t  *file;

            clf = ngx_alloc_chain_link(c->pool);
            bf = ngx_calloc_buf(c->pool);
            file = ngx_pcalloc(c->pool, sizeof(ngx_file_t));
            if (clf == NULL || bf == NULL || file == NULL) {
                return NULL;
            }

            file->fd = fd;
            file->name.data = (u_char *) path;
            file->name.len = path ? ngx_strlen(path) : 0;
            file->log = c->log;

            bf->file = file;
            bf->in_file = 1;
            bf->file_pos = offset + (off_t) di;
            bf->file_last = bf->file_pos + (off_t) chunk_data;
            clf->buf = bf;
            clf->next = NULL;

            tail->next = clf;
            tail = clf;
            di += chunk_data;
        }
    }

    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    return head;
}
