#include "core/ngx_brix_module.h"

/*
 * Response buffer and chain builders shared by synchronous read paths and
 * nginx thread-pool AIO completions.
 */

/*
 * brix_get_pool_scratch — return a reusable scratch buffer from the
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
u_char *
brix_get_pool_scratch(ngx_pool_t *pool, u_char **slot, size_t *slot_size,
    size_t need)
{
    u_char *p;

    if (need == 0) {
        need = 1;
    }

    if (*slot != NULL && *slot_size >= need) {
        return *slot;
    }

    /*
     * Phase 31: scratch buffers are raw heap allocations (ngx_alloc/ngx_free),
     * NOT pool allocations.  The earlier pool-backed version corrupted memory
     * when brix_trim_scratch() freed and re-grew read_scratch: ngx_pfree/
     * ngx_palloc churn nginx's pool large-allocation list while stale pointers
     * (the reused read_aio_task->databuf, read_fast_body_buf) still referenced
     * the old block — a use-after-free triggered by a large kXR_read followed by
     * a large kXR_readv.  Raw heap allocation has no such pool lifecycle: the
     * ctx owns the buffer and frees it explicitly on disconnect (mirroring how
     * payload_buf is handled in src/connection/recv.c).
     */
    p = ngx_alloc(need, pool->log);
    if (p == NULL) {
        return NULL;
    }

    if (*slot != NULL) {
        ngx_free(*slot);
    }

    *slot = p;
    *slot_size = need;
    return p;
}


/*
 * brix_release_read_buffer — return a response data buffer to the pool,
 * unless it is one of the reusable per-connection scratch slots.
 *
 * The scratch slots (read_scratch / read_hdr_scratch / write_scratch) are
 * long-lived raw heap allocations (see brix_get_pool_scratch) that must NOT
 * be freed on every response — they are reused across requests and freed once
 * at disconnect.  Any OTHER buffer reaching here (e.g. a dirlist response) is a
 * single-request ngx_palloc from c->pool and is returned with ngx_pfree.
 *
 * Called from brix_release_pending_buffer() in write_helpers.c.
 */
void
brix_release_read_buffer(brix_ctx_t *ctx, ngx_connection_t *c, u_char *buf)
{
    ngx_uint_t i;

    if (buf == NULL) {
        return;
    }

    if (buf == ctx->read_scratch || buf == ctx->read_hdr_scratch
        || buf == ctx->write_scratch || buf == ctx->cmp_scratch)
    {
        return;
    }

    /*
     * Per-in-flight read-pool buffer (read pipelining): return the slot to the
     * pool rather than freeing it — the buffer is reused for the next read and
     * freed once at disconnect.  Idempotent: a slot already marked free is a
     * no-op, so the queued-then-error double-release path cannot underflow
     * rd_inflight.
     */
    for (i = 0; i < ctx->pipeline_depth; i++) {
        if (ctx->rd_pool[i].buf == buf) {
            if (ctx->rd_pool[i].in_use) {
                ctx->rd_pool[i].in_use = 0;
                if (ctx->rd_inflight > 0) {
                    ctx->rd_inflight--;
                }
            }
            return;
        }
    }

    (void) ngx_pfree(c->pool, buf);
}

/*
 * brix_acquire_read_buffer — borrow a per-in-flight data buffer from the
 * connection's read pool (rd_pool), growing the chosen slot to >= need bytes.
 *
 * Unlike the single shared read_scratch, each in-flight read gets its OWN buffer,
 * so a memory-backed (userspace-TLS) read response can stay queued in the out_ring
 * and drain while the recv loop already issues the NEXT read into a different
 * buffer — i.e. memory reads can pipeline.  The slot is returned to the pool by
 * brix_release_read_buffer() when its out_ring response drains; the buffer is
 * freed once at disconnect (raw heap, Phase-31 discipline).
 *
 * The recv loop bounds in-flight reads at pipeline_depth (== rd_pool slot count),
 * so a free slot always exists on the hot path; NULL is returned only on OOM.
 */
u_char *
brix_acquire_read_buffer(brix_ctx_t *ctx, ngx_connection_t *c, size_t need)
{
    ngx_uint_t i;

    if (need == 0) {
        need = 1;
    }

    for (i = 0; i < ctx->pipeline_depth; i++) {
        if (ctx->rd_pool[i].in_use) {
            continue;
        }
        if (ctx->rd_pool[i].size < need) {
            u_char *p = ngx_alloc(need, c->log);
            if (p == NULL) {
                return NULL;
            }
            if (ctx->rd_pool[i].buf != NULL) {
                ngx_free(ctx->rd_pool[i].buf);
            }
            ctx->rd_pool[i].buf  = p;
            ctx->rd_pool[i].size = need;
        }
        ctx->rd_pool[i].in_use = 1;
        ctx->rd_inflight++;
        return ctx->rd_pool[i].buf;
    }

    return NULL;   /* pool exhausted — should not happen given the recv bound */
}

/*
 * brix_trim_scratch — shrink the per-session transfer scratch buffers back to
 * BRIX_READ_WINDOW once a large request has fully drained (Phase 31).
 *
 * read_scratch and write_scratch grow to the largest read / pgwrite the session
 * has served and are then kept for reuse.  Without trimming, a single 64 MiB
 * read pins ~64 MiB of resident heap for the entire connection lifetime even
 * while idle — the dominant memory-scaling term for a TLS gateway.  This trims
 * them back to the streaming window so the steady-state per-connection heap is
 * ~window, not ~request-max.
 *
 * MUST be called only when the connection is between requests (state
 * XRD_ST_REQ_HEADER with nothing buffered), so that no in-flight response chain
 * still points into these buffers.  The recv loop calls it at the top of a fresh
 * request.  Buffers at or below BRIX_SCRATCH_TRIM_THRESHOLD are left untouched
 * (hysteresis avoids realloc thrash on sessions that oscillate near the window).
 *
 * read_hdr_scratch (per-chunk wire headers) is tiny and never trimmed.
 * payload_buf has detach semantics owned by the write path and is trimmed there.
 */
static void
brix_trim_one(ngx_pool_t *pool, u_char **slot, size_t *slot_size)
{
    u_char *p;

    if (*slot == NULL || *slot_size <= BRIX_SCRATCH_TRIM_THRESHOLD) {
        return;
    }

    /* Raw heap free/alloc — see brix_get_pool_scratch for why these buffers
     * are not pool-backed.  This is what makes the trim safe to run. */
    ngx_free(*slot);

    p = ngx_alloc(BRIX_READ_WINDOW, pool->log);
    if (p == NULL) {
        /* Could not re-seat a warm buffer; drop it so the next request
         * allocates fresh at exactly the size it needs. */
        *slot = NULL;
        *slot_size = 0;
        return;
    }

    *slot = p;
    *slot_size = BRIX_READ_WINDOW;
}

void
brix_trim_scratch(brix_ctx_t *ctx, ngx_connection_t *c)
{
    brix_trim_one(c->pool, &ctx->read_scratch, &ctx->read_scratch_size);
    brix_trim_one(c->pool, &ctx->write_scratch, &ctx->write_scratch_size);
}

/*
 * brix_build_single_memory_chain — build a two-link chain for a kXR_ok
 * response whose data fits in one wire chunk (data_total <= BRIX_READ_CHUNK_MAX).
 *
 * WHAT: Constructs an nginx ngx_chain_t with exactly two links: a header buffer
 * containing the ServerResponseHdr (streamid, status=kXR_ok, length) followed by
 * a single data buffer pointing into databuf. Both buffers are memory-backed
 * (memory=1), enabling nginx to write via read()+write() rather than sendfile.
 *
 * WHY: The vast majority of xrdcp reads produce responses under 16 MiB that fit
 * in one wire chunk. Allocating fresh ngx_chain_t and ngx_buf_t structures on
 * every response would waste pool memory and CPU cycles. This function uses the
 * pre-allocated slot->read_fast_* structs (hdr_chain, body_chain, hdr_buf, body_buf)
 * to avoid any pool allocation — zero-cost for the common case.
 *
 * HOW: 1) Acquires read_hdr_scratch via brix_get_read_header_scratch.
 *      2) Calls brix_build_resp_hdr() to populate ServerResponseHdr with
 *         ctx->cur_streamid, kXR_ok status, and data_total length.
 *      3) Memzeros the fast structs then configures hdr_buf → hdr_chain (header).
 *      4) If data_total==0 returns header-only chain; otherwise configures
 *         body_buf pointing into databuf → body_chain (data), linking them.
 *      5) Sets last_buf/last_in_chain on the final buffer to signal end-of-response.
 *
 * Precondition: data_total <= BRIX_READ_CHUNK_MAX.
 */
static ngx_chain_t *
brix_build_single_memory_chain(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t data_total)
{
    brix_resp_slot_t *slot = &ctx->out_ring[ctx->out_tail];
    /*
     * Header lives in THIS slot's private buffer (not the shared
     * read_hdr_scratch), so pipelining the next memory read into another slot
     * cannot overwrite a still-draining response's 8-byte header.  This is what
     * makes the memory (userspace-TLS) read path safe to pipeline; the body
     * buffer is made per-in-flight by brix_acquire_read_buffer() in read.c.
     */
    u_char *hdrbuf = slot->hdr_bytes;

    (void) c;
    brix_build_resp_hdr(ctx->cur_streamid, kXR_ok, (uint32_t) data_total,
                          (ServerResponseHdr *) hdrbuf);

    ngx_memzero(&slot->read_fast_hdr_chain, sizeof(slot->read_fast_hdr_chain));
    ngx_memzero(&slot->read_fast_body_chain, sizeof(slot->read_fast_body_chain));
    ngx_memzero(&slot->read_fast_hdr_buf, sizeof(slot->read_fast_hdr_buf));
    ngx_memzero(&slot->read_fast_body_buf, sizeof(slot->read_fast_body_buf));

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

    slot->read_fast_body_buf.pos = databuf;
    slot->read_fast_body_buf.last = databuf + data_total;
    slot->read_fast_body_buf.memory = 1;
    slot->read_fast_body_buf.temporary = 1;
    slot->read_fast_body_buf.last_buf = 1;
    slot->read_fast_body_buf.last_in_chain = 1;

    slot->read_fast_body_chain.buf = &slot->read_fast_body_buf;
    slot->read_fast_body_chain.next = NULL;
    slot->read_fast_hdr_chain.next = &slot->read_fast_body_chain;

    return &slot->read_fast_hdr_chain;
}

/*
 * brix_build_window_chain — build a single memory-backed response chunk with
 * an explicit wire status (Phase 31 W2.1 windowed reads).
 *
 * Identical layout to brix_build_single_memory_chain (header + one data buf,
 * reusing the pre-allocated read_fast_* structs), but the caller chooses the
 * status: kXR_oksofar for every window except the last, kXR_ok for the final
 * window.  The client accumulates the oksofar frames (same streamid) until the
 * kXR_ok, reassembling the full read — the same wire sequence the >16 MiB
 * multi-chunk path already emits, just sourced one window at a time.
 *
 * Precondition: data_total <= BRIX_READ_CHUNK_MAX (a window is <= 2 MiB).
 */
ngx_chain_t *
brix_build_window_chain(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t data_total, uint16_t status)
{
    brix_resp_slot_t *slot = &ctx->out_ring[ctx->out_tail];
    u_char *hdrbuf;

    hdrbuf = BRIX_GET_SCRATCH(ctx, c, read_hdr_scratch, read_hdr_scratch_size,
                                XRD_RESPONSE_HDR_LEN);
    if (hdrbuf == NULL) {
        return NULL;
    }

    brix_build_resp_hdr(ctx->cur_streamid, status, (uint32_t) data_total,
                          (ServerResponseHdr *) hdrbuf);

    ngx_memzero(&slot->read_fast_hdr_chain, sizeof(slot->read_fast_hdr_chain));
    ngx_memzero(&slot->read_fast_body_chain, sizeof(slot->read_fast_body_chain));
    ngx_memzero(&slot->read_fast_hdr_buf, sizeof(slot->read_fast_hdr_buf));
    ngx_memzero(&slot->read_fast_body_buf, sizeof(slot->read_fast_body_buf));

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

    slot->read_fast_body_buf.pos = databuf;
    slot->read_fast_body_buf.last = databuf + data_total;
    slot->read_fast_body_buf.memory = 1;
    slot->read_fast_body_buf.temporary = 1;
    /*
     * last_buf/last_in_chain mark the end of THIS wire frame for nginx's output
     * filter; they do not mean end-of-response.  The client keys end-of-response
     * off the kXR_ok status, so an oksofar frame still sets them.
     */
    slot->read_fast_body_buf.last_buf = 1;
    slot->read_fast_body_buf.last_in_chain = 1;
    slot->read_fast_body_chain.buf = &slot->read_fast_body_buf;
    slot->read_fast_body_chain.next = NULL;
    slot->read_fast_hdr_chain.next = &slot->read_fast_body_chain;

    return &slot->read_fast_hdr_chain;
}

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
 * HOW: 1) Acquires read_hdr_scratch for the header buffer (same as memory chain).
 *      2) Calls brix_build_resp_hdr() with ctx->cur_streamid, kXR_ok, data_total.
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
    brix_resp_slot_t *slot = &ctx->out_ring[ctx->out_tail];
    u_char *hdrbuf = slot->hdr_bytes;

    /*
     * Phase 29: write the 8-byte header into THIS slot's private header buffer
     * (not the shared read_hdr_scratch), so pipelining the next read cannot
     * overwrite a still-draining read's header.  The header is owned by the slot
     * for its lifetime, so there is nothing to release — base_out stays NULL.
     */
    if (base_out != NULL) {
        *base_out = NULL;
    }

    brix_build_resp_hdr(ctx->cur_streamid, kXR_ok, (uint32_t) data_total,
                          (ServerResponseHdr *) hdrbuf);

    /* A single-chunk sendfile read is the one response the recv loop pipelines. */
    ctx->resp_pipelinable = 1;

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
 * brix_build_chunked_chain — build a multi-chunk memory chain for large
 * reads (data_total > BRIX_READ_CHUNK_MAX = 16 MiB).
 *
 * XRootD responses larger than 16 MiB must be split into multiple wire frames:
 *   [kXR_oksofar frame][data][kXR_oksofar frame][data]...[kXR_ok frame][data]
 *
 * Each header is written into a contiguous block in read_hdr_scratch (avoiding
 * N separate pool allocations).  Each data link points into databuf at the
 * corresponding offset — zero copy from the AIO receive buffer to the wire.
 *
 * Falls through to brix_build_single_memory_chain for data_total <= CHUNK_MAX.
 */
ngx_chain_t *
brix_build_chunked_chain(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t data_total)
{
    size_t       n_chunks, last_size;
    u_char      *hdrbuf;
    ngx_chain_t *head = NULL, *tail = NULL;
    size_t       di = 0;
    size_t       chunk;

    if (data_total <= BRIX_READ_CHUNK_MAX) {
        return brix_build_single_memory_chain(ctx, c, databuf, data_total);
    }

    /*
     * Chunk-count math (mirrored in brix_build_sendfile_chain):
     *   n_chunks   = ceil(data_total / CHUNK_MAX) via the +MAX-1 trick.
     *   last_size  = size of the FINAL chunk.  data_total % CHUNK_MAX is 0 when
     *                data_total is an exact multiple, but a zero-byte final chunk
     *                is wrong here — the last frame must carry the trailing
     *                CHUNK_MAX bytes — so remap 0 back to CHUNK_MAX.
     * The n_chunks==0 guard is unreachable given data_total > CHUNK_MAX above,
     * but kept as defence-in-depth so the loop never runs zero times.
     */
    n_chunks = (data_total + BRIX_READ_CHUNK_MAX - 1)
               / BRIX_READ_CHUNK_MAX;
    if (n_chunks == 0) {
        n_chunks = 1;
    }
    last_size = data_total % BRIX_READ_CHUNK_MAX;
    if (last_size == 0 && data_total > 0) {
        last_size = BRIX_READ_CHUNK_MAX;
    }

    /*
     * One contiguous scratch block holds all N wire headers back-to-back
     * (8 bytes each); each iteration writes into its own slice at
     * hdrbuf + chunk*XRD_RESPONSE_HDR_LEN, avoiding N separate allocations.
     */
    hdrbuf = BRIX_GET_SCRATCH(ctx, c, read_hdr_scratch, read_hdr_scratch_size,
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

        /*
         * Every chunk but the last is a full CHUNK_MAX; the last carries
         * last_size.  The final frame's status is kXR_ok (end of response);
         * all earlier frames are kXR_oksofar — the client accumulates the
         * oksofar frames under the same streamid until the kXR_ok arrives.
         */
        chunk_data = (chunk < n_chunks - 1) ? BRIX_READ_CHUNK_MAX
                                            : last_size;
        status = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;
        hptr = hdrbuf + chunk * XRD_RESPONSE_HDR_LEN;

        brix_build_resp_hdr(ctx->cur_streamid, status,
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

            /* di walks the data offset; each data link points straight into
             * databuf — zero copy from the AIO receive buffer to the wire. */
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

    /* Same chunk-count math as brix_build_chunked_chain: ceil-divide, then
     * remap a zero final remainder back to a full CHUNK_MAX (the last frame
     * must carry the trailing bytes, never zero). */
    n_chunks = (data_total + BRIX_READ_CHUNK_MAX - 1)
               / BRIX_READ_CHUNK_MAX;
    if (n_chunks == 0) {
        n_chunks = 1;
    }
    last_size = data_total % BRIX_READ_CHUNK_MAX;
    if (last_size == 0 && data_total > 0) {
        last_size = BRIX_READ_CHUNK_MAX;
    }

    /*
     * Phase 32 WS2: keep the per-chunk headers in THIS slot's private header
     * buffer (slot->hdr_bytes), not the shared read_hdr_scratch, so a multi-chunk
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
    hdrbuf = ctx->out_ring[ctx->out_tail].hdr_bytes;

    ctx->resp_pipelinable = 1;

    for (chunk = 0; chunk < n_chunks; chunk++) {
        size_t        chunk_data;
        uint16_t      status;
        ngx_chain_t  *clh;
        ngx_buf_t    *bh;
        u_char       *hptr;

        /* Same frame layout as the memory path: full CHUNK_MAX per chunk
         * except the last (last_size); kXR_oksofar on every frame but the
         * final kXR_ok, all sharing ctx->cur_streamid. */
        chunk_data = (chunk < n_chunks - 1) ? BRIX_READ_CHUNK_MAX
                                            : last_size;
        status = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;
        hptr = hdrbuf + chunk * XRD_RESPONSE_HDR_LEN;

        brix_build_resp_hdr(ctx->cur_streamid, status,
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

            /*
             * in_file=1 is what makes nginx emit sendfile(2) for this link
             * instead of read()+write().  Every data link shares the SAME fd;
             * di walks the byte offset so chunk k covers fd bytes
             * [offset+di .. offset+di+chunk_data) — successive windows of one
             * open file, no per-chunk seek or copy.
             */
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
