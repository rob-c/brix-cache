#include "core/ngx_brix_module.h"
#include "core/aio/buffers_internal.h"   /* extern decls for the 3 cross-file helpers */

/*
 * buffers.c — memory-backed response-chain builders and the shared low-level
 * chain-assembly helpers, for synchronous read paths and nginx thread-pool AIO
 * completions.
 *
 * Split (phase-79 file-size cap) into three focused files:
 *   buffers.c          — this file: memory chains (single/window/chunked) plus
 *                        the geometry + link-append helpers shared with sendfile
 *   buffers_sendfile.c — file-backed sendfile chains + the pgread chain
 *   buffers_scratch.c  — pool/scratch/read-buffer lifecycle
 * The three geometry/append helpers below are non-static (declared in
 * buffers_internal.h) because the sendfile builders reuse them; everything else
 * here is file-local.
 */

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
 * HOW: 1) Acquires rd.read_hdr_scratch via brix_get_read_header_scratch.
 *      2) Calls brix_build_resp_hdr() to populate ServerResponseHdr with
 *         ctx->recv.cur_streamid, kXR_ok status, and data_total length.
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
    brix_resp_slot_t *slot = &ctx->out.ring[ctx->out.tail];
    /*
     * Header lives in THIS slot's private buffer (not the shared
     * rd.read_hdr_scratch), so pipelining the next memory read into another slot
     * cannot overwrite a still-draining response's 8-byte header.  This is what
     * makes the memory (userspace-TLS) read path safe to pipeline; the body
     * buffer is made per-in-flight by brix_acquire_read_buffer() in read.c.
     */
    u_char *hdrbuf = slot->hdr_bytes;

    (void) c;
    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok, (uint32_t) data_total,
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
    brix_resp_slot_t *slot = &ctx->out.ring[ctx->out.tail];
    u_char *hdrbuf;

    hdrbuf = BRIX_GET_SCRATCH(ctx, c, rd.read_hdr_scratch, rd.read_hdr_scratch_size,
                                XRD_RESPONSE_HDR_LEN);
    if (hdrbuf == NULL) {
        return NULL;
    }

    brix_build_resp_hdr(ctx->recv.cur_streamid, status, (uint32_t) data_total,
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
 * brix_chunk_geometry — compute the wire-frame count and final-frame size for
 * a multi-chunk read.
 *
 * WHAT: Writes *n_chunks_out = ceil(data_total / CHUNK_MAX) and *last_size_out =
 * the size of the FINAL frame, remapping an exact-multiple remainder of 0 back
 * to a full CHUNK_MAX. No return value.
 *
 * WHY: Both brix_build_chunked_chain and brix_build_sendfile_chain need the same
 * chunk-count arithmetic; centralising it keeps the two builders in lock-step and
 * removes the duplicated ceil-divide + remainder-remap decision points from each.
 * (Non-static: brix_build_sendfile_chain lives in buffers_sendfile.c — see
 * buffers_internal.h.)
 *
 * HOW: 1) n_chunks = (data_total + CHUNK_MAX - 1) / CHUNK_MAX (the +MAX-1 ceil
 *         trick); clamp 0 to 1 as defence-in-depth (unreachable when called after
 *         the data_total > CHUNK_MAX guard, but keeps the loop non-empty).
 *      2) last_size = data_total % CHUNK_MAX; a zero remainder with data_total > 0
 *         means the last frame must carry a full CHUNK_MAX, not zero bytes, so
 *         remap 0 back to CHUNK_MAX.
 */
void
brix_chunk_geometry(size_t data_total, size_t *n_chunks_out,
    size_t *last_size_out)
{
    size_t n_chunks;
    size_t last_size;

    n_chunks = (data_total + BRIX_READ_CHUNK_MAX - 1)
               / BRIX_READ_CHUNK_MAX;
    if (n_chunks == 0) {
        n_chunks = 1;
    }

    last_size = data_total % BRIX_READ_CHUNK_MAX;
    if (last_size == 0 && data_total > 0) {
        last_size = BRIX_READ_CHUNK_MAX;
    }

    *n_chunks_out = n_chunks;
    *last_size_out = last_size;
}

/*
 * brix_chain_link_push — append one already-populated chain link to a
 * head/tail-tracked singly linked list.
 *
 * WHAT: Terminates cl (cl->next = NULL), then links it as the new tail: sets
 * *head on the first push, otherwise splices onto (*tail)->next. Updates *tail.
 * No return value.
 *
 * WHY: The chunked and sendfile builders both grow their response chain link by
 * link; funnelling the head-first vs append-to-tail decision through one helper
 * keeps the two loop bodies flat and identical in ordering.
 *
 * HOW: 1) Null-terminate the new link. 2) If the list is empty (*head == NULL)
 *         it becomes the head; otherwise the current tail's next points at it.
 *      3) Advance *tail to the new link.
 */
static void
brix_chain_link_push(ngx_chain_t **head, ngx_chain_t **tail, ngx_chain_t *cl)
{
    cl->next = NULL;

    if (*head == NULL) {
        *head = cl;
    } else {
        (*tail)->next = cl;
    }

    *tail = cl;
}

/*
 * brix_chain_append_mem — allocate and append a memory-backed buffer link
 * spanning [pos, last).
 *
 * WHAT: Allocates one ngx_chain_t + ngx_buf_t from pool, points the buffer at
 * [pos, last) as memory/temporary, and appends it via brix_chain_link_push.
 * Returns NGX_OK, or NGX_ERROR if either allocation fails (list left unchanged).
 *
 * WHY: Every wire header link — and every data link on the memory (chunked) path
 * — is an identical memory-backed buffer; sharing one builder removes the
 * duplicated alloc + NULL-check + splice from both callers. (Non-static: the
 * sendfile builder in buffers_sendfile.c also appends the memory header links.)
 *
 * HOW: 1) Allocate the chain link and buffer; return NGX_ERROR on either NULL.
 *      2) Set pos/last and memory=temporary=1. 3) Attach the buffer and push the
 *         link onto the caller's head/tail list.
 */
ngx_int_t
brix_chain_append_mem(ngx_pool_t *pool, ngx_chain_t **head, ngx_chain_t **tail,
    u_char *pos, u_char *last)
{
    ngx_chain_t *cl;
    ngx_buf_t   *b;

    cl = ngx_alloc_chain_link(pool);
    b = ngx_calloc_buf(pool);
    if (cl == NULL || b == NULL) {
        return NGX_ERROR;
    }

    b->pos = pos;
    b->last = last;
    b->memory = 1;
    b->temporary = 1;

    cl->buf = b;
    brix_chain_link_push(head, tail, cl);
    return NGX_OK;
}

/*
 * brix_chain_append_file — allocate and append a file-backed (sendfile) buffer
 * link covering fd bytes [file_pos, file_last).
 *
 * WHAT: Allocates one ngx_chain_t + ngx_buf_t + ngx_file_t from pool, wires the
 * buffer to fd with in_file=1 over [file_pos, file_last), and appends it via
 * brix_chain_link_push. Returns NGX_OK, or NGX_ERROR if any allocation fails
 * (list left unchanged).
 *
 * WHY: in_file=1 is what makes nginx emit sendfile(2) for the link; every data
 * link on the multi-chunk sendfile path is the same shape referencing the SAME
 * fd at successive offsets, so it belongs in one builder. (Non-static: the
 * sendfile builder lives in buffers_sendfile.c — see buffers_internal.h.)
 *
 * HOW: 1) Allocate link, buffer, and ngx_file_t; return NGX_ERROR on any NULL.
 *      2) Populate the file (fd, name from path, log). 3) Point the buffer at the
 *         file with in_file=1 and the [file_pos, file_last) window. 4) Attach the
 *         buffer and push the link onto the caller's head/tail list.
 */
ngx_int_t
brix_chain_append_file(ngx_pool_t *pool, ngx_connection_t *c,
    ngx_chain_t **head, ngx_chain_t **tail, int fd, const char *path,
    off_t file_pos, off_t file_last)
{
    ngx_chain_t *cl;
    ngx_buf_t   *b;
    ngx_file_t  *file;

    cl = ngx_alloc_chain_link(pool);
    b = ngx_calloc_buf(pool);
    file = ngx_pcalloc(pool, sizeof(ngx_file_t));
    if (cl == NULL || b == NULL || file == NULL) {
        return NGX_ERROR;
    }

    file->fd = fd;
    file->name.data = (u_char *) path;
    file->name.len = path ? ngx_strlen(path) : 0;
    file->log = c->log;

    b->file = file;
    b->in_file = 1;
    b->file_pos = file_pos;
    b->file_last = file_last;

    cl->buf = b;
    brix_chain_link_push(head, tail, cl);
    return NGX_OK;
}

/*
 * brix_build_chunked_chain — build a multi-chunk memory chain for large
 * reads (data_total > BRIX_READ_CHUNK_MAX = 16 MiB).
 *
 * XRootD responses larger than 16 MiB must be split into multiple wire frames:
 *   [kXR_oksofar frame][data][kXR_oksofar frame][data]...[kXR_ok frame][data]
 *
 * Each header is written into a contiguous block in rd.read_hdr_scratch (avoiding
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
     * Chunk-count math (shared with brix_build_sendfile_chain via
     * brix_chunk_geometry): n_chunks = ceil(data_total / CHUNK_MAX); last_size =
     * size of the FINAL chunk, with a zero-remainder exact multiple remapped back
     * to CHUNK_MAX so the last frame carries the trailing bytes, never zero.
     */
    brix_chunk_geometry(data_total, &n_chunks, &last_size);

    /*
     * One contiguous scratch block holds all N wire headers back-to-back
     * (8 bytes each); each iteration writes into its own slice at
     * hdrbuf + chunk*XRD_RESPONSE_HDR_LEN, avoiding N separate allocations.
     */
    hdrbuf = BRIX_GET_SCRATCH(ctx, c, rd.read_hdr_scratch, rd.read_hdr_scratch_size,
                                n_chunks * XRD_RESPONSE_HDR_LEN);
    if (hdrbuf == NULL) {
        return NULL;
    }

    for (chunk = 0; chunk < n_chunks; chunk++) {
        size_t        chunk_data;
        uint16_t      status;
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

        brix_build_resp_hdr(ctx->recv.cur_streamid, status,
                              (uint32_t) chunk_data,
                              (ServerResponseHdr *) hptr);

        if (brix_chain_append_mem(c->pool, &head, &tail, hptr,
                                    hptr + XRD_RESPONSE_HDR_LEN) != NGX_OK)
        {
            return NULL;
        }

        if (chunk_data > 0) {
            /* di walks the data offset; each data link points straight into
             * databuf — zero copy from the AIO receive buffer to the wire. */
            if (brix_chain_append_mem(c->pool, &head, &tail, databuf + di,
                                        databuf + di + chunk_data) != NGX_OK)
            {
                return NULL;
            }
            di += chunk_data;
        }
    }

    if (tail != NULL) {
        tail->buf->last_buf = 1;
    }

    return head;
}
