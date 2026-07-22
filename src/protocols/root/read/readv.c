#include "read.h"
#include "fs/backend/sd.h"      /* phase-55: route preadv through the SD seam */
#include "core/compat/safe_size.h"   /* Phase 27 W1: overflow-checked size math */

#include "core/ngx_brix_module.h"
#include "protocols/root/connection/budget.h"
#include "prefetch.h"
#include "core/compat/range_vector.h"
#include "protocols/root/protocol/readv_seg.h"   /* shared kXR_readv segment-header codec */

#include <stdlib.h>
#include <sys/uio.h>

#define BRIX_MAX_READV_TOTAL  (256u * 1024u * 1024u)

/* The coalesced preadv I/O engine — brix_readv_read_segments() and its
 * file-local helpers — lives in the sibling readv_engine.c; the exported
 * prototype is declared in core/aio/aio.h. */

/* ---- File-local kXR_readv request working state ----
 *
 * WHAT: Bundles the per-request fields shared by brix_handle_readv's helper
 *   steps (config, wire view, segment count, per-element cap, and the two
 *   allocations once they exist).  Not a wire structure — purely in-process.
 *
 * WHY: The validate / build-descriptors / async-post / sync-execute steps each
 *   need most of these fields; threading one struct keeps helper parameter
 *   counts within the gate and makes the data flow explicit.
 *
 * HOW: The orchestrator zero-inits it, fills the constant fields, then hands a
 *   pointer to each step; steps that allocate (response_buffer, segment_descs)
 *   write back into the same struct.
 */
typedef struct {
    ngx_stream_brix_srv_conf_t *rconf;
    readahead_list               *wire_segments;
    size_t                        segment_count;
    size_t                        readv_seg_max;
    size_t                        max_response_bytes;
    u_char                       *response_buffer;
    brix_readv_seg_desc_t      *segment_descs;
} brix_readv_req_t;

/* ---- Validate handles and compute the response upper bound ----
 *
 * WHAT: First pass over the wire segments: validates every file handle and
 *   accumulates req->max_response_bytes (capping each element at readv_seg_max).
 *   Returns 1 on success; returns 0 and stores the terminating status in
 *   *rc_out on a bad handle or an over-limit total.
 *
 * WHY: Allocation must happen only after the whole request is known sane; this
 *   isolates the sanity pass from the buffer setup and keeps the error triplet
 *   (metric + send_error) at a single named step.
 *
 * HOW:
 *   1. For each segment decode the handle index and requested length.
 *   2. Reject an invalid handle via brix_validate_read_handle (sets *rc_out).
 *   3. Clamp the length to the per-element cap and add the framed size.
 *   4. Reject the request if the running total exceeds BRIX_MAX_READV_TOTAL.
 */
static ngx_flag_t
brix_readv_validate_and_size(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_readv_req_t *req, ngx_int_t *rc_out)
{
    size_t segment_index;

    req->max_response_bytes = 0;
    for (segment_index = 0; segment_index < req->segment_count;
         segment_index++)
    {
        int      handle_index;
        uint32_t read_length;
        ngx_int_t validate_rc;

        handle_index =
            (int) (unsigned char) req->wire_segments[segment_index].fhandle[0];
        read_length =
            (uint32_t) ntohl((uint32_t) req->wire_segments[segment_index].rlen);

        if (!brix_validate_read_handle(ctx, c, handle_index, "READV",
                                         BRIX_OP_READV, &validate_rc)) {
            *rc_out = validate_rc;
            return 0;
        }

        if ((size_t) read_length > req->readv_seg_max) {
            read_length = (uint32_t) req->readv_seg_max;
        }
        req->max_response_bytes += BRIX_READV_SEGSIZE + read_length;

        if (req->max_response_bytes > BRIX_MAX_READV_TOTAL) {
            BRIX_OP_ERR(ctx, BRIX_OP_READV);
            *rc_out = brix_send_error(ctx, c, kXR_ArgTooLong,
                                        "readv total would exceed server limit");
            return 0;
        }
    }

    return 1;
}

/* ---- Build the response wire body and the segment descriptor array ----
 *
 * WHAT: Lays out the final kXR_readv response body in req->response_buffer and
 *   fills req->segment_descs so each descriptor's payload pointer names the
 *   exact place preadv() will land that segment's bytes.  No return value; both
 *   buffers are pre-allocated by the orchestrator.
 *
 * WHY: The body layout and descriptor construction is a single pure pass with
 *   no I/O; isolating it keeps brix_handle_readv flat and the byte layout (the
 *   4-byte fhandle, 4-byte length, 8-byte offset header per segment) reviewable
 *   in one place.
 *
 * HOW:
 *   1. Walk a cursor over the response buffer, one framed segment at a time.
 *   2. For each segment write the fhandle, clamped big-endian length, and raw
 *      offset into the leading header, then record fd/obj/offset/length and the
 *      header/payload pointers into the descriptor.
 *   3. Advance the cursor past the header and clamped payload region.
 */
static void
brix_readv_build_descriptors(brix_ctx_t *ctx, brix_readv_req_t *req)
{
    u_char *response_cursor = req->response_buffer;
    size_t  segment_index;

    for (segment_index = 0; segment_index < req->segment_count;
         segment_index++)
    {
        int      handle_index;
        uint32_t read_length;
        uint32_t read_length_be;

        handle_index =
            (int) (unsigned char) req->wire_segments[segment_index].fhandle[0];
        read_length = (uint32_t) ntohl(
            (uint32_t) req->wire_segments[segment_index].rlen);

        if ((size_t) read_length > req->readv_seg_max) {
            read_length = (uint32_t) req->readv_seg_max;
        }

        ngx_memcpy(response_cursor,
                   req->wire_segments[segment_index].fhandle, 4);
        read_length_be = htonl(read_length);
        ngx_memcpy(response_cursor + 4, &read_length_be, 4);
        ngx_memcpy(response_cursor + 8,
                   &req->wire_segments[segment_index].offset, 8);

        req->segment_descs[segment_index].fd =
            ctx->files[handle_index].fd;
        req->segment_descs[segment_index].obj =
            ctx->files[handle_index].sd_obj;  /* Layer 3: driver or zeroed */
        req->segment_descs[segment_index].handle_index = handle_index;
        req->segment_descs[segment_index].offset = (off_t) (int64_t)
            be64toh((uint64_t) req->wire_segments[segment_index].offset);
        req->segment_descs[segment_index].read_length = read_length;
        req->segment_descs[segment_index].header_read_length_ptr =
            response_cursor + 4;
        req->segment_descs[segment_index].payload_ptr =
            response_cursor + BRIX_READV_SEGSIZE;

        response_cursor += BRIX_READV_SEGSIZE + read_length;
    }
}

/* ---- Try to offload the readv I/O onto the AIO thread pool ----
 *
 * WHAT: When a thread pool is configured, populates the reusable readv AIO task
 *   and posts it.  Returns 1 if the task was posted (the caller must return
 *   NGX_OK immediately); returns 0 to fall back to synchronous execution.  On an
 *   allocation failure it frees the descriptors + response buffer and returns 1
 *   with *rc_out = NGX_ERROR.
 *
 * WHY: The async offload is an optional fast path; separating it lets the
 *   orchestrator read as "post; else run synchronously" and keeps the task-setup
 *   fields in one place.
 *
 * HOW:
 *   1. No thread pool → return 0 (sync path).
 *   2. Reuse ctx->rd.readv_aio_task, allocating it on first use (free + return
 *      on OOM); otherwise reset its completion state.
 *   3. Fill the task context (connection, ctx, segments, buffer, stream id),
 *      bind the thread/done callbacks, and post it.
 *   4. Return 1 only when brix_aio_post_task reports it was actually posted.
 */
static ngx_flag_t
brix_readv_try_post_async(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_readv_req_t *req, ngx_int_t *rc_out)
{
    ngx_thread_task_t  *task;
    brix_readv_aio_t *t;
    ngx_flag_t          posted;

    if (req->rconf->common.thread_pool == NULL) {
        return 0;
    }

    task = ctx->rd.readv_aio_task;
    if (task == NULL) {
        task = ngx_thread_task_alloc(c->pool, sizeof(brix_readv_aio_t));
        if (task == NULL) {
            ngx_free(req->segment_descs);
            brix_release_read_buffer(ctx, c, req->response_buffer);
            *rc_out = NGX_ERROR;
            return 1;
        }
        ctx->rd.readv_aio_task = task;
    } else {
        task->next = NULL;
        task->event.complete = 0;
    }

    t = task->ctx;
    t->c = c;
    t->ctx = ctx;
    t->segment_count = req->segment_count;
    t->segments = req->segment_descs;
    t->response_buffer = req->response_buffer;
    t->bytes_read_total = 0;
    t->response_bytes = 0;
    t->io_error = 0;
    t->streamid[0] = ctx->recv.cur_streamid[0];
    t->streamid[1] = ctx->recv.cur_streamid[1];

    brix_task_bind(task, brix_readv_aio_thread, brix_readv_aio_done);

    (void) brix_aio_post_task(ctx, c, req->rconf->common.thread_pool, task,
                                "brix: thread_task_post failed, falling back to sync readv",
                                &posted);
    if (posted) {
        *rc_out = NGX_OK;
        return 1;
    }

    return 0;
}

/* ---- Run the readv I/O synchronously and send the assembled response ----
 *
 * WHAT: Executes the vectored read through the VFS I/O seam, updates per-handle
 *   and total byte counters, emits the access-log line, and queues the chunked
 *   response chain.  Returns the status to propagate to the dispatcher; on I/O
 *   error emits the READV error triplet with kXR_IOError.
 *
 * WHY: This is the fallback path (no thread pool, or post declined); isolating
 *   it keeps the orchestrator flat and puts all response-side side effects
 *   (byte accounting, logging, framing, send) behind one named step.
 *
 * HOW:
 *   1. Build a BRIX_VFS_IO_READV job over the descriptors and execute it.
 *   2. On I/O error free the buffers and send the kXR_IOError triplet.
 *   3. Add each segment's read_length to its handle's counter, then free descs.
 *   4. Log access when enabled, bump metrics/total bytes.
 *   5. Build the chunked chain and queue it, releasing the buffer on failure or
 *      when the connection is no longer sending.
 */
static ngx_int_t
brix_readv_execute_sync(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_readv_req_t *req)
{
    size_t         bytes_read_total = 0;
    size_t         response_bytes;
    size_t         segment_index;
    ngx_chain_t   *rsp_chain;
    char           error_message[128];
    brix_vfs_job_t job;

    error_message[0] = '\0';
    ngx_memzero(&job, sizeof(job));
    job.op = BRIX_VFS_IO_READV;
    job.segs = req->segment_descs;
    job.nsegs = req->segment_count;
    job.err_msg = error_message;
    job.err_msg_cap = sizeof(error_message);

    brix_vfs_io_execute(&job);

    if (job.io_errno != 0) {
        ngx_free(req->segment_descs);
        brix_release_read_buffer(ctx, c, req->response_buffer);
        BRIX_OP_ERR(ctx, BRIX_OP_READV);
        return brix_send_error(ctx, c, kXR_IOError,
                                 error_message[0] ? error_message
                                                   : "readv I/O error");
    }

    bytes_read_total = (size_t) job.nio;
    response_bytes = job.out_size;

    for (segment_index = 0; segment_index < req->segment_count;
         segment_index++)
    {
        ctx->files[req->segment_descs[segment_index].handle_index].bytes_read +=
            req->segment_descs[segment_index].read_length;
    }
    ngx_free(req->segment_descs);

    if (req->rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];

        snprintf(detail, sizeof(detail), "%zu_segs", req->segment_count);
        brix_log_access(ctx, c, "READV", "-", detail, 1, 0, NULL,
                          bytes_read_total);
    }
    BRIX_OP_OK(ctx, BRIX_OP_READV);
    ctx->totals.bytes += bytes_read_total;

    rsp_chain = brix_build_chunked_chain(ctx, c, req->response_buffer,
                                           response_bytes);
    if (rsp_chain == NULL) {
        brix_release_read_buffer(ctx, c, req->response_buffer);
        return NGX_ERROR;
    }

    {
        ngx_int_t rc = brix_queue_response_chain(ctx, c, rsp_chain,
                                                   req->response_buffer);

        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            brix_release_read_buffer(ctx, c, req->response_buffer);
        }
        return rc;
    }
}

/* Handle kXR_readv — validate the request (payload a multiple of the readv
 * element size, segment lengths within bounds), read all segments, and assemble
 * the chained response. */
ngx_int_t
brix_handle_readv(brix_ctx_t *ctx, ngx_connection_t *c)
{
    /* phase-42 W4 invariant: readv is ALWAYS plaintext — it never consults
     * read_codec.  Inline read compression applies only to single-segment
     * kXR_read; readv's interleaved per-segment framing (and its pgread-style
     * integrity expectations) stay byte-for-byte intact. */
    brix_readv_req_t req;
    ngx_int_t        rc;

    ngx_memzero(&req, sizeof(req));

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0 ||
        (ctx->recv.cur_dlen % BRIX_READV_SEGSIZE) != 0)
    {
        BRIX_OP_ERR(ctx, BRIX_OP_READV);
        return brix_send_error(ctx, c, kXR_ArgInvalid,
                                 "malformed readv request");
    }

    req.wire_segments = (readahead_list *) ctx->recv.payload;
    req.segment_count = ctx->recv.cur_dlen / BRIX_READV_SEGSIZE;

    /* Phase 27 W2/F1: explicit segment-count cap at the callsite (defense in
     * depth over the recv-layer payload cap). */
    if (req.segment_count == 0 || req.segment_count > BRIX_READV_MAXSEGS) {
        BRIX_OP_ERR(ctx, BRIX_OP_READV);
        return brix_send_error(ctx, c, kXR_ArgTooLong,
                                 "readv segment count exceeds server limit");
    }

    req.rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

    /* Per-element read cap = the configured readv segment size (official
     * maxReadv_ior, advertised via Qconfig readv_ior_max).  An element requesting
     * more is served SHORT (capped): our native client reads each segment's
     * actual returned length (see test_readv_variable_blocks).  Well-behaved
     * clients honour the advertised readv_ior_max and never request more; a
     * client that ignores it and cannot handle a short element (e.g. XrdCl's
     * VectorRead) must therefore size its elements within the cap. */
    req.readv_seg_max = req.rconf->readv_segment_size;

    /*
     * First pass validates every file handle and computes the upper bound for
     * the single response scratch buffer.  Allocation happens only after the
     * whole request is known to be sane.
     */
    if (!brix_readv_validate_and_size(ctx, c, &req, &rc)) {
        return rc;
    }

    brix_prefetch_readv_segments(ctx, c, req.wire_segments, req.segment_count,
                                   req.readv_seg_max);

    /*
     * Phase 31 W4: kXR_readv assembles its whole response (up to
     * BRIX_MAX_READV_TOTAL = 256 MiB) in rd.read_scratch.  Admit it against the
     * SHM-global transfer budget so a burst of large readv requests cannot blow
     * the memory cap; over budget, defer with kXR_wait and let the client
     * re-issue.  (readv is not yet windowed like kXR_read — a single large readv
     * still allocates its full response; the budget bounds the aggregate.)
     */
    if (!brix_budget_admit(ctx, req.rconf->memory_budget,
                             req.max_response_bytes)) {
        return brix_send_wait(ctx, c, 1);
    }

    req.response_buffer = BRIX_GET_SCRATCH(ctx, c, rd.read_scratch,
                                             rd.read_scratch_size,
                                             req.max_response_bytes);
    if (req.response_buffer == NULL) {
        return NGX_ERROR;
    }

    /* Charge the assembled-response footprint to the budget promptly. */
    brix_budget_sync(ctx);

    req.segment_descs = brix_alloc_array(c->log, req.segment_count,
                                           sizeof(brix_readv_seg_desc_t));
    if (req.segment_descs == NULL) {
        brix_release_read_buffer(ctx, c, req.response_buffer);
        return NGX_ERROR;
    }

    /*
     * Build the final wire body up front.  The descriptor payload pointers are
     * the exact places where preadv() will land each segment's bytes.
     */
    brix_readv_build_descriptors(ctx, &req);

    /* Prefer the AIO offload; on a successful post the response completes in the
     * done callback and we return its status directly. */
    if (brix_readv_try_post_async(ctx, c, &req, &rc)) {
        return rc;
    }

    /* No thread pool, or the post declined — read synchronously and reply. */
    return brix_readv_execute_sync(ctx, c, &req);
}
