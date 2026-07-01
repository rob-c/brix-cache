#include "read.h"
#include "../fs/backend/sd.h"      /* phase-55: route preadv through the SD seam */
#include "../shared/safe_size.h"   /* Phase 27 W1: overflow-checked size math */

#include "../ngx_xrootd_module.h"
#include "../connection/budget.h"
#include "prefetch.h"
#include "../compat/range_vector.h"
#include "../protocol/readv_seg.h"   /* shared kXR_readv segment-header codec */

#include <stdlib.h>
#include <sys/uio.h>

#define XROOTD_MAX_READV_TOTAL  (256u * 1024u * 1024u)
#define XROOTD_READV_PREADV_MAXIOV  64

/* Perform the readv I/O: coalesce contiguous same-fd segments into grouped
 * preadv calls (preserving on-wire order) and fill each segment's buffer.
 * Returns NGX_OK, or NGX_ERROR with the kXR error set. */
ngx_int_t
xrootd_readv_read_segments(xrootd_readv_seg_desc_t *segments,
    size_t segment_count, size_t *bytes_read_total, char *error_message,
    size_t error_message_len)
{
    struct iovec         iov[XROOTD_READV_PREADV_MAXIOV];
    xrootd_byte_range_t *ranges;
    size_t               segment_index;
    size_t               i;

    if (bytes_read_total == NULL) {
        return NGX_ERROR;
    }

    *bytes_read_total = 0;

    /* Phase 27 W1/F1: defense-in-depth — bound the segment count and use an
     * overflow-checked multiply for the array size (segment_count is derived
     * from the wire dlen and capped at recv time, but this guards a bypass). */
    {
        size_t ranges_sz;
        if (segment_count == 0 || segment_count > XROOTD_READV_MAXSEGS
            || xrootd_size_mul(segment_count, sizeof(*ranges), &ranges_sz)
               != NGX_OK)
        {
            snprintf(error_message, error_message_len,
                     "readv: segment count out of range");
            return NGX_ERROR;
        }
        ranges = malloc(ranges_sz);
    }
    if (ranges == NULL) {
        snprintf(error_message, error_message_len, "readv: out of memory");
        return NGX_ERROR;
    }

    /*
     * Validate all segments upfront and build the xrootd_byte_range_t array
     * used by the shared coalescer.  Overflow and negative-offset errors are
     * caught here before any I/O.
     */
    for (i = 0; i < segment_count; i++) {
        if (segments[i].offset < 0) {
            snprintf(error_message, error_message_len,
                     "negative readv offset at seg %zu", i);
            free(ranges);
            return NGX_ERROR;
        }
        if (segments[i].read_length > 0
            && (off_t) segments[i].read_length
               > NGX_MAX_OFF_T_VALUE - segments[i].offset)
        {
            snprintf(error_message, error_message_len,
                     "readv offset overflow at seg %zu", i);
            free(ranges);
            return NGX_ERROR;
        }
        ranges[i].fd     = segments[i].fd;
        ranges[i].start  = segments[i].offset;
        ranges[i].end    = (segments[i].read_length > 0)
                           ? segments[i].offset
                             + (off_t) segments[i].read_length - 1
                           : segments[i].offset - 1; /* degenerate, no coalescing */
        ranges[i].handle = 0;
    }

    for (segment_index = 0; segment_index < segment_count; ) {
        xrootd_readv_seg_desc_t *first_segment = &segments[segment_index];
        ngx_uint_t               run_count;
        size_t                   run_bytes;
        ngx_uint_t               k;
        ssize_t                  bytes_read;
        uint32_t                 rlen_be;

        /* Write actual read length back to the wire header. */
        rlen_be = htonl(first_segment->read_length);
        ngx_memcpy(first_segment->header_read_length_ptr, &rlen_be, 4);

        if (first_segment->read_length == 0) {
            segment_index++;
            continue;
        }

        /*
         * Delegate the contiguous-run decision to the shared coalescer.
         * The coalescer checks fd equality and byte adjacency using the
         * ranges array built above.
         */
        run_count = xrootd_range_vector_next_coalesced_run(
            ranges, (ngx_uint_t) segment_count,
            (ngx_uint_t) segment_index,
            (ngx_uint_t) XROOTD_READV_PREADV_MAXIOV);

        /* Assemble the preadv iovec from the original segment descriptors. */
        run_bytes = 0;
        for (k = 0; k < run_count; k++) {
            iov[k].iov_base = segments[segment_index + k].payload_ptr;
            iov[k].iov_len  = (size_t) segments[segment_index + k].read_length;
            run_bytes      += (size_t) segments[segment_index + k].read_length;
        }

        {
            xrootd_sd_obj_t  scratch;
            xrootd_sd_obj_t *obj;

            /* Route the coalesced vectored read through the Storage Driver seam:
             * the handle's bound driver object when set (block-striped/object
             * backend), else a POSIX wrap of the fd (unchanged). The EINTR /
             * coalescing policy stays here. */
            obj = xrootd_vfs_effective_obj(&first_segment->obj,
                                           first_segment->fd, &scratch);
            do {
                bytes_read = obj->driver->preadv(
                    obj, iov, (int) run_count, first_segment->offset);
            } while (bytes_read < 0 && errno == EINTR);
        }

        if (bytes_read < 0) {
            snprintf(error_message, error_message_len,
                     "readv I/O error at seg %zu: %s",
                     segment_index, strerror(errno));
            free(ranges);
            return NGX_ERROR;
        }

        if ((size_t) bytes_read != run_bytes) {
            snprintf(error_message, error_message_len,
                     "readv past EOF at seg %zu", segment_index);
            free(ranges);
            return NGX_ERROR;
        }

        *bytes_read_total += run_bytes;
        segment_index     += run_count;
    }

    free(ranges);
    return NGX_OK;
}

/* Handle kXR_readv — validate the request (payload a multiple of the readv
 * element size, segment lengths within bounds), read all segments, and assemble
 * the chained response. */
ngx_int_t
xrootd_handle_readv(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    /* phase-42 W4 invariant: readv is ALWAYS plaintext — it never consults
     * read_codec.  Inline read compression applies only to single-segment
     * kXR_read; readv's interleaved per-segment framing (and its pgread-style
     * integrity expectations) stay byte-for-byte intact. */
    ngx_stream_xrootd_srv_conf_t *rconf;
    size_t                          readv_seg_max;
    readahead_list                 *wire_segments;
    size_t                          segment_count;
    size_t                          segment_index;
    u_char                         *response_buffer;
    size_t                          max_response_bytes;
    xrootd_readv_seg_desc_t        *segment_descs;

    if (ctx->payload == NULL || ctx->cur_dlen == 0 ||
        (ctx->cur_dlen % XROOTD_READV_SEGSIZE) != 0)
    {
        XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "malformed readv request");
    }

    wire_segments = (readahead_list *) ctx->payload;
    segment_count = ctx->cur_dlen / XROOTD_READV_SEGSIZE;

    /* Phase 27 W2/F1: explicit segment-count cap at the callsite (defense in
     * depth over the recv-layer payload cap). */
    if (segment_count == 0 || segment_count > XROOTD_READV_MAXSEGS) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
        return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                 "readv segment count exceeds server limit");
    }

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);

    /* Per-element read cap = the configured readv segment size (official
     * maxReadv_ior, advertised via Qconfig readv_ior_max).  An element requesting
     * more is served SHORT (capped): our native client reads each segment's
     * actual returned length (see test_readv_variable_blocks).  Well-behaved
     * clients honour the advertised readv_ior_max and never request more; a
     * client that ignores it and cannot handle a short element (e.g. XrdCl's
     * VectorRead) must therefore size its elements within the cap. */
    readv_seg_max = rconf->readv_segment_size;

    /*
     * First pass validates every file handle and computes the upper bound for
     * the single response scratch buffer.  Allocation happens only after the
     * whole request is known to be sane.
     */
    max_response_bytes = 0;
    for (segment_index = 0; segment_index < segment_count; segment_index++) {
        int      handle_index;
        uint32_t read_length;
        ngx_int_t validate_rc;

        handle_index =
            (int) (unsigned char) wire_segments[segment_index].fhandle[0];
        read_length =
            (uint32_t) ntohl((uint32_t) wire_segments[segment_index].rlen);

        if (!xrootd_validate_read_handle(ctx, c, handle_index, "READV",
                                         XROOTD_OP_READV, &validate_rc)) {
            return validate_rc;
        }

        if ((size_t) read_length > readv_seg_max) {
            read_length = (uint32_t) readv_seg_max;
        }
        max_response_bytes += XROOTD_READV_SEGSIZE + read_length;

        if (max_response_bytes > XROOTD_MAX_READV_TOTAL) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
            return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                     "readv total would exceed server limit");
        }
    }

    xrootd_prefetch_readv_segments(ctx, c, wire_segments, segment_count,
                                   readv_seg_max);

    /*
     * Phase 31 W4: kXR_readv assembles its whole response (up to
     * XROOTD_MAX_READV_TOTAL = 256 MiB) in read_scratch.  Admit it against the
     * SHM-global transfer budget so a burst of large readv requests cannot blow
     * the memory cap; over budget, defer with kXR_wait and let the client
     * re-issue.  (readv is not yet windowed like kXR_read — a single large readv
     * still allocates its full response; the budget bounds the aggregate.)
     */
    if (!xrootd_budget_admit(ctx, rconf->memory_budget, max_response_bytes)) {
        return xrootd_send_wait(ctx, c, 1);
    }

    response_buffer = XROOTD_GET_SCRATCH(ctx, c, read_scratch,
                                         read_scratch_size, max_response_bytes);
    if (response_buffer == NULL) {
        return NGX_ERROR;
    }

    /* Charge the assembled-response footprint to the budget promptly. */
    xrootd_budget_sync(ctx);

    segment_descs = xrootd_alloc_array(c->log, segment_count,
                                       sizeof(xrootd_readv_seg_desc_t));
    if (segment_descs == NULL) {
        xrootd_release_read_buffer(ctx, c, response_buffer);
        return NGX_ERROR;
    }

    {
        u_char *response_cursor = response_buffer;

        /*
         * Build the final wire body up front.  The descriptor payload pointers
         * are the exact places where preadv() will land each segment's bytes.
         */
        for (segment_index = 0; segment_index < segment_count;
             segment_index++)
        {
            int      handle_index;
            uint32_t read_length;
            uint32_t read_length_be;

            handle_index =
                (int) (unsigned char) wire_segments[segment_index].fhandle[0];
            read_length = (uint32_t) ntohl(
                (uint32_t) wire_segments[segment_index].rlen);

            if ((size_t) read_length > readv_seg_max) {
                read_length = (uint32_t) readv_seg_max;
            }

            ngx_memcpy(response_cursor, wire_segments[segment_index].fhandle,
                       4);
            read_length_be = htonl(read_length);
            ngx_memcpy(response_cursor + 4, &read_length_be, 4);
            ngx_memcpy(response_cursor + 8,
                       &wire_segments[segment_index].offset, 8);

            segment_descs[segment_index].fd =
                ctx->files[handle_index].fd;
            segment_descs[segment_index].obj =
                ctx->files[handle_index].sd_obj;  /* Layer 3: driver or zeroed */
            segment_descs[segment_index].handle_index = handle_index;
            segment_descs[segment_index].offset = (off_t) (int64_t)
                be64toh((uint64_t) wire_segments[segment_index].offset);
            segment_descs[segment_index].read_length = read_length;
            segment_descs[segment_index].header_read_length_ptr =
                response_cursor + 4;
            segment_descs[segment_index].payload_ptr =
                response_cursor + XROOTD_READV_SEGSIZE;

            response_cursor += XROOTD_READV_SEGSIZE + read_length;
        }
    }

    {
        if (rconf->common.thread_pool != NULL) {
            ngx_thread_task_t       *task;
            xrootd_readv_aio_t      *t;
            ngx_flag_t               posted;

            task = ctx->readv_aio_task;
            if (task == NULL) {
                task = ngx_thread_task_alloc(c->pool,
                                             sizeof(xrootd_readv_aio_t));
                if (task == NULL) {
                    ngx_free(segment_descs);
                    xrootd_release_read_buffer(ctx, c, response_buffer);
                    return NGX_ERROR;
                }
                ctx->readv_aio_task = task;
            } else {
                task->next = NULL;
                task->event.complete = 0;
            }

            t = task->ctx;
            t->c = c;
            t->ctx = ctx;
            t->segment_count = segment_count;
            t->segments = segment_descs;
            t->response_buffer = response_buffer;
            t->bytes_read_total = 0;
            t->response_bytes = 0;
            t->io_error = 0;
            t->streamid[0] = ctx->cur_streamid[0];
            t->streamid[1] = ctx->cur_streamid[1];

            xrootd_task_bind(task, xrootd_readv_aio_thread, xrootd_readv_aio_done);

            (void) xrootd_aio_post_task(ctx, c, rconf->common.thread_pool, task,
                                        "xrootd: thread_task_post failed, falling back to sync readv",
                                        &posted);
            if (posted) {
                return NGX_OK;
            }
        }
    }

    {
        size_t       bytes_read_total = 0;
        size_t       response_bytes;
        ngx_chain_t *rsp_chain;
        char         error_message[128];
        xrootd_vfs_job_t job;

        error_message[0] = '\0';
        ngx_memzero(&job, sizeof(job));
        job.op = XROOTD_VFS_IO_READV;
        job.segs = segment_descs;
        job.nsegs = segment_count;
        job.err_msg = error_message;
        job.err_msg_cap = sizeof(error_message);

        xrootd_vfs_io_execute(&job);

        if (job.io_errno != 0) {
            ngx_free(segment_descs);
            xrootd_release_read_buffer(ctx, c, response_buffer);
            XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     error_message[0] ? error_message
                                                       : "readv I/O error");
        }

        bytes_read_total = (size_t) job.nio;
        response_bytes = job.out_size;

        for (segment_index = 0; segment_index < segment_count;
             segment_index++)
        {
            ctx->files[segment_descs[segment_index].handle_index].bytes_read +=
                segment_descs[segment_index].read_length;
        }
        ngx_free(segment_descs);

        if (rconf->access_log_fd != NGX_INVALID_FILE) {
            char detail[64];

            snprintf(detail, sizeof(detail), "%zu_segs", segment_count);
            xrootd_log_access(ctx, c, "READV", "-", detail, 1, 0, NULL,
                              bytes_read_total);
        }
        XROOTD_OP_OK(ctx, XROOTD_OP_READV);
        ctx->session_bytes += bytes_read_total;

        rsp_chain = xrootd_build_chunked_chain(ctx, c, response_buffer,
                                               response_bytes);
        if (rsp_chain == NULL) {
            xrootd_release_read_buffer(ctx, c, response_buffer);
            return NGX_ERROR;
        }

        {
            ngx_int_t rc = xrootd_queue_response_chain(ctx, c, rsp_chain,
                                                       response_buffer);

            if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
                xrootd_release_read_buffer(ctx, c, response_buffer);
            }
            return rc;
        }
    }
}
