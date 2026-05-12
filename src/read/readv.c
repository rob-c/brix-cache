#include "read.h"

#include "../ngx_xrootd_module.h"
#include "prefetch.h"

#include <sys/uio.h>

#define XROOTD_MAX_READV_TOTAL  (256u * 1024u * 1024u)
#define XROOTD_READV_PREADV_MAXIOV  64

ngx_int_t
xrootd_readv_read_segments(xrootd_readv_seg_desc_t *segments,
    size_t segment_count, size_t *bytes_read_total, char *error_message,
    size_t error_message_len)
{
    struct iovec iov[XROOTD_READV_PREADV_MAXIOV];
    size_t       segment_index;

    if (bytes_read_total == NULL) {
        return NGX_ERROR;
    }

    *bytes_read_total = 0;

    for (segment_index = 0; segment_index < segment_count; ) {
        xrootd_readv_seg_desc_t *first_segment;
        uint32_t                 read_length_be;
        size_t                   run_iov_count;
        size_t                   run_bytes;
        off_t                    run_offset;
        off_t                    run_end;
        ssize_t                  bytes_read;

        first_segment = &segments[segment_index];

        read_length_be = htonl(first_segment->read_length);
        ngx_memcpy(first_segment->header_read_length_ptr, &read_length_be, 4);

        if (first_segment->read_length == 0) {
            segment_index++;
            continue;
        }

        if (first_segment->offset < 0) {
            snprintf(error_message, error_message_len,
                     "negative readv offset at seg %zu", segment_index);
            return NGX_ERROR;
        }

        run_iov_count = 0;
        run_bytes = 0;
        run_offset = first_segment->offset;
        run_end = first_segment->offset;

        /*
         * Coalesce only contiguous ranges from the same open fd.  That keeps
         * the on-wire segment order unchanged while reducing syscall count for
         * ROOT clients that issue adjacent readv slices.
         */
        while (segment_index + run_iov_count < segment_count
               && run_iov_count < XROOTD_READV_PREADV_MAXIOV)
        {
            xrootd_readv_seg_desc_t *current_segment;
            off_t                    current_end;

            current_segment = &segments[segment_index + run_iov_count];

            if (current_segment->read_length == 0) {
                if (run_iov_count == 0) {
                    break;
                }
                break;
            }

            if (current_segment->fd != first_segment->fd
                || current_segment->offset != run_end
                || current_segment->offset < 0)
            {
                break;
            }

            if ((off_t) current_segment->read_length
                > NGX_MAX_OFF_T_VALUE - current_segment->offset)
            {
                snprintf(error_message, error_message_len,
                         "readv offset overflow at seg %zu",
                         segment_index + run_iov_count);
                return NGX_ERROR;
            }

            current_end = current_segment->offset
                          + (off_t) current_segment->read_length;
            iov[run_iov_count].iov_base = current_segment->payload_ptr;
            iov[run_iov_count].iov_len =
                (size_t) current_segment->read_length;
            run_bytes += (size_t) current_segment->read_length;
            run_end = current_end;
            run_iov_count++;
        }

        if (run_iov_count == 0) {
            continue;
        }

        do {
            bytes_read = preadv(first_segment->fd, iov,
                                (int) run_iov_count, run_offset);
        } while (bytes_read < 0 && errno == EINTR);

        if (bytes_read < 0) {
            snprintf(error_message, error_message_len,
                     "readv I/O error at seg %zu: %s",
                     segment_index, strerror(errno));
            return NGX_ERROR;
        }

        if ((size_t) bytes_read != run_bytes) {
            snprintf(error_message, error_message_len,
                     "readv past EOF at seg %zu", segment_index);
            return NGX_ERROR;
        }

        *bytes_read_total += run_bytes;
        segment_index += run_iov_count;
    }

    return NGX_OK;
}


ngx_int_t
xrootd_handle_readv(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_xrootd_srv_conf_t *rconf;
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

        if (read_length > XROOTD_READ_MAX) {
            read_length = XROOTD_READ_MAX;
        }
        max_response_bytes += XROOTD_READV_SEGSIZE + read_length;

        if (max_response_bytes > XROOTD_MAX_READV_TOTAL) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
            return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                     "readv total would exceed server limit");
        }
    }

    xrootd_prefetch_readv_segments(ctx, c, wire_segments, segment_count);

    rconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);

    response_buffer = xrootd_get_read_scratch(ctx, c, max_response_bytes);
    if (response_buffer == NULL) {
        return NGX_ERROR;
    }

    segment_descs = ngx_alloc(segment_count * sizeof(xrootd_readv_seg_desc_t),
                              c->log);
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

            if (read_length > XROOTD_READ_MAX) {
                read_length = XROOTD_READ_MAX;
            }

            ngx_memcpy(response_cursor, wire_segments[segment_index].fhandle,
                       4);
            read_length_be = htonl(read_length);
            ngx_memcpy(response_cursor + 4, &read_length_be, 4);
            ngx_memcpy(response_cursor + 8,
                       &wire_segments[segment_index].offset, 8);

            segment_descs[segment_index].fd =
                ctx->files[handle_index].fd;
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

#if (NGX_THREADS)
    {
        if (rconf->thread_pool != NULL) {
            ngx_thread_task_t       *task;
            xrootd_readv_aio_t      *t;
            ngx_flag_t               posted;

            task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_readv_aio_t));
            if (task == NULL) {
                ngx_free(segment_descs);
                xrootd_release_read_buffer(ctx, c, response_buffer);
                return NGX_ERROR;
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

            task->handler = xrootd_readv_aio_thread;
            task->event.handler = xrootd_readv_aio_done;
            task->event.data = task;

            (void) xrootd_aio_post_task(ctx, c, rconf->thread_pool, task,
                                        "xrootd: thread_task_post failed, falling back to sync readv",
                                        &posted);
            if (posted) {
                return NGX_OK;
            }
        }
    }
#endif

    {
        size_t       bytes_read_total = 0;
        size_t       response_bytes;
        ngx_chain_t *rsp_chain;
        char         error_message[128];

        error_message[0] = '\0';
        if (xrootd_readv_read_segments(segment_descs, segment_count,
                                       &bytes_read_total, error_message,
                                       sizeof(error_message)) != NGX_OK)
        {
            ngx_free(segment_descs);
            xrootd_release_read_buffer(ctx, c, response_buffer);
            XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     error_message[0] ? error_message
                                                       : "readv I/O error");
        }

        response_bytes = segment_count * XROOTD_READV_SEGSIZE
                         + bytes_read_total;

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
