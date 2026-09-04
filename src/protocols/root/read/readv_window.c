/*
 * readv_window.c — bounded-resident kXR_readv response streaming.
 *
 * The protocol's logical body is [16-byte segment header][segment bytes] for
 * every returned range.  Stock XrdCl matches each returned header against the
 * exact requested offset and length, so neither a range nor its header may be
 * split into extra protocol records.  We instead advertise the complete body
 * length once, then produce its bytes through a reusable bounded window.
 */
#include "read.h"
#include "protocols/root/connection/budget.h"
#include "protocols/root/connection/write_helpers.h"
#include "protocols/root/protocol/readv_seg.h"

static readahead_list *
readv_window_wire(brix_ctx_t *ctx)
{
    return (readahead_list *) ctx->rd.win_readv_wire;
}

/* Select the indexed segment as the shared window pump's current file/range. */
static void
readv_window_select(brix_ctx_t *ctx, size_t length)
{
    readahead_list *wire = readv_window_wire(ctx);
    readahead_list *seg = &wire[ctx->rd.win_readv_index];
    int             idx = (int) (unsigned char) seg->fhandle[0];

    ctx->rd.win_idx = idx;
    ctx->rd.win_fd = ctx->files[idx].fd;
    ctx->rd.win_offset = (off_t) (int64_t)
        be64toh((uint64_t) seg->offset);
    ctx->rd.win_remaining = length;
}

void
brix_readv_window_sizes(brix_ctx_t *ctx, size_t *want,
    size_t *scratch_need)
{
    size_t prefix = ctx->rd.win_readv_seg_started
                    ? 0 : BRIX_READV_SEGSIZE;
    size_t capacity = (size_t) BRIX_READ_WINDOW - prefix;

    *want = ctx->rd.win_remaining < capacity
            ? ctx->rd.win_remaining : capacity;
    *scratch_need = prefix + *want;
}

u_char *
brix_readv_window_payload(brix_ctx_t *ctx, u_char *scratch)
{
    readahead_list *wire;
    uint32_t        length_be;
    uint64_t        offset_be;
    size_t          want;
    size_t          scratch_need;

    brix_readv_window_sizes(ctx, &want, &scratch_need);
    if (ctx->rd.win_readv_seg_started) {
        return scratch;
    }

    wire = readv_window_wire(ctx);
    ngx_memcpy(scratch, wire[ctx->rd.win_readv_index].fhandle, 4);
    length_be = htonl((uint32_t) ctx->rd.win_remaining);
    offset_be = htobe64((uint64_t) (int64_t) ctx->rd.win_offset);
    ngx_memcpy(scratch + 4, &length_be, 4);
    ngx_memcpy(scratch + 8, &offset_be, 8);
    return scratch + BRIX_READV_SEGSIZE;
}

static void
readv_window_finish(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf)
{
    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char detail[64];

        snprintf(detail, sizeof(detail), "%zu_segs",
                 ctx->rd.win_readv_count);
        brix_log_access(ctx, c, "READV", "-", detail, 1, 0, NULL,
                          ctx->rd.win_readv_total);
    }
    ctx->rd.win_active = 0;
    ctx->rd.win_readv = 0;
    ctx->rd.win_readv_started = 0;
    ctx->rd.win_readv_seg_started = 0;
    ctx->rd.win_readv_wire = NULL;
    BRIX_OP_OK(ctx, BRIX_OP_READV);
}

static ngx_int_t
readv_window_fail(brix_ctx_t *ctx, ngx_connection_t *c, const char *message)
{
    ngx_flag_t started = ctx->rd.win_readv_started;

    ctx->rd.win_active = 0;
    ctx->rd.win_readv = 0;
    ctx->rd.win_readv_started = 0;
    ctx->rd.win_readv_seg_started = 0;
    ctx->rd.win_readv_wire = NULL;
    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;
    BRIX_OP_ERR(ctx, BRIX_OP_READV);
    if (started) {
        /* A response header has already promised the remaining raw body.  A
         * framed error here would be consumed as file data and desynchronise
         * the connection, so force the normal disconnect funnel instead. */
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "brix: readv body stream aborted: %s", message);
        c->close = 1;
        return NGX_ERROR;
    }
    return brix_send_error_sid(ctx, c, ctx->rd.win_streamid, kXR_IOError,
                                 message);
}

static ngx_flag_t
readv_window_advance(brix_ctx_t *ctx)
{
    ctx->rd.win_readv_index++;
    if (ctx->rd.win_readv_index >= ctx->rd.win_readv_count) {
        return 0;
    }

    return 1;
}

ngx_int_t
brix_readv_window_emit(brix_ctx_t *ctx, ngx_connection_t *c,
    ssize_t nread, int io_errno)
{
    ngx_stream_session_t         *session = c->data;
    ngx_stream_brix_srv_conf_t *rconf;
    ngx_chain_t                  *chain;
    size_t                        prefix;
    size_t                        want;
    size_t                        got;
    ngx_flag_t                    first;

    rconf = ngx_stream_get_module_srv_conf(session, ngx_stream_brix_module);
    brix_readv_window_sizes(ctx, &want, &prefix);
    prefix -= want;

    if (nread < 0 || (size_t) nread != want) {
        const char *message = nread < 0 && io_errno != 0
                              ? strerror(io_errno) : "readv past EOF";
        return readv_window_fail(ctx, c, message);
    }

    got = (size_t) nread;
    ctx->files[ctx->rd.win_idx].bytes_read += got;
    ctx->totals.bytes += got;
    ctx->rd.win_readv_total += got;
    ctx->rd.win_offset += (off_t) got;
    ctx->rd.win_remaining -= got;
    first = !ctx->rd.win_readv_started;
    ctx->rd.win_readv_seg_started = 1;

    if (ctx->rd.win_remaining == 0) {
        size_t segment_cap = rconf->readv_segment_size;

        if (readv_window_advance(ctx)) {
            /* Decode and clamp the next segment now; the next pump iteration
             * can therefore select a different handle safely. */
            size_t length;
            readahead_list *wire = readv_window_wire(ctx);

            length = (size_t) ntohl(
                (uint32_t) wire[ctx->rd.win_readv_index].rlen);
            if (length > segment_cap) {
                length = segment_cap;
            }
            readv_window_select(ctx, length);
            ctx->rd.win_readv_seg_started = 0;
        }
    }

    chain = brix_build_body_fragment_chain(ctx, c, ctx->rd.read_scratch,
                                              prefix + got,
                                              ctx->rd.win_readv_body_size,
                                              first);
    if (chain == NULL) {
        return readv_window_fail(ctx, c, "readv response framing failed");
    }
    ctx->rd.win_readv_started = 1;
    if (ctx->rd.win_readv_index >= ctx->rd.win_readv_count) {
        readv_window_finish(ctx, c, rconf);
    }

    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.hdr_pos = 0;
    if (first) {
        brix_queue_response_chain(ctx, c, chain, ctx->rd.read_scratch);
    } else {
        brix_queue_response_fragment_chain(ctx, c, chain,
                                              ctx->rd.read_scratch);
    }
    if (ctx->state != XRD_ST_SENDING) {
        brix_release_read_buffer(ctx, c, ctx->rd.read_scratch);
    }
    return NGX_OK;
}

ngx_int_t
brix_readv_serve_windowed(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, void *wire_segments,
    size_t segment_count, size_t body_size)
{
    readahead_list *wire = wire_segments;
    size_t          length;

    if (!brix_budget_admit(ctx, rconf->memory_budget,
                             (size_t) BRIX_READ_WINDOW)) {
        return brix_fsoverload_backoff(ctx, c, rconf);
    }

    ctx->rd.win_active = 1;
    ctx->rd.win_pgread = 0;
    ctx->rd.win_readv = 1;
    ctx->rd.win_readv_started = 0;
    ctx->rd.win_readv_seg_started = 0;
    ctx->rd.win_prefetch = 0;
    ctx->rd.win_ready = 0;
    ctx->rd.win_readv_wire = wire_segments;
    ctx->rd.win_readv_count = segment_count;
    ctx->rd.win_readv_index = 0;
    ctx->rd.win_readv_total = 0;
    ctx->rd.win_readv_body_size = body_size;
    ctx->rd.win_streamid[0] = ctx->recv.cur_streamid[0];
    ctx->rd.win_streamid[1] = ctx->recv.cur_streamid[1];

    length = (size_t) ntohl((uint32_t) wire[0].rlen);
    if (length > rconf->readv_segment_size) {
        length = rconf->readv_segment_size;
    }
    readv_window_select(ctx, length);
    brix_read_window_pump(ctx, c, rconf);
    return NGX_OK;
}
