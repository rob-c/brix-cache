/*
 * write_stream.c — streaming large plain kXR_write.
 *
 * WHAT: A single kXR_write whose dlen exceeds BRIX_WRITE_STREAM_CHUNK is
 *       delivered to the open file / staged writer in bounded, chunk-sized
 *       installments instead of being buffered whole and written once.  The recv
 *       framing loop (recv_process.c) drives the chunking: brix_write_stream_begin
 *       arms the streaming state at the request-header phase, each filled chunk is
 *       applied by brix_write_stream_apply_chunk, and after the last chunk
 *       brix_write_stream_finish emits exactly one reply for the logical write.
 *
 * WHY:  BriX previously buffered the entire write payload before the pwrite, so
 *       the per-write cap (BRIX_MAX_WRITE_PAYLOAD, 16 MiB) doubled as a hard
 *       ceiling on a single kXR_write.  A client that legitimately sends one very
 *       large inline write (go-hep's 64 MiB WriteAtContext, some Rust clients)
 *       was rejected outright.  Streaming lifts the ceiling to
 *       BRIX_MAX_WRITE_STREAM while keeping resident memory bounded to a single
 *       chunk, and it is the shared consumer the kXR_bind data-path feeds too.
 *
 * HOW:  The chunk buffer is the existing recv payload buffer (allocated one chunk
 *       wide by the shared REQ_PAYLOAD setup); ctx->recv.cur_dlen is repurposed as
 *       the CURRENT chunk length while sw_active is set, and sw_done tracks how
 *       much of sw_total has been applied.  Chunks are applied SYNCHRONOUSLY (no
 *       AIO), in offset order — a staged handle appends via the reply-free
 *       brix_staged_append_raw, a plain fd/driver handle writes via a VFS job,
 *       exactly like the synchronous kXR_write fallback.  The kXR_write protocol
 *       acknowledges the whole write once: the first failure is latched into
 *       sw_err, later chunks are discarded (their bytes still drained off the wire
 *       so framing stays aligned), and finish() sends one kXR_IOError instead of
 *       the kXR_ok.  A handle that is invalid / not writable at begin() arms a
 *       drain: bytes are consumed and discarded, and the latched validation error
 *       is sent at the end — never a mid-stream reply that would desync framing.
 *
 *       SSI, inline-decompression (write_codec), and require_pgwrite handles are
 *       NOT streamed here — begin() declines them so their specialised buffered
 *       paths keep their exact behaviour and per-page-CRC invariants.
 */

#include "core/ngx_brix_module.h"
#include "write.h"
#include "fs/cache/writethrough_metrics.h"
#include "wrts_journal.h"

/*
 * brix_write_stream_arm_drain — mark the streaming write as a drain: consume and
 * discard sw_total bytes, then reply with the latched (code,msg) at finish.  Used
 * when the handle is unusable (invalid / not writable) but the payload is already
 * inbound, so replying now would desync the framing.
 */
static void
brix_write_stream_arm_drain(brix_ctx_t *ctx, int code, const char *msg)
{
    ctx->recv.sw_drain  = 1;
    ctx->recv.sw_err    = code;
    ctx->recv.sw_errmsg = msg;
}

ngx_flag_t
brix_write_stream_begin(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    const u_char   *body = ((ClientRequestHdr *) ctx->recv.hdr_buf)->body;
    xrdw_write_req_t req;
    brix_file_t     *file;
    int              idx;
    uint32_t         total = ctx->recv.cur_dlen;   /* whole logical write length */

    (void) c;

    /* A deployment forcing the checksummed pgwrite path refuses cleartext writes;
     * leave that to the buffered handler (which emits the kXR_Unsupported reply). */
    if (conf->common.require_pgwrite) {
        return 0;
    }

    xrdw_write_req_unpack(body, &req);
    idx = (int) (unsigned char) req.fhandle[0];

    ctx->recv.sw_active   = 1;
    ctx->recv.sw_staged   = 0;
    ctx->recv.sw_drain    = 0;
    ctx->recv.sw_idx      = idx;
    ctx->recv.sw_base_off = req.offset;
    ctx->recv.sw_total    = total;
    ctx->recv.sw_done     = 0;
    ctx->recv.sw_err      = 0;
    ctx->recv.sw_errmsg   = NULL;

    if (idx < 0 || idx >= BRIX_MAX_FILES) {
        brix_write_stream_arm_drain(ctx, kXR_FileNotOpen, "invalid file handle");
    } else {
        file = &ctx->files[idx];

        /* "open" mirrors brix_validate_file_handle: a kernel fd, a driver-backed
         * object handle, or a whole-object staged writer all count as open. */
        if (file->fd < 0 && file->sd_obj.driver == NULL && file->writer == NULL) {
            brix_write_stream_arm_drain(ctx, kXR_FileNotOpen,
                                          "invalid file handle");
        } else if (!file->writable) {
            brix_write_stream_arm_drain(ctx, kXR_NotAuthorized,
                                          "file not open for writing");
        } else if (file->ssi != NULL || file->write_codec != 0) {
            /* SSI accumulation and inline write-decompression have their own
             * buffered handlers — do not stream them. */
            ctx->recv.sw_active = 0;
            return 0;
        } else {
            ctx->recv.sw_staged = (file->writer != NULL) ? 1 : 0;
        }
    }

    /* Repurpose cur_dlen as the FIRST chunk length; streaming is only entered when
     * total > BRIX_WRITE_STREAM_CHUNK, so the first chunk is always a full chunk.
     * cur_body_extra stays 0 (writes carry no trailing streamed body). */
    ctx->recv.cur_dlen      = BRIX_WRITE_STREAM_CHUNK;
    ctx->recv.cur_body_extra = 0;
    return 1;
}

/*
 * brix_write_stream_apply_direct — synchronously write one chunk to a plain fd /
 * driver-backed handle via a VFS job (mirrors the synchronous kXR_write
 * fallback), latching the first error and committing the success-path accounting.
 */
static void
brix_write_stream_apply_direct(brix_ctx_t *ctx, brix_file_t *file,
    int64_t off, const u_char *buf, size_t len)
{
    brix_vfs_job_t job;
    ssize_t        n;

    brix_vfs_job_write_init(&job, file->fd, (off_t) off, buf, len);
    job.csi = file->csi;                      /* phase-59 W2: page tags */
    brix_vfs_job_set_obj(&job, &file->sd_obj);/* route via driver if bound */
    brix_vfs_io_execute(&job);
    n = job.nio;
    if (job.io_errno != 0) {
        errno = job.io_errno;
    }

    if (n < 0) {
        ctx->recv.sw_err    = kXR_IOError;
        ctx->recv.sw_errmsg = "async write error";
        return;
    }
    if ((size_t) n < len) {
        ctx->recv.sw_err    = kXR_IOError;
        ctx->recv.sw_errmsg = "short write (disk full?)";
        return;
    }

    file->bytes_written       += (size_t) n;
    ctx->totals.bytes_written += (size_t) n;
    brix_rl_charge_ctx(ctx, (size_t) n);

    if (file->wt_enabled) {
        brix_wt_mark_dirty(ctx, ctx->recv.sw_idx,
                             off + (int64_t) n - 1, (size_t) n);
    }
    if (file->wrts_enabled) {
        brix_wrts_record(file, off, (uint32_t) n);
    }
}

void
brix_write_stream_apply_chunk(brix_ctx_t *ctx, ngx_connection_t *c)
{
    const u_char *buf = ctx->recv.payload;
    size_t        len = ctx->recv.cur_dlen;
    int64_t       off = ctx->recv.sw_base_off + (int64_t) ctx->recv.sw_done;
    brix_file_t  *file;

    (void) c;

    /* Draining an unusable handle, or a prior chunk already failed: keep the wire
     * aligned by consuming these bytes without applying them (all-or-nothing). */
    if (ctx->recv.sw_drain || ctx->recv.sw_err != 0) {
        return;
    }

    file = &ctx->files[ctx->recv.sw_idx];

    if (ctx->recv.sw_staged) {
        int ar = brix_staged_append_raw(ctx, ctx->recv.sw_idx, off, buf, len);
        if (ar == BRIX_STAGED_APPEND_ORDER) {
            ctx->recv.sw_err    = kXR_Unsupported;
            ctx->recv.sw_errmsg =
                "random-offset write to whole-object backend unsupported";
        } else if (ar == BRIX_STAGED_APPEND_IO) {
            ctx->recv.sw_err    = kXR_IOError;
            ctx->recv.sw_errmsg = "staged write I/O error";
        }
        return;
    }

    brix_write_stream_apply_direct(ctx, file, off, buf, len);
}

ngx_int_t
brix_write_stream_finish(brix_ctx_t *ctx, ngx_connection_t *c)
{
    int         idx    = ctx->recv.sw_idx;
    int64_t     base   = ctx->recv.sw_base_off;
    uint32_t    total  = ctx->recv.sw_total;
    int         err    = ctx->recv.sw_err;
    const char *errmsg = ctx->recv.sw_errmsg;
    int         drain  = ctx->recv.sw_drain;
    const char *path;
    char        detail[64];

    /* Clear streaming state before replying (the reply may re-enter recv). */
    ctx->recv.sw_active = 0;
    ctx->recv.sw_staged = 0;
    ctx->recv.sw_drain  = 0;
    ctx->recv.sw_err    = 0;
    ctx->recv.sw_errmsg = NULL;

    path = (!drain && idx >= 0 && idx < BRIX_MAX_FILES && ctx->files[idx].path)
           ? ctx->files[idx].path : "-";

    snprintf(detail, sizeof(detail), "%lld+%u", (long long) base,
             (unsigned) total);

    if (err != 0) {
        brix_log_access(ctx, c, "WRITE", path, detail, 0, err,
                          errmsg ? errmsg : "write failed", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_WRITE);
        return brix_send_error(ctx, c, (uint16_t) err,
                                 errmsg ? errmsg : "write failed");
    }

    brix_log_access(ctx, c, "WRITE", path, detail, 1, 0, NULL, total);
    BRIX_OP_OK(ctx, BRIX_OP_WRITE);
    return brix_send_ok(ctx, c, NULL, 0);
}
