/*
 * WHAT: xrootd_read_compressed() serves a kXR_read for a handle that was opened
 *       with the opaque "?xrootd.compress=<codec>" while the server has
 *       xrootd_read_compress on.  It reads a bounded plaintext window from the
 *       file, compresses it as ONE self-contained codec frame, and queues the
 *       compressed bytes as a single kXR_read response.  The negotiating client
 *       (which learned the codec from the kXR_open reply cpsize/cptype) inflates
 *       the frame back to plaintext.
 *
 * WHY:  This is an opt-in extension beyond stock XRootD (whose root:// data path
 *       is always plaintext) — the swiss-army goal of trading CPU for bytes on
 *       the wire for compressible data.  It is deliberately ISOLATED from the
 *       proven hot read path in read.c: xrootd_handle_read() routes here only
 *       when read_codec != IDENTITY, so the default (uncompressed) path — its
 *       sendfile fast path, windowed streaming and AIO pipeline — is completely
 *       untouched and byte-identical.  pgread/readv never call this, preserving
 *       the pgread kXR_status + per-page CRC32c invariant byte-for-byte.
 *
 * HOW:  Each request is an independent whole-range frame, so reads stay offset-
 *       addressable and resumable (re-reading the same offset reproduces the
 *       same plaintext, hence an equivalent frame).  The plaintext window is
 *       staged in ctx->read_scratch and the codec output in ctx->cmp_scratch —
 *       both raw-alloc'd session-lifetime keep-slots (xrootd_get_pool_scratch /
 *       xrootd_release_read_buffer).  To stay event-loop friendly the VFS-core
 *       read is synchronous but clamped to XROOTD_READ_CHUNK_MAX; a larger
 *       client request simply gets a short (but legal) read and asks again.
 */

#include "read.h"

#include "../ngx_xrootd_module.h"
#include "../compat/codec_core.h"
#include "../response/response.h"
#include "prefetch.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>

/* Worst-case codec expansion bound for `plain` bytes: every supported codec
 * (zlib/zstd/xz/brotli/bzip2) stays well under +50% + a small fixed header for
 * any input, so this single bound is safe without a per-codec compressBound. */
static size_t
xrootd_codec_max_out(size_t plain)
{
    return plain + (plain / 2) + 4096;
}

/*
 * Compress `in_len` plaintext bytes into `out` (capacity *out_cap) as one finished
 * codec frame.  Returns the produced length, or (size_t)-1 on failure.  Grows the
 * caller's cmp_scratch via XROOTD_GET_SCRATCH if the codec needs more room than
 * the initial bound (defensive — the bound is sized so this never trips).
 */
static size_t
xrootd_compress_frame(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      uint8_t codec_id, const u_char *in, size_t in_len)
{
    xrootd_codec_stream_t *s;
    size_t                 cap;
    size_t                 in_pos = 0, out_pos = 0;
    xrootd_codec_rc_t      rc;

    cap = xrootd_codec_max_out(in_len);

    if (XROOTD_GET_SCRATCH(ctx, c, cmp_scratch, cmp_scratch_size, cap) == NULL) {
        return (size_t) -1;
    }

    s = xrootd_codec_open((xrootd_codec_id_t) codec_id,
                          XROOTD_CODEC_DIR_COMPRESS, -1, NULL);
    if (s == NULL) {
        return (size_t) -1;
    }

    /* cap = xrootd_codec_max_out(in_len) is >= the worst-case compressed size for
     * every supported codec, so the single output buffer never fills before END.
     * A codec may still need several step() calls (e.g. lz4 consumes its input in
     * chunks, returning OK with room remaining) — keep calling until END.  Only a
     * genuinely full buffer before END would be an overflow, which max_out rules
     * out; treat it as an error rather than a (lossy) realloc-grow. */
    for ( ;; ) {
        size_t prev_in = in_pos;
        size_t prev_out = out_pos;

        rc = xrootd_codec_step(s, in, in_len, &in_pos,
                               ctx->cmp_scratch, ctx->cmp_scratch_size, &out_pos,
                               1 /* finish */);

        if (rc == XROOTD_CODEC_END) {
            break;
        }
        if (rc != XROOTD_CODEC_OK
            || out_pos >= ctx->cmp_scratch_size
            || (in_pos == prev_in && out_pos == prev_out))
        {
            xrootd_codec_close(s);
            return (size_t) -1;
        }
        /* OK with room remaining: the codec made progress but isn't finished;
         * call again to drain the rest of the frame into the same buffer. */
    }

    xrootd_codec_close(s);
    return out_pos;
}

ngx_int_t
xrootd_read_compressed(xrootd_ctx_t *ctx, ngx_connection_t *c,
                       ngx_stream_xrootd_srv_conf_t *rconf,
                       int idx, off_t offset, size_t rlen)
{
    int           fd = ctx->files[idx].fd;
    uint8_t       codec_id = ctx->files[idx].read_codec;
    off_t         file_size;
    size_t        data_total, clen;
    u_char       *plain;
    ssize_t       nread;
    ngx_chain_t  *rsp_chain;
    ngx_int_t     rc;

    /*
     * Determine readable extent.  Read-only handles use the size cached at open
     * (stable); writable handles re-stat so same-session writes are visible.
     */
    if (!ctx->files[idx].writable) {
        file_size = ctx->files[idx].cached_size;
    } else {
        struct stat st;
        if (fstat(fd, &st) != 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_READ, "READ",
                              ctx->files[idx].path, "-",
                              kXR_IOError, strerror(errno));
        }
        file_size = st.st_size;
    }

    /* Clamp to bytes present and to a single inline window (short reads are a
     * legal XRootD response — the client re-reads from the next offset). */
    if (offset >= file_size) {
        data_total = 0;
    } else {
        off_t avail = file_size - offset;
        data_total = (avail < (off_t) rlen) ? (size_t) avail : rlen;
    }
    if (data_total > XROOTD_READ_CHUNK_MAX) {
        data_total = XROOTD_READ_CHUNK_MAX;
    }

    if (data_total == 0) {
        /* EOF / empty range: an empty frame inflates to zero bytes. */
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    /* Stage the plaintext window. */
    plain = XROOTD_GET_SCRATCH(ctx, c, read_scratch, read_scratch_size,
                               data_total);
    if (plain == NULL) {
        return NGX_ERROR;
    }

    xrootd_prefetch_read_file(c->log, &ctx->files[idx], offset, data_total,
                              file_size);

    {
        xrootd_vfs_job_t job;

        xrootd_vfs_job_read_init(&job, fd, offset, data_total, plain,
                                  data_total, 0);
        xrootd_vfs_io_execute(&job);
        nread = job.nio;
        if (job.io_errno != 0 || nread < 0) {
            int err = job.io_errno != 0 ? job.io_errno : EIO;

            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_READ, "READ",
                              ctx->files[idx].path, "-",
                              kXR_IOError, strerror(err));
        }
    }
    data_total = (size_t) nread;

    if (data_total == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    /* Compress the window into cmp_scratch as one self-contained frame. */
    clen = xrootd_compress_frame(ctx, c, codec_id, plain, data_total);
    if (clen == (size_t) -1) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_READ, "READ",
                          ctx->files[idx].path, "-",
                          kXR_IOError, "inline read compression failed");
    }

    /* Accounting mirrors the plaintext read path: counters reflect PLAINTEXT
     * bytes served (what the client receives after inflate), not wire bytes. */
    ctx->files[idx].bytes_read += data_total;
    ctx->session_bytes += data_total;
    xrootd_rl_charge_ctx(ctx, clen);   /* bandwidth: charge actual wire bytes */

    if (ctx->files[idx].dashboard_slot >= 0 &&
        ngx_xrootd_dashboard_shm_zone != NULL)
    {
        xrootd_transfer_slot_update(ngx_xrootd_dashboard_shm_zone->data,
                                    ctx->files[idx].dashboard_slot,
                                    (ngx_atomic_int_t) data_total,
                                    (int64_t) ngx_current_msec);
        xrootd_transfer_slot_count_op(ngx_xrootd_dashboard_shm_zone->data,
                                      ctx->files[idx].dashboard_slot, "read");
    }

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char read_detail[80];

        snprintf(read_detail, sizeof(read_detail), "%lld+%zu z=%zu",
                 (long long) offset, data_total, clen);
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path,
                          read_detail, 1, 0, NULL, data_total);
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_READ);

    /* Frame the compressed bytes as a single kXR_read response over cmp_scratch
     * (a keep-slot, so xrootd_release_read_buffer leaves it for reuse). */
    rsp_chain = xrootd_build_chunked_chain(ctx, c, ctx->cmp_scratch, clen);
    if (rsp_chain == NULL) {
        return NGX_ERROR;
    }

    rc = xrootd_queue_response_chain(ctx, c, rsp_chain, ctx->cmp_scratch);
    if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
        xrootd_release_read_buffer(ctx, c, ctx->cmp_scratch);
    }
    return rc;
}
