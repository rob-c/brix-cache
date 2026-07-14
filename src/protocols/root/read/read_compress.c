/*
 * WHAT: brix_read_compressed() serves a kXR_read for a handle that was opened
 *       with the opaque "?xrootd.compress=<codec>" while the server has
 *       brix_read_compress on.  It reads a bounded plaintext window from the
 *       file, compresses it as ONE self-contained codec frame, and queues the
 *       compressed bytes as a single kXR_read response.  The negotiating client
 *       (which learned the codec from the kXR_open reply cpsize/cptype) inflates
 *       the frame back to plaintext.
 *
 * WHY:  This is an opt-in extension beyond stock XRootD (whose root:// data path
 *       is always plaintext) — the swiss-army goal of trading CPU for bytes on
 *       the wire for compressible data.  It is deliberately ISOLATED from the
 *       proven hot read path in read.c: brix_handle_read() routes here only
 *       when read_codec != IDENTITY, so the default (uncompressed) path — its
 *       sendfile fast path, windowed streaming and AIO pipeline — is completely
 *       untouched and byte-identical.  pgread/readv never call this, preserving
 *       the pgread kXR_status + per-page CRC32c invariant byte-for-byte.
 *
 * HOW:  Each request is an independent whole-range frame, so reads stay offset-
 *       addressable and resumable (re-reading the same offset reproduces the
 *       same plaintext, hence an equivalent frame).  The plaintext window is
 *       staged in ctx->rd.read_scratch and the codec output in ctx->rd.cmp_scratch —
 *       both raw-alloc'd session-lifetime keep-slots (brix_get_pool_scratch /
 *       brix_release_read_buffer).  To stay event-loop friendly the VFS-core
 *       read is synchronous but clamped to BRIX_READ_CHUNK_MAX; a larger
 *       client request simply gets a short (but legal) read and asks again.
 */

#include "read.h"

#include "core/ngx_brix_module.h"
#include "core/compat/codec_core.h"
#include "protocols/root/response/response.h"
#include "prefetch.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>

/* Worst-case codec expansion bound for `plain` bytes: every supported codec
 * (zlib/zstd/xz/brotli/bzip2) stays well under +50% + a small fixed header for
 * any input, so this single bound is safe without a per-codec compressBound. */
static size_t
brix_codec_max_out(size_t plain)
{
    return plain + (plain / 2) + 4096;
}

/*
 * Compress `in_len` plaintext bytes into `out` (capacity *out_cap) as one finished
 * codec frame.  Returns the produced length, or (size_t)-1 on failure.  Grows the
 * caller's rd.cmp_scratch via BRIX_GET_SCRATCH if the codec needs more room than
 * the initial bound (defensive — the bound is sized so this never trips).
 */
static size_t
brix_compress_frame(brix_ctx_t *ctx, ngx_connection_t *c,
                      uint8_t codec_id, const u_char *in, size_t in_len)
{
    brix_codec_stream_t *s;
    size_t                 cap;
    size_t                 in_pos = 0, out_pos = 0;
    brix_codec_rc_t      rc;

    cap = brix_codec_max_out(in_len);

    if (BRIX_GET_SCRATCH(ctx, c, rd.cmp_scratch, rd.cmp_scratch_size, cap) == NULL) {
        return (size_t) -1;
    }

    s = brix_codec_open((brix_codec_id_t) codec_id,
                          BRIX_CODEC_DIR_COMPRESS, -1, NULL);
    if (s == NULL) {
        return (size_t) -1;
    }

    /* cap = brix_codec_max_out(in_len) is >= the worst-case compressed size for
     * every supported codec, so the single output buffer never fills before END.
     * A codec may still need several step() calls (e.g. lz4 consumes its input in
     * chunks, returning OK with room remaining) — keep calling until END.  Only a
     * genuinely full buffer before END would be an overflow, which max_out rules
     * out; treat it as an error rather than a (lossy) realloc-grow. */
    for ( ;; ) {
        size_t prev_in = in_pos;
        size_t prev_out = out_pos;

        rc = brix_codec_step(s, in, in_len, &in_pos,
                               ctx->rd.cmp_scratch, ctx->rd.cmp_scratch_size, &out_pos,
                               1 /* finish */);

        if (rc == BRIX_CODEC_END) {
            break;
        }
        if (rc != BRIX_CODEC_OK
            || out_pos >= ctx->rd.cmp_scratch_size
            || (in_pos == prev_in && out_pos == prev_out))
        {
            brix_codec_close(s);
            return (size_t) -1;
        }
        /* OK with room remaining: the codec made progress but isn't finished;
         * call again to drain the rest of the frame into the same buffer. */
    }

    brix_codec_close(s);
    return out_pos;
}

/* ---- Compute the readable extent and clamped inline window for this request ----
 *
 * WHAT: Resolves the handle's current file size into *file_size and the number
 *       of plaintext bytes to stage this request into *data_total (0 at/after
 *       EOF).  Returns NGX_OK, or NGX_ERROR with *io_err set to the fstat errno
 *       when a writable handle cannot be re-stat'd.
 *
 * WHY:  Read-only handles use the size cached at open (stable); writable handles
 *       re-stat so same-session writes are visible.  Isolating this branch keeps
 *       the orchestrator flat and the size/clamp policy in one testable place.
 *
 * HOW:  1. Pick cached_size for read-only handles, else fstat the fd (errno out
 *          on failure).  2. Clamp the window to bytes present past offset — a
 *          short read is a legal XRootD response, the client re-reads the next
 *          offset.  3. Cap to a single inline window (BRIX_READ_CHUNK_MAX).
 */
static ngx_int_t
brix_compressed_extent(brix_ctx_t *ctx, int idx, off_t offset, size_t rlen,
                        off_t *file_size, size_t *data_total, int *io_err)
{
    off_t   size;
    size_t  total;

    if (!ctx->files[idx].writable) {
        size = ctx->files[idx].cached_size;
    } else {
        struct stat st;
        if (fstat(ctx->files[idx].fd, &st) != 0) {
            *io_err = errno;
            return NGX_ERROR;
        }
        size = st.st_size;
    }

    if (offset >= size) {
        total = 0;
    } else {
        off_t avail = size - offset;
        total = (avail < (off_t) rlen) ? (size_t) avail : rlen;
    }
    if (total > BRIX_READ_CHUNK_MAX) {
        total = BRIX_READ_CHUNK_MAX;
    }

    *file_size = size;
    *data_total = total;
    return NGX_OK;
}

/* ---- Read the plaintext window synchronously through the VFS core ----
 *
 * WHAT: Reads up to data_total bytes at offset from the handle into plain via a
 *       VFS read job, storing the byte count in *nread_out.  Returns NGX_OK, or
 *       NGX_ERROR with *io_err set (io_errno, or EIO for a bare short/negative
 *       return) on failure.
 *
 * WHY:  All file-data byte I/O must flow through the VFS core seam; extracting
 *       the job dance keeps the orchestrator free of raw job-struct plumbing and
 *       preserves the exact errno→message mapping of the inline version.
 *
 * HOW:  1. Init a read job for the handle fd.  2. Execute it synchronously.
 *          3. On io_errno or a negative return, surface an errno (EIO fallback).
 *          4. Otherwise publish the non-negative byte count.
 */
static ngx_int_t
brix_compressed_read_window(brix_ctx_t *ctx, int idx, off_t offset,
                            u_char *plain, size_t data_total,
                            size_t *nread_out, int *io_err)
{
    brix_vfs_job_t  job;
    ssize_t         nread;

    brix_vfs_job_read_init(&job, ctx->files[idx].fd, offset, data_total, plain,
                              data_total, 0);
    brix_vfs_io_execute(&job);
    nread = job.nio;
    if (job.io_errno != 0 || nread < 0) {
        *io_err = job.io_errno != 0 ? job.io_errno : EIO;
        return NGX_ERROR;
    }

    *nread_out = (size_t) nread;
    return NGX_OK;
}

/* ---- Record metrics, dashboard, and access-log side effects for a served frame ----
 *
 * WHAT: Advances the per-handle and per-session byte counters, charges the
 *       rate-limiter, updates the dashboard slot, writes the access-log line,
 *       and marks the READ op OK.  No return value.
 *
 * WHY:  Accounting mirrors the plaintext read path — counters reflect PLAINTEXT
 *       bytes served (what the client receives after inflate), while the
 *       rate-limiter is charged the actual compressed wire bytes.  Grouping the
 *       side effects at one edge keeps the orchestrator a pure control flow.
 *
 * HOW:  1. Add plaintext bytes to handle + session totals, charge wire bytes to
 *          the limiter.  2. If a dashboard slot is active, publish bytes and a
 *          read op.  3. When an access-log fd is configured, emit the framed
 *          detail line.  4. Increment the READ ok metric.
 */
static void
brix_compressed_account(brix_ctx_t *ctx, ngx_connection_t *c,
                        ngx_stream_brix_srv_conf_t *rconf, int idx,
                        off_t offset, size_t data_total, size_t clen)
{
    ctx->files[idx].bytes_read += data_total;
    ctx->totals.bytes += data_total;
    brix_rl_charge_ctx(ctx, clen);   /* bandwidth: charge actual wire bytes */

    if (ctx->files[idx].dashboard_slot >= 0 &&
        ngx_brix_dashboard_shm_zone != NULL)
    {
        brix_transfer_slot_update(ngx_brix_dashboard_shm_zone->data,
                                    ctx->files[idx].dashboard_slot,
                                    (ngx_atomic_int_t) data_total,
                                    (int64_t) ngx_current_msec);
        brix_transfer_slot_count_op(ngx_brix_dashboard_shm_zone->data,
                                      ctx->files[idx].dashboard_slot, "read");
    }

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char read_detail[80];

        snprintf(read_detail, sizeof(read_detail), "%lld+%zu z=%zu",
                 (long long) offset, data_total, clen);
        brix_log_access(ctx, c, "READ", ctx->files[idx].path,
                          read_detail, 1, 0, NULL, data_total);
    }
    BRIX_OP_OK(ctx, BRIX_OP_READ);
}

/* ---- Serve a kXR_read for a compress-negotiated handle as one codec frame ----
 *
 * WHAT: Reads a bounded plaintext window, compresses it into one self-contained
 *       codec frame over rd.cmp_scratch, and queues it as a single kXR_read
 *       response.  Returns the queue rc, NGX_ERROR on scratch/chain failure, or
 *       a sent-error rc for stat/IO/compression failures.
 *
 * WHY:  Keeps the compressed read path a short linear orchestration: extent,
 *       stage, read, compress, account, frame — each step a named helper — so
 *       the byte-exact framing and codec selection are easy to audit.
 *
 * HOW:  1. Resolve the readable window (short-circuit an empty frame at EOF).
 *          2. Stage plaintext into rd.read_scratch and prefetch.  3. Read the
 *          window through the VFS core (empty read → empty frame).  4. Compress
 *          into rd.cmp_scratch.  5. Record side effects.  6. Frame and queue the
 *          compressed bytes, releasing the keep-slot if it was not handed off.
 */
ngx_int_t
brix_read_compressed(brix_ctx_t *ctx, ngx_connection_t *c,
                       ngx_stream_brix_srv_conf_t *rconf,
                       int idx, off_t offset, size_t rlen)
{
    uint8_t       codec_id = ctx->files[idx].read_codec;
    off_t         file_size;
    size_t        data_total, clen, nread;
    u_char       *plain;
    ngx_chain_t  *rsp_chain;
    ngx_int_t     rc;
    int           io_err = 0;

    if (brix_compressed_extent(ctx, idx, offset, rlen, &file_size,
                               &data_total, &io_err) != NGX_OK) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_READ, "READ",
                          ctx->files[idx].path, "-",
                          kXR_IOError, strerror(io_err));
    }

    if (data_total == 0) {
        /* EOF / empty range: an empty frame inflates to zero bytes. */
        BRIX_OP_OK(ctx, BRIX_OP_READ);
        return brix_send_ok(ctx, c, NULL, 0);
    }

    /* Stage the plaintext window. */
    plain = BRIX_GET_SCRATCH(ctx, c, rd.read_scratch, rd.read_scratch_size,
                               data_total);
    if (plain == NULL) {
        return NGX_ERROR;
    }

    brix_prefetch_read_file(c->log, &ctx->files[idx], offset, data_total,
                              file_size);

    if (brix_compressed_read_window(ctx, idx, offset, plain, data_total,
                                    &nread, &io_err) != NGX_OK) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_READ, "READ",
                          ctx->files[idx].path, "-",
                          kXR_IOError, strerror(io_err));
    }
    data_total = nread;

    if (data_total == 0) {
        BRIX_OP_OK(ctx, BRIX_OP_READ);
        return brix_send_ok(ctx, c, NULL, 0);
    }

    /* Compress the window into rd.cmp_scratch as one self-contained frame. */
    clen = brix_compress_frame(ctx, c, codec_id, plain, data_total);
    if (clen == (size_t) -1) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_READ, "READ",
                          ctx->files[idx].path, "-",
                          kXR_IOError, "inline read compression failed");
    }

    brix_compressed_account(ctx, c, rconf, idx, offset, data_total, clen);

    /* Frame the compressed bytes as a single kXR_read response over rd.cmp_scratch
     * (a keep-slot, so brix_release_read_buffer leaves it for reuse). */
    rsp_chain = brix_build_chunked_chain(ctx, c, ctx->rd.cmp_scratch, clen);
    if (rsp_chain == NULL) {
        return NGX_ERROR;
    }

    rc = brix_queue_response_chain(ctx, c, rsp_chain, ctx->rd.cmp_scratch);
    if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
        brix_release_read_buffer(ctx, c, ctx->rd.cmp_scratch);
    }
    return rc;
}
