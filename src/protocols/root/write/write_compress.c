/*
 * WHAT: xrootd_write_compressed() serves a kXR_write for a handle opened for
 *       write with the opaque "?xrootd.compress=<codec>" while the server has
 *       xrootd_write_compress on.  The request payload is ONE self-contained
 *       codec frame (the symmetric inverse of W4's per-request read frames); the
 *       server decompresses it under a decompression-bomb guard and streams the
 *       recovered plaintext through the VFS write core at the request offset,
 *       storing the file plaintext on disk.  The client thus trades CPU for
 *       upload-wire bytes.
 *
 * WHY:  This is the write-direction counterpart of W4 (read decompression) and
 *       the last plan workstream (W5).  It is deliberately ISOLATED from the
 *       proven write path: xrootd_handle_write() routes here only when
 *       write_codec != IDENTITY, so the default (uncompressed) write — its AIO
 *       fast path and the write-recovery journal — is untouched and byte-
 *       identical.  pgwrite/writev never call this, so the pgwrite per-page
 *       CRC32c invariant is preserved.  The decode is on UNTRUSTED client input,
 *       so the bomb guard (absolute cap + expansion ratio) is mandatory.
 *
 * HOW:  Each kXR_write is an independent whole-frame, so writes stay offset-
 *       addressable (re-writing the same offset reproduces the same plaintext).
 *       The plaintext is produced into a fixed window (write_scratch) and
 *       written chunk-by-chunk at advancing offsets through the VFS core, so
 *       memory stays bounded regardless of the decompressed size.  A
 *       synchronous VFS write keeps the opt-in path simple; the default path
 *       keeps its AIO offload.
 */

#include "write.h"

#include "core/ngx_xrootd_module.h"
#include "core/compat/codec_core.h"
#include "core/compat/http_body.h"   /* XROOTD_DECODE_MAX_RATIO */
#include "protocols/root/response/response.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>

/* Fixed plaintext window streamed through VFS; bounds memory for any output size. */
#define XROOTD_WCMP_WINDOW   (1u << 20)              /* 1 MiB                    */
/* Absolute ceiling on the plaintext produced from ONE write frame — a bomb that
 * tries to exceed this is rejected (the ratio guard catches the classic case). */
#define XROOTD_WCMP_OUT_CAP  (256ULL * 1024 * 1024)  /* 256 MiB                  */

ngx_int_t
xrootd_write_compressed(xrootd_ctx_t *ctx, ngx_connection_t *c,
                        int idx, int64_t offset, size_t wlen)
{
    int                           fd = ctx->files[idx].fd;
    uint8_t                       codec = ctx->files[idx].write_codec;
    ngx_stream_xrootd_srv_conf_t *rconf;
    u_char                       *win;
    xrootd_codec_stream_t        *s;
    xrootd_codec_guard_t          guard;
    size_t                        in_pos = 0, produced = 0;
    off_t                         cur = (off_t) offset;
    int                           io_err = 0, data_err = 0;
    int                           saved_errno = 0;
    char                          detail[80];

    rconf = ngx_stream_get_module_srv_conf(
                (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);

    win = XROOTD_GET_SCRATCH(ctx, c, write_scratch, write_scratch_size,
                             XROOTD_WCMP_WINDOW);
    if (win == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&guard, sizeof(guard));
    /* Bomb protection here is the ABSOLUTE per-frame output ceiling, not an
     * expansion ratio: legitimate writes are often highly compressible (logs,
     * sparse/zero regions, repetitive scientific data exceed 1000:1), so a ratio
     * guard would false-reject real data.  Memory stays bounded by the streaming
     * window regardless, and the bytes land in the client's OWN quota-limited
     * file, so the absolute cap is the right and sufficient guard. */
    guard.out_cap   = XROOTD_WCMP_OUT_CAP;
    guard.max_ratio = 0;

    s = xrootd_codec_open((xrootd_codec_id_t) codec,
                          XROOTD_CODEC_DIR_DECOMPRESS, -1, &guard);
    if (s == NULL) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
                          ctx->files[idx].path, "-",
                          kXR_IOError, "inline write decompression unavailable");
    }

    for ( ;; ) {
        size_t            out_pos = 0, prev_in = in_pos;
        xrootd_codec_rc_t rc = xrootd_codec_step(s, ctx->payload, wlen, &in_pos,
                                                 win, XROOTD_WCMP_WINDOW,
                                                 &out_pos, 1 /* finish */);
        if (out_pos > 0) {
            xrootd_vfs_job_t job;

            xrootd_vfs_job_write_init(&job, fd, cur, win, out_pos);
            xrootd_vfs_io_execute(&job);
            if (job.io_errno != 0 || job.nio < 0
                || (size_t) job.nio != out_pos)
            {
                /* Capture the write errno NOW: xrootd_codec_close() below runs
                 * backend teardown (free/library cleanup) that may clobber errno
                 * before the io_err branch formats strerror(). */
                saved_errno = job.io_errno != 0 ? job.io_errno : EIO;
                io_err = 1;
                break;
            }
            cur      += (off_t) job.nio;
            produced += (size_t) job.nio;
        }
        if (rc == XROOTD_CODEC_END) {
            break;
        }
        if (rc != XROOTD_CODEC_OK || (in_pos == prev_in && out_pos == 0)) {
            data_err = 1;   /* corrupt / bomb / no-progress */
            break;
        }
    }
    xrootd_codec_close(s);

    snprintf(detail, sizeof(detail), "%lld+%zu z=%zu",
             (long long) offset, produced, wlen);

    if (io_err) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
                          ctx->files[idx].path, detail,
                          kXR_IOError, strerror(saved_errno));
    }
    if (data_err) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_WRITE, "WRITE",
                          ctx->files[idx].path, detail,
                          kXR_IOError, "corrupt or oversized compressed write");
    }

    /* Accounting: counters reflect PLAINTEXT bytes stored; bandwidth is charged
     * the actual wire (compressed) bytes received. */
    ctx->files[idx].bytes_written += produced;
    ctx->session_bytes_written    += produced;
    xrootd_rl_charge_ctx(ctx, wlen);

    if (ctx->files[idx].dashboard_slot >= 0 &&
        ngx_xrootd_dashboard_shm_zone != NULL)
    {
        xrootd_transfer_slot_update(ngx_xrootd_dashboard_shm_zone->data,
                                    ctx->files[idx].dashboard_slot,
                                    (ngx_atomic_int_t) produced,
                                    (int64_t) ngx_current_msec);
        xrootd_transfer_slot_count_op(ngx_xrootd_dashboard_shm_zone->data,
                                      ctx->files[idx].dashboard_slot, "write");
    }

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                          detail, 1, 0, NULL, produced);
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);
    return xrootd_send_ok(ctx, c, NULL, 0);
}
