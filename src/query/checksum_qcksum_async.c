/*
 * WHAT: Async kXR_Qcksum — compute a single-file checksum (adler32/crc32c/md5/sha1/sha256) off the event loop via nginx thread pool.
 *       The thread worker opens a confined fd, computes checksum via xrootd_checksum_hex_fd, writes "algo hex" result to t->resp.
 *       On failure sets error_code + error_msg. Never touches nginx event-loop state (no ctx, no c, no ngx_pool).
 *
 * WHY:  Qcksum file checksums can be expensive for large files. Running on the event loop blocks all other connections while reading.
 *       The async path uses ngx_thread_pool_run to execute the open+checksum in a background worker thread, keeping nginx responsive.
 *       Results delivered via aio_done callback which restores request streamid, sends response to client, and resumes connection.
 *
 * HOW:  xrootd_cksum_aio_thread() parses algo from t->algo string, computes checksum via hex_fd on pre-opened fd,
 *       formats result as "algo hex" into resp buffer. On parse failure sets kXR_ArgInvalid; on compute failure sets kXR_IOError.
 *       xrootd_cksum_aio_done() closes fd if path-based request (t->close_fd), restores streamid via aio_restore_request, sends ok+resp or error, frees resources, resumes client connection event loop via aio_resume().
 */
#include "query_internal.h"
#include "../compat/checksum.h"
#include "../compat/integrity_info.h"
#include "../response/response.h"
#include "../aio/aio.h"


/*
 * xrootd_cksum_aio_thread — runs on a thread-pool worker.
 *
 * Computes the checksum of t->fd using t->algo and writes the result
 * into t->resp.  On failure sets t->error_code to the appropriate kXR_*
 * code and t->error_msg to a human-readable description.  Never touches
 * nginx event-loop state (no ctx, no c, no ngx_pool).
 */
/* ---- public API: xrootd_cksum_aio_thread() — async qcksum thread worker ----
 * WHAT: Thread pool worker that computes single-file checksum. Parses algo string via xrootd_checksum_parse, computes checksum via xrootd_checksum_hex_fd on pre-opened fd, writes "algo hex" result to resp buffer. On parse failure sets kXR_ArgInvalid; on compute failure sets kXR_IOError + error message. Never touches nginx event-loop state (no ctx, no c, no ngx_pool). */

void
xrootd_cksum_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_cksum_aio_t      *t = data;
    xrootd_integrity_info_t  info;
    xrootd_integrity_opts_t  iopts;
    char                     token[256];

    ngx_memzero(&iopts, sizeof(iopts));
    iopts.allow_xattr_cache  = 1;
    iopts.update_xattr_cache = 1;

    if (xrootd_integrity_get_fd(log, t->fd, t->resolved, t->algo,
                                &iopts, &info) != NGX_OK)
    {
        t->error_code = kXR_IOError;
        snprintf(t->error_msg, sizeof(t->error_msg),
                 "checksum computation failed");
        return;
    }

    /* kXR_Qcksum wire format: "algo hexvalue" (space-separated) */
    snprintf(token, sizeof(token), "%s %s", info.alg_name, info.hex);
    ngx_cpystrn((u_char *) t->resp, (u_char *) token, sizeof(t->resp));
}

/*
 * xrootd_cksum_aio_done — main-thread completion callback.
 *
 * Closes t->fd if t->close_fd is set (path-based requests), then sends
 * the response built by the thread worker and re-arms the connection.
 * The fd is closed before the destroy check so it is never leaked even
 * when the client disconnected while the AIO was in flight.
 */
/* ---- public API: xrootd_cksum_aio_done() — async qcksum completion callback ----
 * WHAT: Main-thread event handler invoked when the thread worker completes. Closes t->fd if path-based request (t->close_fd), restores request streamid via aio_restore_request, sends error response or ok+checksum data to client, resumes client connection event loop via xrootd_aio_resume(). */

void
xrootd_cksum_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    xrootd_cksum_aio_t *t    = task->ctx;
    xrootd_ctx_t       *ctx  = t->ctx;
    ngx_connection_t   *c    = t->c;

    if (t->close_fd && t->fd >= 0) {
        close(t->fd);
        t->fd = -1;
    }

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->error_code != 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
        xrootd_send_error(ctx, c, (uint16_t) t->error_code, t->error_msg);
    } else {
        XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSUM);
        xrootd_log_access(ctx, c, "QUERY", t->resolved, "cksum", 1, 0, NULL, 0);
        xrootd_send_ok(ctx, c, t->resp, (uint32_t) (strlen(t->resp) + 1));
    }

    xrootd_aio_resume(c);
}

