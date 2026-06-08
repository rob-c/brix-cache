/*
 * tpc_marker.c - 202 Accepted response with WLCG Performance-Marker streaming.
 *
 * When xrootd_webdav_tpc_marker_interval is non-zero, HTTP-TPC COPY requests
 * receive a "202 Accepted" response immediately and then stream
 * Performance-Marker blocks in the chunked body while the curl subprocess runs.
 * The body ends with "success\r\n" or "failure\r\n" when the transfer
 * completes.  This matches the XrdHttp wire behaviour expected by FTS and RUCIO.
 *
 * Performance-Marker format (WLCG HTTP-TPC §3.3):
 *
 *   Perf Marker\r\n
 *   Timestamp: <unix-epoch-seconds>\r\n
 *   Stripe Index: 0\r\n
 *   Stripe Bytes Transferred: <bytes>\r\n
 *   Total Stripe Count: 1\r\n
 *   End\r\n
 *
 * Byte counts for pull transfers are obtained from stat(2) on the in-progress
 * temp file at each marker interval.  Push transfers report 0 bytes in interim
 * markers; the final marker carries the full file size.
 *
 * The curl child is polled with waitpid(WNOHANG) on every timer tick.  A
 * Performance-Marker block is emitted whenever the elapsed time since the last
 * marker exceeds tpc_marker_interval seconds.  The poll timer fires every
 * TPC_MARKER_POLL_MSEC milliseconds and does not block the nginx event loop.
 *
 * A pool cleanup callback kills the curl child and removes the temp file if the
 * request is aborted before the transfer completes (client disconnect, worker
 * shutdown).
 */

#include "webdav.h"
#include "../tpc/common/registry.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Poll the curl child every 200 ms; a marker block is emitted on interval. */
#define TPC_MARKER_POLL_MSEC  200u

/*
 * Per-TPC-transfer state.  Allocated from r->pool; valid until the request
 * pool is destroyed.  Accessed only from the nginx event loop thread.
 *
 * Timer lifetime: ngx_add_timer starts the poll loop; tpc_marker_finish stops
 * it by not re-arming.  If the request is aborted, tpc_marker_cleanup stops it
 * explicitly via ngx_del_timer.
 */
typedef struct {
    ngx_http_request_t  *r;

    /* curl child process — set to 0 by tpc_marker_finish after waitpid. */
    volatile pid_t       curl_pid;

    ngx_event_t          timer;
    time_t               last_marker_time;
    ngx_uint_t           marker_interval_secs;

    /* Pull-mode paths.  tmp_path[0] == '\0' when not applicable. */
    char                 tmp_path[WEBDAV_MAX_PATH];
    char                 final_path[WEBDAV_MAX_PATH];

    /* Root used for confined filesystem operations. */
    const char          *root_canon;

    ngx_flag_t           overwrite;
    ngx_flag_t           existed;     /* was final_path present before pull? */
    ngx_flag_t           is_pull;     /* 0 = push */

    /* Size of the local file being pushed (for the final Perf Marker). */
    off_t                push_file_size;

    uint64_t             transfer_id;
} tpc_marker_ctx_t;

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                            */
/* -------------------------------------------------------------------------- */

/*
 * tpc_marker_send_block — write one Performance-Marker block to the chunked
 * HTTP response body.
 *
 * Allocates a temporary buffer from r->pool so it is freed when the request
 * completes.  Silently ignores OOM or output-filter errors; the marker is
 * advisory and a dropped block does not fail the transfer.
 */
static void
tpc_marker_send_block(ngx_http_request_t *r, time_t ts, off_t bytes_transferred)
{
    char        block[512];
    int         n;
    ngx_buf_t  *b;
    ngx_chain_t out;

    n = snprintf(block, sizeof(block),
                 "Perf Marker\r\n"
                 "Timestamp: %ld\r\n"
                 "Stripe Index: 0\r\n"
                 "Stripe Bytes Transferred: %lld\r\n"
                 "Total Stripe Count: 1\r\n"
                 "End\r\n",
                 (long) ts, (long long) bytes_transferred);

    if (n <= 0 || n >= (int) sizeof(block)) {
        return;
    }

    b = ngx_create_temp_buf(r->pool, (size_t) n);
    if (b == NULL) {
        return;
    }

    ngx_memcpy(b->pos, block, (size_t) n);
    b->last = b->pos + n;

    out.buf  = b;
    out.next = NULL;

    (void) ngx_http_output_filter(r, &out);
}

/*
 * tpc_marker_finish — commit or roll back the transfer and close the response.
 *
 * For pull transfers: on success, renames (or hard-links) the temp file to the
 * final path.  On failure, removes the temp file.
 *
 * Writes a final Performance-Marker and then "success\r\n" or "failure\r\n"
 * before terminating the chunked body.
 *
 * Called from the timer handler when waitpid reports curl has exited, or from
 * tpc_marker_cleanup if the request is aborted.
 */
static void
tpc_marker_finish(ngx_http_request_t *r, tpc_marker_ctx_t *ctx, int failed)
{
    time_t      now;
    off_t       final_bytes;
    ngx_buf_t  *b;
    ngx_chain_t out;
    const char *status_line;
    size_t      status_len;

    ctx->curl_pid = 0;

    now         = time(NULL);
    final_bytes = 0;

    if (ctx->is_pull && ctx->tmp_path[0] != '\0') {
        struct stat sb;
        if (stat(ctx->tmp_path, &sb) == 0) {
            final_bytes = sb.st_size;
        }
    } else if (!ctx->is_pull) {
        final_bytes = ctx->push_file_size;
    }

    /* Final Performance-Marker with actual bytes. */
    (void) xrootd_tpc_progress_emit(ctx->transfer_id, final_bytes, final_bytes,
                                    failed ? XROOTD_TPC_STATE_ERROR
                                           : XROOTD_TPC_STATE_DONE,
                                    r->connection->log);
    tpc_marker_send_block(r, now, final_bytes);

    /* Commit the temp file (pull only). */
    if (!failed && ctx->is_pull && ctx->tmp_path[0] != '\0') {
        if (!ctx->overwrite) {
            /*
             * Hard-link the temp file to the final path.  If the link fails
             * with EEXIST the destination appeared between our pre-check and
             * curl completing — treat it as a commit failure (can't return
             * 412 after 202, so "failure" in the body is the closest signal).
             */
            if (xrootd_link_confined_canon(r->connection->log, ctx->root_canon,
                                           ctx->tmp_path,
                                           ctx->final_path) != 0)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "xrootd_webdav: TPC marker link() failed");
                xrootd_unlink_confined_canon(r->connection->log,
                                             ctx->root_canon,
                                             ctx->tmp_path, 0);
                ctx->tmp_path[0] = '\0';
                XROOTD_WEBDAV_METRIC_INC(
                    tpc_total[XROOTD_WEBDAV_TPC_COMMIT_ERROR]);
                failed = 1;
            } else {
                xrootd_unlink_confined_canon(r->connection->log,
                                             ctx->root_canon,
                                             ctx->tmp_path, 0);
                ctx->tmp_path[0] = '\0';
            }
        } else {
            if (xrootd_rename_confined_canon(r->connection->log,
                                             ctx->root_canon,
                                             ctx->tmp_path,
                                             ctx->final_path) != 0)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                              "xrootd_webdav: TPC marker rename() failed");
                xrootd_unlink_confined_canon(r->connection->log,
                                             ctx->root_canon,
                                             ctx->tmp_path, 0);
                ctx->tmp_path[0] = '\0';
                XROOTD_WEBDAV_METRIC_INC(
                    tpc_total[XROOTD_WEBDAV_TPC_COMMIT_ERROR]);
                failed = 1;
            } else {
                ctx->tmp_path[0] = '\0';
            }
        }
    } else if (failed && ctx->is_pull && ctx->tmp_path[0] != '\0') {
        xrootd_unlink_confined_canon(r->connection->log, ctx->root_canon,
                                     ctx->tmp_path, 0);
        ctx->tmp_path[0] = '\0';
    }

    /* Update metrics. */
    if (failed) {
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_ERROR]);
        status_line = "failure\r\n";
        status_len  = sizeof("failure\r\n") - 1;
    } else {
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_SUCCESS]);
        if (ctx->is_pull) {
            XROOTD_WEBDAV_METRIC_INC(
                tpc_total[XROOTD_WEBDAV_TPC_PULL_SUCCESS]);
        } else {
            XROOTD_WEBDAV_METRIC_INC(
                tpc_total[XROOTD_WEBDAV_TPC_PUSH_SUCCESS]);
        }
        status_line = "success\r\n";
        status_len  = sizeof("success\r\n") - 1;
    }

    /* Write final status line. */
    b = ngx_create_temp_buf(r->pool, status_len);
    if (b != NULL) {
        ngx_memcpy(b->pos, status_line, status_len);
        b->last = b->pos + status_len;
        out.buf  = b;
        out.next = NULL;
        (void) ngx_http_output_filter(r, &out);
    }

    /* Terminate the chunked body and release the extra request reference. */
    (void) ngx_http_send_special(r, NGX_HTTP_LAST);
    ngx_http_finalize_request(r, NGX_DONE);
}

/* -------------------------------------------------------------------------- */
/* Event and cleanup callbacks                                                 */
/* -------------------------------------------------------------------------- */

/*
 * tpc_marker_poll — nginx event timer callback, fires every TPC_MARKER_POLL_MSEC.
 *
 * Checks if the curl child has exited via waitpid(WNOHANG).  Emits a
 * Performance-Marker block if the marker interval has elapsed.  Re-arms the
 * timer if curl is still running.
 */
static void
tpc_marker_poll(ngx_event_t *ev)
{
    tpc_marker_ctx_t   *ctx = ev->data;
    ngx_http_request_t *r = ctx->r;
    int                 wstatus;
    pid_t               ret;
    time_t              now;
    off_t               bytes;

    ret = waitpid(ctx->curl_pid, &wstatus, WNOHANG);

    if (ret < 0 && errno != EINTR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "xrootd_webdav: TPC marker waitpid() error");
        kill(ctx->curl_pid, SIGKILL);
        waitpid(ctx->curl_pid, NULL, 0);
        tpc_marker_finish(r, ctx, 1 /* failed */);
        return;
    }

    now = time(NULL);

    /* Emit a Performance-Marker if the configured interval has elapsed. */
    if (ctx->marker_interval_secs > 0
        && (now - ctx->last_marker_time) >= (time_t) ctx->marker_interval_secs)
    {
        bytes = 0;
        if (ctx->is_pull && ctx->tmp_path[0] != '\0') {
            struct stat sb;
            if (stat(ctx->tmp_path, &sb) == 0) {
                bytes = sb.st_size;
            }
        }
        tpc_marker_send_block(r, now, bytes);
        (void) xrootd_tpc_progress_emit(ctx->transfer_id, bytes, 0,
                                        XROOTD_TPC_STATE_ACTIVE,
                                        r->connection->log);
        ctx->last_marker_time = now;
    }

    if (ret == ctx->curl_pid) {
        int failed = !(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0);

        if (failed) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: TPC curl exited with status %d",
                          wstatus);
        }

        tpc_marker_finish(r, ctx, failed);
        return;
    }

    /* curl is still running — re-arm for the next poll tick. */
    ngx_add_timer(ev, TPC_MARKER_POLL_MSEC);
}

/*
 * tpc_marker_cleanup — request pool cleanup handler.
 *
 * Called when the request pool is destroyed (client disconnect, error path,
 * or normal completion).  Stops the poll timer, kills any still-running curl
 * child, and removes any leftover temp file.  Safe to call after
 * tpc_marker_finish has already cleaned up (both curl_pid and tmp_path are
 * zeroed by finish before cleanup runs).
 */
static void
tpc_marker_cleanup(void *data)
{
    tpc_marker_ctx_t *ctx = data;

    if (ctx->timer.timer_set) {
        ngx_del_timer(&ctx->timer);
    }

    if (ctx->curl_pid > 0) {
        kill(ctx->curl_pid, SIGKILL);
        waitpid(ctx->curl_pid, NULL, 0);
        ctx->curl_pid = 0;
    }

    if (ctx->is_pull && ctx->tmp_path[0] != '\0') {
        (void) unlink(ctx->tmp_path);
        ctx->tmp_path[0] = '\0';
    }
}

/* -------------------------------------------------------------------------- */
/* Public entry point                                                          */
/* -------------------------------------------------------------------------- */

/*
 * webdav_tpc_marker_start — start an asynchronous TPC transfer with
 * Performance-Marker streaming.
 *
 * The caller must have already forked the curl child (curl_pid).  This
 * function sends 202 Accepted, registers a poll timer, emits the first
 * Performance-Marker immediately, and returns NGX_DONE.
 *
 * For pull transfers: tmp_path is the in-progress write target; final_path is
 *   where it is renamed (or linked) on success.  Both must fit WEBDAV_MAX_PATH.
 * For push transfers: tmp_path and final_path are NULL.  push_file_size carries
 *   the local file size (used in the final Perf Marker).
 *
 * On error (OOM, send-header failure): kills the curl child, removes tmp_path,
 * and returns an HTTP error code.  The caller must return that code to nginx.
 */
ngx_int_t
webdav_tpc_marker_start(ngx_http_request_t *r,
                        ngx_http_xrootd_webdav_loc_conf_t *conf,
                        pid_t curl_pid,
                        const char *tmp_path,
                        const char *final_path,
                        ngx_flag_t is_pull,
                        ngx_flag_t overwrite,
                        ngx_flag_t existed,
                        off_t push_file_size)
{
    tpc_marker_ctx_t    *ctx;
    ngx_pool_cleanup_t  *cln;
    ngx_int_t            rc;

    ctx = ngx_palloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        kill(curl_pid, SIGKILL);
        waitpid(curl_pid, NULL, 0);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->r                    = r;
    ctx->curl_pid             = curl_pid;
    ctx->is_pull              = is_pull;
    ctx->overwrite            = overwrite;
    ctx->existed              = existed;
    ctx->root_canon           = conf->common.root_canon;
    ctx->transfer_id          = 0;
    ctx->marker_interval_secs = conf->tpc_marker_interval;
    ctx->last_marker_time     = 0;  /* ensure first marker fires immediately */
    ctx->push_file_size       = push_file_size;

    ngx_cpystrn((u_char *) ctx->tmp_path,
                (u_char *) (tmp_path ? tmp_path : ""),
                sizeof(ctx->tmp_path));
    ngx_cpystrn((u_char *) ctx->final_path,
                (u_char *) (final_path ? final_path : ""),
                sizeof(ctx->final_path));

    /* Register the cleanup to handle aborted requests. */
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        kill(curl_pid, SIGKILL);
        waitpid(curl_pid, NULL, 0);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = tpc_marker_cleanup;
    cln->data    = ctx;

    /* Initialise the timer event struct; handler and data are set below. */
    ngx_memzero(&ctx->timer, sizeof(ctx->timer));
    ctx->timer.handler = tpc_marker_poll;
    ctx->timer.data    = ctx;
    ctx->timer.log     = r->connection->log;

    /*
     * Send "202 Accepted" with a chunked body.  Setting content_length_n to -1
     * with no explicit Transfer-Encoding header causes nginx's chunked-encoding
     * filter to frame the body automatically.
     */
    r->headers_out.status              = 202;
    r->headers_out.content_length_n    = -1;
    r->headers_out.content_type.data   = (u_char *) "text/plain";
    r->headers_out.content_type.len    = sizeof("text/plain") - 1;
    r->headers_out.content_type_len    = sizeof("text/plain") - 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        kill(curl_pid, SIGKILL);
        waitpid(curl_pid, NULL, 0);
        if (ctx->is_pull && ctx->tmp_path[0] != '\0') {
            xrootd_unlink_confined_canon(r->connection->log, ctx->root_canon,
                                         ctx->tmp_path, 0);
            ctx->tmp_path[0] = '\0';
        }
        return rc != NGX_ERROR ? rc : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Increment the request reference count so nginx does not destroy the
     * request when the handler returns NGX_DONE.  tpc_marker_finish
     * decrements it via ngx_http_finalize_request(r, NGX_DONE).
     */
    r->main->count++;

    /* Emit the first Performance-Marker immediately. */
    tpc_marker_send_block(r, time(NULL), 0);
    ctx->last_marker_time = time(NULL);

    /* Start the poll timer. */
    ngx_add_timer(&ctx->timer, TPC_MARKER_POLL_MSEC);

    return NGX_DONE;
}
