/*
 * close.c — kXR_close (3003) opcode handler: finalise and release an open file handle.
 *
 * WHAT: Implements xrootd_handle_close(), the protocol handler for kXR_close.
 *       It validates the client's file handle, emits an access-log line with
 *       transfer throughput, performs POSC commit, optional write-through
 *       mirroring and dashboard slot release, flushes the write-recovery
 *       journal, frees the handle, and replies with an empty kXR_ok.
 *
 * WHY:  Close is where a transfer is made durable and visible. POSC
 *       (Persist-On-Successful-Close) files are written to a staging temp path
 *       and only promoted to their final name on a clean close, so close must
 *       fsync and rename atomically before the per-handle state is torn down;
 *       a rename failure must surface as kXR_IOError rather than silently
 *       leaving a partial file. It is also the only point where final byte
 *       counters, timing, and the intended (non-temp) path are still available
 *       for accurate logging and metrics.
 *
 * HOW:  Resolve the handle index from req->fhandle[0] and validate it via
 *       xrootd_validate_file_handle(). Compute throughput ("%.2fMB/s") from
 *       bytes_written/bytes_read and (ngx_current_msec - open_time) and log
 *       against posc_final_path when set (never the staging temp path). If
 *       posc_final_path is set, fsync(fd) then rename(temp -> final); on
 *       failure free the handle and return kXR_IOError, on success retarget
 *       write-through to the final path. Run xrootd_wt_flush_on_close() when
 *       write-through is enabled, clear posc_final_path so xrootd_free_fhandle()
 *       does not unlink the now-renamed file, release any dashboard transfer
 *       slot, flush the write-recovery journal (xrootd_wrts_flush) so post-
 *       reconnect writes at the same offsets are not skipped as replays, free
 *       the handle, and send an empty kXR_ok.
 */

#include "close.h"
#include "../ngx_xrootd_module.h"
#include "../cache/cache_internal.h"
#include "../write/wrts_journal.h"
#include <stdio.h>
#include <unistd.h>

ngx_int_t xrootd_handle_close(xrootd_ctx_t *ctx, ngx_connection_t *c) {
    ClientCloseRequest *req = (ClientCloseRequest *) ctx->hdr_buf;
    ngx_stream_xrootd_srv_conf_t *conf;
    int idx = (int)(unsigned char) req->fhandle[0];
    ngx_int_t rc;
    const char *wt_local_path;

    if (!xrootd_validate_file_handle(ctx, c, idx, "CLOSE",
                                      XROOTD_OP_CLOSE, &rc)) {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_close handle=%d", idx);

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_xrootd_module);
    wt_local_path = ctx->files[idx].path;

    /* Log before freeing so we still have the path and byte counters.
     * detail = average throughput for the transfer ("%.2fMB/s").
     * bytes  = total data bytes transferred (read or written). */
    {
        char       close_detail[64];
        size_t     br     = ctx->files[idx].bytes_read;
        size_t     bw     = ctx->files[idx].bytes_written;
        size_t     btotal = (bw > 0) ? bw : br;
        ngx_msec_t dur    = ngx_current_msec - ctx->files[idx].open_time;

        if (btotal > 0 && dur > 0) {
            double mbps = (double) btotal / (double) dur / 1000.0;
            snprintf(close_detail, sizeof(close_detail), "%.2fMB/s", mbps);
        } else {
            snprintf(close_detail, sizeof(close_detail), "-");
        }

        /* Log using the final (intended) path name, not the staging temp path. */
        const char *log_path = (ctx->files[idx].posc_final_path != NULL)
                               ? ctx->files[idx].posc_final_path
                               : ctx->files[idx].path;

        xrootd_log_access(ctx, c, "CLOSE", log_path, close_detail,
                          1, 0, NULL, btotal);
    }

    /*
     * POSC: on a clean kXR_close atomically rename the staging temp file to
     * the final target path.  We must do this before xrootd_free_fhandle()
     * clears the fields.  On success, clear posc_final_path so the free
     * function does NOT unlink the now-renamed (and thus final) file.
     */
    if (ctx->files[idx].posc_final_path != NULL) {
        const char *temp_path  = ctx->files[idx].path;
        const char *final_path = ctx->files[idx].posc_final_path;

        /* fsync before rename to ensure durability. */
        (void) fsync(ctx->files[idx].fd);

        if (rename(temp_path, final_path) != 0) {
            int err = errno;
            ngx_log_error(NGX_LOG_ERR, c->log, err,
                          "xrootd: POSC rename \"%s\" -> \"%s\" failed",
                          temp_path, final_path);
            /* Discard the temp file and return an I/O error to the client. */
            xrootd_free_fhandle(ctx, idx);
            XROOTD_OP_ERR(ctx, XROOTD_OP_CLOSE);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "POSC rename failed");
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: POSC rename \"%s\" -> \"%s\" ok",
                       temp_path, final_path);

        wt_local_path = final_path;
    }

    if (conf != NULL && ctx->files[idx].wt_enabled) {
        (void) xrootd_wt_flush_on_close(ctx, c, conf, idx, wt_local_path);
    }

    /* Clear posc_final_path so xrootd_free_fhandle() does not unlink the
     * now-renamed final file.  This is intentionally after write-through so
     * the flush can mirror the final POSC path instead of the temp path. */
    if (ctx->files[idx].posc_final_path != NULL) {
        ngx_free(ctx->files[idx].posc_final_path);
        ctx->files[idx].posc_final_path = NULL;
    }

    if (ctx->files[idx].dashboard_slot >= 0 &&
        ngx_xrootd_dashboard_shm_zone != NULL)
    {
        xrootd_transfer_slot_count_op(ngx_xrootd_dashboard_shm_zone->data,
                                      ctx->files[idx].dashboard_slot,
                                      "close");
        xrootd_transfer_slot_free(ngx_xrootd_dashboard_shm_zone->data,
                                  ctx->files[idx].dashboard_slot);
        ctx->files[idx].dashboard_slot = -1;
    }

    /* Flush the write-recovery journal so future writes with the same
     * offsets after a reconnect are not mistakenly skipped as replays. */
    xrootd_wrts_flush(&ctx->files[idx]);

    xrootd_free_fhandle(ctx, idx);
    XROOTD_OP_OK(ctx, XROOTD_OP_CLOSE);

    return xrootd_send_ok(ctx, c, NULL, 0);
}
