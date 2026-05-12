#include "close.h"
#include "../ngx_xrootd_module.h"

#include <stdio.h>
#include <unistd.h>

ngx_int_t xrootd_handle_close(xrootd_ctx_t *ctx, ngx_connection_t *c) {
    ClientCloseRequest *req = (ClientCloseRequest *) ctx->hdr_buf;
    int idx = (int)(unsigned char) req->fhandle[0];
    ngx_int_t rc;

    if (!xrootd_validate_file_handle(ctx, c, idx, "CLOSE",
                                     XROOTD_OP_CLOSE, &rc)) {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_close handle=%d", idx);

    /* Log before freeing so we still have the path and byte counters.
     * detail = average throughput for the transfer ("%.2fMB/s").
     * bytes  = total data bytes transferred (read or written). */
    {
        char       close_detail[64];
        size_t     br  = ctx->files[idx].bytes_read;
        size_t     bw  = ctx->files[idx].bytes_written;
        size_t     btotal = (bw > 0) ? bw : br;
        ngx_msec_t dur = ngx_current_msec - ctx->files[idx].open_time;

        /* Prefer written-byte totals when uploads happened so write handles log correctly. */

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

        /* Clear posc_final_path so xrootd_free_fhandle() does not unlink the
         * now-renamed final file. */
        ngx_free(ctx->files[idx].posc_final_path);
        ctx->files[idx].posc_final_path = NULL;
    }

    xrootd_free_fhandle(ctx, idx);
    XROOTD_OP_OK(ctx, XROOTD_OP_CLOSE);

    return xrootd_send_ok(ctx, c, NULL, 0);
}
