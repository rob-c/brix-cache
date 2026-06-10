#include "close.h"
#include "../ngx_xrootd_module.h"
#include "../cache/cache_internal.h"
#include "../write/wrts_journal.h"

/* ------------------------------------------------------------------ */
/* File Handle Close — kXR_close handler                                 */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_close opcode — terminating a file handle's lifecycle. When a client finishes reading or writing
 *      to a file, it sends kXR_close to release the open handle. The handler performs multi-phase cleanup: logging throughput metrics,
 *      handling POSC (persist-on-successful-close) atomic rename, flushing write-through dirty data to origin, freeing all resources,
 *      and returning kXR_ok response.
 *
 * WHY: Close is critical for resource management — every open handle consumes a slot in fd_table.c (0–255 range), holds an OS file
 *      descriptor, and accumulates byte counters used for metrics. Without proper close handling, slots would leak, FDs would remain
 *      open indefinitely, and write-through data would never propagate to the origin server. POSC mode additionally requires atomic
 *      rename of staging temp file before freeing resources.
 *
 * HOW: Six-phase cleanup sequence → handle validation (xrootd_validate_file_handle) → access-log throughput logging (before field cleanup) →
 *      POSC rename + fsync (if staging active) → write-through flush (sync or async depending on wt_policy) → xrootd_free_fhandle()
 *      (close FD, free path, unlink checkpoint file) → return kXR_ok response with no body payload. */

/* ------------------------------------------------------------------ */
/* Section: Close handler section overview                              */
/* ------------------------------------------------------------------ */
/*
 * xrootd_handle_close terminates a file handle's lifecycle. The flow is:
 *   1. Validate the requested handle is open and valid
 *   2. Log access details (throughput calculation before field cleanup)
 *   3. If POSC enabled → fsync + rename staging temp to final path
 *   4. If WT enabled → flush dirty writes to origin (sync or async depending on mode)
 *   5. Free all handle resources (fd, path, checkpoint file)
 *   6. Return kXR_ok response to client
 */

/* ---- Access-log section ----
 *
 * Log throughput before freeing handle fields. detail = average transfer speed
 * ("%.2fMB/s"). bytes = total data transferred (prefer written-byte totals for
 * upload operations so write handles log correctly). */

/* ---- POSC rename section ----
 *
 * Persist-on-Successful-Close: atomically rename the staging temp file to the
 * final target path. Must happen before xrootd_free_fhandle() clears fields.
 * On success, clear posc_final_path so free function does NOT unlink the now-
 * renamed (and thus final) file. */

/* ---- Write-through flush section (WT close-flush) ----
 *
 * WHAT: Propagates dirty writes back to the origin XRootD server before closing
 *       the local file descriptor. This is the write-back phase of Policy File Cache.
 *
 * WHY: Ensures data consistency when nginx-xrootd acts as a caching layer — any
 *      writes made locally since last flush must be mirrored to the origin so
 *      other nodes in the cluster see identical content.
 *
 * HOW: The active code records write-through policy and dirty ranges on each
 * handle.  If dirty, close delegates to cache/writethrough_flush.c, which
 * mirrors the final local file to the configured origin and then issues
 * origin truncate/sync/close.
 *
 * Decision at open-time stored in ctx->files[idx].wt_policy: DENY/ALLOW_SYNC/ALLOW_ASYNC.
 * Dirty state tracked by ctx->files[idx].wt_dirty_offset (highest unflushed offset, -1 = clean).
 */

/* ---- WT flush failure handling (fail-open policy) ----
 *
 * WHAT: Close-time flush errors are logged but not propagated as client errors
 *       because the write already succeeded locally and the close path keeps a
 *       fail-open policy. Explicit kXR_sync flushes still report failures.
 *
 * WHY: Matches read-through behavior where a failed cache fill returns error (client can't proceed),
 *      but write-back failure doesn't block the client because data is already written locally.
 *
 * HOW: Log error via ngx_log_error(NGX_LOG_ERR, log, 0, "wt: flush failed..."), increment metrics,
 *      continue with normal close flow. No kXR_error sent to client. */

/* ---- Handle free section ----
 *
 * xrootd_free_fhandle(ctx, idx) closes the kernel fd, frees heap-allocated path,
 * and unlinks any checkpoint file if one exists. This is the final cleanup step
 * in handle lifecycle — after this call the slot index becomes available again. */

/* ---- Function: xrootd_handle_close() ----
 *
 * WHAT: Handles the kXR_close opcode — terminates a file handle's lifecycle by performing six-phase cleanup: (1) validate handle is open and valid,
 *      (2) log throughput metrics before freeing fields, (3) fsync + atomic rename staging temp to final path if POSC enabled,
 *      (4) free all resources via xrootd_free_fhandle() (close FD, free path buffer, unlink checkpoint file), and
 *      (5) return kXR_ok response with no body payload. Throughput detail is logged as "%.2fMB/s" average transfer speed. */

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
