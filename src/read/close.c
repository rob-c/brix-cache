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
#include "core/ngx_xrootd_module.h"
#include "net/ratelimit/throttle_compat.h"   /* phase-59 W3a: open-files release */
#include "fs/cache/cache_internal.h"
#include "core/compat/staged_file.h"
#include "fs/xfer/xfer.h"   /* unified transfer audit ledger (root:// STAGE) */
#include "write/wrts_journal.h"
#include "write/pgw_fob.h"
#include "net/cms/cns.h"
#include "net/cms/cms_internal.h"   /* ngx_xrootd_cms_ctx_t */
#include "net/cms/frame_io.h"       /* xrootd_cms_send_frame */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * xrootd_cns_emit_close — §6: report a just-written file to the manager.
 *
 * Best-effort, fire-and-forget: only in EMIT mode, only for a writable handle,
 * only when the worker's manager link is connected + logged in. The logical path
 * (export-root-relative, what a client would stat) is derived by stripping
 * root_canon from the handle's final path; size/mtime come from fstat of the fd.
 */
static void
xrootd_cns_emit_close(xrootd_ctx_t *ctx, ngx_stream_xrootd_srv_conf_t *conf,
    int idx)
{
    const char  *fpath, *logical, *root;
    size_t       rlen;
    struct stat  st;
    uint8_t      buf[XROOTD_CNS_HDR_LEN + XROOTD_CNS_PATH_MAX];
    size_t       n;

    if (conf->cns_mode != XROOTD_CNS_EMIT || !ctx->files[idx].writable) {
        return;
    }
    if (conf->cms_ctx == NULL || conf->cms_ctx->connection == NULL
        || !conf->cms_ctx->logged_in)
    {
        return;
    }

    fpath = (ctx->files[idx].posc_final_path != NULL)
            ? ctx->files[idx].posc_final_path : ctx->files[idx].path;
    if (fpath == NULL) {
        return;
    }
    if (ctx->files[idx].fd < 0 || fstat(ctx->files[idx].fd, &st) != 0
        || !S_ISREG(st.st_mode))
    {
        return;
    }

    root    = conf->common.root_canon;
    rlen    = ngx_strlen(root);
    logical = fpath;
    if (rlen > 0 && ngx_strncmp(fpath, root, rlen) == 0 && fpath[rlen] == '/') {
        logical = fpath + rlen;   /* keep the leading '/' → client-facing path */
    }

    n = xrootd_cns_event_encode(XROOTD_CNS_ADD, logical, (uint64_t) st.st_size,
                                (uint64_t) st.st_mtime, buf, sizeof(buf));
    if (n == 0) {
        return;
    }
    (void) xrootd_cms_send_frame(conf->cms_ctx->connection, 0, CMS_RR_CNS,
                                 CMS_MOD_RAW, buf, n);
}

ngx_int_t xrootd_handle_close(xrootd_ctx_t *ctx, ngx_connection_t *c) {
    xrdw_close_req_t req;
    ngx_stream_xrootd_srv_conf_t *conf;
    int idx;
    ngx_int_t rc;

    xrdw_close_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    idx = (int)(unsigned char) req.fhandle[0];

    if (!xrootd_validate_file_handle(ctx, c, idx, "CLOSE",
                                      XROOTD_OP_CLOSE, &rc)) {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_close handle=%d", idx);

    /* pgwrite CSE close gate     * Refuse to close while any page written via kXR_pgwrite failed CRC32c and
     * was never corrected by a kXR_pgRetry.  Otherwise the POSC rename / write-
     * through flush below would commit known-corrupt bytes.  The handle is left
     * OPEN (no free) so the client can resend the bad pages and close again —
     * matching stock do_PgClose, which returns before FTab->Del(). */
    if (ctx->files[idx].pgw_fob_enabled) {
        uint32_t left = xrootd_pgw_fob_count(&ctx->files[idx]);

        if (left > 0) {
            char emsg[64];

            snprintf(emsg, sizeof(emsg), "%u uncorrected checksum error%s",
                     left, left == 1 ? "" : "s");
            XROOTD_OP_ERR(ctx, XROOTD_OP_CLOSE);
            return xrootd_send_error(ctx, c, kXR_ChkSumErr, emsg);
        }
    }

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_xrootd_module);

    /* §6 CNS: a data server reports a just-written file to the manager so the
     * cluster name space learns its size/mtime. Best-effort, fire-and-forget over
     * the worker's manager link; only for writable handles being closed. */
    xrootd_cns_emit_close(ctx, conf, idx);

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

        /* When the partial lives on a separate stage device, record a durable
         * "complete, pending stage-out" marker BEFORE the cross-device move so a
         * worker death mid-move is recoverable: the reaper finishes the move on
         * the next startup/sweep.  Removed once the commit succeeds. */
        ngx_flag_t stage_tracked = (conf != NULL
            && conf->upload_stage_dir_canon[0] != '\0'
            && ctx->files[idx].is_resume);
        if (stage_tracked) {
            (void) xrootd_stage_mark_pending(temp_path, final_path, c->log);
        }

        /* Commit the staged temp onto the final path: fsync + atomic rename on
         * the same filesystem, or copy-then-rename when the staging device
         * (xrootd_stage_dir) differs from the storage (cross-device EXDEV). */
        if (xrootd_commit_staged(ctx->files[idx].fd, temp_path, final_path,
                                 c->log) != NGX_OK) {
            int err = errno;
            ngx_log_error(NGX_LOG_ERR, c->log, err,
                          "xrootd: staged commit \"%s\" -> \"%s\" failed",
                          temp_path, final_path);
            /* Keep the staged partial (resume) — only the publish failed; the
             * client can retry the close.  Surface an I/O error. */
            xrootd_free_fhandle(ctx, idx);
            XROOTD_OP_ERR(ctx, XROOTD_OP_CLOSE);
            xrootd_xfer_finish(XROOTD_XFER_STAGE, "in", final_path,
                               ctx->dn[0] ? ctx->dn : NULL, 0,
                               XROOTD_XFER_COMMIT_ERR, err, c->log);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "staged commit failed");
        }

        if (stage_tracked) {
            xrootd_stage_unmark_pending(temp_path);
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: staged commit \"%s\" -> \"%s\" ok",
                       temp_path, final_path);

        /* Unified ledger: the root:// upload publication — the same audit line
         * S3/WebDAV PUT and the other kinds emit (this path also covers a
         * resumed upload's final commit). */
        {
            struct stat sb;
            size_t      n = (fstat(ctx->files[idx].fd, &sb) == 0
                             && S_ISREG(sb.st_mode)) ? (size_t) sb.st_size : 0;
            xrootd_xfer_finish(XROOTD_XFER_STAGE, "in", final_path,
                               ctx->dn[0] ? ctx->dn : NULL, n,
                               XROOTD_XFER_OK, 0, c->log);
        }
    }

    /* Write-through flush is part of the storage path now (Option A): a wt sd_stage
     * handle flushes to the origin on close via sd_stage_wb_close (and on kXR_sync via
     * the fsync job, which surfaces failures). The legacy run_flush loop is retired. */

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

    /* phase-59 W3a: release this user's throttle open-files slot. */
    if (ctx->throttle_open_held > 0) {
        ngx_stream_xrootd_srv_conf_t *tconf = ngx_stream_get_module_srv_conf(
            (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);
        if (tconf->throttle_zone != NULL) {
            xrootd_throttle_open_dec(tconf->throttle_zone,
                ctx->dn[0] ? ctx->dn : "anonymous");
        }
        ctx->throttle_open_held--;
    }

    /* A failed SYNC write-through flush means the file did not reach the origin;
     * report the close as an error so the client does not assume durability. */
    XROOTD_OP_OK(ctx, XROOTD_OP_CLOSE);

    return xrootd_send_ok(ctx, c, NULL, 0);
}
