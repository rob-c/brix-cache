/*
 * close.c — kXR_close (3003) opcode handler: finalise and release an open file handle.
 *
 * WHAT: Implements brix_handle_close(), the protocol handler for kXR_close.
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
 *       brix_validate_file_handle(). Compute throughput ("%.2fMB/s") from
 *       bytes_written/bytes_read and (ngx_current_msec - open_time) and log
 *       against posc_final_path when set (never the staging temp path). If
 *       posc_final_path is set, fsync(fd) then rename(temp -> final); on
 *       failure free the handle and return kXR_IOError, on success retarget
 *       write-through to the final path. Run brix_wt_flush_on_close() when
 *       write-through is enabled, clear posc_final_path so brix_free_fhandle()
 *       does not unlink the now-renamed file, release any dashboard transfer
 *       slot, flush the write-recovery journal (brix_wrts_flush) so post-
 *       reconnect writes at the same offsets are not skipped as replays, free
 *       the handle, and send an empty kXR_ok.
 */

#include "close.h"
#include "core/ngx_brix_module.h"
#include "net/ratelimit/throttle_compat.h"   /* phase-59 W3a: open-files release */
#include "fs/cache/cache_internal.h"
#include "core/compat/staged_file.h"
#include "fs/xfer/xfer.h"   /* unified transfer audit ledger (root:// STAGE) */
#include "protocols/root/write/wrts_journal.h"
#include "protocols/root/write/pgw_fob.h"
#include "net/cms/cns.h"
#include "net/cms/cms_internal.h"   /* ngx_brix_cms_ctx_t */
#include "net/cms/frame_io.h"       /* brix_cms_send_frame */
#include "observability/sesslog/sesslog_ngx.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * brix_cns_emit_close — §6: report a just-written file to the manager.
 *
 * Best-effort, fire-and-forget: only in EMIT mode, only for a writable handle,
 * only when the worker's manager link is connected + logged in. The logical path
 * (export-root-relative, what a client would stat) is derived by stripping
 * root_canon from the handle's final path; size/mtime come from fstat of the fd.
 */
static void
brix_cns_emit_close(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    int idx)
{
    const char  *fpath, *logical, *root;
    size_t       rlen;
    struct stat  st;
    uint8_t      buf[BRIX_CNS_HDR_LEN + BRIX_CNS_PATH_MAX];
    size_t       n;

    if (conf->cns_mode != BRIX_CNS_EMIT || !ctx->files[idx].writable) {
        return;
    }
    if (conf->cms.ctx == NULL || conf->cms.ctx->connection == NULL
        || !conf->cms.ctx->logged_in)
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

    n = brix_cns_event_encode(BRIX_CNS_ADD, logical, (uint64_t) st.st_size,
                                (uint64_t) st.st_mtime, buf, sizeof(buf));
    if (n == 0) {
        return;
    }
    (void) brix_cms_send_frame(conf->cms.ctx->connection, 0, CMS_RR_CNS,
                                 CMS_MOD_RAW, buf, n);
}

/*
 * WHAT: Finish the sesslog transfer attached to a root file handle.
 * WHY: kXR_close is the first point where final byte counters and the durable
 * commit outcome are known while the handle state is still alive.
 * HOW: Reconcile the intrusive xfer byte counter from the existing per-handle
 * read/write totals, then emit COMPLETE or ABORTED before brix_free_fhandle().
 */
static void
brix_close_finish_sess_xfer(brix_ctx_t *ctx, int idx,
    brix_sess_xfer_status_t status)
{
    brix_file_t *file;
    size_t       total;

    file = &ctx->files[idx];
    total = (file->bytes_written > 0) ? file->bytes_written : file->bytes_read;
    if (file->sess_xfer.active && total > file->sess_xfer.bytes) {
        brix_sess_xfer_add(&file->sess_xfer,
                           (uint64_t) (total - file->sess_xfer.bytes));
    }
    brix_sess_xfer_end(ctx->sess, &file->sess_xfer, status);
}

/*
 * WHAT: kXR_pgwrite close gate — refuse close while uncorrected CRC32c errors
 * remain on the handle.
 * WHY: A clean close below would POSC-commit / write-through known-corrupt bytes;
 * stock do_PgClose returns before FTab->Del(), so the handle stays OPEN for the
 * client to resend the bad pages and close again.
 * HOW: NGX_DECLINED = "no gate, continue". Otherwise stash the error-send's
 * NGX_OK in *rc and return NGX_DONE = "handled, stop".
 */
static ngx_int_t
brix_close_pgw_gate(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    ngx_int_t *rc)
{
    uint32_t  left;
    char      emsg[64];

    if (!ctx->files[idx].pgw_fob_enabled) {
        return NGX_DECLINED;
    }
    left = brix_pgw_fob_count(&ctx->files[idx]);
    if (left == 0) {
        return NGX_DECLINED;
    }
    snprintf(emsg, sizeof(emsg), "%u uncorrected checksum error%s",
             left, left == 1 ? "" : "s");
    BRIX_OP_ERR(ctx, BRIX_OP_CLOSE);
    *rc = brix_send_error(ctx, c, kXR_ChkSumErr, emsg);
    return NGX_DONE;
}

/*
 * WHAT: Whole-object staged-commit adapter (phase-70) — commit a staged write
 * handle's object at close via a single backend PUT.
 * WHY: A staged handle publishes only on a clean close, unless kXR_sync already
 * committed it (idempotent); a commit failure must surface kXR_IOError and abort
 * the handle so no partial object is published.
 * HOW: NGX_DECLINED = "nothing to commit, continue". On failure, abort the
 * session xfer, free the handle, stash the error-send's NGX_OK in *rc and return
 * NGX_DONE = "handled, stop".
 */
static ngx_int_t
brix_close_staged_commit(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    ngx_int_t *rc)
{
    int  cerr = 0;

    if (ctx->files[idx].staged == NULL || ctx->files[idx].staged_committed) {
        return NGX_DECLINED;
    }
    if (brix_staged_commit_handle(ctx, idx, &cerr) == NGX_OK) {
        return NGX_DECLINED;
    }
    brix_close_finish_sess_xfer(ctx, idx, BRIX_SESS_XFER_ABORTED);
    brix_free_fhandle(ctx, idx);
    BRIX_OP_ERR(ctx, BRIX_OP_CLOSE);
    *rc = brix_send_error(ctx, c, kXR_IOError, "staged commit failed");
    return NGX_DONE;
}

/*
 * WHAT: Emit the CLOSE access-log line with average throughput.
 * WHY: Must run before brix_free_fhandle() clears the path and byte counters,
 * and must log the final (intended) path, never the staging temp path.
 * HOW: total bytes = written or (else) read; detail = "%.2fMB/s" over the open
 * duration, or "-" when nothing transferred / zero elapsed.
 */
static void
brix_close_log_access(brix_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    char        close_detail[64];
    size_t      br     = ctx->files[idx].bytes_read;
    size_t      bw     = ctx->files[idx].bytes_written;
    size_t      btotal = (bw > 0) ? bw : br;
    ngx_msec_t  dur    = ngx_current_msec - ctx->files[idx].open_time;
    const char *log_path;

    if (btotal > 0 && dur > 0) {
        double mbps = (double) btotal / (double) dur / 1000.0;
        snprintf(close_detail, sizeof(close_detail), "%.2fMB/s", mbps);
    } else {
        snprintf(close_detail, sizeof(close_detail), "-");
    }

    log_path = (ctx->files[idx].posc_final_path != NULL)
               ? ctx->files[idx].posc_final_path
               : ctx->files[idx].path;

    brix_log_access(ctx, c, "CLOSE", log_path, close_detail,
                      1, 0, NULL, btotal);
}

/*
 * WHAT: POSC commit — atomically publish the staging temp file onto its final
 * target path on a clean close.
 * WHY: Must run before brix_free_fhandle() clears the fields; a rename failure
 * surfaces as kXR_IOError rather than silently leaving a partial file, keeping
 * the staged partial for a client retry.
 * HOW: NGX_DECLINED = "no POSC handle, continue". Mark a durable pending marker
 * before a cross-device move, fsync+rename via brix_commit_staged(), emit the
 * unified ledger line, and clear posc_final_path on success. On failure, abort
 * the session xfer, free the handle, stash the error-send's NGX_OK in *rc and
 * return NGX_DONE.
 */
static ngx_int_t
brix_close_posc_commit(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int idx, ngx_int_t *rc)
{
    const char *temp_path;
    const char *final_path;
    ngx_flag_t  stage_tracked;

    if (ctx->files[idx].posc_final_path == NULL) {
        return NGX_DECLINED;
    }

    temp_path  = ctx->files[idx].path;
    final_path = ctx->files[idx].posc_final_path;

    /* When the partial lives on a separate stage device, record a durable
     * "complete, pending stage-out" marker BEFORE the cross-device move so a
     * worker death mid-move is recoverable: the reaper finishes the move on
     * the next startup/sweep.  Removed once the commit succeeds. */
    stage_tracked = (conf != NULL
        && conf->upload_stage_dir_canon[0] != '\0'
        && ctx->files[idx].is_resume);
    if (stage_tracked) {
        (void) brix_stage_mark_pending(temp_path, final_path, c->log);
    }

    /* Commit the staged temp onto the final path: fsync + atomic rename on
     * the same filesystem, or copy-then-rename when the staging device
     * (brix_stage_dir) differs from the storage (cross-device EXDEV). */
    /* final_mode 0: the root:// POSC temp is driver-created with the client's
     * create mode already, so leave it as-is (rename preserves it). */
    if (brix_commit_staged(ctx->files[idx].fd, temp_path, final_path,
                             0, c->log) != NGX_OK) {
        int err = errno;
        ngx_log_error(NGX_LOG_ERR, c->log, err,
                      "brix: staged commit \"%s\" -> \"%s\" failed",
                      temp_path, final_path);
        /* Keep the staged partial (resume) — only the publish failed; the
         * client can retry the close.  Surface an I/O error. */
        brix_close_finish_sess_xfer(ctx, idx, BRIX_SESS_XFER_ABORTED);
        brix_free_fhandle(ctx, idx);
        BRIX_OP_ERR(ctx, BRIX_OP_CLOSE);
        brix_xfer_finish(BRIX_XFER_STAGE, "in", final_path,
                           ctx->login.dn[0] ? ctx->login.dn : NULL, 0,
                           BRIX_XFER_COMMIT_ERR, err, c->log);
        *rc = brix_send_error(ctx, c, kXR_IOError, "staged commit failed");
        return NGX_DONE;
    }

    if (stage_tracked) {
        brix_stage_unmark_pending(temp_path);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: staged commit \"%s\" -> \"%s\" ok",
                   temp_path, final_path);

    /* Unified ledger: the root:// upload publication — the same audit line
     * S3/WebDAV PUT and the other kinds emit (this path also covers a
     * resumed upload's final commit). */
    {
        struct stat sb;
        size_t      n = (fstat(ctx->files[idx].fd, &sb) == 0
                         && S_ISREG(sb.st_mode)) ? (size_t) sb.st_size : 0;
        brix_xfer_finish(BRIX_XFER_STAGE, "in", final_path,
                           ctx->login.dn[0] ? ctx->login.dn : NULL, n,
                           BRIX_XFER_OK, 0, c->log);
    }

    return NGX_DECLINED;
}

/*
 * WHAT: Post-commit teardown — release the dashboard transfer slot and flush the
 * write-recovery journal.
 * WHY: The dashboard slot must be counted+freed and the wrts journal flushed so
 * future writes at the same offsets after a reconnect are not skipped as replays;
 * both run after a successful commit while the handle is still alive.
 * HOW: Clear posc_final_path (so brix_free_fhandle does not unlink the renamed
 * final file), then count/free any dashboard slot and brix_wrts_flush().
 */
static void
brix_close_release_slots(brix_ctx_t *ctx, int idx)
{
    /* Clear posc_final_path so brix_free_fhandle() does not unlink the
     * now-renamed final file.  This is intentionally after write-through so
     * the flush can mirror the final POSC path instead of the temp path. */
    if (ctx->files[idx].posc_final_path != NULL) {
        ngx_free(ctx->files[idx].posc_final_path);
        ctx->files[idx].posc_final_path = NULL;
    }

    if (ctx->files[idx].dashboard_slot >= 0 &&
        ngx_brix_dashboard_shm_zone != NULL)
    {
        brix_transfer_slot_count_op(ngx_brix_dashboard_shm_zone->data,
                                      ctx->files[idx].dashboard_slot,
                                      "close");
        brix_transfer_slot_free(ngx_brix_dashboard_shm_zone->data,
                                  ctx->files[idx].dashboard_slot);
        ctx->files[idx].dashboard_slot = -1;
    }

    /* Flush the write-recovery journal so future writes with the same
     * offsets after a reconnect are not mistakenly skipped as replays. */
    brix_wrts_flush(&ctx->files[idx]);
}

/*
 * WHAT: Release this user's throttle open-files slot (phase-59 W3a).
 * WHY: An open handle held a throttle open-files reservation; closing it returns
 * that slot to the user's budget.
 * HOW: When a slot is held and the server has a throttle zone, decrement it for
 * the login DN (or "anonymous"), then drop the held count.
 */
static void
brix_close_release_throttle(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_brix_srv_conf_t *tconf;

    if (ctx->throttle.open_held <= 0) {
        return;
    }
    tconf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_brix_module);
    if (tconf->throttle.zone != NULL) {
        brix_throttle_open_dec(tconf->throttle.zone,
            ctx->login.dn[0] ? ctx->login.dn : "anonymous");
    }
    ctx->throttle.open_held--;
}

ngx_int_t brix_handle_close(brix_ctx_t *ctx, ngx_connection_t *c) {
    xrdw_close_req_t req;
    ngx_stream_brix_srv_conf_t *conf;
    int idx;
    ngx_int_t rc = NGX_OK;

    xrdw_close_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    idx = (int)(unsigned char) req.fhandle[0];

    if (!brix_validate_file_handle(ctx, c, idx, "CLOSE",
                                      BRIX_OP_CLOSE, &rc)) {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXR_close handle=%d", idx);

    if (brix_close_pgw_gate(ctx, c, idx, &rc) == NGX_DONE) {
        return rc;
    }

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_brix_module);

    if (brix_close_staged_commit(ctx, c, idx, &rc) == NGX_DONE) {
        return rc;
    }

    /* §6 CNS: a data server reports a just-written file to the manager so the
     * cluster name space learns its size/mtime. Best-effort, fire-and-forget over
     * the worker's manager link; only for writable handles being closed. */
    brix_cns_emit_close(ctx, conf, idx);

    brix_close_log_access(ctx, c, idx);

    if (brix_close_posc_commit(ctx, c, conf, idx, &rc) == NGX_DONE) {
        return rc;
    }

    /* Write-through flush is part of the storage path now (Option A): a wt sd_stage
     * handle flushes to the origin on close via sd_stage_wb_close (and on kXR_sync via
     * the fsync job, which surfaces failures). The legacy run_flush loop is retired. */

    brix_close_release_slots(ctx, idx);

    brix_close_finish_sess_xfer(ctx, idx, BRIX_SESS_XFER_COMPLETE);

    brix_free_fhandle(ctx, idx);

    brix_close_release_throttle(ctx, c);

    /* A failed SYNC write-through flush means the file did not reach the origin;
     * report the close as an error so the client does not assume durability. */
    BRIX_OP_OK(ctx, BRIX_OP_CLOSE);

    return brix_send_ok(ctx, c, NULL, 0);
}
