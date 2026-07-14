/* File: done.c — Main-thread completion callback for native TPC pull
 * WHAT: Handles the thread-pool-to-event-loop handoff when a TPC pull operation completes. Restores the deferred request context, then dispatches based on reply_kind: SYNC mode sends kXR_open success response with fhandle+stat data (or error if pull failed), async mode sends open success response with file handle and optional stat block including tpc.key for xrdcp extraction. On connection close during in-flight pull, releases dst_fd, unlinks dst_path, frees fhandle slot.
 *
 * WHY: Native TPC pull runs blocking socket I/O inside a detached thread-pool worker; the nginx event loop must resume when the thread finishes because it deferred the kXR_open response. This callback bridges the thread→event-loop boundary — restoring streamid context, updating file metadata (tpc_done flag, bytes_written, cached stat info), and sending the wire response that the client is waiting for. Sync vs async reply_kind determines whether to build a full ServerOpenBody with stat data or just send an ok status code.
 *
 * HOW: ev->data = ngx_thread_task_t → extract t (brix_tpc_pull_t) from task→ctx → restore request context via brix_aio_restore_request(streamid) → if connection closed, close dst_fd + unlink dst_path + free fhandle slot → reply_kind == BRIX_TPC_REPLY_SYNC: build ServerOpenBody with fhandle[idx] + optional statbuf (inode/size/permissions/mtime + tpc.key) via snprintf, allocate response buffer with ngx_palloc, build wire header + body via brix_build_resp_hdr + ngx_memcpy, queue response via brix_queue_response → async reply_kind: send ok status code only → brix_aio_resume(c) in all paths. Returns void (callback).
 * */

#include "tpc_internal.h"
#include "fs/vfs/vfs.h"   /* confined unlink of the export destination */
#include "observability/sesslog/sesslog_ngx.h"

#include <string.h>
#include <unistd.h>

static void
tpc_sess_finish_pull(brix_tpc_pull_t *t, int ok, brix_sess_end_t why)
{
    char        errscratch[BRIX_SESSLOG_ERR_MAX];
    const char *err;

    if (t == NULL) {
        return;
    }

    err = ok ? NULL : brix_sesslog_err_from_kxr(
        t->xrd_error ? t->xrd_error : kXR_ServerError,
        errscratch, sizeof(errscratch));
    brix_sess_xfer_add(&t->sess_xfer, t->bytes_written);
    brix_sess_result(t->sess, ok, t->src_path, BRIX_SESS_MODE_READ, err);
    brix_sess_xfer_end(t->sess, &t->sess_xfer,
                       ok ? BRIX_SESS_XFER_COMPLETE
                          : BRIX_SESS_XFER_ABORTED);
    brix_sess_end(t->sess, why);
    t->sess = NULL;
}

/* WHAT: Finish transfer accounting — registry state update, TPC metric, registry remove.
 * WHY: Every completion path (orphaned, connection-gone, sync ok/fail, async ok/fail)
 *      performs exactly this triple with the same log target; centralizing it keeps the
 *      registry and metrics in lockstep across all outcomes.
 * HOW: ok selects DONE+SUCCESS vs ERROR+ERROR; bytes_written is reported both to the
 *      registry (as offset) and to the metric, then the registry entry is removed. */
static void
tpc_done_account(brix_tpc_pull_t *t, int ok, ngx_log_t *log)
{
    (void) brix_tpc_registry_update(t->transfer_id,
                                      (off_t) t->bytes_written,
                                      ok ? BRIX_TPC_STATE_DONE
                                         : BRIX_TPC_STATE_ERROR, log);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_STREAM,
                               BRIX_TPC_DIR_PULL,
                               ok ? BRIX_TPC_METRIC_SUCCESS
                                  : BRIX_TPC_METRIC_ERROR,
                               t->bytes_written, log);
    (void) brix_tpc_registry_remove(t->transfer_id, log);
}

/* WHAT: Reclaim the destination of a failed/abandoned pull — close fd, unlink the
 *       partial file, release the fhandle slot when a live ctx still owns one.
 * WHY: A failed transfer must never leave a truncated object or a leaked fd/fhandle
 *      behind; the same close→unlink→slot-free sequence is shared by the orphaned,
 *      connection-gone and async-failure paths.
 * HOW: close(dst_fd) then confined unlink of dst_path under root_canon; if ctx is
 *      still present and idx is a valid slot, clear fd/transfer_id and free the
 *      fhandle (fd already -1, so the free cannot double-close). Pass ctx=NULL when
 *      there is no fhandle table to touch. */
static void
tpc_done_teardown_dst(brix_tpc_pull_t *t, brix_ctx_t *ctx, int idx,
                      ngx_log_t *log)
{
    close(t->dst_fd);
    (void) brix_vfs_unlink_path(log, t->conf->common.root_canon,
                                  t->dst_path);
    if (ctx != NULL && idx >= 0 && idx < BRIX_MAX_FILES) {
        ctx->files[idx].fd = -1;
        ctx->files[idx].tpc_transfer_id = 0;
        brix_free_fhandle(ctx, idx);
    }
}

/* WHAT: SYNC-mode failure reply — discard the half-written destination, account the
 *       error, and answer the waiting kXR_sync with the pull's error code.
 * WHY: In SYNC mode the client already holds the open handle; on failure we must
 *      free the slot (or close the raw fd if the slot was reaped) and unlink the
 *      partial file so a failed transfer never leaves a truncated object behind.
 * HOW: slot-free XOR raw close depending on whether the handle survived, confined
 *      unlink, then registry/metric accounting and the error response + aio resume.
 *      c is never NULL here: brix_tpc_pull_done gates the no-connection case before
 *      dispatching to any reply helper. */
static void
tpc_done_sync_fail(brix_tpc_pull_t *t, brix_ctx_t *ctx, ngx_connection_t *c,
                   int idx)
{
    brix_file_t *file;
    int          err = t->xrd_error ? t->xrd_error : kXR_ServerError;

    /* idx may be out of range if the handle was reaped; guard before use. */
    file = (idx >= 0 && idx < BRIX_MAX_FILES) ? &ctx->files[idx] : NULL;

    tpc_sess_finish_pull(t, 0, BRIX_SESS_END_ERROR);

    /* Failed copy: discard the half-written destination. If the slot is
     * still valid, free it (which also closes the fd); otherwise close
     * the raw fd directly. Either way unlink the partial file so a
     * failed transfer never leaves a truncated object behind. */
    if (file != NULL) {
        file->fd = -1;
        file->tpc_transfer_id = 0;
        brix_free_fhandle(ctx, idx);
    } else {
        close(t->dst_fd);
    }
    (void) brix_vfs_unlink_path(c->log, t->conf->common.root_canon, t->dst_path);

    tpc_done_account(t, 0, c->log);

    brix_log_access(ctx, c, "TPC-PULL", t->dst_path, "error",
                      0, (uint16_t) err,
                      t->err_msg[0] ? t->err_msg : "TPC pull failed",
                      0);
    BRIX_OP_ERR(ctx, BRIX_OP_SYNC);
    brix_send_error(ctx, c, (uint16_t) err,
                      t->err_msg[0] ? t->err_msg : "TPC pull failed");
    brix_aio_resume(c);
}

/* WHAT: SYNC-mode reply — the waiting request is a kXR_sync on an already-open
 *       destination handle; answer it with ok/error and keep the handle open.
 * WHY: The pull was triggered by a kXR_sync (the client opened the file, then
 *      sync'd to start the copy), so the client closes the handle itself; on
 *      success we refresh the handle's cached metadata from the completed file.
 * HOW: failure delegates to tpc_done_sync_fail; success marks the handle done,
 *      accumulates bytes_written, fstat-refreshes cached size/inode so subsequent
 *      stat/read on the handle needs no path syscall (INVARIANT 7), then accounts
 *      the transfer and sends ok + aio resume. */
static void
tpc_done_reply_sync(brix_tpc_pull_t *t, brix_ctx_t *ctx, ngx_connection_t *c,
                    int idx)
{
    brix_file_t *file;

    if (t->result != NGX_OK) {
        tpc_done_sync_fail(t, ctx, c, idx);
        return;
    }

    /* idx may be out of range if the handle was reaped; guard before use. */
    file = (idx >= 0 && idx < BRIX_MAX_FILES) ? &ctx->files[idx] : NULL;

    /* Success: mark the handle done and refresh its cached metadata from
     * the now-complete file so a subsequent stat/read on the same handle
     * sees the real size/inode without another path syscall (INVARIANT 7). */
    tpc_sess_finish_pull(t, 1, BRIX_SESS_END_SERVER);
    if (file != NULL) {
        struct stat st;

        file->tpc_done = 1;
        file->tpc_started = 0;
        file->tpc_transfer_id = 0;
        file->bytes_written += t->bytes_written;

        if (fstat(file->fd, &st) == 0) {
            file->cached_size = (off_t) st.st_size;
            file->device = st.st_dev;
            file->inode = st.st_ino;
            file->is_regular = S_ISREG(st.st_mode) ? 1 : 0;
        }
    }

    brix_log_access(ctx, c, "TPC-PULL", t->dst_path, "ok",
                      1, 0, NULL, t->bytes_written);
    BRIX_OP_OK(ctx, BRIX_OP_SYNC);
    tpc_done_account(t, 1, c->log);
    brix_send_ok(ctx, c, NULL, 0);
    brix_aio_resume(c);
}

/* WHAT: Format the optional ASCII stat/tpc.key trailer for the kXR_open ok body.
 * WHY: xrdcp scrapes tpc.key from the open response, and kXR_retstat clients need
 *      the "ino size flags mtime" stat line; the trailer shape depends on which of
 *      the two the client can consume.
 * HOW: fstat(dst_fd) → derive xrootd readable/writable flags from POSIX mode bits →
 *      snprintf one of three trailer shapes:
 *        retstat + key  -> "ino size flags mtime\ntpc.key=KEY"
 *        retstat only   -> "ino size flags mtime"
 *        key only       -> "\ntpc.key=KEY" (so xrdcp can still scrape the key even
 *                          though it didn't request a stat)
 *      On fstat failure or neither-wanted, statbuf stays empty. */
static void
tpc_done_stat_trailer(brix_tpc_pull_t *t, char *statbuf, size_t buflen)
{
    struct stat st;
    ngx_flag_t  want_stat = (t->options & kXR_retstat) ? 1 : 0;
    int         sf = 0;

    statbuf[0] = '\0';

    if (fstat(t->dst_fd, &st) != 0) {
        return;
    }

    /* xrootd stat flags are derived from POSIX mode bits. */
    if (st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) { sf |= kXR_readable; }
    if (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) { sf |= kXR_writable; }

    if (want_stat && t->tpc_key[0] != '\0') {
        snprintf(statbuf, buflen, "%llu %lld %d %ld\ntpc.key=%s",
                 (unsigned long long) st.st_ino, (long long) st.st_size,
                 sf, (long) st.st_mtime, t->tpc_key);
    } else if (want_stat) {
        snprintf(statbuf, buflen, "%llu %lld %d %ld",
                 (unsigned long long) st.st_ino, (long long) st.st_size,
                 sf, (long) st.st_mtime);
    } else if (t->tpc_key[0] != '\0') {
        /* Include key even without kXR_retstat so xrdcp can extract it. */
        snprintf(statbuf, buflen, "\ntpc.key=%s", t->tpc_key);
    }
}

/* WHAT: Build and queue the deferred kXR_open ok response for the async path.
 * WHY: The client's OPEN was deferred while the pull ran in the worker thread;
 *      it now needs the ServerOpenBody carrying its fhandle index, plus the
 *      optional stat/tpc.key trailer so xrdcp can extract the key.
 * HOW: Body layout: fixed ServerOpenBody (carries the 1-byte fhandle index)
 *      optionally followed by a NUL-terminated ASCII stat/tpc.key trailer.
 *      `bodylen` is grown to cover the trailer before allocating; the wire
 *      header's dlen must equal bodylen (header length is added separately).
 *      Assemble buf in wire order: [response header][ServerOpenBody][trailer] —
 *      header first with dlen=bodylen, body at the fixed header offset, optional
 *      trailer (with its NUL) appended immediately after the body — then queue
 *      it and resume the connection. Alloc failure replies kXR_NoMemory. */
static void
tpc_done_send_open_ok(brix_tpc_pull_t *t, brix_ctx_t *ctx,
                      ngx_connection_t *c, int idx)
{
    ServerOpenBody  body_s;
    char            statbuf[256];
    size_t          bodylen, total;
    u_char         *buf;

    tpc_done_stat_trailer(t, statbuf, sizeof(statbuf));

    bodylen = sizeof(ServerOpenBody);
    /* +1 for the NUL terminator that the trailer carries on the wire. */
    if (statbuf[0] != '\0') {
        bodylen += strlen(statbuf) + 1;
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        brix_send_error(ctx, c, kXR_NoMemory, "alloc failed");
        brix_aio_resume(c);
        return;
    }

    brix_build_resp_hdr(t->streamid, kXR_ok, (uint32_t) bodylen,
                          (ServerResponseHdr *) buf);

    ngx_memzero(&body_s, sizeof(body_s));
    body_s.fhandle[0] = (u_char) idx;
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body_s, sizeof(body_s));

    if (statbuf[0]) {
        size_t slen = strlen(statbuf) + 1; /* include NUL terminator */
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                   statbuf, slen);
    }

    brix_queue_response(ctx, c, buf, total);
    brix_aio_resume(c);
}

/* WHAT: Async-mode reply — the deferred request is the kXR_open itself; answer
 *       it with the pull result, tearing the handle down ourselves on failure.
 * WHY: The pull was kicked off directly from the kXR_open, so on failure the
 *      client never got a usable fhandle — we must close+unlink the partial
 *      destination and release the slot before replying with the error.
 * HOW: failure: session finish, destination teardown, accounting, access log,
 *      error response, aio resume. success: session finish, access log, clear
 *      the slot's transfer id, accounting, then build/queue the open ok
 *      response (with stat/tpc.key trailer) via tpc_done_send_open_ok. */
static void
tpc_done_reply_open(brix_tpc_pull_t *t, brix_ctx_t *ctx, ngx_connection_t *c,
                    int idx)
{
    if (t->result != NGX_OK) {
        int err = t->xrd_error ? t->xrd_error : kXR_ServerError;

        tpc_sess_finish_pull(t, 0, BRIX_SESS_END_ERROR);

        /* Failed copy: close+unlink the partial destination and release the
         * fhandle slot before replying with the error to the OPEN. (c is never
         * NULL here — brix_tpc_pull_done gates the no-connection case.) */
        tpc_done_teardown_dst(t, ctx, idx, c->log);

        tpc_done_account(t, 0, c->log);

        brix_log_access(ctx, c, "TPC-PULL", t->dst_path, "error",
                          0, (uint16_t) err,
                          t->err_msg[0] ? t->err_msg : "TPC pull failed", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_OPEN_WR);
        brix_send_error(ctx, c, (uint16_t) err,
                          t->err_msg[0] ? t->err_msg : "TPC pull failed");
        brix_aio_resume(c);
        return;
    }

    tpc_sess_finish_pull(t, 1, BRIX_SESS_END_SERVER);
    brix_log_access(ctx, c, "TPC-PULL", t->dst_path, "ok", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_OPEN_WR);
    if (idx >= 0 && idx < BRIX_MAX_FILES) {
        ctx->files[idx].tpc_transfer_id = 0;
    }
    tpc_done_account(t, 1, c->log);

    tpc_done_send_open_ok(t, ctx, c, idx);
}

/* WHAT: Main-thread completion callback — restore deferred request, dispatch SYNC vs async reply, build/send kXR_open response or error. */
void
brix_tpc_pull_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task;
    brix_tpc_pull_t *t;
    brix_ctx_t      *ctx;
    ngx_connection_t  *c;
    int                idx;

    /*
     * Re-entry point from the thread pool: nginx delivers the completion as an
     * event whose ->data is the original ngx_thread_task_t. The pull state
     * (brix_tpc_pull_t) lives in task->ctx; we recover ctx/connection/handle
     * from it. From here on we are back on the event thread — no blocking I/O.
     */
    task = ev->data;
    t    = task->ctx;
    ctx  = t->ctx;
    c    = t->c;
    idx  = t->fhandle_idx;

    /*
     * Defensive: the pull state can outlive its session/connection (the worker
     * thread completes after a teardown). With no ctx/connection there is
     * nobody to reply to and no fhandle table to touch — finish the transfer
     * bookkeeping against the cycle log and reclaim the destination.
     */
    if (ctx == NULL || c == NULL) {
        ngx_log_t *log = (c != NULL) ? c->log : ngx_cycle->log;

        tpc_sess_finish_pull(t, 0, BRIX_SESS_END_ERROR);
        tpc_done_account(t, 0, log);
        tpc_done_teardown_dst(t, NULL, idx, log);
        return;
    }

    /*
     * restore_request rebinds the deferred kXR_open streamid context. If it
     * fails the client connection went away while the pull was running in the
     * worker thread: there is nobody to reply to, so just reclaim everything
     * (fd, partially-written file, fhandle slot, registry entry) and bail —
     * no brix_aio_resume(), because there is no connection to resume.
     */
    if (!brix_aio_restore_request(ctx, t->streamid)) {
        tpc_sess_finish_pull(t, t->result == NGX_OK,
                             t->result == NGX_OK ? BRIX_SESS_END_SERVER
                                                 : BRIX_SESS_END_ERROR);
        /* Connection closed while pull was in-flight — release resources. */
        tpc_done_account(t, 0, c->log);
        tpc_done_teardown_dst(t, ctx, idx, c->log);
        return;
    }

    /*
     * SYNC reply path: the pull was triggered by a kXR_sync on an already-open
     * destination handle (the client opened the file, then sync'd to start the
     * copy). The waiting request is the sync, so we reply with ok/error for
     * SYNC and keep the file handle open for the client to close itself.
     *
     * Async reply path (reply_kind != SYNC): the pull was kicked off directly
     * from the kXR_open, so the deferred request awaiting us is the OPEN.
     */
    if (t->reply_kind == BRIX_TPC_REPLY_SYNC) {
        tpc_done_reply_sync(t, ctx, c, idx);
    } else {
        tpc_done_reply_open(t, ctx, c, idx);
    }
}
