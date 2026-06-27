/* File: done.c — Main-thread completion callback for native TPC pull
 * WHAT: Handles the thread-pool-to-event-loop handoff when a TPC pull operation completes. Restores the deferred request context, then dispatches based on reply_kind: SYNC mode sends kXR_open success response with fhandle+stat data (or error if pull failed), async mode sends open success response with file handle and optional stat block including tpc.key for xrdcp extraction. On connection close during in-flight pull, releases dst_fd, unlinks dst_path, frees fhandle slot.
 *
 * WHY: Native TPC pull runs blocking socket I/O inside a detached thread-pool worker; the nginx event loop must resume when the thread finishes because it deferred the kXR_open response. This callback bridges the thread→event-loop boundary — restoring streamid context, updating file metadata (tpc_done flag, bytes_written, cached stat info), and sending the wire response that the client is waiting for. Sync vs async reply_kind determines whether to build a full ServerOpenBody with stat data or just send an ok status code.
 *
 * HOW: ev->data = ngx_thread_task_t → extract t (xrootd_tpc_pull_t) from task→ctx → restore request context via xrootd_aio_restore_request(streamid) → if connection closed, close dst_fd + unlink dst_path + free fhandle slot → reply_kind == XROOTD_TPC_REPLY_SYNC: build ServerOpenBody with fhandle[idx] + optional statbuf (inode/size/permissions/mtime + tpc.key) via snprintf, allocate response buffer with ngx_palloc, build wire header + body via xrootd_build_resp_hdr + ngx_memcpy, queue response via xrootd_queue_response → async reply_kind: send ok status code only → xrootd_aio_resume(c) in all paths. Returns void (callback).
 * */

#include "tpc_internal.h"


#include <string.h>
#include <unistd.h>


/* WHAT: Main-thread completion callback — restore deferred request, dispatch SYNC vs async reply, build/send kXR_open response or error. */
void
xrootd_tpc_pull_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task;
    xrootd_tpc_pull_t *t;
    xrootd_ctx_t      *ctx;
    ngx_connection_t  *c;
    int                idx;

    /*
     * Re-entry point from the thread pool: nginx delivers the completion as an
     * event whose ->data is the original ngx_thread_task_t. The pull state
     * (xrootd_tpc_pull_t) lives in task->ctx; we recover ctx/connection/handle
     * from it. From here on we are back on the event thread — no blocking I/O.
     */
    task = ev->data;
    t    = task->ctx;
    ctx  = t->ctx;
    c    = t->c;
    idx  = t->fhandle_idx;

    /*
     * restore_request rebinds the deferred kXR_open streamid context. If it
     * fails the client connection went away while the pull was running in the
     * worker thread: there is nobody to reply to, so just reclaim everything
     * (fd, partially-written file, fhandle slot, registry entry) and bail —
     * no xrootd_aio_resume(), because there is no connection to resume.
     */
    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        /* Connection closed while pull was in-flight — release resources. */
        (void) xrootd_tpc_registry_update(t->transfer_id,
                                          (off_t) t->bytes_written,
                                          XROOTD_TPC_STATE_ERROR,
                                          c != NULL ? c->log : NULL);
        xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_STREAM,
                                   XROOTD_TPC_DIR_PULL,
                                   XROOTD_TPC_METRIC_ERROR,
                                   t->bytes_written,
                                   c != NULL ? c->log : NULL);
        (void) xrootd_tpc_registry_remove(t->transfer_id,
                                          c != NULL ? c->log : NULL);
        close(t->dst_fd);
        unlink(t->dst_path);
        if (idx >= 0 && idx < XROOTD_MAX_FILES) {
            ctx->files[idx].fd = -1;
            ctx->files[idx].tpc_transfer_id = 0;
            xrootd_free_fhandle(ctx, idx);
        }
        return;
    }

    /*
     * SYNC reply path: the pull was triggered by a kXR_sync on an already-open
     * destination handle (the client opened the file, then sync'd to start the
     * copy). The waiting request is the sync, so we reply with ok/error for
     * SYNC and keep the file handle open for the client to close itself.
     */
    if (t->reply_kind == XROOTD_TPC_REPLY_SYNC) {
        xrootd_file_t *file;

        /* idx may be out of range if the handle was reaped; guard before use. */
        file = (idx >= 0 && idx < XROOTD_MAX_FILES) ? &ctx->files[idx] : NULL;

        if (t->result != NGX_OK) {
            int err = t->xrd_error ? t->xrd_error : kXR_ServerError;

            /* Failed copy: discard the half-written destination. If the slot is
             * still valid, free it (which also closes the fd); otherwise close
             * the raw fd directly. Either way unlink the partial file so a
             * failed transfer never leaves a truncated object behind. */
            if (file != NULL) {
                file->fd = -1;
                file->tpc_transfer_id = 0;
                xrootd_free_fhandle(ctx, idx);
            } else {
                close(t->dst_fd);
            }
            unlink(t->dst_path);

            (void) xrootd_tpc_registry_update(t->transfer_id,
                                              (off_t) t->bytes_written,
                                              XROOTD_TPC_STATE_ERROR,
                                              c->log);
            xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_STREAM,
                                       XROOTD_TPC_DIR_PULL,
                                       XROOTD_TPC_METRIC_ERROR,
                                       t->bytes_written, c->log);
            (void) xrootd_tpc_registry_remove(t->transfer_id, c->log);

            xrootd_log_access(ctx, c, "TPC-PULL", t->dst_path, "error",
                              0, (uint16_t) err,
                              t->err_msg[0] ? t->err_msg : "TPC pull failed",
                              0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_SYNC);
            xrootd_send_error(ctx, c, (uint16_t) err,
                              t->err_msg[0] ? t->err_msg : "TPC pull failed");
            xrootd_aio_resume(c);
            return;
        }

        /* Success: mark the handle done and refresh its cached metadata from
         * the now-complete file so a subsequent stat/read on the same handle
         * sees the real size/inode without another path syscall (INVARIANT 7). */
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

        xrootd_log_access(ctx, c, "TPC-PULL", t->dst_path, "ok",
                          1, 0, NULL, t->bytes_written);
        XROOTD_OP_OK(ctx, XROOTD_OP_SYNC);
        (void) xrootd_tpc_registry_update(t->transfer_id,
                                          (off_t) t->bytes_written,
                                          XROOTD_TPC_STATE_DONE, c->log);
        xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_STREAM,
                                   XROOTD_TPC_DIR_PULL,
                                   XROOTD_TPC_METRIC_SUCCESS,
                                   t->bytes_written, c->log);
        (void) xrootd_tpc_registry_remove(t->transfer_id, c->log);
        xrootd_send_ok(ctx, c, NULL, 0);
        xrootd_aio_resume(c);
        return;
    }

    /*
     * Async reply path (reply_kind != SYNC): the pull was kicked off directly
     * from the kXR_open, so the deferred request awaiting us is the OPEN. We
     * therefore reply with the kXR_open result and tear the handle down
     * ourselves on failure (the client never got a usable fhandle).
     */
    if (t->result != NGX_OK) {
        int err = t->xrd_error ? t->xrd_error : kXR_ServerError;

        /* Failed copy: close+unlink the partial destination and release the
         * fhandle slot before replying with the error to the OPEN. */
        close(t->dst_fd);
        unlink(t->dst_path);
        ctx->files[idx].fd = -1;
        ctx->files[idx].tpc_transfer_id = 0;
        xrootd_free_fhandle(ctx, idx);

        (void) xrootd_tpc_registry_update(t->transfer_id,
                                          (off_t) t->bytes_written,
                                          XROOTD_TPC_STATE_ERROR, c->log);
        xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_STREAM,
                                   XROOTD_TPC_DIR_PULL,
                                   XROOTD_TPC_METRIC_ERROR,
                                   t->bytes_written, c->log);
        (void) xrootd_tpc_registry_remove(t->transfer_id, c->log);

        xrootd_log_access(ctx, c, "TPC-PULL", t->dst_path, "error",
                          0, (uint16_t) err,
                          t->err_msg[0] ? t->err_msg : "TPC pull failed", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
        xrootd_send_error(ctx, c, (uint16_t) err,
                          t->err_msg[0] ? t->err_msg : "TPC pull failed");
        xrootd_aio_resume(c);
        return;
    }

    xrootd_log_access(ctx, c, "TPC-PULL", t->dst_path, "ok", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_OPEN_WR);
    if (idx >= 0 && idx < XROOTD_MAX_FILES) {
        ctx->files[idx].tpc_transfer_id = 0;
    }
    (void) xrootd_tpc_registry_update(t->transfer_id,
                                      (off_t) t->bytes_written,
                                      XROOTD_TPC_STATE_DONE, c->log);
    xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_STREAM,
                               XROOTD_TPC_DIR_PULL,
                               XROOTD_TPC_METRIC_SUCCESS,
                               t->bytes_written, c->log);
    (void) xrootd_tpc_registry_remove(t->transfer_id, c->log);

    /*
     * Success, async path: build the deferred kXR_open ok response.
     * Body layout: fixed ServerOpenBody (carries the 1-byte fhandle index)
     * optionally followed by a NUL-terminated ASCII stat/tpc.key trailer.
     * `bodylen` is grown to cover the trailer before allocating; the wire
     * header's dlen must equal bodylen (header length is added separately).
     */
    {
        ServerOpenBody  body_s;
        struct stat     st;
        char            statbuf[256];
        size_t          bodylen, total;
        u_char         *buf;
        ngx_flag_t      want_stat;

        want_stat = (t->options & kXR_retstat) ? 1 : 0;
        bodylen   = sizeof(ServerOpenBody);
        statbuf[0] = '\0';

        if (fstat(t->dst_fd, &st) == 0) {
            /* xrootd stat flags are derived from POSIX mode bits. */
            int sf = 0;
            if (st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) { sf |= kXR_readable; }
            if (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) { sf |= kXR_writable; }

            /*
             * Three trailer shapes depending on what the client asked for and
             * whether we have a tpc.key:
             *   retstat + key  -> "ino size flags mtime\ntpc.key=KEY"
             *   retstat only   -> "ino size flags mtime"
             *   key only       -> "\ntpc.key=KEY" (so xrdcp can still scrape the
             *                      key even though it didn't request a stat)
             */
            if (want_stat && t->tpc_key[0] != '\0') {
                snprintf(statbuf, sizeof(statbuf), "%llu %lld %d %ld\ntpc.key=%s",
                         (unsigned long long) st.st_ino, (long long) st.st_size,
                         sf, (long) st.st_mtime, t->tpc_key);
            } else if (want_stat) {
                snprintf(statbuf, sizeof(statbuf), "%llu %lld %d %ld",
                         (unsigned long long) st.st_ino, (long long) st.st_size,
                         sf, (long) st.st_mtime);
            } else if (t->tpc_key[0] != '\0') {
                /* Include key even without kXR_retstat so xrdcp can extract it. */
                snprintf(statbuf, sizeof(statbuf), "\ntpc.key=%s", t->tpc_key);
            }

            /* +1 for the NUL terminator that the trailer carries on the wire. */
            if (statbuf[0] != '\0') {
                bodylen += strlen(statbuf) + 1;
            }
        }

        total = XRD_RESPONSE_HDR_LEN + bodylen;
        buf   = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            xrootd_send_error(ctx, c, kXR_NoMemory, "alloc failed");
            xrootd_aio_resume(c);
            return;
        }

        /* Assemble buf in wire order: [response header][ServerOpenBody][trailer].
         * The header is written first with dlen=bodylen; the body follows at
         * the fixed header offset, and the optional trailer (with its NUL) is
         * appended immediately after the body. */
        xrootd_build_resp_hdr(t->streamid, kXR_ok, (uint32_t) bodylen,
                              (ServerResponseHdr *) buf);

        ngx_memzero(&body_s, sizeof(body_s));
        body_s.fhandle[0] = (u_char) idx;
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body_s, sizeof(body_s));

        if (statbuf[0]) {
            size_t slen = strlen(statbuf) + 1; /* include NUL terminator */
            ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                       statbuf, slen);
        }

        xrootd_queue_response(ctx, c, buf, total);
    }

    xrootd_aio_resume(c);
}
