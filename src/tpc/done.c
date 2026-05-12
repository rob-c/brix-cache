#include "tpc_internal.h"

#if (NGX_THREADS)

#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Main-thread completion callback: sends kXR_open response or error     */
/* ------------------------------------------------------------------ */

void
xrootd_tpc_pull_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task;
    xrootd_tpc_pull_t *t;
    xrootd_ctx_t      *ctx;
    ngx_connection_t  *c;
    int                idx;

    task = ev->data;
    t    = task->ctx;
    ctx  = t->ctx;
    c    = t->c;
    idx  = t->fhandle_idx;

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        /* Connection closed while pull was in-flight — release resources. */
        close(t->dst_fd);
        unlink(t->dst_path);
        if (idx >= 0 && idx < XROOTD_MAX_FILES) {
            ctx->files[idx].fd = -1;
            xrootd_free_fhandle(ctx, idx);
        }
        return;
    }

    if (t->reply_kind == XROOTD_TPC_REPLY_SYNC) {
        xrootd_file_t *file;

        file = (idx >= 0 && idx < XROOTD_MAX_FILES) ? &ctx->files[idx] : NULL;

        if (t->result != NGX_OK) {
            int err = t->xrd_error ? t->xrd_error : kXR_ServerError;

            if (file != NULL) {
                file->fd = -1;
                xrootd_free_fhandle(ctx, idx);
            } else {
                close(t->dst_fd);
            }
            unlink(t->dst_path);

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

        if (file != NULL) {
            struct stat st;

            file->tpc_done = 1;
            file->tpc_started = 0;
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
        xrootd_send_ok(ctx, c, NULL, 0);
        xrootd_aio_resume(c);
        return;
    }

    if (t->result != NGX_OK) {
        int err = t->xrd_error ? t->xrd_error : kXR_ServerError;

        close(t->dst_fd);
        unlink(t->dst_path);
        ctx->files[idx].fd = -1;
        xrootd_free_fhandle(ctx, idx);

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

    /* Build and send the kXR_open success response. */
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
            int sf = 0;
            if (st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) { sf |= kXR_readable; }
            if (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) { sf |= kXR_writable; }

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

        xrootd_build_resp_hdr(t->streamid, kXR_ok, (uint32_t) bodylen,
                              (ServerResponseHdr *) buf);

        ngx_memzero(&body_s, sizeof(body_s));
        body_s.fhandle[0] = (u_char) idx;
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body_s, sizeof(body_s));

        if (statbuf[0]) {
            size_t slen = strlen(statbuf) + 1;
            ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                       statbuf, slen);
        }

        xrootd_queue_response(ctx, c, buf, total);
    }

    xrootd_aio_resume(c);
}

#endif /* NGX_THREADS */
