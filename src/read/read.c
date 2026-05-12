#include "read.h"

#include "../ngx_xrootd_module.h"
#include "prefetch.h"

ngx_int_t
xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientReadRequest            *req = (ClientReadRequest *) ctx->hdr_buf;
    int                           idx;
    int64_t                       offset;
    size_t                        rlen;
    u_char                       *databuf;
    ssize_t                       nread;
    size_t                        data_total;
    u_char                       *send_base = NULL;
    ngx_chain_t                  *rsp_chain;
    ngx_stream_xrootd_srv_conf_t *rconf;
    int                           fd;
    ngx_int_t                     rc;

    idx = (int) (unsigned char) req->fhandle[0];
    offset = (int64_t) be64toh((uint64_t) req->offset);
    rlen = (size_t) (uint32_t) ntohl((uint32_t) req->rlen);

    if (!xrootd_validate_read_handle(ctx, c, idx, "READ",
                                     XROOTD_OP_READ, &rc)) {
        return rc;
    }

    if (rlen == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    if (rlen > XROOTD_READ_REQUEST_MAX) {
        rlen = XROOTD_READ_REQUEST_MAX;
    }

    fd = ctx->files[idx].fd;

    if (offset < 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_READ, "READ",
                          ctx->files[idx].path, "-",
                          kXR_IOError, "negative read offset");
    }

    rconf = ngx_stream_get_module_srv_conf(
                (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);

    if (ctx->files[idx].is_regular && !c->ssl) {
        off_t file_size;
        off_t avail;

        /*
         * Read-only handles: file size is stable, use the value cached at open
         * time to skip the fstat(2) syscall on every chunk request.
         * Writable handles (kXR_open_updt): re-stat so a write on the same
         * session is visible to subsequent reads.
         */
        if (!ctx->files[idx].writable) {
            file_size = ctx->files[idx].cached_size;
        } else {
            struct stat st;
            if (fstat(fd, &st) != 0) {
                XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_READ, "READ",
                                  ctx->files[idx].path, "-",
                                  kXR_IOError, strerror(errno));
            }
            file_size = st.st_size;
        }

        if ((off_t) offset >= file_size) {
            data_total = 0;
        } else {
            avail = file_size - (off_t) offset;
            data_total = (avail < (off_t) rlen) ? (size_t) avail : rlen;
        }

        xrootd_prefetch_read_file(c->log, &ctx->files[idx], (off_t) offset,
                                  data_total, file_size);

        ctx->files[idx].bytes_read += data_total;
        ctx->session_bytes += data_total;

        if (rconf->access_log_fd != NGX_INVALID_FILE) {
            char read_detail[64];

            snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                     (long long) offset, rlen);
            xrootd_log_access(ctx, c, "READ", ctx->files[idx].path,
                              read_detail, 1, 0, NULL, data_total);
        }
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);

        rsp_chain = xrootd_build_sendfile_chain(ctx, c, fd,
                                                ctx->files[idx].path,
                                                (off_t) offset, data_total,
                                                &send_base);
        if (rsp_chain == NULL) {
            xrootd_release_read_buffer(ctx, c, send_base);
            return NGX_ERROR;
        }

        {
            ngx_int_t rc = xrootd_queue_response_chain(ctx, c, rsp_chain,
                                                       send_base);

            if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
                xrootd_release_read_buffer(ctx, c, send_base);
            }
            return rc;
        }
    }

    databuf = xrootd_get_read_scratch(ctx, c, rlen);
    if (databuf == NULL) {
        return NGX_ERROR;
    }

    if (ctx->files[idx].is_regular) {
        off_t  file_size;
        size_t hint_len;

        file_size = ctx->files[idx].writable ? 0
                                              : ctx->files[idx].cached_size;
        hint_len = rlen;

        if (file_size > 0) {
            if ((off_t) offset >= file_size) {
                hint_len = 0;
            } else if ((off_t) hint_len > file_size - (off_t) offset) {
                hint_len = (size_t) (file_size - (off_t) offset);
            }
        }

        xrootd_prefetch_read_file(c->log, &ctx->files[idx], (off_t) offset,
                                  hint_len, file_size);
    }

#if (NGX_THREADS)
    if (rconf->thread_pool != NULL) {
        ngx_thread_task_t *task;
        xrootd_read_aio_t *t;
        ngx_flag_t         posted;

        task = ctx->read_aio_task;
        if (task == NULL) {
            task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_read_aio_t));
            if (task == NULL) {
                xrootd_release_read_buffer(ctx, c, databuf);
                return NGX_ERROR;
            }
            ctx->read_aio_task = task;
        } else {
            task->next = NULL;
            task->event.complete = 0;
        }

        t = task->ctx;
        t->c = c;
        t->ctx = ctx;
        t->fd = fd;
        t->handle_idx = idx;
        t->offset = (off_t) offset;
        t->rlen = rlen;
        t->databuf = databuf;
        t->streamid[0] = ctx->cur_streamid[0];
        t->streamid[1] = ctx->cur_streamid[1];
        t->nread = 0;
        t->io_errno = 0;

        task->handler = xrootd_read_aio_thread;
        task->event.handler = xrootd_read_aio_done;
        task->event.data = task;

        (void) xrootd_aio_post_task(ctx, c, rconf->thread_pool, task,
                                    "xrootd: thread_task_post failed, sync read fallback",
                                    &posted);
        if (posted) {
            return NGX_OK;
        }
    }
#endif

    nread = pread(fd, databuf, rlen, (off_t) offset);
    if (nread < 0) {
        xrootd_release_read_buffer(ctx, c, databuf);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_READ, "READ",
                          ctx->files[idx].path, "-",
                          kXR_IOError, strerror(errno));
    }

    data_total = (size_t) nread;

    ctx->files[idx].bytes_read += data_total;
    ctx->session_bytes += data_total;

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char read_detail[64];

        snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                 (long long) offset, rlen);
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path,
                          read_detail, 1, 0, NULL, data_total);
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_READ);

    rsp_chain = xrootd_build_chunked_chain(ctx, c, databuf, data_total);
    if (rsp_chain == NULL) {
        xrootd_release_read_buffer(ctx, c, databuf);
        return NGX_ERROR;
    }

    {
        ngx_int_t rc = xrootd_queue_response_chain(ctx, c, rsp_chain, databuf);

        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            xrootd_release_read_buffer(ctx, c, databuf);
        }
        return rc;
    }
}
