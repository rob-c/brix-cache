/*
 * slice_read.c — Phase 26 Step D: stream-plane slice-cache open and read.
 *
 * Slice caching keeps the existing whole-file cache untouched and adds a
 * read-time path used only when xrootd_cache_slice > 0:
 *
 *   open  (xrootd_open_slice_handle): schedule an async fill of slice 0 (which
 *         also yields the origin file size); the done callback registers a
 *         slice-mode handle (fd points at /dev/null as a "slot in use" sentinel)
 *         and sends the kXR_open response carrying the real size.
 *
 *   read  (xrootd_read_from_slices): enumerate the slices covering the request;
 *         on a full hit, stitch the bytes from the slice files; on a miss,
 *         schedule a fill for the first missing slice and suspend the request,
 *         re-entering after the fill lands.
 *
 * All fills reuse xrootd_cache_slice_fill_thread (slice_fill.c) and the existing
 * AIO suspend/resume machinery, so the client connection stays alive (and its
 * pool valid) for the duration of every fill task.
 */

#include "slice_read.h"
#include "open.h"
#include "../cache/cache_internal.h"
#include "../cache/slice.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "../compat/alloc_guard.h"


/*
 * Allocate and populate a slice fill task, then post it to the thread pool.
 * The task keeps the client refs (c/ctx/streamid) so its done callback can
 * resume the suspended request.  read_idx/read_offset/read_rlen carry the
 * original kXR_read so the read handler can be re-entered after the fill.
 */
static ngx_int_t
slice_post_fill(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf,
    const char *clean_path, const char *file_cache_path,
    ngx_uint_t slice_idx, size_t slice_size, uint16_t options,
    int read_idx, off_t read_offset, size_t read_rlen,
    void (*done)(ngx_event_t *ev))
{
    ngx_thread_task_t   *task;
    xrootd_cache_fill_t *t;

    if (conf->common.thread_pool == NULL) {
        return NGX_DECLINED;
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_cache_fill_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    ngx_memzero(t, sizeof(*t));
    t->c          = c;
    t->ctx        = ctx;
    t->conf       = conf;
    t->options    = options;
    t->streamid[0] = ctx->cur_streamid[0];
    t->streamid[1] = ctx->cur_streamid[1];
    t->slice_start = (off_t) slice_idx * (off_t) slice_size;
    t->slice_len   = (off_t) slice_size;
    t->slice_read_idx    = read_idx;
    t->slice_read_offset = read_offset;
    t->slice_read_rlen   = read_rlen;

    ngx_cpystrn((u_char *) t->clean_path, (u_char *) clean_path,
                sizeof(t->clean_path));
    ngx_cpystrn((u_char *) t->file_cache_path, (u_char *) file_cache_path,
                sizeof(t->file_cache_path));

    if (xrootd_slice_path(file_cache_path, slice_size, slice_idx,
                          t->cache_path, sizeof(t->cache_path)) != NGX_OK
        || xrootd_cache_append_suffix(t->part_path, sizeof(t->part_path),
                                      t->cache_path,
                                      XROOTD_CACHE_PART_SUFFIX) != 0
        || xrootd_cache_append_suffix(t->lock_path, sizeof(t->lock_path),
                                      t->cache_path,
                                      XROOTD_CACHE_LOCK_SUFFIX) != 0)
    {
        return NGX_ERROR;
    }

    xrootd_task_bind(task, xrootd_cache_slice_fill_thread, done);

    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* -------------------------------------------------------------------------
 * Open path
 * ---------------------------------------------------------------------- */

static ngx_int_t
slice_send_open_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int idx, off_t file_size, uint16_t options)
{
    ServerOpenBody  body;
    char            statbuf[256];
    size_t          bodylen, total;
    u_char         *buf;
    ngx_flag_t      want_stat = (options & kXR_retstat) ? 1 : 0;

    statbuf[0] = '\0';
    if (want_stat) {
        int stat_flags = kXR_readable | kXR_cachersp;
        snprintf(statbuf, sizeof(statbuf), "%llu %lld %d %ld",
                 0ULL, (long long) file_size, stat_flags, (long) 0);
    }

    bodylen = sizeof(ServerOpenBody);
    if (want_stat) {
        bodylen += strlen(statbuf) + 1;
    }
    total = XRD_RESPONSE_HDR_LEN + bodylen;

    XROOTD_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, (uint32_t) bodylen,
                          (ServerResponseHdr *) buf);

    ngx_memzero(&body, sizeof(body));
    body.fhandle[0] = (u_char) idx;
    body.cpsize     = 0;
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    if (want_stat) {
        size_t slen = strlen(statbuf) + 1;
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                   statbuf, slen);
    }

    return xrootd_queue_response(ctx, c, buf, total);
}


/* Completion of the slice-0 open fill: register the slice handle, respond. */
static void
xrootd_slice_open_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    xrootd_cache_fill_t *t    = task->ctx;
    xrootd_ctx_t        *ctx  = t->ctx;
    ngx_connection_t    *c    = t->c;
    int                  idx;
    xrootd_file_t       *f;
    int                  devnull;

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->result != NGX_OK) {
        int err = t->xrd_error ? t->xrd_error : kXR_ServerError;
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
        xrootd_send_error(ctx, c, (uint16_t) err,
                          t->err_msg[0] ? t->err_msg : "slice open fill failed");
        xrootd_aio_resume(c);
        return;
    }

    idx = xrootd_alloc_fhandle(ctx);
    if (idx < 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
        xrootd_send_error(ctx, c, kXR_ServerError, "too many open files");
        xrootd_aio_resume(c);
        return;
    }

    /*
     * A handle slot is considered "in use" only when fd >= 0, so a slice handle
     * (which has no single backing file) parks a harmless O_RDONLY fd on
     * /dev/null.  kXR_read checks slice_mode and never touches this fd; close
     * releases it normally.
     */
    devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (devnull < 0) {
        xrootd_free_fhandle(ctx, idx);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
        xrootd_send_error(ctx, c, kXR_ServerError, "slice handle fd failed");
        xrootd_aio_resume(c);
        return;
    }

    f = &ctx->files[idx];
    f->fd              = devnull;
    f->readable        = 1;
    f->writable        = 0;
    f->from_cache      = 1;
    f->is_regular      = 1;
    f->cached_size     = t->file_size;
    f->read_last_end   = -1;
    f->read_ahead_end  = 0;
    f->dashboard_slot  = -1;
    f->slice_mode      = 1;
    f->slice_size      = (size_t) t->slice_len;

    f->slice_cache_path = ngx_alloc(ngx_strlen(t->file_cache_path) + 1, c->log);
    f->slice_clean_path = ngx_alloc(ngx_strlen(t->clean_path) + 1, c->log);
    if (f->slice_cache_path == NULL || f->slice_clean_path == NULL) {
        xrootd_free_fhandle(ctx, idx);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
        xrootd_send_error(ctx, c, kXR_NoMemory, "slice handle alloc failed");
        xrootd_aio_resume(c);
        return;
    }
    ngx_cpystrn((u_char *) f->slice_cache_path, (u_char *) t->file_cache_path,
                ngx_strlen(t->file_cache_path) + 1);
    ngx_cpystrn((u_char *) f->slice_clean_path, (u_char *) t->clean_path,
                ngx_strlen(t->clean_path) + 1);

    if (xrootd_set_fhandle_path(ctx, c, idx, t->file_cache_path) != NGX_OK) {
        xrootd_free_fhandle(ctx, idx);
        xrootd_aio_resume(c);
        return;
    }

    f->bytes_read    = 0;
    f->bytes_written = 0;
    f->open_time     = ngx_current_msec;

    xrootd_log_access(ctx, c, "OPEN", t->clean_path, "slice", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_OPEN_RD);

    (void) slice_send_open_response(ctx, c, idx, t->file_size, t->options);
    xrootd_aio_resume(c);
}


ngx_int_t
xrootd_open_slice_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *clean_path,
    const char *cache_path, uint16_t options)
{
    ngx_int_t rc;

    rc = slice_post_fill(ctx, c, conf, clean_path, cache_path,
                         0 /* slice 0 */, conf->cache_slice_size, options,
                         -1, 0, 0, xrootd_slice_open_done);
    if (rc == NGX_DECLINED) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN", clean_path,
                          "slice", kXR_ServerError, "cache thread pool missing");
    }
    if (rc != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN", clean_path,
                          "slice", kXR_ServerError, "slice open schedule failed");
    }

    ctx->state = XRD_ST_AIO;
    return NGX_OK;
}


/* -------------------------------------------------------------------------
 * Read path
 * ---------------------------------------------------------------------- */

/* Done callback of a read-triggered slice fill: re-enter the read handler. */
static void
xrootd_slice_read_resume(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    xrootd_cache_fill_t *t    = task->ctx;
    xrootd_ctx_t        *ctx  = t->ctx;
    ngx_connection_t    *c    = t->c;

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->result != NGX_OK) {
        int err = t->xrd_error ? t->xrd_error : kXR_IOError;
        xrootd_send_error(ctx, c, (uint16_t) err,
                          t->err_msg[0] ? t->err_msg : "slice fill failed");
        xrootd_aio_resume(c);
        return;
    }

    /*
     * Re-run the read.  It either serves the response (state leaves XRD_ST_AIO)
     * or suspends again on the next missing slice (state stays XRD_ST_AIO, a new
     * fill task is posted).  Only resume the connection in the former case.
     */
    (void) xrootd_read_from_slices(ctx, c, t->conf, t->slice_read_idx,
                                   t->slice_read_offset, t->slice_read_rlen);
    if (ctx->state != XRD_ST_AIO) {
        xrootd_aio_resume(c);
    }
}


ngx_int_t
xrootd_read_from_slices(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, off_t offset, size_t rlen)
{
    xrootd_file_t  *f = &ctx->files[idx];
    xrootd_slice_t  slices[XROOTD_SLICE_MAX_PER_REQUEST];
    ngx_uint_t      nslices, i;
    ngx_int_t       rc;
    off_t           req_end;
    size_t          total;
    u_char         *buf, *ptr;

    if (rlen == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    req_end = offset + (off_t) rlen;

    rc = xrootd_slice_enumerate(f->slice_cache_path, f->cached_size,
                                f->slice_size, offset, req_end,
                                slices, XROOTD_SLICE_MAX_PER_REQUEST,
                                &nslices);
    if (rc == NGX_DECLINED) {
        return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                 "read spans too many cache slices");
    }
    if (rc != NGX_OK) {
        /* offset at/after EOF (or bad range): a zero-length read is correct. */
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    /* Fill the first missing slice (suspend), then re-enter on completion. */
    for (i = 0; i < nslices; i++) {
        if (!slices[i].ready) {
            rc = slice_post_fill(ctx, c, conf, f->slice_clean_path,
                                 f->slice_cache_path, slices[i].idx,
                                 f->slice_size, 0,
                                 idx, offset, rlen,
                                 xrootd_slice_read_resume);
            if (rc != NGX_OK) {
                return xrootd_send_error(ctx, c, kXR_ServerError,
                                         "slice fill schedule failed");
            }
            ctx->state = XRD_ST_AIO;
            return NGX_OK;
        }
    }

    /* All slices present — stitch the requested bytes into one buffer. */
    total = 0;
    for (i = 0; i < nslices; i++) {
        total += (size_t) (slices[i].req_end - slices[i].req_start);
    }
    if (total == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    buf = ngx_alloc(total, c->log);
    if (buf == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "slice read alloc");
    }

    ptr = buf;
    for (i = 0; i < nslices; i++) {
        off_t  soff = slices[i].req_start - slices[i].file_start;
        size_t slen = (size_t) (slices[i].req_end - slices[i].req_start);
        int    sfd;
        xrootd_vfs_job_t job;

        sfd = open(slices[i].path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (sfd < 0) {
            ngx_free(buf);
            return xrootd_send_error(ctx, c, kXR_IOError, "slice read failed");
        }

        xrootd_vfs_job_read_init(&job, sfd, soff, slen, ptr, slen, 0);
        xrootd_vfs_io_execute(&job);
        if (job.io_errno != 0 || job.nio < 0 || (size_t) job.nio != slen) {
            if (sfd >= 0) {
                close(sfd);
            }
            ngx_free(buf);
            return xrootd_send_error(ctx, c, kXR_IOError, "slice read failed");
        }
        close(sfd);
        ptr += slen;
    }

    f->bytes_read += total;
    rc = xrootd_send_ok(ctx, c, buf, (uint32_t) total);
    ngx_free(buf);
    return rc;
}
