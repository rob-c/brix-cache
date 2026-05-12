#include "cache_internal.h"

#include <errno.h>
#include <string.h>

#if (NGX_THREADS)

ngx_int_t
xrootd_cache_open_or_fill(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *clean_path,
    const char *cache_path, uint16_t options, uint16_t mode_bits)
{
    ngx_thread_task_t   *task;
    xrootd_cache_fill_t *t;
    int                  ready;

    ready = xrootd_cache_file_ready(cache_path);
    if (ready == 1) {
        return xrootd_open_resolved_file(ctx, c, conf, cache_path,
                                         options, mode_bits, 0);
    }
    if (ready < 0) {
        xrootd_log_access(ctx, c, "OPEN", cache_path, "cache",
                          0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    if (conf->thread_pool == NULL) {
        xrootd_log_access(ctx, c, "OPEN", clean_path, "cache",
                          0, kXR_ServerError, "cache thread pool missing", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_ServerError,
                                 "cache thread pool missing");
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_cache_fill_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    ngx_memzero(t, sizeof(*t));
    t->c = c;
    t->ctx = ctx;
    t->conf = conf;
    t->streamid[0] = ctx->cur_streamid[0];
    t->streamid[1] = ctx->cur_streamid[1];
    t->options = options;
    t->mode_bits = mode_bits;

    ngx_cpystrn((u_char *) t->clean_path, (u_char *) clean_path,
                sizeof(t->clean_path));
    ngx_cpystrn((u_char *) t->cache_path, (u_char *) cache_path,
                sizeof(t->cache_path));

    if (xrootd_cache_append_suffix(t->part_path, sizeof(t->part_path),
                                   cache_path, XROOTD_CACHE_PART_SUFFIX) != 0
        || xrootd_cache_append_suffix(t->lock_path, sizeof(t->lock_path),
                                      cache_path, XROOTD_CACHE_LOCK_SUFFIX) != 0)
    {
        xrootd_log_access(ctx, c, "OPEN", clean_path, "cache",
                          0, kXR_ArgTooLong, "cache path too long", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                 "cache path too long");
    }

    task->handler = xrootd_cache_fill_thread;
    task->event.handler = xrootd_cache_fill_done;
    task->event.data = task;

    if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
        xrootd_log_access(ctx, c, "OPEN", clean_path, "cache",
                          0, kXR_ServerError, "cache thread post failed", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_ServerError,
                                 "cache thread post failed");
    }

    ctx->state = XRD_ST_AIO;
    return NGX_OK;
}

#else

ngx_int_t
xrootd_cache_open_or_fill(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *clean_path,
    const char *cache_path, uint16_t options, uint16_t mode_bits)
{
    (void) conf;
    (void) cache_path;
    (void) options;
    (void) mode_bits;

    xrootd_log_access(ctx, c, "OPEN", clean_path, "cache",
                      0, kXR_ServerError, "cache requires thread support", 0);
    XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
    return xrootd_send_error(ctx, c, kXR_ServerError,
                             "cache requires thread support");
}

#endif /* NGX_THREADS */
