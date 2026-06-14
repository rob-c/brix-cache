#include "cache_internal.h"

#include <errno.h>
#include <string.h>


/* ---- xrootd_cache_open_or_fill — cache open-on-hit / schedule-fill entry point ----
 *
 * WHAT: Public entry point called when a kXR_open request hits. Decides whether to serve from cached file or schedule a fill worker.
 *       If cache_path exists and is ready → opens directly from cache (fast path). Otherwise allocates a thread-pool task for origin fetch. */

/* ---- Open decision logic ----
 *
 * HOW: Check xrootd_cache_file_ready() return value: 1 = file present and complete → serve immediately; -1 = check failed → error; else → schedule fill. */

/* ---- Task allocation invariant ----
 *
 * WHY: Uses ngx_thread_task_alloc (not pool-alloc) because task ctx is accessed by a separate thread-pool worker.
 *      The task struct contains all context needed for the fetch operation including streamid, options, and both clean_path/cache_path. */

/* ---- Thread posting flow ----
 *
 * HOW: Post task to conf->common.thread_pool → set client state to XRD_ST_AIO (AIO phase) → wait for completion callback xrootd_cache_fill_done. */

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
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN", cache_path,
                          "cache", kXR_IOError, strerror(errno));
    }

    if (conf->common.thread_pool == NULL) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN", clean_path,
                          "cache", kXR_ServerError, "cache thread pool missing");
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
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN", clean_path,
                          "cache", kXR_ArgTooLong, "cache path too long");
    }

    xrootd_task_bind(task, xrootd_cache_fill_thread, xrootd_cache_fill_done);

    if (ngx_thread_task_post(conf->common.thread_pool, task) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_OPEN_RD, "OPEN", clean_path,
                          "cache", kXR_ServerError, "cache thread post failed");
    }

    ctx->state = XRD_ST_AIO;
    return NGX_OK;
}

