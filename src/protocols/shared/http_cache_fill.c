/*
 * http_cache_fill.c - off-event-loop cache-miss fill for the HTTP read plane.
 * See http_cache_fill.h for the WHAT/WHY/HOW.
 */
#include "http_cache_fill.h"
#include "fs/backend/cache/sd_cache.h"   /* xrootd_sd_cache_* */
#include "core/aio/aio.h"                      /* xrootd_task_bind */

#include <limits.h>                          /* PATH_MAX */

#if (NGX_THREADS)

/* Per-fill task context (lives on r->pool inside the ngx_thread_task_t). */
typedef struct {
    ngx_http_request_t           *r;
    xrootd_sd_instance_t         *inst;
    xrootd_http_cache_reenter_pt  reenter;
    void                         *reenter_data;
    ngx_int_t                     result;     /* NGX_OK / NGX_DECLINED / NGX_ERROR */
    int                           err;        /* errno captured from the fill */
    char                          key[PATH_MAX];
} xrootd_http_cache_fill_ctx_t;

/* Worker thread: run the blocking source->store fill off the event loop. */
static void
xrootd_http_cache_fill_thread(void *data, ngx_log_t *log)
{
    xrootd_http_cache_fill_ctx_t *t = data;

    (void) log;
    errno = 0;
    t->result = xrootd_sd_cache_fill_key(t->inst, t->key);
    t->err = errno;
}

/* Event loop: re-enter the handler (now a cache hit) on success, else finalize
 * with a clear gateway error. The single ngx_http_finalize_request() balances the
 * r->main->count++ taken at post (mirrors webdav/copy.c). */
static void
xrootd_http_cache_fill_done(ngx_event_t *ev)
{
    ngx_thread_task_t            *task = ev->data;
    xrootd_http_cache_fill_ctx_t *t = task->ctx;
    ngx_http_request_t           *r = t->r;
    ngx_connection_t             *c = r->connection;
    ngx_int_t                     rc;

    if (t->result == NGX_OK) {
        rc = t->reenter(r, t->reenter_data);    /* hit -> serve (zero-copy) */
    } else if (t->result == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
            "xrootd: cache fill declined for \"%s\" (object not cacheable and "
            "remote-source streaming is not yet supported) - returning 502",
            t->key);
        rc = NGX_HTTP_BAD_GATEWAY;
    } else if (t->err == ENOENT || t->err == ENOTDIR) {
        /* The origin's definitive answer: the object does not exist. */
        rc = NGX_HTTP_NOT_FOUND;
    } else if (t->err == EACCES || t->err == EPERM) {
        rc = NGX_HTTP_FORBIDDEN;
    } else {
        ngx_log_error(NGX_LOG_ERR, c->log, t->err,
            "xrootd: cache fill failed for \"%s\" - returning 502", t->key);
        rc = NGX_HTTP_BAD_GATEWAY;
    }

    ngx_http_finalize_request(r, rc);
    ngx_http_run_posted_requests(c);
}

/* Lazily resolve the export's async thread pool: server postconfig fills only the
 * server-level loc_conf, so a nested location block resolves on first use (the
 * webdav/copy.c idiom). NULL when no pool is configured. */
static ngx_thread_pool_t *
xrootd_http_cache_fill_pool(ngx_http_xrootd_shared_conf_t *common)
{
    ngx_thread_pool_t *pool = common->thread_pool;

    if (pool == NULL) {
        static ngx_str_t  default_name = ngx_string("default");
        ngx_str_t        *pname = common->thread_pool_name.len > 0
                                  ? &common->thread_pool_name : &default_name;

        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
        if (pool != NULL) {
            common->thread_pool = pool;
        }
    }
    return pool;
}

ngx_int_t
xrootd_http_cache_fill_if_needed(ngx_http_request_t *r,
    xrootd_sd_instance_t *inst, const char *key,
    ngx_http_xrootd_shared_conf_t *common,
    xrootd_http_cache_reenter_pt reenter, void *reenter_data)
{
    ngx_thread_task_t            *task;
    xrootd_http_cache_fill_ctx_t *t;
    ngx_thread_pool_t            *pool;

    if (inst == NULL || key == NULL || reenter == NULL || common == NULL
        || !xrootd_sd_cache_fill_needs_offload(inst, key))
    {
        return NGX_DECLINED;                 /* serve inline (hit / local / none) */
    }

    pool = xrootd_http_cache_fill_pool(common);
    if (pool == NULL) {
        /* No pool: nothing can run off-loop, so fall through to the inline path
         * (preserves the pre-SP2 behaviour - a remote miss may stall/fail). */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "xrootd: cache miss on \"%s\" needs an async thread pool to fill a "
            "remote tier; none configured - serving inline (may stall)", key);
        return NGX_DECLINED;
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(xrootd_http_cache_fill_ctx_t));
    if (task == NULL) {
        return NGX_ERROR;
    }
    t = task->ctx;
    t->r            = r;
    t->inst         = inst;
    t->reenter      = reenter;
    t->reenter_data = reenter_data;
    t->result       = NGX_ERROR;
    ngx_cpystrn((u_char *) t->key, (u_char *) key, sizeof(t->key));

    xrootd_task_bind(task, xrootd_http_cache_fill_thread,
                     xrootd_http_cache_fill_done);
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "xrootd: offloaded cache fill of \"%s\" to the thread pool", key);
    r->main->count++;
    return NGX_DONE;
}

#else  /* !NGX_THREADS */

/* Built without --with-threads: no pool to offload onto, so the caller keeps its
 * inline open/fill path (correct for a local tier; a remote tier is unsupported
 * without threads, exactly as before SP2). */
ngx_int_t
xrootd_http_cache_fill_if_needed(ngx_http_request_t *r,
    xrootd_sd_instance_t *inst, const char *key,
    ngx_http_xrootd_shared_conf_t *common,
    xrootd_http_cache_reenter_pt reenter, void *reenter_data)
{
    (void) r;
    (void) inst;
    (void) key;
    (void) common;
    (void) reenter;
    (void) reenter_data;
    return NGX_DECLINED;
}

#endif /* NGX_THREADS */
