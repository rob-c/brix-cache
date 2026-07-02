/*
 * http_cache_fill.c - off-event-loop cache-miss fill for the HTTP read plane.
 * See http_cache_fill.h for the WHAT/WHY/HOW.
 */
#include "http_cache_fill.h"
#include "fs/backend/cache/sd_cache.h"   /* xrootd_sd_cache_* */
#include "core/aio/aio.h"                      /* xrootd_task_bind */

#include <limits.h>                          /* PATH_MAX */
#include <stdlib.h>                          /* malloc/free (worker heap) */

#if (NGX_THREADS)

/* One request parked on an in-flight fill (event-loop-only list). */
typedef struct xrootd_http_fill_waiter_s {
    ngx_http_request_t                *r;
    xrootd_http_cache_reenter_pt       reenter;
    void                              *reenter_data;
    struct xrootd_http_fill_waiter_s  *next;
} xrootd_http_fill_waiter_t;

/* Per-fill task context — ONE per (inst,key) in flight, shared by every
 * concurrent request for that object (phase-68: a 40-request stampede is
 * exactly ONE origin fetch). Heap-owned (worker lifetime, freed in done);
 * the waiter list is touched on the event loop only, so no locking. */
typedef struct xrootd_http_cache_fill_ctx_s {
    xrootd_sd_instance_t                *inst;
    xrootd_http_fill_waiter_t           *waiters;
    struct xrootd_http_cache_fill_ctx_s *next;      /* in-flight list */
    ngx_thread_task_t                   *task;
    ngx_int_t                            result;    /* NGX_OK/DECLINED/ERROR */
    int                                  err;       /* errno from the fill  */
    char                                 key[PATH_MAX];
} xrootd_http_cache_fill_ctx_t;

/* Per-worker in-flight fills (event-loop-only; a handful at a time). */
static xrootd_http_cache_fill_ctx_t  *xrootd_http_fills;

static xrootd_http_cache_fill_ctx_t *
xrootd_http_fill_find(xrootd_sd_instance_t *inst, const char *key)
{
    xrootd_http_cache_fill_ctx_t *t;

    for (t = xrootd_http_fills; t != NULL; t = t->next) {
        if (t->inst == inst && ngx_strcmp(t->key, key) == 0) {
            return t;
        }
    }
    return NULL;
}

/* Park `r` on fill `t` (r->main->count++ balanced by the finalize in done). */
static ngx_int_t
xrootd_http_fill_attach(xrootd_http_cache_fill_ctx_t *t,
    ngx_http_request_t *r, xrootd_http_cache_reenter_pt reenter,
    void *reenter_data)
{
    xrootd_http_fill_waiter_t *w = malloc(sizeof(*w));

    if (w == NULL) {
        return NGX_ERROR;
    }
    w->r            = r;
    w->reenter      = reenter;
    w->reenter_data = reenter_data;
    w->next         = t->waiters;
    t->waiters      = w;
    r->main->count++;
    return NGX_DONE;
}

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

/* Resolve one waiter with the fill outcome (event loop). */
static void
xrootd_http_fill_resolve_waiter(xrootd_http_cache_fill_ctx_t *t,
    xrootd_http_fill_waiter_t *w)
{
    ngx_http_request_t *r = w->r;
    ngx_connection_t   *c = r->connection;
    ngx_int_t           rc;

    if (t->result == NGX_OK) {
        rc = w->reenter(r, w->reenter_data);    /* hit -> serve (zero-copy) */
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

/* Event loop: resolve EVERY parked waiter with the one fill outcome (the
 * stampede coalescing contract), then release the fill. The per-waiter
 * finalize balances the count++ taken at attach. */
static void
xrootd_http_cache_fill_done(ngx_event_t *ev)
{
    ngx_thread_task_t             *task = ev->data;
    xrootd_http_cache_fill_ctx_t  *t = task->ctx;
    xrootd_http_cache_fill_ctx_t **pp;
    xrootd_http_fill_waiter_t     *w, *next;

    /* Unlink from the in-flight list FIRST so a re-entered handler that
     * misses again starts a fresh fill rather than attaching to this one. */
    for (pp = &xrootd_http_fills; *pp != NULL; pp = &(*pp)->next) {
        if (*pp == t) {
            *pp = t->next;
            break;
        }
    }

    for (w = t->waiters; w != NULL; w = next) {
        next = w->next;
        xrootd_http_fill_resolve_waiter(t, w);
        free(w);
    }
    free(t->task);           /* the calloc'd task+ctx block (task is first) */
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
    u_char                       *block;

    if (inst == NULL || key == NULL || reenter == NULL || common == NULL
        || !xrootd_sd_cache_fill_needs_offload(inst, key))
    {
        return NGX_DECLINED;                 /* serve inline (hit / local / none) */
    }

    /* Coalesce onto an in-flight fill of the same object: the stampede case
     * (N concurrent cold reads) is exactly ONE origin fetch. */
    t = xrootd_http_fill_find(inst, key);
    if (t != NULL) {
        return xrootd_http_fill_attach(t, r, reenter, reenter_data);
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

    /* Heap-owned task + ctx: the fill is shared by every parked request and
     * must not live in any one request's pool (an aborted first requester
     * would otherwise free the memory under the running task). */
    block = calloc(1, sizeof(ngx_thread_task_t)
                      + sizeof(xrootd_http_cache_fill_ctx_t));
    if (block == NULL) {
        return NGX_ERROR;
    }
    task = (ngx_thread_task_t *) block;
    task->ctx = block + sizeof(ngx_thread_task_t);
    t = task->ctx;
    t->inst   = inst;
    t->task   = task;
    t->result = NGX_ERROR;
    ngx_cpystrn((u_char *) t->key, (u_char *) key, sizeof(t->key));

    xrootd_task_bind(task, xrootd_http_cache_fill_thread,
                     xrootd_http_cache_fill_done);
    task->event.log = r->connection->log;

    if (xrootd_http_fill_attach(t, r, reenter, reenter_data) != NGX_DONE) {
        free(block);
        return NGX_ERROR;
    }

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        r->main->count--;                    /* undo the attach            */
        free(t->waiters);
        free(block);
        return NGX_ERROR;
    }

    t->next = xrootd_http_fills;             /* publish for coalescing     */
    xrootd_http_fills = t;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "xrootd: offloaded cache fill of \"%s\" to the thread pool", key);
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
