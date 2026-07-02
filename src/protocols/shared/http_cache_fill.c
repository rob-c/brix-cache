/*
 * http_cache_fill.c - off-event-loop cache-miss fill for the HTTP read plane.
 * See http_cache_fill.h for the WHAT/WHY/HOW.
 *
 * Phase-68 additions:
 *   - COALESCING: every concurrent request for one (inst,key) parks on a
 *     single heap-owned fill — a 40-request stampede is exactly ONE origin
 *     fetch. The waiter list is event-loop-only (no locks).
 *   - NEVER-DROP (T20): with a client-hold configured, the fill worker
 *     retries transient origin failures with jittered backoff until the
 *     hold deadline; a waiter whose hold expires detaches and receives
 *     504 + Retry-After on a KEPT-ALIVE connection (a TCP close is never
 *     an error signal — convention #6). A client abort detaches its waiter
 *     but never cancels the fill: the fill keeps retrying (max-life
 *     deadline) and publishes so the client's retry is a hit.
 *
 * Ownership: the fill ctx (+ its ngx_thread_task_t) is one calloc block,
 * freed in the done handler. Each waiter is freed by ITS REQUEST's pool
 * cleanup (which always fires exactly once), so a late cleanup can never
 * use-after-free a waiter the done handler already resolved.
 */
#include "http_cache_fill.h"
#include "fs/backend/cache/sd_cache.h"   /* xrootd_sd_cache_* */
#include "fs/backend/http/sd_http.h"    /* sd_http_n_endpoints (verify budget) */
#include "fs/cache/fill_retry.h"        /* T20 classification + backoff */
#include "core/aio/aio.h"                      /* xrootd_task_bind */

#include <limits.h>                          /* PATH_MAX */
#include <stdatomic.h>
#include <stdlib.h>                          /* calloc/free (worker heap) */

#if (NGX_THREADS)

struct xrootd_http_cache_fill_ctx_s;

/* One request parked on an in-flight fill (event-loop-only). */
typedef struct xrootd_http_fill_waiter_s {
    ngx_http_request_t                   *r;
    xrootd_http_cache_reenter_pt          reenter;
    void                                 *reenter_data;
    struct xrootd_http_fill_waiter_s     *next;
    struct xrootd_http_cache_fill_ctx_s  *owner;   /* valid while !resolved */
    ngx_event_t                           hold;    /* T20 client-hold timer */
    unsigned                              resolved:1;
} xrootd_http_fill_waiter_t;

/* Per-fill task context — ONE per (inst,key) in flight, shared by every
 * concurrent request for that object. */
typedef struct xrootd_http_cache_fill_ctx_s {
    xrootd_sd_instance_t                *inst;
    xrootd_http_fill_waiter_t           *waiters;
    _Atomic int                          waiters_n;  /* read by the worker */
    struct xrootd_http_cache_fill_ctx_s *next;       /* in-flight list     */
    ngx_thread_task_t                   *task;       /* the calloc block   */
    time_t                               client_hold; /* T20 deadlines     */
    time_t                               max_life;
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

/* Unlink `w` from its fill (idempotent; both the hold timer and the request
 * cleanup may race to it on the event loop). */
static void
xrootd_http_fill_detach(xrootd_http_fill_waiter_t *w)
{
    xrootd_http_fill_waiter_t **pp;

    if (w->resolved) {
        return;
    }
    w->resolved = 1;
    if (w->hold.timer_set) {
        ngx_del_timer(&w->hold);
    }
    for (pp = &w->owner->waiters; *pp != NULL; pp = &(*pp)->next) {
        if (*pp == w) {
            *pp = w->next;
            break;
        }
    }
    atomic_fetch_sub_explicit(&w->owner->waiters_n, 1, memory_order_relaxed);
}

/* 504 + Retry-After on a KEPT-ALIVE connection (convention #6: origin
 * trouble is a well-formed HTTP answer, never a broken socket). */
static void
xrootd_http_fill_send_retry_later(ngx_http_request_t *r)
{
    static u_char     body[] = "origin temporarily unreachable; retrying - "
                               "please retry\n";
    ngx_table_elt_t  *h;
    ngx_buf_t        *b;
    ngx_chain_t       out;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Retry-After");
    ngx_str_set(&h->value, "2");

    r->headers_out.status = NGX_HTTP_GATEWAY_TIME_OUT;
    r->headers_out.content_length_n = sizeof(body) - 1;
    r->keepalive = 1;                       /* NEVER close on origin trouble */
    if (ngx_http_send_header(r) != NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, NGX_OK);
        return;
    }
    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    b->pos = b->start = body;
    b->last = b->end = body + sizeof(body) - 1;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;
    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
}

/* T20 hold timer: the client has waited long enough — answer 504 on the
 * kept-alive connection and leave the fill running (its own retry, arriving
 * on the same warm socket, coalesces onto this still-running fill). */
static void
xrootd_http_fill_hold_expire(ngx_event_t *ev)
{
    xrootd_http_fill_waiter_t *w = ev->data;
    ngx_http_request_t        *r = w->r;
    ngx_connection_t          *c = r->connection;

    xrootd_http_fill_detach(w);
    xrootd_http_fill_send_retry_later(r);
    ngx_http_run_posted_requests(c);
}

/* Request-pool cleanup: the waiter's single owner for freeing. Fires exactly
 * once per parked request — after the done handler resolved it (resolved=1,
 * just free) or on a client abort mid-fill (detach, then free; the fill
 * itself is NEVER cancelled). */
static void
xrootd_http_fill_waiter_cleanup(void *data)
{
    xrootd_http_fill_waiter_t *w = data;

    xrootd_http_fill_detach(w);
    free(w);
}

/* Park `r` on fill `t` (r->main->count++ balanced by the finalize in done /
 * hold-expiry / abort teardown). */
static ngx_int_t
xrootd_http_fill_attach(xrootd_http_cache_fill_ctx_t *t,
    ngx_http_request_t *r, xrootd_http_cache_reenter_pt reenter,
    void *reenter_data)
{
    xrootd_http_fill_waiter_t *w = calloc(1, sizeof(*w));
    ngx_pool_cleanup_t        *cln;

    if (w == NULL) {
        return NGX_ERROR;
    }
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        free(w);
        return NGX_ERROR;
    }
    w->r            = r;
    w->reenter      = reenter;
    w->reenter_data = reenter_data;
    w->owner        = t;
    w->next         = t->waiters;
    t->waiters      = w;
    atomic_fetch_add_explicit(&t->waiters_n, 1, memory_order_relaxed);

    cln->handler = xrootd_http_fill_waiter_cleanup;
    cln->data    = w;

    if (t->client_hold > 0) {
        w->hold.handler = xrootd_http_fill_hold_expire;
        w->hold.data    = w;
        w->hold.log     = r->connection->log;
        ngx_add_timer(&w->hold, (ngx_msec_t) t->client_hold * 1000);
    }

    r->main->count++;
    return NGX_DONE;
}

/* Worker thread: run the blocking source->store fill off the event loop,
 * retrying transient origin failures to the T20 deadlines (single-pass when
 * no hold is configured — the pre-phase-68 semantics for other protocols). */
static void
xrootd_http_cache_fill_thread(void *data, ngx_log_t *log)
{
    xrootd_http_cache_fill_ctx_t *t = data;
    xrootd_fill_retry_t           rs;
    unsigned                      n_eps;

    (void) log;
    n_eps = (unsigned) sd_http_n_endpoints(
                xrootd_sd_cache_source_instance(t->inst));
    xrootd_fill_retry_init(&rs, t->client_hold, t->max_life, &t->waiters_n,
                           n_eps);
    for ( ;; ) {
        errno = 0;
        t->result = xrootd_sd_cache_fill_key(t->inst, t->key);
        t->err = errno;
        switch (xrootd_fill_classify(t->result, t->err, &rs)) {
        case XROOTD_FILL_OK:
        case XROOTD_FILL_DEFINITIVE:
            return;
        case XROOTD_FILL_RETRY:
            break;
        }
        if (!xrootd_fill_retry_wait(&rs)) {
            if (t->err == EBADMSG) {
                return;              /* proven-bad data: 502, not "later" */
            }
            t->err = ETIMEDOUT;      /* deadline exhausted: 504 to waiters */
            return;
        }
    }
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
    } else if (t->err == ETIMEDOUT) {
        /* T20: deadline exhausted while this waiter was still attached —
         * same keep-alive 504 the hold timer sends. */
        xrootd_http_fill_send_retry_later(r);
        ngx_http_run_posted_requests(c);
        return;
    } else {
        ngx_log_error(NGX_LOG_ERR, c->log, t->err,
            "xrootd: cache fill failed for \"%s\" - returning 502", t->key);
        rc = NGX_HTTP_BAD_GATEWAY;
    }

    ngx_http_finalize_request(r, rc);
    ngx_http_run_posted_requests(c);
}

/* Event loop: resolve EVERY still-attached waiter with the one fill outcome
 * (the stampede coalescing contract), then release the fill. Waiter memory
 * stays with its request's pool cleanup. */
static void
xrootd_http_cache_fill_done(ngx_event_t *ev)
{
    ngx_thread_task_t             *task = ev->data;
    xrootd_http_cache_fill_ctx_t  *t = task->ctx;
    xrootd_http_cache_fill_ctx_t **pp;
    xrootd_http_fill_waiter_t     *w;

    /* Unlink from the in-flight list FIRST so a re-entered handler that
     * misses again starts a fresh fill rather than attaching to this one. */
    for (pp = &xrootd_http_fills; *pp != NULL; pp = &(*pp)->next) {
        if (*pp == t) {
            *pp = t->next;
            break;
        }
    }

    while ((w = t->waiters) != NULL) {
        xrootd_http_fill_detach(w);              /* unlink + stop the hold */
        xrootd_http_fill_resolve_waiter(t, w);
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
    t->inst        = inst;
    t->task        = task;
    t->result      = NGX_ERROR;
    t->client_hold = common->cache_client_hold;   /* 0 = single-pass fill */
    t->max_life    = common->cache_fill_max_life;
    ngx_cpystrn((u_char *) t->key, (u_char *) key, sizeof(t->key));

    xrootd_task_bind(task, xrootd_http_cache_fill_thread,
                     xrootd_http_cache_fill_done);
    task->event.log = r->connection->log;

    if (xrootd_http_fill_attach(t, r, reenter, reenter_data) != NGX_DONE) {
        free(block);
        return NGX_ERROR;
    }

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        xrootd_http_fill_detach(t->waiters);     /* undo the attach        */
        r->main->count--;
        free(block);
        return NGX_ERROR;
    }

    t->next = xrootd_http_fills;                 /* publish for coalescing */
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
