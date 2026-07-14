/*
 * http_cache_fill.c - off-event-loop cache-miss fill for the HTTP read plane.
 * See http_cache_fill.h for the WHAT/WHY/HOW.
 *
 * This unit is the public entry point + async-pool resolver. The concurrency
 * machinery it drives was split out mechanically (zero behaviour change) for
 * auditability — see http_cache_fill_internal.h:
 *   http_cache_fill_registry.c  coalescing waiter registry (attach/detach/hold/abort)
 *   http_cache_fill_worker.c    worker thread + resolve + done finalize
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
#include "fs/backend/cache/sd_cache.h"   /* brix_sd_cache_* */
#include "fs/backend/http/sd_http.h"    /* sd_http_n_endpoints (verify budget) */
#include "fs/cache/fill_retry.h"        /* T20 classification + backoff */
#include "core/aio/aio.h"                      /* brix_task_bind */
#include "fs/path/path.h"        /* brix_sanitize_log_string (wire keys) */
#include "observability/sesslog/sesslog_ngx.h"

#include <limits.h>                          /* PATH_MAX */
#include <stdatomic.h>
#include <stdlib.h>                          /* calloc/free (worker heap) */
#include <sys/socket.h>                     /* recv(MSG_PEEK): client-abort probe */

#include "http_cache_fill_internal.h"

#if (NGX_THREADS)

/* Lazily resolve the export's async thread pool: server postconfig fills only the
 * server-level loc_conf, so a nested location block resolves on first use (the
 * webdav/copy.c idiom). NULL when no pool is configured. */
static ngx_thread_pool_t *
brix_http_cache_fill_pool(ngx_http_brix_shared_conf_t *common)
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
brix_http_cache_fill_if_needed(ngx_http_request_t *r,
    brix_sd_instance_t *inst, const char *key,
    ngx_http_brix_shared_conf_t *common,
    brix_http_cache_reenter_pt reenter, void *reenter_data)
{
    ngx_thread_task_t            *task;
    brix_http_cache_fill_ctx_t *t;
    ngx_thread_pool_t            *pool;
    u_char                       *block;

    if (inst == NULL || key == NULL || reenter == NULL || common == NULL
        || !brix_sd_cache_fill_needs_offload(inst, key))
    {
        return NGX_DECLINED;                 /* serve inline (hit / local / none) */
    }

    /* Coalesce onto an in-flight fill of the same object: the stampede case
     * (N concurrent cold reads) is exactly ONE origin fetch. */
    t = brix_http_fill_find(inst, key);
    if (t != NULL) {
        return brix_http_fill_attach(t, r, reenter, reenter_data);
    }

    pool = brix_http_cache_fill_pool(common);
    if (pool == NULL) {
        /* No pool: nothing can run off-loop, so fall through to the inline path
         * (preserves the pre-SP2 behaviour - a remote miss may stall/fail). */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix: cache miss on \"%s\" needs an async thread pool to fill a "
            "remote tier; none configured - serving inline (may stall)", key);
        return NGX_DECLINED;
    }

    /* Heap-owned task + ctx: the fill is shared by every parked request and
     * must not live in any one request's pool (an aborted first requester
     * would otherwise free the memory under the running task). */
    block = calloc(1, sizeof(ngx_thread_task_t)
                      + sizeof(brix_http_cache_fill_ctx_t));
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
    t->started_ms  = ngx_current_msec;
    ngx_cpystrn((u_char *) t->key, (u_char *) key, sizeof(t->key));
    t->sess = brix_sess_begin(common->session_log,
        brix_http_shared_access_log_fd(common), BRIX_SESS_PROTO_FILL,
        BRIX_SESS_DIR_OUT, "cache-origin", sizeof("cache-origin") - 1,
        BRIX_SESS_AM_ANON, NULL);
    brix_sess_auth_once(t->sess, BRIX_SESS_AM_ANON, "-", "-");
    brix_sess_attempt(t->sess, t->key, BRIX_SESS_MODE_READ);
    brix_sess_xfer_start(t->sess, &t->sess_xfer, t->key,
                         BRIX_SESS_MODE_READ, -1);

    brix_task_bind(task, brix_http_cache_fill_thread,
                     brix_http_cache_fill_done);
    task->event.log = r->connection->log;

    if (brix_http_fill_attach(t, r, reenter, reenter_data) != NGX_DONE) {
        brix_sess_end(t->sess, BRIX_SESS_END_ERROR);
        free(block);
        return NGX_ERROR;
    }

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        brix_http_fill_detach(t->waiters);     /* undo the attach        */
        r->main->count--;
        brix_sess_end(t->sess, BRIX_SESS_END_ERROR);
        free(block);
        return NGX_ERROR;
    }

    t->next = brix_http_fills;                 /* publish for coalescing */
    brix_http_fills = t;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "brix: offloaded cache fill of \"%s\" to the thread pool", key);
    return NGX_DONE;
}

#else  /* !NGX_THREADS */

/* Built without --with-threads: no pool to offload onto, so the caller keeps its
 * inline open/fill path (correct for a local tier; a remote tier is unsupported
 * without threads, exactly as before SP2). */
ngx_int_t
brix_http_cache_fill_if_needed(ngx_http_request_t *r,
    brix_sd_instance_t *inst, const char *key,
    ngx_http_brix_shared_conf_t *common,
    brix_http_cache_reenter_pt reenter, void *reenter_data)
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
