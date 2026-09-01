/*
 * walk_offload.c — thread-offload for blocking metadata walks (phase 109 W1).
 *
 * WHAT: Runs the PROPFIND build phase (propfind_build: resolve/stat, the
 *       recursive walk's opendir/readdir, per-prop residency queries, XML
 *       assembly) on the shared thread pool, and the send phase
 *       (propfind_send) on the event loop, so a slow REMOTE backend no longer
 *       stalls every connection on the worker.
 *
 * WHY:  The metadata methods were the only webdav handlers still doing backend
 *       I/O inline (GET/PUT/COPY/MOVE already offload).  Against a remote
 *       backend, brix_vfs_opendir is an origin PROPFIND through the blocking
 *       curl transport — bounded, but on the event loop (phase-106 W5, R-7).
 *
 * HOW:  Three load-bearing decisions:
 *
 *       1. GATE, not blanket.  The offload fires only when the backend is
 *          remote (brix_storage_backend_is_remote), a thread pool is
 *          configured, and impersonation is OFF.  A local-POSIX opendir is a
 *          fast syscall — offloading it would add a thread hop to the common
 *          case for nothing, so the local path stays inline and byte-
 *          identical.
 *
 *       2. IMPERSONATION DECLINES, exactly as copy_collection.c:300: the
 *          per-worker broker socket is a single fd owned by the event-loop
 *          thread (concurrent use from a task corrupts the request/reply
 *          framing and wedges the worker's broker channel), and the thread
 *          lacks the per-worker principal.  Under brix_imp_enabled() the walk
 *          runs inline, where the principal is set — today's behaviour,
 *          which the phase-106 authz work already tests.  This is a SECURITY
 *          decline: an offloaded walk without the principal would enumerate
 *          as the WORKER, not the mapped user.
 *
 *       3. TASK-PRIVATE POOL.  nginx pools are not thread-safe, and the event
 *          loop can run abort/teardown handlers touching r->pool while the
 *          task is in flight.  The build therefore allocates exclusively from
 *          a pool created here (routed via propfind_pool()), and that pool is
 *          registered as a cleanup on r->pool so the response chains survive
 *          until the request is torn down — never freed under a draining
 *          send.  The request itself is held alive across the dispatch with
 *          r->main->count++, balanced in the done handler (the PUT pattern,
 *          put_body.c).
 */
#include "walk_offload.h"
#include "propfind_internal.h"
#include "webdav_metrics.h"
#include "core/config/shared_conf.h"
#include "fs/backend/sd.h"          /* BRIX_CRED_EXCHANGE */

#include "auth/impersonate/impersonate.h"
#include "core/aio/aio.h"


typedef struct {
    ngx_http_request_t   *r;
    webdav_walk_build_pt  build;
    webdav_walk_send_pt   send;
    ngx_chain_t          *head;      /* built 207 body (task pool memory)  */
    ngx_chain_t          *tail;      /* carried for sends that want it     */
    off_t                 total_len;
    ngx_int_t             rc;        /* the build's verdict                */
} webdav_walk_task_t;


/* Thread body: the method's build.  No r->pool, no event-loop calls — the
 * build allocates through webdav_req_pool(r), which the dispatcher pointed at
 * the task-private pool before posting. */
static void
webdav_walk_thread(void *data, ngx_log_t *log)
{
    webdav_walk_task_t *t = data;

    (void) log;
    t->rc = t->build(t->r, &t->head, &t->tail, &t->total_len);
}


/* Event-loop completion: send (or fail) and finalize with the same metrics
 * accounting the inline body handler performs. */
static void
webdav_walk_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    webdav_walk_task_t *t = task->ctx;
    ngx_http_request_t *r = t->r;
    ngx_int_t           rc = t->rc;

    /* Balance the count++ from the dispatch that kept the request alive. */
    r->main->count--;

    if (rc == NGX_OK) {
        rc = t->send(r, t->head, t->tail, t->total_len);
    }
    webdav_metrics_finalize_request(r, rc);
}


/* Free the task-private pool when the REQUEST is torn down — after the send
 * has drained, since the response chains live in this pool. */
static void
webdav_walk_pool_cleanup(void *data)
{
    ngx_destroy_pool(data);
}


static ngx_int_t
webdav_walk_offload_wanted(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_thread_pool_t **pool)
{
    /* Security decline first — see HOW(2) above. */
    if (brix_imp_enabled()) {
        return 0;
    }
    /* Local backend: fast syscalls, nothing to offload — see HOW(1).
     * EXCEPTION: EXCHANGE-mode delegation mints an RFC-8693 token through a
     * blocking POST inside the walk's cred gate even when the storage itself
     * is local, so that combination offloads too (phase-109 W3 — it is the
     * exact event-loop stall phase-106 R-7 traced). */
    if (!brix_storage_backend_is_remote(&conf->common)
        && conf->common.backend_delegation != BRIX_CRED_EXCHANGE)
    {
        return 0;
    }
    *pool = brix_shared_thread_pool(&conf->common);
    return *pool != NULL;
}


ngx_int_t
webdav_walk_offload(ngx_http_request_t *r, webdav_walk_build_pt build,
    webdav_walk_send_pt send)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t  *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    ngx_thread_pool_t   *pool = NULL;
    ngx_pool_t          *wpool;
    ngx_pool_cleanup_t  *cln;
    ngx_thread_task_t   *task;
    webdav_walk_task_t  *t;

    if (rx == NULL || !webdav_walk_offload_wanted(r, conf, &pool)) {
        return NGX_DECLINED;
    }

    wpool = ngx_create_pool(4096, r->connection->log);
    if (wpool == NULL) {
        return NGX_DECLINED;             /* inline path still works */
    }
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        ngx_destroy_pool(wpool);
        return NGX_DECLINED;
    }
    cln->handler = webdav_walk_pool_cleanup;
    cln->data = wpool;

    task = ngx_thread_task_alloc(r->pool, sizeof(webdav_walk_task_t));
    if (task == NULL) {
        return NGX_DECLINED;             /* cleanup owns wpool now */
    }
    t = task->ctx;
    t->r = r;
    t->build = build;
    t->send = send;
    t->head = NULL;
    t->tail = NULL;
    t->total_len = 0;
    t->rc = NGX_HTTP_INTERNAL_SERVER_ERROR;

    /* Route every build-phase allocation to the task pool (propfind_pool). */
    rx->walk_pool = wpool;

    brix_task_bind(task, webdav_walk_thread, webdav_walk_done);
    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        rx->walk_pool = NULL;            /* inline path, back on r->pool */
        return NGX_DECLINED;
    }

    r->main->count++;                    /* balanced in webdav_walk_done */
    return NGX_DONE;
}


/* ---- PROPFIND adapter ---------------------------------------------------- */

static ngx_int_t
webdav_propfind_build_cb(ngx_http_request_t *r, ngx_chain_t **head,
    ngx_chain_t **tail, off_t *total_len)
{
    (void) tail;                          /* the chain is finalized in build */
    return propfind_build(r, head, total_len);
}

static ngx_int_t
webdav_propfind_send_cb(ngx_http_request_t *r, ngx_chain_t *head,
    ngx_chain_t *tail, off_t total_len)
{
    (void) tail;
    return propfind_send(r, head, total_len);
}

ngx_int_t
webdav_propfind_offload(ngx_http_request_t *r)
{
    return webdav_walk_offload(r, webdav_propfind_build_cb,
                               webdav_propfind_send_cb);
}


/* ---- SEARCH adapter ------------------------------------------------------ */

static ngx_int_t
webdav_search_build_cb(ngx_http_request_t *r, ngx_chain_t **head,
    ngx_chain_t **tail, off_t *total_len)
{
    (void) total_len;                     /* SEARCH's send sums the chain    */
    return webdav_search_build(r, head, tail);
}

static ngx_int_t
webdav_search_send_cb(ngx_http_request_t *r, ngx_chain_t *head,
    ngx_chain_t *tail, off_t total_len)
{
    (void) total_len;
    return webdav_search_send(r, head, tail);
}

ngx_int_t
webdav_search_offload(ngx_http_request_t *r)
{
    return webdav_walk_offload(r, webdav_search_build_cb,
                               webdav_search_send_cb);
}
