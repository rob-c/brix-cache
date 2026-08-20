/*
 * oci_gc.c — the registry's own garbage collection, on a maintenance timer
 * (phase-104 §D15.5).
 *
 * WHAT: a config-time registry of store roots plus one worker-0 timer that
 *       runs the shared mark-and-sweep pass (shared/oci/gc.h) over each of
 *       them at its configured interval.
 * WHY:  `brixoci gc` already answers the whole-store question correctly, but
 *       it answers it only when somebody remembers to ask. A registry that
 *       accepts DELETEs and never reclaims is a registry whose disk usage
 *       only ever goes up, so the deployment that cannot run a cron job —
 *       a container, a read-only host, an operator who has one config file
 *       and no shell — needs the proxy to ask on its own.
 * HOW:  the SAME kernel, deliberately: a divergence between what the tool
 *       sweeps and what the server sweeps would be a divergence nobody could
 *       see from either side. This file contributes only *when*: one store at
 *       a time, on the thread pool so the walk stays off the event loop, on
 *       worker 0 alone so N workers do not sweep one store N times, and never
 *       while a previous pass is still running. The grace window is what makes
 *       that safe against a push in flight — see shared/oci/gc.h — and the
 *       pass is off unless `brix_oci_gc_interval` says otherwise.
 */

#include "oci.h"

#include "core/aio/aio.h"        /* brix_task_bind (thread offload)  */
#include "oci/gc.h"

#include <limits.h>
#include <string.h>

/* Registered store roots. One registry per host is what a config file can
 * plausibly describe; a deployment with more distinct registry roots than
 * this is one that wants a cron job, not a bigger array. */
#define OCI_GC_MAX_STORES  16

typedef struct {
    char        root[PATH_MAX];
    time_t      grace;
    ngx_msec_t  interval;
    ngx_msec_t  due;            /* ngx_current_msec of the next pass */
} oci_gc_store_t;

/* Config-time state, read by worker 0's timer. Written before the fork, so
 * every worker sees the same table and only one of them acts on it. */
static oci_gc_store_t  oci_gc_stores[OCI_GC_MAX_STORES];
static ngx_uint_t      oci_gc_store_count;

/* The timer event lives beside its handler and its arming function, which is
 * the tree's rule for a connection-less maintenance timer. */
static ngx_event_t     oci_gc_timer;
static ngx_uint_t      oci_gc_inflight;


void
brix_oci_gc_register(const char *root, ngx_msec_t interval, time_t grace)
{
    oci_gc_store_t *s;
    ngx_uint_t      i;
    size_t          n;

    if (root == NULL || root[0] != '/' || interval == 0) {
        return;
    }
    n = ngx_strlen(root);
    if (n == 0 || n >= PATH_MAX) {
        return;
    }
    /* Every location that inherits the directives registers the same root, so
     * the dedup is the normal case rather than an operator mistake. First
     * registration wins: two locations describing one store with different
     * cadences are describing one store, and the store can only have one. */
    for (i = 0; i < oci_gc_store_count; i++) {
        if (ngx_strcmp(oci_gc_stores[i].root, root) == 0) {
            return;
        }
    }
    if (oci_gc_store_count >= OCI_GC_MAX_STORES) {
        return;
    }
    s = &oci_gc_stores[oci_gc_store_count++];
    ngx_memcpy(s->root, root, n + 1);
    s->interval = interval;
    s->grace = grace;
}


ngx_uint_t
brix_oci_gc_registered(void)
{
    return oci_gc_store_count;
}


/* What one finished pass has to say. A store with nothing to reclaim says
 * nothing at all: a maintenance timer that logs every time it runs teaches
 * operators to filter it out, and then it cannot tell them anything. */
static void
oci_gc_report(const brix_oci_gc_t *c, int rc, const char *err, ngx_log_t *log)
{
    if (rc != BRIX_OCI_GC_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix oci: registry gc over \"%s\" failed: %s",
                      c->root, err);
        return;
    }
    if (c->st.blobs_swept == 0 && c->st.marks == 0 && c->st.refs == 0) {
        return;
    }
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "brix oci: registry gc over \"%s\" swept %ui blob(s) "
                  "(%uL bytes), %ui layer mark(s), %ui referrer(s); "
                  "kept %ui live, %ui within grace",
                  c->root, (ngx_uint_t) c->st.blobs_swept,
                  (uint64_t) c->st.bytes, (ngx_uint_t) c->st.marks,
                  (ngx_uint_t) c->st.refs, (ngx_uint_t) c->st.blobs_live,
                  (ngx_uint_t) c->st.blobs_young);
}


/* The pass itself, with the context zeroed the way the kernel requires. */
static void
oci_gc_fill(brix_oci_gc_t *c, const oci_gc_store_t *s)
{
    ngx_memzero(c, sizeof(*c));
    c->root = s->root;
    c->grace = s->grace;
}


#if (NGX_THREADS)

typedef struct {
    ngx_pool_t    *pool;
    ngx_log_t     *log;
    brix_oci_gc_t  gc;
    char           err[256];
    int            rc;
} oci_gc_task_t;


static void
oci_gc_thread(void *data, ngx_log_t *log)
{
    oci_gc_task_t *t = data;

    (void) log;
    t->rc = brix_oci_gc_run(&t->gc, t->err, sizeof(t->err));
}


static void
oci_gc_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task = ev->data;
    oci_gc_task_t     *t = task->ctx;
    ngx_pool_t        *pool = t->pool;

    if (oci_gc_inflight > 0) {
        oci_gc_inflight--;
    }
    oci_gc_report(&t->gc, t->rc, t->err, t->log);
    ngx_destroy_pool(pool);
}


/* Post one store's pass to the thread pool. NGX_DECLINED = no pool, or the
 * post failed; the caller then runs it inline. */
static ngx_int_t
oci_gc_offload(const oci_gc_store_t *s, ngx_log_t *log)
{
    static ngx_str_t   pname = ngx_string("default");
    ngx_thread_pool_t *pool;
    ngx_thread_task_t *task;
    oci_gc_task_t     *t;
    ngx_pool_t        *tp;

    pool = (ngx_cycle != NULL)
           ? ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &pname) : NULL;
    if (pool == NULL) {
        return NGX_DECLINED;
    }
    tp = ngx_create_pool(4096, log);
    if (tp == NULL) {
        return NGX_DECLINED;
    }
    task = ngx_thread_task_alloc(tp, sizeof(oci_gc_task_t));
    if (task == NULL) {
        ngx_destroy_pool(tp);
        return NGX_DECLINED;
    }
    t = task->ctx;
    t->pool = tp;
    t->log = log;
    t->rc = BRIX_OCI_GC_OK;
    t->err[0] = '\0';
    oci_gc_fill(&t->gc, s);

    brix_task_bind(task, oci_gc_thread, oci_gc_done);
    task->event.log = log;
    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        ngx_destroy_pool(tp);
        return NGX_DECLINED;
    }
    oci_gc_inflight++;
    return NGX_OK;
}

#endif /* NGX_THREADS */


/* Without a thread pool the walk runs here, on the event loop. That is the
 * tree's standing fallback (stage_engine_scheduler.c makes the same choice),
 * and it is the honest one: a pass that silently does not happen is worse
 * than a pass that costs worker 0 a stall it can be configured away from with
 * `aio threads`. */
static void
oci_gc_inline(const oci_gc_store_t *s, ngx_log_t *log)
{
    brix_oci_gc_t c;
    char          err[256] = "";
    int           rc;

    oci_gc_fill(&c, s);
    rc = brix_oci_gc_run(&c, err, sizeof(err));
    oci_gc_report(&c, rc, err, log);
}


/* The store whose next pass is due, or NULL. Every store carries its own due
 * time, so no rotation is needed: one that has just run is not due again
 * until its own interval has elapsed. */
static oci_gc_store_t *
oci_gc_due(void)
{
    ngx_uint_t i;

    for (i = 0; i < oci_gc_store_count; i++) {
        if ((ngx_msec_int_t) (ngx_current_msec - oci_gc_stores[i].due) >= 0) {
            return &oci_gc_stores[i];
        }
    }
    return NULL;
}


/* Timer callback: at most ONE store per tick, and never while a previous pass
 * is still walking — a registry under GC should cost the disk one sweep, not
 * as many as the timer can start. */
static void
oci_gc_tick(ngx_event_t *ev)
{
    oci_gc_store_t *s;

    if (oci_gc_inflight == 0 && (s = oci_gc_due()) != NULL) {
        s->due = ngx_current_msec + s->interval;
#if (NGX_THREADS)
        if (oci_gc_offload(s, ev->log) != NGX_OK) {
            oci_gc_inline(s, ev->log);
        }
#else
        oci_gc_inline(s, ev->log);
#endif
    }
    if (!ngx_exiting) {
        ngx_add_timer(ev, brix_oci_gc_tick_ms());
    }
}


ngx_msec_t
brix_oci_gc_tick_ms(void)
{
    ngx_msec_t tick = 0;
    ngx_uint_t i;

    /* The tick is the shortest configured interval: a store asking to be
     * swept every 2s cannot be served by a timer that wakes every minute,
     * and a longer-interval store is held back by its own due time anyway. */
    for (i = 0; i < oci_gc_store_count; i++) {
        if (tick == 0 || oci_gc_stores[i].interval < tick) {
            tick = oci_gc_stores[i].interval;
        }
    }
    return tick < BRIX_OCI_GC_MIN_INTERVAL ? BRIX_OCI_GC_MIN_INTERVAL : tick;
}


void
brix_oci_gc_arm_timer(ngx_cycle_t *cycle)
{
    /* Shared dummy connection (src/core/config/process_timers.c): nginx's
     * --with-debug timer-expiry log reads ngx_event_ident(ev->data)->fd, so a
     * connection-less timer must not leave ev->data NULL (worker SIGSEGV). */
    extern ngx_connection_t brix_maint_timer_conn;
    ngx_uint_t              i;

    if (ngx_worker != 0 || oci_gc_store_count == 0) {
        return;
    }
    /* A pass costs a full walk of the store, so the first one waits out an
     * interval rather than landing on a worker that has just started. */
    for (i = 0; i < oci_gc_store_count; i++) {
        oci_gc_stores[i].due = ngx_current_msec + oci_gc_stores[i].interval;
    }
    oci_gc_timer.handler = oci_gc_tick;
    oci_gc_timer.data = &brix_maint_timer_conn;
    oci_gc_timer.log = cycle->log;
    oci_gc_timer.cancelable = 1;      /* never delay a graceful shutdown */
    ngx_add_timer(&oci_gc_timer, brix_oci_gc_tick_ms());
}
