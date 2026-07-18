/*
 * stage_engine_scheduler.c — the async front door + per-worker scheduler of the
 * staging engine (split from stage_engine.c, phase-79).
 *
 * WHAT: Owns the submit front door (brix_stage_submit — run inline or defer onto
 *       the per-worker FIFO), the terminal post-processing of a completed mover
 *       (stage_complete — drop a flushed stage copy, dead-letter a permanent deny,
 *       keep a transient failure), the optional thread-pool offload of a flush,
 *       and the per-worker timer that drains the deferred queue
 *       (brix_stage_scheduler_tick).
 *
 * WHY:  stage_engine.c owned three concerns and exceeded the file-size cap. The
 *       queue + scheduler is a self-contained concern: it builds the in-memory
 *       pending FIFO, persists it through the journal seam, and drains it through
 *       the generic mover seam. The FIFO ordering, the bounded per-tick budget,
 *       the bounded in-flight offload count, and the inline fallback are unchanged
 *       by the split — this is a re-home, not a behavior change.
 *
 * HOW:  brix_stage_submit appends a stage_pending_t and journals it;
 *       brix_stage_scheduler_tick pops the head, offloads to the thread pool when
 *       one exists (bounded), else runs the mover inline, and calls stage_complete
 *       on the terminal result. All durable-record I/O is reached through
 *       stage_engine_internal.h; the byte mover is stage_engine_run.
 */

#include "stage_engine.h"
#include "stage_engine_internal.h"
#include "xfer.h"                /* BRIX_XFER_* result vocabulary */
#include "core/aio/aio.h"        /* brix_task_bind (mover thread-offload) */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static stage_pending_t *stage_pending_head;          /* per-worker FIFO tail-append */
static stage_pending_t *stage_pending_tail;

/* ---- the public front door ------------------------------------------------ */

const char *
brix_stage_submit(brix_stage_kind_t kind, brix_sd_instance_t *src,
    const char *src_key, brix_sd_instance_t *dst, const char *dst_key,
    const brix_stage_opts_t *opts)
{
    static const char ran_inline[] = "";
    static char       last_reqid[40];   /* event-loop single-threaded: stable enough */
    stage_pending_t  *p;

    if (src == NULL || src_key == NULL || dst == NULL || dst_key == NULL
        || src->driver == NULL || dst->driver == NULL)
    {
        return NULL;
    }

    /* Synchronous (the default): move now and return "" = done inline. */
    if (opts == NULL || !opts->async) {
        (void) stage_engine_run(kind, src, src_key, dst, dst_key,
                                (opts != NULL) ? opts->cred : NULL);
        return ran_inline;
    }

    /* Asynchronous: defer to the scheduler (durable). The src/dst instances are
     * the memoised per-worker tier instances, so holding them is safe. */
    p = calloc(1, sizeof(*p));
    if (p == NULL) {
        (void) stage_engine_run(kind, src, src_key, dst, dst_key, opts->cred);
        return ran_inline;
    }
    stage_reqid_mint(p->reqid);
    p->kind = kind;
    p->src  = src;
    p->dst  = dst;
    snprintf(p->src_key, sizeof(p->src_key), "%s", src_key);
    snprintf(p->dst_key, sizeof(p->dst_key), "%s", dst_key);
    if (opts->export_root != NULL) {
        snprintf(p->export_root, sizeof(p->export_root), "%s", opts->export_root);
    }
    if (opts->cred != NULL) {
        p->cred = *opts->cred;    /* copy the owner identity into the pending item */
    }

    if (stage_pending_tail != NULL) {
        stage_pending_tail->next = p;
    } else {
        stage_pending_head = p;
    }
    stage_pending_tail = p;

    stage_journal_write(p);
    snprintf(last_reqid, sizeof(last_reqid), "%s", p->reqid);
    return last_reqid;          /* non-empty = deferred; the caller may park on it */
}

/* Max transfers a single tick STARTS, so a backlog never monopolises the worker.
 * The next tick continues the queue. */
#define STAGE_TICK_BUDGET 32

/* Terminal post-processing for a completed mover (inline or thread): on success a
 * FLUSH drops the now-redundant stage copy (the migrate semantic, §9.5) and the
 * journal record is removed; on a permanent deny (BRIX_XFER_DENIED) the attempt
 * counter is bumped and, when the cap is reached, the record is moved to the
 * deadletter/ subdirectory (stage copy kept for operator recovery); on any other
 * failure the record is KEPT (transient — the reconcile retries on restart or a
 * later tick re-drives it). Shared by both the scheduler and thread paths.
 *
 * WHAT: Distinguishes three outcomes: OK (remove journal + drop stage copy),
 *       DENIED (call stage_deny_terminal to enforce the dead-letter cap), and
 *       all other errors (WARN + keep for retry).
 *
 * WHY:  A BRIX_XFER_DENIED result is not transient: the per-user credential is
 *       permanently missing/expired in deny mode.  Treating it like a transient
 *       error leaves the record looping forever.  The dead-letter cap bounds
 *       that loop while preserving the data for operator recovery.
 *
 * HOW:  On DENIED, re-reads the on-disk record to get the current attempts
 *       count (surviving across restarts), then delegates to stage_deny_terminal
 *       which bumps, persists, and conditionally moves to deadletter/. */
static void
stage_complete(brix_stage_kind_t kind, brix_sd_instance_t *src,
    const char *src_key, const char *dst_key, const char *reqid,
    brix_xfer_result_t res, int last_errno, ngx_log_t *log)
{
    if (res == BRIX_XFER_OK) {
        if (kind == BRIX_STAGE_FLUSH && src->driver->unlink != NULL) {
            (void) src->driver->unlink(src, src_key, 0);
        }
        stage_journal_remove(reqid);
        return;
    }

    if (res == BRIX_XFER_DENIED && stage_journal_dir[0] != '\0') {
        /* Permanent deny: re-read the on-disk record to get the current
         * attempts count (may have been bumped by a prior drive after a
         * restart), then apply the dead-letter cap. */
        char        path[1200];
        char        rbuf[sizeof(brix_sreq_t)];
        brix_sreq_t rec;
        int         fd;
        ssize_t     n;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                              stage_journal_dir, reqid) < sizeof(path))
        {
            fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                n = read(fd, rbuf, sizeof(rbuf));
                (void) close(fd);
                if (brix_sreq_decode(rbuf, (size_t) n, &rec) == NGX_OK) {
                    (void) stage_deny_terminal(stage_journal_dir, reqid, &rec,
                                               log);
                    return;
                }
            }
        }
        /* Journal record unreadable: fall through to the WARN+keep path so
         * the transient I/O error does not silently swallow the failure. */
    }

    /* Transient failure (dead/unreachable origin): mark the durable record
     * FAILED so a crash-visible, replayable row survives — the restart reconcile
     * re-drives it. Left in the ACTIVE journal (never dead-letter): unlike a
     * permanent deny, a transient origin outage is expected to clear. */
    stage_journal_mark_failed(stage_journal_dir, reqid, last_errno);

    ngx_log_error(NGX_LOG_WARN, log, 0,
        "xrootd stage: deferred %s of \"%s\" failed (reqid %s errno %d) - "
        "record marked FAILED, kept for retry",
        brix_stage_kind_str(kind), dst_key, reqid, last_errno);
}

#if (NGX_THREADS)

/* In-flight offloaded movers (per-worker), bounded so a burst never floods the
 * thread pool nor unbounds memory. The tick stops starting new ones at the cap and
 * resumes next tick as they drain. */
static ngx_uint_t stage_inflight;
#define STAGE_MAX_INFLIGHT 8

/* The off-loop mover task (lives on its own small pool, freed in the done event).
 * `cred` carries the owner identity so the flush thread can re-resolve the per-user
 * proxy at flush time via stage_engine_run's cred logic. */
typedef struct {
    ngx_pool_t           *pool;
    brix_stage_kind_t   kind;
    brix_sd_instance_t *src;
    brix_sd_instance_t *dst;
    brix_xfer_result_t  res;
    int                   last_errno;    /* mover errno, carried to the done event */
    ngx_log_t            *log;
    char                  reqid[40];
    char                  src_key[1024];
    char                  dst_key[1024];
    brix_stage_cred_t     cred;          /* owner identity for per-user cred check */
} stage_flush_task_t;

static void
stage_flush_thread(void *data, ngx_log_t *log)
{
    stage_flush_task_t      *t    = data;
    const brix_stage_cred_t *credp = (t->cred.key[0] != '\0') ? &t->cred : NULL;

    (void) log;
    errno = 0;
    t->res = stage_engine_run(t->kind, t->src, t->src_key, t->dst, t->dst_key,
                              credp);
    t->last_errno = (t->res == BRIX_XFER_OK) ? 0 : errno;
}

static void
stage_flush_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    stage_flush_task_t *t = task->ctx;
    ngx_pool_t         *pool = t->pool;

    if (stage_inflight > 0) {
        stage_inflight--;
    }
    stage_complete(t->kind, t->src, t->src_key, t->dst_key, t->reqid, t->res,
                   t->last_errno, t->log);
    ngx_destroy_pool(pool);              /* frees the task + ctx */
}

/* Post `p`'s mover to `pool`. NGX_OK = posted (caller drops the pending item; the
 * journal record persists until the thread completes); NGX_DECLINED = setup failed
 * (caller runs it inline). */
static ngx_int_t
stage_flush_offload(const stage_pending_t *p, ngx_thread_pool_t *pool)
{
    ngx_log_t          *log = (p->dst->log != NULL) ? p->dst->log : p->src->log;
    ngx_pool_t         *tp;
    ngx_thread_task_t  *task;
    stage_flush_task_t *t;

    if (log == NULL) {
        log = ngx_cycle->log;
    }
    tp = ngx_create_pool(4096, log);
    if (tp == NULL) {
        return NGX_DECLINED;
    }
    task = ngx_thread_task_alloc(tp, sizeof(stage_flush_task_t));
    if (task == NULL) {
        ngx_destroy_pool(tp);
        return NGX_DECLINED;
    }
    t = task->ctx;
    t->pool = tp;
    t->kind = p->kind;
    t->src  = p->src;
    t->dst  = p->dst;
    t->res  = BRIX_XFER_DST_ERR;
    t->last_errno = EIO;
    t->log  = log;
    t->cred = p->cred;    /* copy owner identity for cred re-resolution in thread */
    snprintf(t->reqid, sizeof(t->reqid), "%s", p->reqid);
    snprintf(t->src_key, sizeof(t->src_key), "%s", p->src_key);
    snprintf(t->dst_key, sizeof(t->dst_key), "%s", p->dst_key);

    brix_task_bind(task, stage_flush_thread, stage_flush_done);
    task->event.log = log;
    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        ngx_destroy_pool(tp);
        return NGX_DECLINED;
    }
    stage_inflight++;
    return NGX_OK;
}

/* The export's async thread pool (the common "default" pool). NULL = serve inline. */
static ngx_thread_pool_t *
stage_thread_pool(void)
{
    static ngx_str_t name = ngx_string("default");

    return (ngx_cycle != NULL)
         ? ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name) : NULL;
}

#endif /* NGX_THREADS */

void
brix_stage_scheduler_tick(void)
{
    int budget = STAGE_TICK_BUDGET;
#if (NGX_THREADS)
    ngx_thread_pool_t *pool = stage_thread_pool();
#endif

    while (stage_pending_head != NULL && budget-- > 0) {
        stage_pending_t     *p = stage_pending_head;
        brix_xfer_result_t res;
        int                  oerr;
        ngx_log_t           *log = (p->dst->log != NULL) ? p->dst->log
                                                         : p->src->log;

#if (NGX_THREADS)
        /* Run the mover OFF the event loop so a flush to a REMOTE backend (or from a
         * remote stage store) never blocks/fails on the un-pumped loop. Bounded
         * in-flight; the durable journal record is what survives a crash mid-flush
         * (recovered by reconcile), so the on-disk record is dropped only in the
         * completion. */
        if (pool != NULL) {
            if (stage_inflight >= STAGE_MAX_INFLIGHT) {
                break;                      /* let in-flight drain; resume next tick */
            }
            if (stage_flush_offload(p, pool) == NGX_OK) {
                stage_pending_head = p->next;
                if (stage_pending_head == NULL) {
                    stage_pending_tail = NULL;
                }
                free(p);
                continue;
            }
            /* offload setup failed - fall through to the inline path */
        }
#endif

        stage_pending_head = p->next;
        if (stage_pending_head == NULL) {
            stage_pending_tail = NULL;
        }
        {
            const brix_stage_cred_t *credp =
                (p->cred.key[0] != '\0') ? &p->cred : NULL;
            errno = 0;
            res = stage_engine_run(p->kind, p->src, p->src_key, p->dst,
                                   p->dst_key, credp);
            oerr = (res == BRIX_XFER_OK) ? 0 : errno;
        }
        stage_complete(p->kind, p->src, p->src_key, p->dst_key, p->reqid, res,
                       oerr, log);
        free(p);
    }
}
