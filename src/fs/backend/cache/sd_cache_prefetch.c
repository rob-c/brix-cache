/*
 * sd_cache_prefetch.c — background block prefetch for slice partial objects
 * (parity audit §4.1: XrdPfc's speculative successor-block fills).
 *
 * WHAT: The cache decorator's read_advise vtable slot. A WILLNEED hint on a
 *       slice partial object posts a detached thread-pool job that fills the
 *       hinted range's ABSENT blocks from the source, so a sequential reader
 *       finds its successor blocks already cached instead of paying an origin
 *       round-trip per block. Bounded by policy.prefetch_jobs (in-flight cap,
 *       0 = off) and policy.prefetch_window (max bytes speculation may run
 *       ahead of the hint cursor — a rolling runway, see the frontier note
 *       in sd_cache_read_advise).
 *
 * WHY:  Before this, the only prefetch was the local POSIX_FADV_WILLNEED hint
 *       — driver-backed (partial-cache) handles got nothing, and every cold
 *       block cost a synchronous origin read on the serving path. The generic
 *       seam is the existing read_advise slot: the sequential-window engines
 *       (root:// read prefetch, the HTTP memory-backed serve loop) hint
 *       through the handle's driver object, and this decorator turns the hint
 *       into background fills. Any future driver can do the same.
 *
 * HOW:  EVENT-LOOP ONLY (documented on the slot): the hint snapshots a
 *       self-contained heap job — key, captured per-user credential, block
 *       range — so the job shares NOTHING with the event-loop handle and
 *       survives its close. The thread half opens its OWN partial object
 *       (sd_cache_partial_open re-adopts the cinfo bitmap, so blocks the
 *       foreground filled meanwhile are skipped) and fills the still-absent
 *       blocks via sd_cache_fill_block — the same "pure driver pread/pwrite"
 *       doctrine brix_sd_cache_fill_key already runs on worker threads. The
 *       done callback (event loop) drops the in-flight count and publishes
 *       the process-wide counters. Concurrent foreground fills of the same
 *       block are idempotent (same bytes, same offsets) — the pre-existing
 *       two-workers-one-object scenario, not a new concurrency class.
 */
#include "sd_cache.h"
#include "sd_cache_internal.h"    /* sd_cache_inst_state + sd_cache_partial_t */
#include "core/aio/aio.h"         /* brix_task_bind */
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"

#include <errno.h>
#include <string.h>

#if (NGX_THREADS)

/* Self-contained job: everything the thread needs, copied at post time. inst
 * and st are per-worker registry-owned (worker-lifetime — they outlive every
 * request); all request-scoped state is embedded by value. */
typedef struct {
    ngx_pool_t          *pool;          /* owns the task + this ctx           */
    brix_sd_instance_t  *inst;          /* the cache decorator instance       */
    sd_cache_inst_state *st;            /* its state (in-flight + policy)     */
    uint64_t              blk_first;     /* first block to consider            */
    uint64_t              blk_last;      /* last block (inclusive)             */
    uint32_t              filled;        /* thread out: blocks actually filled */
    unsigned              failed:1;      /* thread out: open/fill failure      */
    char                  key[1024];
    char                  cred_proxy[1024];
    char                  cred_key[128];
    char                  cred_principal[512];
} sd_cache_prefetch_job_t;

/* The process-wide metrics SHM, or NULL before the zone is mapped. */
static ngx_brix_metrics_t *
prefetch_shm(void)
{
    if (ngx_brix_shm_zone == NULL || ngx_brix_shm_zone->data == NULL
        || ngx_brix_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return ngx_brix_shm_zone->data;
}

/* The common "default" thread pool (the stage-scheduler precedent). NULL =
 * no pool configured — prefetch silently off. */
static ngx_thread_pool_t *
prefetch_thread_pool(void)
{
    static ngx_str_t name = ngx_string("default");

    return (ngx_cycle != NULL)
         ? ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name) : NULL;
}

/* Worker thread: open an own partial object for the key and fill the absent
 * blocks in [blk_first, blk_last]. The fresh open re-adopts the cinfo bitmap,
 * so blocks the foreground (or another job) filled meanwhile are skipped. */
static void
sd_cache_prefetch_thread(void *data, ngx_log_t *log)
{
    sd_cache_prefetch_job_t *j = data;
    brix_sd_cred_t            rc;
    const brix_sd_cred_t     *credp = NULL;
    brix_sd_obj_t            *o;
    sd_cache_partial_t       *p;
    uint64_t                   blk;
    int                        e = 0;

    (void) log;

    if (j->cred_proxy[0] != '\0') {
        ngx_memzero(&rc, sizeof(rc));
        rc.x509_proxy = j->cred_proxy;
        rc.key        = j->cred_key;
        rc.principal  = j->cred_principal;
        credp = &rc;
    }

    o = sd_cache_partial_open(j->inst, j->st, j->key, credp, &e);
    if (o == NULL) {
        j->failed = 1;
        return;
    }
    p = o->state;

    for (blk = j->blk_first; blk <= j->blk_last; blk++) {
        if (p->bitmap != NULL && blk < p->nblocks
            && brix_cache_cinfo_block_present(p->bitmap, blk))
        {
            continue;
        }
        if (sd_cache_fill_block(p, blk) != 0) {
            j->failed = 1;
            break;
        }
        j->filled++;
    }

    brix_sd_obj_release(o);             /* close + free the heap shell */
}

/* Event loop: drop the in-flight count, publish counters, free the job. */
static void
sd_cache_prefetch_done(ngx_event_t *ev)
{
    ngx_thread_task_t        *task = ev->data;
    sd_cache_prefetch_job_t *j = task->ctx;
    ngx_brix_metrics_t      *shm = prefetch_shm();

    if (j->st->prefetch_active > 0) {
        j->st->prefetch_active--;
    }
    if (shm != NULL) {
        BRIX_ATOMIC_ADD(&shm->unified.cache_prefetch_blocks_total, j->filled);
        if (j->failed) {
            BRIX_ATOMIC_INC(&shm->unified.cache_prefetch_failures_total);
        }
    }
    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, j->st->log, 0,
                   "brix: cache prefetch done: %ui blocks, failed=%d, "
                   "in-flight=%ui", (ngx_uint_t) j->filled, (int) j->failed,
                   j->st->prefetch_active);
    ngx_destroy_pool(j->pool);          /* frees the task + ctx */
}

/* Skip leading blocks already present so a hint over cached bytes costs
 * nothing; returns the first absent block at or after b0 (or b1 + 1). (Benign
 * race: a foreground fill from an AIO worker may flip a bit under this read —
 * worst case the job re-checks and skips it.) */
static uint64_t
sd_cache_prefetch_skip_present(sd_cache_partial_t *p, uint64_t b0, uint64_t b1)
{
    while (b0 <= b1 && p->bitmap != NULL && b0 < p->nblocks
           && brix_cache_cinfo_block_present(p->bitmap, b0))
    {
        b0++;
    }
    return b0;
}

/* Resolve a WILLNEED hint to the block range [*b0_out, *b1_out] worth posting,
 * or return 0 when nothing needs fetching. The operator window caps how far
 * speculation may run past the CURRENT hint cursor (blocks whose first byte
 * lies before off + window), and the per-handle frontier ratchet skips blocks
 * an earlier hint on this handle already queued. Together they turn the
 * engines' repeated [cursor, cursor + engine-window) hints into a continuous
 * runway that stays at most `window` bytes ahead of the reader — no
 * burst-then-starve, no compounding runaway, no double-posting. */
static int
sd_cache_prefetch_range(sd_cache_partial_t *p, sd_cache_inst_state *st,
    off_t off, size_t len, uint64_t *b0_out, uint64_t *b1_out)
{
    off_t     end;
    uint64_t  b0, b1;

    if (p->block_size == 0 || off < 0 || len == 0 || off >= p->size) {
        return 0;
    }
    end = ((off_t) len > p->size - off) ? p->size : off + (off_t) len;

    b0 = (uint64_t) off / p->block_size;
    b1 = (uint64_t) (end - 1) / p->block_size;

    if (st->policy.prefetch_window > 0) {
        uint64_t limit = ((uint64_t) off + st->policy.prefetch_window
                          + p->block_size - 1) / p->block_size;

        if (limit == 0 || b0 >= limit) {
            return 0;
        }
        if (b1 >= limit) {
            b1 = limit - 1;
        }
    }
    if (b0 < p->prefetch_next_blk) {
        b0 = p->prefetch_next_blk;
    }
    b0 = sd_cache_prefetch_skip_present(p, b0, b1);
    if (b0 > b1) {
        return 0;                  /* already cached, queued, or past window */
    }

    *b0_out = b0;
    *b1_out = b1;
    return 1;
}

/* Snapshot a self-contained job for blocks [b0, b1] and post it to the
 * "default" thread pool; on success advance the handle's frontier ratchet and
 * the in-flight/jobs counters. Every failure path is a silent no-op — a hint
 * is advisory. */
static void
sd_cache_prefetch_post(brix_sd_obj_t *obj, sd_cache_partial_t *p,
    sd_cache_inst_state *st, uint64_t b0, uint64_t b1)
{
    sd_cache_prefetch_job_t *j;
    ngx_thread_pool_t        *tp;
    ngx_pool_t               *pool;
    ngx_thread_task_t        *task;
    ngx_brix_metrics_t       *shm;

    tp = prefetch_thread_pool();
    if (tp == NULL) {
        return;
    }
    pool = ngx_create_pool(4096, st->log);
    if (pool == NULL) {
        return;
    }
    task = ngx_thread_task_alloc(pool, sizeof(sd_cache_prefetch_job_t));
    if (task == NULL) {
        ngx_destroy_pool(pool);
        return;
    }
    j = task->ctx;
    j->pool      = pool;
    j->inst      = obj->inst;
    j->st        = st;
    j->blk_first = b0;
    j->blk_last  = b1;
    ngx_cpystrn((u_char *) j->key, (u_char *) p->key, sizeof(j->key));
    ngx_cpystrn((u_char *) j->cred_proxy, (u_char *) p->cred_proxy,
                sizeof(j->cred_proxy));
    ngx_cpystrn((u_char *) j->cred_key, (u_char *) p->cred_key,
                sizeof(j->cred_key));
    ngx_cpystrn((u_char *) j->cred_principal, (u_char *) p->cred_principal,
                sizeof(j->cred_principal));

    brix_task_bind(task, sd_cache_prefetch_thread, sd_cache_prefetch_done);
    task->event.log = st->log;
    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        ngx_destroy_pool(pool);
        return;
    }
    st->prefetch_active++;
    p->prefetch_next_blk = b1 + 1;      /* advance this handle's ratchet */

    shm = prefetch_shm();
    if (shm != NULL) {
        BRIX_ATOMIC_INC(&shm->unified.cache_prefetch_jobs_total);
    }
    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, st->log, 0,
                   "brix: cache prefetch posted: blocks %uL..%uL, in-flight=%ui",
                   b0, b1, st->prefetch_active);
}

ngx_int_t
sd_cache_read_advise(brix_sd_obj_t *obj, off_t off, size_t len, int advice)
{
    sd_cache_partial_t   *p;
    sd_cache_inst_state  *st;
    uint64_t               b0, b1;

    /* Only a WILLNEED hint triggers speculative work: SEQUENTIAL is a no-op
     * and RANDOM must never amplify origin traffic (XrdPfc disable-on-random
     * parity — the engines already suppress hints on random access). */
    if (obj == NULL || obj->state == NULL || obj->inst == NULL
        || advice != BRIX_SD_ADV_WILLNEED)
    {
        return NGX_OK;
    }
    p  = obj->state;
    st = SD_CACHE_ST(obj->inst);

    if (st->policy.prefetch_jobs == 0                        /* feature off  */
        || st->prefetch_active >= st->policy.prefetch_jobs)  /* in-flight cap */
    {
        return NGX_OK;
    }
    if (sd_cache_prefetch_range(p, st, off, len, &b0, &b1)) {
        sd_cache_prefetch_post(obj, p, st, b0, b1);
    }
    return NGX_OK;
}

#else  /* !NGX_THREADS */

/* No thread pool support compiled in: the hint stays advisory-only. */
ngx_int_t
sd_cache_read_advise(brix_sd_obj_t *obj, off_t off, size_t len, int advice)
{
    (void) obj;
    (void) off;
    (void) len;
    (void) advice;
    return NGX_OK;
}

#endif /* NGX_THREADS */
