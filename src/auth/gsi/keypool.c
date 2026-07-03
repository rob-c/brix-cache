/*
 * keypool.c — Phase 33 per-worker ephemeral ffdhe2048 DH key pool.
 *
 * See keypool.h for the rationale.  In one line: keep GSI keygen OFF the single
 * nginx event thread so a concurrent kXGC_certreq burst cannot head-of-line-block
 * every other connection on the worker.
 */

#include "keypool.h"
#include "gsi_core.h"             /* brix_gsi_dh_keygen (shared kernel) */
#include "core/aio/aio.h"            /* brix_task_bind */
#include "core/types/tunables.h"     /* BRIX_GSI_KEYPOOL_* */

#include <openssl/evp.h>
#include <openssl/params.h>

/*
 * Per-worker pool state.  The nginx event thread is the ONLY mutator: it pops on
 * kXGC_certreq and pushes from the refill done-callback (which also runs on the
 * event thread).  The refill THREAD function touches only its own task-local
 * storage, never this state — so no locking is required.
 *
 * `target` is the runtime warm ceiling (brix_gsi_keypool_size); `pool` is the
 * thread pool captured at init so the done-callback can chain further off-thread
 * refills until the target is reached without blocking the event loop.
 */
static EVP_PKEY          *brix_kp_ring[BRIX_GSI_KEYPOOL_CAP];
static ngx_uint_t         brix_kp_count;
static ngx_uint_t         brix_kp_target = BRIX_GSI_KEYPOOL_SIZE_DEFAULT;
static ngx_uint_t         brix_kp_refill_pending;
static ngx_uint_t         brix_kp_warmed_logged;   /* one-shot "warmed" notice */
static ngx_thread_pool_t *brix_kp_pool;
static ngx_log_t         *brix_kp_log;

/* Refill once the pool drops to half the target (was a fixed REFILL_LOW). */
static ngx_inline ngx_uint_t
brix_kp_low_water(void)
{
    return brix_kp_target / 2;
}

/* Off-thread refill task: generates a batch into task-local storage. */
typedef struct {
    EVP_PKEY  *keys[BRIX_GSI_KEYPOOL_REFILL_BATCH];
    ngx_uint_t n;
} brix_gsi_refill_t;

/* brix_gsi_dh_keygen() now lives in the shared gsi_core.c (single source for
 * both the module and the native client). */


/* Worker-thread half of a refill: pure keygen into task-local storage. */
static void
brix_kp_refill_thread(void *data, ngx_log_t *log)
{
    brix_gsi_refill_t *r = data;
    ngx_uint_t           i;

    (void) log;
    for (i = 0; i < BRIX_GSI_KEYPOOL_REFILL_BATCH; i++) {
        EVP_PKEY *k = brix_gsi_dh_keygen();
        if (k == NULL) {
            break;             /* keep whatever we managed to generate */
        }
        r->keys[i] = k;
    }
    r->n = i;
}


/* Event-thread half of a refill: move generated keys into the pool. */
static void brix_kp_schedule_refill(ngx_thread_pool_t *pool);

static void
brix_kp_refill_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    brix_gsi_refill_t *r = task->ctx;
    ngx_uint_t           i;

    for (i = 0; i < r->n; i++) {
        if (brix_kp_count < brix_kp_target) {
            brix_kp_ring[brix_kp_count++] = r->keys[i];
        } else {
            EVP_PKEY_free(r->keys[i]);   /* pool refilled meanwhile — drop extra */
        }
    }
    brix_kp_refill_pending = 0;
    ngx_free(task);

    /* Chain another batch while still below target (initial off-thread warm-up
     * to the configured size, one batch at a time, all off the event thread). */
    if (brix_kp_pool != NULL && brix_kp_count < brix_kp_target) {
        brix_kp_schedule_refill(brix_kp_pool);
        return;
    }

    /* Log once when the background warm-up first reaches the configured target,
     * so an operator can confirm the off-thread fill completed (and as the test
     * hook that the lazy seed path really did finish filling the pool). */
    if (!brix_kp_warmed_logged && brix_kp_count >= brix_kp_target) {
        brix_kp_warmed_logged = 1;
        ngx_log_error(NGX_LOG_NOTICE, brix_kp_log, 0,
                      "brix: GSI DH key pool warmed to %ui/%ui keys "
                      "(off-thread)", brix_kp_count, brix_kp_target);
    }
}


static void
brix_kp_schedule_refill(ngx_thread_pool_t *pool)
{
    ngx_thread_task_t *task;

    task = ngx_calloc(sizeof(ngx_thread_task_t) + sizeof(brix_gsi_refill_t),
                      brix_kp_log);
    if (task == NULL) {
        return;                /* leave pending=0; retried on the next low pop */
    }
    task->ctx = task + 1;
    brix_task_bind(task, brix_kp_refill_thread, brix_kp_refill_done);

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        ngx_free(task);
        return;
    }
    brix_kp_refill_pending = 1;
}


void
brix_gsi_keypool_init(ngx_cycle_t *cycle, ngx_thread_pool_t *pool,
                        ngx_uint_t target, ngx_uint_t seed)
{
    ngx_uint_t warm;

    brix_kp_log = cycle->log;

    /* Clamp to the static ring ceiling and a sane seed window. */
    if (target == 0 || target > BRIX_GSI_KEYPOOL_CAP) {
        target = BRIX_GSI_KEYPOOL_CAP;
    }
    if (seed == 0) {
        seed = 1;
    }
    if (seed > target) {
        seed = target;
    }
    brix_kp_target = target;
    brix_kp_pool   = pool;

    /*
     * With a thread pool, generate only `seed` keys synchronously (cheap, keeps
     * the worker accepting connections fast) and fill the rest OFF the event
     * thread.  Without a pool there is nowhere to offload, so fall back to the
     * old behaviour and warm the full target synchronously — correctness over
     * boot latency.
     */
    warm = (pool != NULL) ? seed : target;

    while (brix_kp_count < warm) {
        EVP_PKEY *k = brix_gsi_dh_keygen();
        if (k == NULL) {
            break;
        }
        brix_kp_ring[brix_kp_count++] = k;
    }

    if (pool != NULL && brix_kp_count < brix_kp_target) {
        brix_kp_schedule_refill(pool);   /* background warm-up to target */
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "brix: GSI DH key pool seeded %ui/%ui keys (%s)",
                  brix_kp_count, brix_kp_target,
                  pool != NULL ? "rest filling off-thread"
                               : "synchronous, no thread pool");
}


ngx_int_t
brix_gsi_keypool_pop(ngx_thread_pool_t *pool, ngx_log_t *log, EVP_PKEY **out)
{
    ngx_int_t hit = 0;

    if (brix_kp_log == NULL) {
        brix_kp_log = log;       /* lazy capture for refill task logging */
    }

    if (brix_kp_count > 0) {
        *out = brix_kp_ring[--brix_kp_count];
        hit = 1;
    }

    /* Top the pool back up off-thread once it runs low (and a pool exists). */
    if (pool != NULL
        && !brix_kp_refill_pending
        && brix_kp_count <= brix_kp_low_water())
    {
        brix_kp_schedule_refill(pool);
    }

    return hit;
}
