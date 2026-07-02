#ifndef XROOTD_BUDGET_H
#define XROOTD_BUDGET_H

#include "ngx_xrootd_module.h"

/*
 * Phase 31 W4 — transfer-heap memory budget (SHM-global pool).
 *
 * WHAT: a single shared atomic (metrics->xfer_heap_in_use) tracks, across all
 * worker processes, the bytes currently held in per-connection transfer scratch
 * buffers (read/write scratch + recv payload).  xrootd_memory_budget caps that
 * sum; when a read would push it over, the read is deferred with kXR_wait and
 * the client re-issues it — no server-side suspend/resume needed.
 *
 * WHY: per-connection trimming (W1) bounds idle memory, but only a global cap
 * bounds the *sum* under arbitrary concurrency, turning an OOM-kill risk into
 * graceful backpressure — the enforcement that makes the 1 GB target a guarantee.
 *
 * HOW: charging is done by idempotent reconciliation, not paired inc/dec, so it
 * can never drift negative or double-count: xrootd_budget_sync() compares the
 * connection's *current* scratch footprint to what it has already charged and
 * applies only the delta.  xrootd_budget_release() (disconnect) zeroes it.
 */

static ngx_inline size_t
xrootd_budget_ctx_footprint(xrootd_ctx_t *ctx)
{
    size_t      total;
    ngx_uint_t  i;

    total = ctx->read_scratch_size + ctx->read_hdr_scratch_size
          + ctx->write_scratch_size + ctx->payload_buf_size
          + ctx->cmp_scratch_size;   /* phase-42 W4 inline-read codec output buf */

    /* Phase 32 WS3: include the concurrent-AIO read-pool buffers (several may be
     * in flight at once once read pipelining is enabled). */
    for (i = 0; i < ctx->pipeline_depth; i++) {
        total += ctx->rd_pool[i].size;
    }

    return total;
}

/*
 * Reconcile this connection's charged bytes with its current scratch footprint.
 * Idempotent — safe to call as often as wanted (after any scratch grow/trim).
 */
static ngx_inline void
xrootd_budget_sync(xrootd_ctx_t *ctx)
{
    ngx_xrootd_srv_metrics_t *m = ctx->metrics;
    size_t                cur;

    if (m == NULL) {
        return;
    }

    cur = xrootd_budget_ctx_footprint(ctx);
    if (cur == ctx->budget_charged) {
        return;
    }

    if (cur > ctx->budget_charged) {
        ngx_atomic_int_t  add = (ngx_atomic_int_t) (cur - ctx->budget_charged);
        ngx_atomic_uint_t now = ngx_atomic_fetch_add(&m->xfer_heap_in_use, add)
                                + (ngx_atomic_uint_t) add;

        /* Best-effort high-water — a racy monotone hint, not a strict max. */
        if (now > (ngx_atomic_uint_t) m->xfer_heap_high_water) {
            m->xfer_heap_high_water = (ngx_atomic_t) now;
        }
    } else {
        ngx_atomic_int_t  sub = (ngx_atomic_int_t) (ctx->budget_charged - cur);
        (void) ngx_atomic_fetch_add(&m->xfer_heap_in_use, -sub);
    }

    ctx->budget_charged = cur;
}

/* Release all charged bytes — call once on disconnect. */
static ngx_inline void
xrootd_budget_release(xrootd_ctx_t *ctx)
{
    ngx_xrootd_srv_metrics_t *m = ctx->metrics;

    if (m != NULL && ctx->budget_charged > 0) {
        (void) ngx_atomic_fetch_add(&m->xfer_heap_in_use,
                                    -(ngx_atomic_int_t) ctx->budget_charged);
    }
    ctx->budget_charged = 0;
}

/*
 * Admission: return 1 if a transfer that will hold `want` heap bytes may
 * proceed now, 0 if it should be deferred (caller sends kXR_wait).
 *
 * budget <= 0 disables the cap.  A connection is never blocked by the bytes it
 * already holds (subtracted), and a lone transfer is never deadlocked when the
 * pool is otherwise empty.  On deferral, budget_waits_total is incremented.
 */
static ngx_inline ngx_int_t
xrootd_budget_admit(xrootd_ctx_t *ctx, off_t budget, size_t want)
{
    ngx_xrootd_srv_metrics_t *m = ctx->metrics;
    ngx_atomic_uint_t     in_use, others;

    if (m == NULL || budget <= 0) {
        return 1;
    }

    in_use = (ngx_atomic_uint_t) m->xfer_heap_in_use;
    others = (in_use > ctx->budget_charged)
             ? in_use - (ngx_atomic_uint_t) ctx->budget_charged : 0;

    if (others == 0 || others + want <= (ngx_atomic_uint_t) budget) {
        return 1;
    }

    (void) ngx_atomic_fetch_add(&m->budget_waits_total, 1);
    return 0;
}

#endif /* XROOTD_BUDGET_H */
