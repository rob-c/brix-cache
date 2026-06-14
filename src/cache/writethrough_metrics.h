#ifndef XROOTD_CACHE_WRITETHROUGH_METRICS_H
#define XROOTD_CACHE_WRITETHROUGH_METRICS_H

/*
 * writethrough_metrics.h — header-only helpers for write-through metric
 * accounting (the "dirty handle" + flush-queue gauges exported on /metrics).
 *
 * WHAT: small ngx_inline helpers that keep two classes of counter consistent:
 *   (1) the per-handle dirty state (wt_dirty_handles gauge) — incremented the
 *       first time a handle goes dirty and decremented exactly once when it is
 *       flushed/closed, and (2) the flush-queue + flush-outcome counters.
 * WHY: these counters are touched from several call sites (write, flush, close,
 *      abort); centralising the inc/dec logic here keeps a handle from being
 *      double-counted or a gauge from going negative under concurrency.
 * HOW: gauges use a guarded decrement (never drop below zero); the dirty-handle
 *      transitions key off file->wt_dirty_offset (< 0 == clean) so the gauge
 *      moves only on the clean<->dirty EDGE, not on every write.
 *
 * Include after ngx_xrootd_module.h so xrootd_ctx_t, xrootd_file_t, and the
 * XROOTD_* metric macros are already visible.
 */

/* Race-safe gauge decrement: only decrements when the counter is > 0, so a
 * double-clean or a lost increment can never drive the gauge negative. */
static ngx_inline void
xrootd_wt_metric_dec_if_positive(ngx_atomic_t *counter)
{
    if (counter != NULL && ngx_atomic_fetch_add(counter, 0) > 0) {
        ngx_atomic_fetch_add(counter, (ngx_atomic_int_t) -1);
    }
}

/* Record that handle `idx` now holds unflushed (dirty) data ending at
 * dirty_offset.  Bumps the wt_dirty_handles gauge ONLY on the clean->dirty edge
 * (first dirty write of this handle, detected via wt_dirty_offset < 0); later
 * writes just accumulate wt_bytes_written and advance the offset.  No-op unless
 * write-through is enabled for the handle. */
static ngx_inline void
xrootd_wt_mark_dirty(xrootd_ctx_t *ctx, int idx, off_t dirty_offset,
    size_t bytes_written)
{
    xrootd_file_t *file;

    if (ctx == NULL || idx < 0 || idx >= XROOTD_MAX_FILES) {
        return;
    }

    file = &ctx->files[idx];
    if (!file->wt_enabled) {
        return;
    }

    if (file->wt_dirty_offset < 0) {
        XROOTD_SRV_METRIC_INC(ctx, wt_dirty_handles);
    }

    file->wt_bytes_written += bytes_written;
    file->wt_dirty_offset = dirty_offset;
}

/* Clear handle `idx`'s dirty state after a successful flush/close.  Decrements
 * the wt_dirty_handles gauge once (guarded) only if the handle was actually
 * dirty, then resets the offset/byte accounting.  Pairs 1:1 with the edge
 * increment in xrootd_wt_mark_dirty. */
static ngx_inline void
xrootd_wt_mark_clean(xrootd_ctx_t *ctx, int idx)
{
    xrootd_file_t *file;

    if (ctx == NULL || idx < 0 || idx >= XROOTD_MAX_FILES) {
        return;
    }

    file = &ctx->files[idx];
    if (file->wt_dirty_offset >= 0 && ctx->metrics != NULL) {
        xrootd_wt_metric_dec_if_positive(&ctx->metrics->wt_dirty_handles);
    }

    file->wt_dirty_offset = -1;
    file->wt_bytes_written = 0;
}

/* wt_flush_pending gauge: a flush task was queued to the thread pool. */
static ngx_inline void
xrootd_wt_metric_pending_inc(ngx_xrootd_srv_metrics_t *metrics)
{
    if (metrics != NULL) {
        XROOTD_ATOMIC_INC(&metrics->wt_flush_pending);
    }
}

/* wt_flush_pending gauge: a queued flush task completed (guarded decrement). */
static ngx_inline void
xrootd_wt_metric_pending_dec(ngx_xrootd_srv_metrics_t *metrics)
{
    if (metrics != NULL) {
        xrootd_wt_metric_dec_if_positive(&metrics->wt_flush_pending);
    }
}

/* A flush succeeded: bump the success counter and add the bytes flushed to the
 * cumulative wt_flush_bytes_total. */
static ngx_inline void
xrootd_wt_metric_flush_success(ngx_xrootd_srv_metrics_t *metrics,
    size_t bytes)
{
    if (metrics != NULL) {
        XROOTD_ATOMIC_INC(&metrics->wt_flush_success_total);
        XROOTD_ATOMIC_ADD(&metrics->wt_flush_bytes_total, bytes);
    }
}

/* A flush failed (origin write/connect error): bump the error counter. */
static ngx_inline void
xrootd_wt_metric_flush_error(ngx_xrootd_srv_metrics_t *metrics)
{
    if (metrics != NULL) {
        XROOTD_ATOMIC_INC(&metrics->wt_flush_error_total);
    }
}

#endif /* XROOTD_CACHE_WRITETHROUGH_METRICS_H */
