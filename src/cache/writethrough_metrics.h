#ifndef XROOTD_CACHE_WRITETHROUGH_METRICS_H
#define XROOTD_CACHE_WRITETHROUGH_METRICS_H

/*
 * Header-only helpers for write-through dashboard/metrics accounting.
 *
 * Include after ngx_xrootd_module.h so xrootd_ctx_t, xrootd_file_t, and the
 * XROOTD_* metric macros are already visible.
 */

static ngx_inline void
xrootd_wt_metric_dec_if_positive(ngx_atomic_t *counter)
{
    if (counter != NULL && ngx_atomic_fetch_add(counter, 0) > 0) {
        ngx_atomic_fetch_add(counter, (ngx_atomic_int_t) -1);
    }
}

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

static ngx_inline void
xrootd_wt_metric_pending_inc(ngx_xrootd_srv_metrics_t *metrics)
{
    if (metrics != NULL) {
        XROOTD_ATOMIC_INC(&metrics->wt_flush_pending);
    }
}

static ngx_inline void
xrootd_wt_metric_pending_dec(ngx_xrootd_srv_metrics_t *metrics)
{
    if (metrics != NULL) {
        xrootd_wt_metric_dec_if_positive(&metrics->wt_flush_pending);
    }
}

static ngx_inline void
xrootd_wt_metric_flush_success(ngx_xrootd_srv_metrics_t *metrics,
    size_t bytes)
{
    if (metrics != NULL) {
        XROOTD_ATOMIC_INC(&metrics->wt_flush_success_total);
        XROOTD_ATOMIC_ADD(&metrics->wt_flush_bytes_total, bytes);
    }
}

static ngx_inline void
xrootd_wt_metric_flush_error(ngx_xrootd_srv_metrics_t *metrics)
{
    if (metrics != NULL) {
        XROOTD_ATOMIC_INC(&metrics->wt_flush_error_total);
    }
}

#endif /* XROOTD_CACHE_WRITETHROUGH_METRICS_H */
