/*
 * metrics/ratelimit.c — Phase 25 Prometheus export for the rate limiter.
 *
 * Only the four aggregate counters are exported (low cardinality, no labels —
 * per metrics INVARIANT 8).  Per-principal counters live in the SHM nodes and
 * are exposed only via the dashboard /xrootd/api/v1/ratelimit endpoint.
 */
#include "metrics_internal.h"
#include "metrics_macros.h"

void
brix_export_ratelimit_metrics(metrics_writer_t *mw, ngx_brix_metrics_t *shm)
{
    if (shm == NULL) {
        return;
    }

    mw_printf(mw,
        "# HELP brix_rate_limit_throttled_total "
            "Requests throttled by the advanced rate limiter.\n"
        "# TYPE brix_rate_limit_throttled_total counter\n"
        "brix_rate_limit_throttled_total{plane=\"http\"} %lu\n"
        "brix_rate_limit_throttled_total{plane=\"stream\"} %lu\n"
        "# HELP brix_rate_limit_eviction_total "
            "LRU node evictions from rate-limit shared-memory zones.\n"
        "# TYPE brix_rate_limit_eviction_total counter\n"
        "brix_rate_limit_eviction_total %lu\n"
        "# HELP brix_rate_limit_zone_full_errors_total "
            "Allocation failures in rate-limit shared-memory zones.\n"
        "# TYPE brix_rate_limit_zone_full_errors_total counter\n"
        "brix_rate_limit_zone_full_errors_total %lu\n",
        (unsigned long) ngx_atomic_fetch_add(&shm->rl_throttled_http_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->rl_throttled_stream_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->rl_eviction_total, 0),
        (unsigned long) ngx_atomic_fetch_add(&shm->rl_zone_full_errors, 0));
}
