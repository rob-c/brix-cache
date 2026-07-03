/*
 * stage_admit.c — nginx-side glue for the two-tier staging-backpressure gate.
 * See stage_admit.h for the pure band logic and the rationale.
 */

#include "cache_internal.h"
#include "stage_admit.h"
#include "evict_internal.h"       /* brix_cache_fs_usage_sampled */
#include "observability/metrics/unified.h"   /* staging-occupancy gauge */

/*
 * brix_wt_stage_admit — sample the write-back staging filesystem and apply the
 * two-tier band to decide whether a new write may proceed. ALLOW when staging
 * backpressure is unconfigured (high == 0) or no staging root is set. FAIL-OPEN
 * (ALLOW) on a statvfs error: a monitoring fault must never wedge all writes.
 * Hot path (per write-open/PUT) but cheap — the sampler caches statvfs for ~1s.
 */
brix_wt_admit_t
brix_wt_stage_admit(const ngx_stream_brix_srv_conf_t *conf)
{
    brix_cache_fs_usage_t usage;

    if (conf == NULL
        || conf->cache_wt_stage_high_watermark == 0
        || conf->cache_wt_stage_root.len == 0)
    {
        return BRIX_WT_ADMIT_ALLOW;        /* backpressure disabled */
    }

    if (brix_cache_fs_usage_sampled((char *) conf->cache_wt_stage_root.data,
                                      1000, &usage) != NGX_OK)
    {
        return BRIX_WT_ADMIT_ALLOW;        /* fail-open on a statvfs fault */
    }

    brix_metric_wt_stage_usage_ratio(usage.occupancy_ppm);

    return brix_wt_stage_decide((unsigned) usage.occupancy_ppm,
                                  (unsigned) conf->cache_wt_stage_low_watermark,
                                  (unsigned) conf->cache_wt_stage_high_watermark);
}
