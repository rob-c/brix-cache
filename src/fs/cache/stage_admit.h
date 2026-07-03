#ifndef BRIX_CACHE_STAGE_ADMIT_H
#define BRIX_CACHE_STAGE_ADMIT_H

/*
 * stage_admit.h — two-tier write-back-staging backpressure decision.
 *
 * WHAT: The admission verdict for a new WRITE (root:// write-open, WebDAV/S3 PUT)
 *       based on how full the write-back staging filesystem is.
 *
 * WHY:  Write-through mirrors each write into a durable staging copy before the
 *       FRM-journaled flush to the origin. If the origin is slow/down, staging
 *       grows; unbounded, it fills the disk. Backpressure sheds new writes — first
 *       gently (delay → client retries), then hard (reject) — so staging stays
 *       bounded. Reads never consume staging and are never throttled.
 *
 * HOW:  The pure band logic (brix_wt_stage_decide) is kept header-only and
 *       nginx-free so the unit test links it directly (same split as
 *       cache_fs_sampler.h). The nginx-typed entry point brix_wt_stage_admit()
 *       — which samples the staging filesystem and applies this logic to a server
 *       conf — is declared in cache_internal.h.
 */

/* Soft-band retry hint handed to a delayed write: kXR_wait seconds (root://) and
 * the HTTP Retry-After (WebDAV/S3). Short so a draining stage recovers promptly. */
#define BRIX_WT_STAGE_WAIT_SECS  5

/* ALLOW: accept the write. WAIT: soft band — delay (kXR_wait / 503 Retry-After),
 * the client retries. REJECT: hard cap — refuse now (kXR_Overloaded / 429). */
typedef enum {
    BRIX_WT_ADMIT_ALLOW = 0,
    BRIX_WT_ADMIT_WAIT,
    BRIX_WT_ADMIT_REJECT
} brix_wt_admit_t;

/*
 * brix_wt_stage_decide — the pure two-tier band over staging occupancy.
 *
 *   high_ppm == 0          → backpressure disabled → ALLOW (any occupancy).
 *   occ >= high_ppm        → REJECT (hard cap).
 *   low_ppm <= occ < high  → WAIT  (soft band; LOW boundary inclusive).
 *   occ < low_ppm          → ALLOW.
 *
 * All values are filesystem occupancy in parts-per-million (0-1000000).
 */
static inline brix_wt_admit_t
brix_wt_stage_decide(unsigned occ_ppm, unsigned low_ppm, unsigned high_ppm)
{
    if (high_ppm == 0) {
        return BRIX_WT_ADMIT_ALLOW;        /* disabled */
    }
    if (occ_ppm >= high_ppm) {
        return BRIX_WT_ADMIT_REJECT;
    }
    if (occ_ppm >= low_ppm) {
        return BRIX_WT_ADMIT_WAIT;
    }
    return BRIX_WT_ADMIT_ALLOW;
}

#endif /* BRIX_CACHE_STAGE_ADMIT_H */
