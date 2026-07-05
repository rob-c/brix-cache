/*
 * metrics/metrics_frm.h
 *
 * Per-process FRM tape-stage metrics (phase-35): the coarse stage-outcome
 * failure-reason codes, the seconds-scale latency histogram bounds, and the
 * process-global counter struct.  Split out of metrics.h so each observability
 * domain owns a focused, independently reviewable header; referenced by
 * ngx_brix_srv_metrics_t via the embedded `frm` member.
 */

#ifndef NGX_BRIX_METRICS_FRM_H
#define NGX_BRIX_METRICS_FRM_H

#include <ngx_core.h>

/*
 * FRM tape-stage counters (phase-35).  Low-cardinality only — stage outcomes by
 * coarse reason and a seconds-scale latency histogram; never a path/DN/reqid as a
 * label (INVARIANT #8).
 */
#define BRIX_FRM_FAIL_COPYCMD   0   /* copycmd exited non-zero            */
#define BRIX_FRM_FAIL_DISPATCH  1   /* stage agent gone / broken pipe     */
#define BRIX_FRM_FAIL_TIMEOUT   2   /* copy_timeout exceeded              */
#define BRIX_FRM_FAIL_VERIFY    3   /* size/checksum mismatch (Phase 4 F5)*/
#define BRIX_FRM_FAIL_OTHER     4
#define BRIX_FRM_NFAIL          5

/* Stage-latency histogram upper bounds in SECONDS (recall = seconds..hours):
 * 1, 10, 30, 60, 300, 1800, 3600, +Inf — 8 buckets. */
#define BRIX_FRM_LATENCY_BUCKETS  8

/*
 * Per-process FRM tape-stage metrics (phase-35).  All ngx_atomic_t, lock-free.
 * The whole block is process-global (one tape queue per node), so it lives
 * directly in the root metrics object rather than per-listener.  All fields are
 * declared up front (across Phases 1-4) so the SHM struct ABI grows only once.
 */
typedef struct {
    ngx_atomic_t  requests_total;       /* stage requests admitted (new records)  */
    ngx_atomic_t  dedup_hits_total;     /* opens collapsed onto an in-flight stage */
    ngx_atomic_t  reject_inflight_total;/* admissions refused: queue at capacity   */
    ngx_atomic_t  stage_success_total;  /* recalls that completed ONLINE           */
    ngx_atomic_t  stage_fail_total[BRIX_FRM_NFAIL]; /* failed recalls by reason  */
    ngx_atomic_t  in_flight;            /* gauge: requests QUEUED+STAGING right now */
    ngx_atomic_t  evict_total;          /* kXR_evict / Tape-REST release marks      */
    ngx_atomic_t  waitresp_total;       /* Phase 3: kXR_waitresp parks issued       */
    ngx_atomic_t  asynresp_total;       /* Phase 3: kXR_attn asynresp deliveries    */
    ngx_atomic_t  cmsd_have_total;      /* Phase 4 F1: now-resident paths registered*/
    ngx_atomic_t  migrate_total;        /* Phase 4 F6: migrate-out attempts (stub)  */
    ngx_atomic_t  purge_total;          /* Phase 4 F6: purge decisions logged (stub)*/
    /* Coarse seconds-scale latency histogram, stored NON-cumulative in SHM and
     * cumulated into Prometheus le-buckets at scrape time. */
    ngx_atomic_t  stage_latency_bucket[BRIX_FRM_LATENCY_BUCKETS];
    ngx_atomic_t  stage_latency_count;
    ngx_atomic_t  stage_latency_sum_sec;
} ngx_brix_frm_metrics_t;

#endif /* NGX_BRIX_METRICS_FRM_H */
