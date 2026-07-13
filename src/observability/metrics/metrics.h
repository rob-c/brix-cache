/*
 * metrics/metrics.h
 *
 * Shared memory layout for Prometheus-style metrics exposed by the
 * nginx-xrootd stream module.  One slot per server block (up to
 * BRIX_METRICS_MAX_SERVERS).  Both the stream module and the HTTP
 * metrics module reference this header.
 */

#ifndef NGX_BRIX_METRICS_H
#define NGX_BRIX_METRICS_H

#include <limits.h>
#include <stdint.h>
#include <ngx_core.h>

#include "core/types/fs_list.h"   /* brix_fs_id_t — per-backend counter index */
#include "unified.h"

/* Hard cap on exported stream listeners sharing the metrics zone. */
#define BRIX_METRICS_MAX_SERVERS  16

/*
 * Operation indices — order must match brix_op_names[] in
 * metrics/export.c.
 *
 * The stream side increments op_ok/op_err by these numeric slots; the HTTP
 * exporter later turns the same slot number back into a Prometheus label.
 * That means this list is effectively a small ABI between the two modules.
 */
#define BRIX_OP_LOGIN     0
#define BRIX_OP_AUTH      1
#define BRIX_OP_STAT      2
#define BRIX_OP_OPEN_RD   3
#define BRIX_OP_OPEN_WR   4
#define BRIX_OP_READ      5
#define BRIX_OP_WRITE     6
#define BRIX_OP_SYNC      7
#define BRIX_OP_CLOSE     8
#define BRIX_OP_DIRLIST   9
#define BRIX_OP_MKDIR    10
#define BRIX_OP_RMDIR    11
#define BRIX_OP_RM       12
#define BRIX_OP_MV       13
#define BRIX_OP_CHMOD    14
#define BRIX_OP_TRUNCATE    15
#define BRIX_OP_PING        16
#define BRIX_OP_QUERY_CKSUM 17  /* kXR_query / kXR_QChecksum */
#define BRIX_OP_QUERY_SPACE 17  /* kXR_query / kXR_QSpace    */
#define BRIX_OP_READV       18  /* kXR_readv                 */
#define BRIX_OP_PGREAD      19  /* kXR_pgread                */
#define BRIX_OP_WRITEV      20  /* kXR_writev                */
#define BRIX_OP_LOCATE      21  /* kXR_locate                */
#define BRIX_OP_STATX       22  /* kXR_statx                 */
#define BRIX_OP_FATTR       23  /* kXR_fattr                 */
#define BRIX_OP_QUERY_STATS 24  /* kXR_query / kXR_QStats    */
#define BRIX_OP_QUERY_XATTR 25  /* kXR_query / kXR_Qxattr    */
#define BRIX_OP_QUERY_FINFO 26  /* kXR_query / kXR_QFinfo    */
#define BRIX_OP_QUERY_FSINFO 27 /* kXR_query / kXR_QFSinfo   */
#define BRIX_OP_SET          28 /* kXR_set                    */
#define BRIX_OP_QUERY_VISA   29 /* kXR_query / kXR_Qvisa     */
#define BRIX_OP_QUERY_OPAQUE 30 /* kXR_query / kXR_Qopaque   */
#define BRIX_OP_QUERY_OPAQUF 31 /* kXR_query / kXR_Qopaquf   */
#define BRIX_OP_QUERY_OPAQUG 32 /* kXR_query / kXR_Qopaqug   */
#define BRIX_OP_QUERY_CKSCAN 33 /* kXR_query / kXR_Qckscan   */
#define BRIX_OP_CLONE        34 /* kXR_clone                 */
#define BRIX_OP_CHKPOINT     35 /* kXR_chkpoint              */
/* Number of entries in op_ok[] / op_err[] and brix_op_names[]. */
#define BRIX_NOPS           37

/*
 * Cache-line alignment for the hottest shared-memory counters.  64 bytes is the
 * cache-line size on all x86-64 and current aarch64 server parts; over-aligning
 * on a part with a smaller line is harmless.  Used to stop high-frequency
 * per-operation counters from false-sharing with neighbouring fields written by
 * other cores/worker processes.
 */
#define BRIX_METRIC_CACHELINE 64
#define BRIX_METRIC_ALIGNED   __attribute__((aligned(BRIX_METRIC_CACHELINE)))

/* WebDAV metrics — fixed low-cardinality label slots + counter struct (and the
 * shared HTTP status-class slots via metrics_http_labels.h). Split into its own
 * header so the observability domains stay individually reviewable; embedded
 * below via the ngx_brix_srv_metrics_t `webdav` member. */
#include "metrics_webdav.h"

/* S3 metrics — fixed low-cardinality label slots + counter struct (and the
 * shared HTTP status-class slots via metrics_http_labels.h). Split into its own
 * header so the observability domains stay individually reviewable; embedded
 * below via the ngx_brix_srv_metrics_t `s3` member. */
#include "metrics_s3.h"

/* FRM tape-stage metrics — failure-reason codes, latency histogram bounds, and
 * the process-global counter struct. Split into its own header so the
 * observability domains stay individually reviewable; embedded below via the
 * ngx_brix_srv_metrics_t `frm` member. */
#include "metrics_frm.h"

/* CVMFS (cvmfs://) protocol metrics — class enum, bounded repo/upstream slot
 * tables, aggregate struct, and slot helpers. Split into its own header so the
 * observability domains stay individually reviewable; embedded below via the
 * ngx_brix_srv_metrics_t `cvmfs` member. */
#include "metrics_cvmfs.h"

/* root:// reverse-proxy metrics — aggregate block + bounded per-upstream slice
 * table + the BRIX_PROXY_MAX_UPSTREAMS/label-len constants. Split into its own
 * header so the observability domains stay individually reviewable; embedded
 * below via the ngx_brix_srv_metrics_t `proxy` member and referenced by the
 * proxy metric macros in metrics_macros.h (included after this point). */
#include "metrics_proxy.h"

/*
 * Why the stale-dirty cache reaper removed a cached file — the `reason` label on
 * brix_cache_dirty_reaped_total. Derived per file from its .cinfo write-back
 * state (brix_cache_cinfo_state):
 *   ABANDONED  — DIRTY, aged past brix_cache_dirty_max_age, and NEVER written
 *                back (flush_gen==0): the un-flushed bytes are discarded → loss.
 *   INCOMPLETE — DIRTY, aged, but the file HAD a prior successful write-back
 *                (flush_gen>0) and was re-dirtied: only the trailing dirty
 *                episode is discarded (earlier data reached the origin).
 *   COMPLETED  — CLEAN and fully written back (flush_gen>0), last flush aged out:
 *                a finished write-back staging copy reclaimed with NO data loss.
 *                (A read-through fill has flush_gen==0 and is left for eviction.)
 * Keep COUNT last; it sizes the per-reason counter array below.
 */
typedef enum {
    BRIX_CACHE_REAP_ABANDONED = 0,
    BRIX_CACHE_REAP_INCOMPLETE,
    BRIX_CACHE_REAP_COMPLETED,
    BRIX_CACHE_REAP_REASON_COUNT
} brix_cache_reap_reason_t;

/*
 * Per-server counter block.  Lives in shared memory; accessed by all
 * worker processes.  All integer fields are ngx_atomic_t so workers
 * can increment them without locks.
 *
 * auth[] and port are written once at config init time (before workers
 * fork) so no locking is needed for them.
 */
typedef struct {
    /* Connection and traffic counters exported as Prometheus counters/gauges. */
    ngx_atomic_t  connections_total;       /* connections accepted (lifetime) */
    ngx_atomic_t  connections_active;      /* currently open connections      */
    ngx_atomic_t  bytes_rx_total;          /* bytes received (write payloads) */
    ngx_atomic_t  bytes_tx_total;          /* bytes sent (read data)          */

    /* Per-protocol byte counters for stream-layer traffic breakdown. */
    ngx_atomic_t  proto_root_bytes_rx_total;   /* kXR_read/pgread/readv data     */
    ngx_atomic_t  proto_root_bytes_tx_total;   /* kXR_write/pgwrite/writev data  */

    /* Per-IP-version bandwidth counters — avoids high-cardinality label explosion. */
    ngx_atomic_t  bytes_rx_ipv4_total;         /* received from IPv4 clients      */
    ngx_atomic_t  bytes_tx_ipv4_total;         /* sent to IPv4 clients            */
    ngx_atomic_t  bytes_rx_ipv6_total;         /* received from IPv6 clients      */
    ngx_atomic_t  bytes_tx_ipv6_total;         /* sent to IPv6 clients            */

    /* Wire-level counters used for framing/debug/performance diagnosis. */
    ngx_atomic_t  wire_bytes_rx_total;      /* raw bytes received on socket    */
    ngx_atomic_t  wire_bytes_tx_total;      /* raw bytes written on socket     */
    ngx_atomic_t  request_frames_total;     /* parsed client request headers   */
    ngx_atomic_t  request_payload_bytes_total; /* declared request payload bytes */
    ngx_atomic_t  oversized_payloads_total; /* requests rejected as too large  */
    ngx_atomic_t  response_frames_total;    /* response send attempts          */
    ngx_atomic_t  response_write_stalls_total; /* socket send returned AGAIN    */
    ngx_atomic_t  response_write_errors_total; /* socket send/send_chain errors */

    /*
     * Indexed by BRIX_OP_*; success/error are kept separate for export.
     *
     * These two arrays are the highest-frequency writes in the struct (every
     * completed operation bumps one slot).  Cache-line-align each so the hot
     * op_ok block does not false-share a line with the preceding scalar
     * counters, and so the hot success array does not bounce against the
     * mostly-cold op_err array.  The struct lives at a page-aligned SHM base,
     * so BRIX_METRIC_CACHELINE alignment lands on a real 64-byte boundary
     * shared across worker processes.  (Per-slot padding to fully isolate
     * individual ops is deferred until high-core benchmarks justify the bloat:
     * 37 slots x 64 B x 2 arrays.)
     */
    BRIX_METRIC_ALIGNED ngx_atomic_t op_ok [BRIX_NOPS]; /* successful ops */
    BRIX_METRIC_ALIGNED ngx_atomic_t op_err[BRIX_NOPS]; /* failed ops     */

    /* Cache eviction counters, non-zero only for cache-enabled listeners. */
    ngx_atomic_t  cache_evictions_total;      /* files unlinked by eviction  */
    ngx_atomic_t  cache_evicted_bytes_total;  /* bytes reclaimed by eviction */
    ngx_atomic_t  cache_eviction_errors_total;/* eviction/stat/unlink errors */
    /* Files removed by the stale-dirty reaper, split by WHY (see
     * brix_cache_reap_reason_t): [ABANDONED]=un-flushed dirty discarded (loss),
     * [INCOMPLETE]=re-dirtied after a prior flush (partial loss), [COMPLETED]=a
     * finished write-back staging copy reclaimed (no loss). Counted over the
     * unified cache state root shared by the read-through AND write-through caches,
     * so it is reported for any active cache (gated on in_use, like the wt_
     * counters). Exported as brix_cache_dirty_reaped_total{reason="..."}. */
    ngx_atomic_t  cache_dirty_reaped[BRIX_CACHE_REAP_REASON_COUNT];

    /* Write-through health counters. */
    ngx_atomic_t  wt_dirty_handles;
    ngx_atomic_t  wt_flush_pending;
    ngx_atomic_t  wt_flush_success_total;
    ngx_atomic_t  wt_flush_error_total;
    ngx_atomic_t  wt_flush_bytes_total;

    /* Path depth violation counter — requests rejected due to excessive component count.
     * Prevents CPU exhaustion from malicious symlink traversal chains or deep nesting. */
    ngx_atomic_t  path_depth_violations_total;

    /* §7 XrdSsi service counters (low-cardinality: no per-request labels). */
    ngx_atomic_t  ssi_requests_total;          /* SSI requests dispatched */
    ngx_atomic_t  ssi_errors_total;            /* SSI error responses */
    ngx_atomic_t  ssi_alerts_pushed_total;     /* out-of-band alerts pushed */
    ngx_atomic_t  ssi_attn_push_failures_total;/* failed kXR_attn pushes */

    /*
     * Identity for the listener bound to this slot.
     * The stream module assigns one slot per enabled server during startup.
     */
    ngx_uint_t    port;                    /* TCP listen port (0 = unknown)   */
    char          auth[8];                 /* "anon\0" or "gsi\0"             */
    ngx_uint_t    in_use;                  /* 1 = slot has been assigned      */

    /*
     * Cache labels/config copied from stream srv_conf once a listener accepts
     * traffic.  The HTTP metrics exporter uses cache_root for live statvfs()
     * gauges and the threshold for the configured high-water mark gauge.
     */
    ngx_uint_t    cache_enabled;            /* 1 when brix_cache is on       */
    ngx_uint_t    cache_eviction_threshold; /* occupancy ratio in ppm          */
    char          cache_root[PATH_MAX];     /* NUL-terminated cache root       */

    /* Proxy counters — non-zero only for listeners with brix_proxy on. */
    ngx_brix_proxy_metrics_t  proxy;

    /*
     * Phase 31 W4 — transfer-heap memory budget (SHM pool, shared across
     * workers for this server block).  xfer_heap_in_use is the live sum of bytes
     * held in per-connection transfer scratch buffers (read/write scratch + recv
     * payload); reconciled idempotently by brix_budget_sync() so it cannot
     * drift negative.  budget_waits_total counts reads deferred with kXR_wait
     * because they would have pushed in_use past brix_memory_budget.
     */
    ngx_atomic_t  xfer_heap_in_use;       /* bytes held in transfer scratch buffers */
    ngx_atomic_t  xfer_heap_high_water;   /* peak xfer_heap_in_use observed          */
    ngx_atomic_t  budget_waits_total;     /* reads deferred with kXR_wait (over budget) */

    /*
     * Phase 39 — network-fault resilience timeout counters (low-cardinality,
     * no path/UUID labels).  Each counts connections the steady-state deadline
     * machinery reaped; all stay 0 unless the operator enables the matching
     * directive (brix_handshake_timeout / brix_read_timeout / brix_send_timeout).
     */
    ngx_atomic_t  handshake_timeouts_total; /* pre-auth handshake deadline fired   */
    ngx_atomic_t  read_pdu_timeouts_total;  /* steady-state read deadline fired    */
    ngx_atomic_t  send_drain_timeouts_total;/* response-drain deadline fired       */
    ngx_atomic_t  connections_rejected_total; /* refused at brix_max_connections */

    /*
     * Phase 44 — optional io_uring disk-I/O backend (all 0 unless a worker
     * fronting this listener brought up the ring and submitted ops through it).
     * active is a 0/1 gauge set the first time the listener uses io_uring; ops vs
     * fallback give the ring-utilisation ratio for mapped (read/write/single-
     * group readv/writev) ops — unmapped ops (pgread/dirlist) are not counted.
     */
    ngx_atomic_t  io_uring_active;          /* gauge: 1 = listener used io_uring   */
    ngx_atomic_t  io_uring_ops_total;       /* mapped ops submitted via io_uring   */
    ngx_atomic_t  io_uring_fallback_total;  /* mapped ops that fell back to pool    */
} ngx_brix_srv_metrics_t;

/* ---- Per-VO traffic tracking (bounded LRU, low-cardinality) ---- */
#define BRIX_VO_MAX_TRACKED     32
#define BRIX_VO_NAME_LEN        16

typedef struct {
    char          name[BRIX_VO_NAME_LEN];
    ngx_atomic_t  bytes_tx_total;
    ngx_atomic_t  bytes_rx_total;
    ngx_atomic_t  requests_total;
} ngx_brix_vo_slot_t;

typedef struct {
    ngx_brix_vo_slot_t  slots[BRIX_VO_MAX_TRACKED];
    ngx_uint_t            slot_count;
    ngx_atomic_t          overflow_total;
} ngx_brix_vo_global_t;

/* ---- Unique user identity tracking (bounded LRU, hash-based) ---- */
#define BRIX_USERS_MAX_TRACKED  1024

typedef struct {
    uint32_t      id_hash;
    time_t        first_seen;
    ngx_atomic_t  sessions_total;
} ngx_brix_user_slot_t;

typedef struct {
    ngx_brix_user_slot_t  slots[BRIX_USERS_MAX_TRACKED];
    ngx_atomic_t            unique_count;
    ngx_atomic_t            total_unique;
    ngx_atomic_t            evictions_total;
} ngx_brix_user_global_t;

/*
 * Phase 6 unified observability counters.  These counters are intentionally
 * op-centric and protocol-labeled; legacy per-protocol counters remain
 * exported until callers can cut over their dashboards.
 */
typedef struct {
    ngx_atomic_t  io_bytes_read[BRIX_PROTO_COUNT];
    ngx_atomic_t  io_bytes_written[BRIX_PROTO_COUNT];

    /* Per-BACKEND byte totals (storage plane): bytes the storage-driver
     * instance moved, attributed at the VFS observe chokepoint (staged-commit
     * writes), brix_vfs_io_execute (root:// data plane), and the shared HTTP
     * serve helper (sendfile/memory/compressed GET). Indexed by the census
     * enum brix_fs_id_t (core/types/fs_list.h) — bounded, INVARIANT #8. A
     * staged upload counts into BOTH the stage store and the final backend at
     * promote: the semantic is bytes each backend performed, not client bytes. */
    ngx_atomic_t  io_bytes_read_backend[BRIX_FS_ID_COUNT];
    ngx_atomic_t  io_bytes_written_backend[BRIX_FS_ID_COUNT];
    ngx_atomic_t  io_ops_total[BRIX_PROTO_COUNT]
                                  [BRIX_METRIC_OP_COUNT]
                                  [BRIX_ERR_COUNT];
    ngx_atomic_t  io_latency_bucket[BRIX_PROTO_COUNT]
                                      [BRIX_METRIC_OP_COUNT]
                                      [BRIX_IO_LATENCY_BUCKETS];
    ngx_atomic_t  io_latency_count[BRIX_PROTO_COUNT]
                                      [BRIX_METRIC_OP_COUNT];
    ngx_atomic_t  io_latency_sum_usec[BRIX_PROTO_COUNT]
                                         [BRIX_METRIC_OP_COUNT];

    ngx_atomic_t  cache_hits[BRIX_PROTO_COUNT];
    ngx_atomic_t  cache_misses[BRIX_PROTO_COUNT];
    ngx_atomic_t  cache_bytes_evicted[BRIX_PROTO_COUNT];

    /* Per-user backend credential gate outcomes (Phase 2 Task 3).  Indexed by
     * brix_proto_t — the same proto the VFS ctx carries (brix_vfs_metrics_proto).
     * Bumped at the terminal branches of vfs_backend_cred_decide:
     *   cred_select_user_total     — user credential used (ucred_select OK + cap_ok)
     *   cred_select_fallback_total — service-cred fallback allowed (no cred or not
     *                                capable, but fallback_deny=0); includes both
     *                                the "cap not present" and "missing/expired cred"
     *                                allowed-fallback branches.
     *   cred_select_deny_total     — request rejected EACCES (fallback_deny=1 and
     *                                either no/expired cred or driver lacks capability)
     * Feature-off early return (storage_cred_dir unset) is NOT counted — that is not
     * a credential decision.  Flush-deny (stage_engine BRIX_XFER_DENIED) is NOT
     * counted here; it is observable via the xfer audit ledger result=denied line. */
    ngx_atomic_t  cred_select_user_total[BRIX_PROTO_COUNT];
    ngx_atomic_t  cred_select_fallback_total[BRIX_PROTO_COUNT];
    ngx_atomic_t  cred_select_deny_total[BRIX_PROTO_COUNT];

    /* Watermark-driven LRU reaper (reap_watermark.c). Process-wide, connection-
     * less: the background timer has no per-proto/per-server context. usage_ratio
     * is a GAUGE in ppm (0-1e6), emitted as a 0-1 ratio; the rest are counters. */
    ngx_atomic_t  cache_usage_ratio_ppm;         /* gauge: cache_root occupancy, ppm */
    ngx_atomic_t  cache_watermark_purges;        /* counter: purge runs that did work */
    ngx_atomic_t  cache_watermark_evicted_files; /* counter: files reaped by the reaper */
    ngx_atomic_t  cache_watermark_evicted_bytes; /* counter: bytes reaped by the reaper */

    /* Write-back-staging backpressure (stage_admit.c). usage_ratio is a GAUGE in
     * ppm (staging filesystem occupancy); the throttle counters split by action. */
    ngx_atomic_t  wt_stage_usage_ratio_ppm;      /* gauge: staging fs occupancy, ppm */
    ngx_atomic_t  wt_stage_throttled_wait;       /* counter: writes delayed (soft band) */
    ngx_atomic_t  wt_stage_throttled_reject;     /* counter: writes rejected (hard cap) */

    ngx_atomic_t  auth_total[BRIX_PROTO_COUNT]
                            [BRIX_METRIC_AUTH_COUNT]
                            [BRIX_METRIC_AUTH_STATUS_COUNT];

    ngx_atomic_t  tpc_transfers[BRIX_PROTO_COUNT]
                               [BRIX_METRIC_TPC_DIRECTION_COUNT]
                               [BRIX_ERR_COUNT];
    ngx_atomic_t  tpc_bytes[BRIX_PROTO_COUNT]
                           [BRIX_METRIC_TPC_DIRECTION_COUNT];
} ngx_brix_unified_metrics_t;

/*
 * Root shared-memory object stored in ngx_brix_shm_zone->data.
 * A fixed-size array keeps indexing simple and avoids extra allocation once
 * workers are running.
 */
typedef struct {
    ngx_brix_srv_metrics_t     servers[BRIX_METRICS_MAX_SERVERS];
    ngx_brix_webdav_metrics_t  webdav;
    ngx_brix_s3_metrics_t      s3;
    ngx_brix_cvmfs_metrics_t   cvmfs;   /* phase-68 cvmfs:// protocol plane */
    ngx_brix_unified_metrics_t unified;
    ngx_brix_frm_metrics_t     frm;

    /* Server registry diagnostics. */
    ngx_atomic_t  registry_full_total;

    /* Phase 22 — active health-check counters (cluster group). */
    ngx_atomic_t  hc_probes_total;     /* probes started */
    ngx_atomic_t  hc_pass_total;       /* probes that passed */
    ngx_atomic_t  hc_fail_total;       /* probes that failed/timed out */
    ngx_atomic_t  hc_blacklist_total;  /* servers blacklisted via health check */

    /* Phase 24 — traffic-mirror counters (low cardinality, no labels). */
    ngx_atomic_t  mirror_http_total;             /* shadow HTTP responded */
    ngx_atomic_t  mirror_http_errors_total;      /* shadow HTTP connect/proto fail */
    ngx_atomic_t  mirror_http_dropped_total;     /* HTTP sampling/filter skip */
    ngx_atomic_t  mirror_http_divergence_total;  /* shadow status class != primary */
    ngx_atomic_t  mirror_stream_total;           /* shadow XRootD responded */
    ngx_atomic_t  mirror_stream_errors_total;    /* shadow XRootD connect/proto fail */
    ngx_atomic_t  mirror_stream_dropped_total;   /* stream sampling/filter skip */
    ngx_atomic_t  mirror_stream_divergence_total;/* shadow status != primary */

    /* Phase 25 — advanced rate limiting / traffic shaping counters. */
    ngx_atomic_t  rl_throttled_http_total;   /* HTTP/WebDAV requests answered 429   */
    ngx_atomic_t  rl_throttled_stream_total; /* stream requests answered kXR_wait   */
    ngx_atomic_t  rl_eviction_total;         /* LRU node evictions from a RL zone   */
    ngx_atomic_t  rl_zone_full_errors;       /* alloc failures (zone exhausted)     */

    /* Phase 27 F4 — session-registry anti-exhaustion. */
    ngx_atomic_t  session_registry_full_total; /* logins rejected: table full + nothing reapable */
    ngx_atomic_t  session_evict_total;         /* idle sessions reaped to admit a new login */

    /* Phase 34 — SciTags packet marking (low cardinality, no labels). */
    ngx_atomic_t  pmark_flows_started_total;   /* flows that mapped + were marked      */
    ngx_atomic_t  pmark_flows_ended_total;     /* flows that emitted an end firefly    */
    ngx_atomic_t  pmark_firefly_sent_total;    /* firefly datagrams sent OK            */
    ngx_atomic_t  pmark_firefly_dropped_total; /* firefly sendto failures (fail-open)  */
    ngx_atomic_t  pmark_flowlabel_set_total;   /* IPv6 flow labels stamped             */
    ngx_atomic_t  pmark_flowlabel_failed_total;/* flow-label setsockopt refusals       */
    ngx_atomic_t  pmark_map_unresolved_total;  /* opens with no (exp,act) mapping      */

    /* Phase 51 — cross-protocol resilience observability (low cardinality). */
    ngx_atomic_t  cms_read_timeouts_total;      /* A1: client manager-silence reconnects */
    ngx_atomic_t  cms_login_timeouts_total;     /* A1: server LOGIN-handshake deadline fired */
    ngx_atomic_t  cms_idle_closes_total;        /* A1: server post-login idle watchdog closed */
    ngx_atomic_t  cms_cap_rejections_total;     /* A1: accept refused (global or per-IP cap) */
    ngx_atomic_t  cms_frame_yields_total;       /* A2: read-loop yielded (flood fairness) */
    ngx_atomic_t  ocsp_timeouts_total;          /* E1: OCSP fetch hit the socket deadline */
    ngx_atomic_t  auth_l1_hits_total;           /* E2: auth-gate verdict served from L1 */
    ngx_atomic_t  auth_l1_misses_total;         /* E2: auth-gate L1 miss (fell to L2/eval) */
    ngx_atomic_t  acc_nss_breaker_open_total;   /* E3: NSS group-lookup breaker tripped open */
    ngx_atomic_t  acc_dns_breaker_open_total;   /* E3: reverse-DNS breaker tripped open */

    ngx_brix_vo_global_t    vo_global;
    ngx_brix_user_global_t  user_tracking;

    /*
     * Config/reload diagnostics, published by the master in init_module once per
     * config load (brix_config_version_publish()).  Lives in SHM so the HTTP
     * /healthz handler can read it, and so config_generation survives reload
     * (the metrics zone re-attaches).  config_generation counts loads (1 at first
     * start, +1 on every `nginx -s reload`); config_hash is an FNV-1a fingerprint
     * of the main config file (0 if it could not be read).
     */
    ngx_atomic_t  config_generation;
    uint64_t      config_hash;

} ngx_brix_metrics_t;

/*
 * Global pointer to the shared zone — set by the stream module during
 * postconfiguration; read by the HTTP metrics module at request time.
 */
extern ngx_shm_zone_t *ngx_brix_shm_zone;

/*
 * config.c — publish the config/reload fingerprint into the metrics SHM.  Call
 * once per config load from the module's init_module hook (after shared memory
 * is mapped): bumps config_generation and stores the FNV-1a hash of the main
 * config file, then logs a NOTICE.  No-op when no metrics zone exists.
 */
void  brix_config_version_publish(ngx_cycle_t *cycle);

/* tracking.c — per-VO traffic and unique user identity counting. */
ngx_int_t  brix_track_vo_activity(ngx_brix_metrics_t *shm,
    const char *vo_name, size_t bytes_tx, size_t bytes_rx);
ngx_int_t  brix_track_unique_user(ngx_brix_metrics_t *shm,
    const char *identity, size_t identity_len);

#include "metrics_macros.h"

#endif /* NGX_BRIX_METRICS_H */
