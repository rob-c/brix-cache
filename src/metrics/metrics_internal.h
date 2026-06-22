#ifndef NGX_XROOTD_METRICS_INTERNAL_H
#define NGX_XROOTD_METRICS_INTERNAL_H

/*
 * metrics_internal.h — private contract of the /metrics HTTP exporter module.
 *
 * WHAT: the buffered Prometheus-text writer (metrics_writer_t + mw_* helpers)
 *       and the per-subsystem "export" entry points (one per .c) that the
 *       handler calls to stream the counters out of the shared-memory metrics
 *       block (ngx_xrootd_metrics_t, defined in metrics.h) as Prometheus text.
 * WHY:  the counters live in SHM and are written on the hot path by every
 *       protocol; this read-only exporter is a SEPARATE nginx HTTP module
 *       (ngx_http_xrootd_metrics_module) so /metrics can be scraped without
 *       touching the data plane. Splitting the exporters per subsystem
 *       (stream/webdav/s3/cluster/ratelimit/...) keeps each .c small.
 * HOW:  mw_init/mw_printf/mw_emit_* append into a pool-backed ngx_chain_t of
 *       64 KiB buffers; mw_finish caps the chain; the handler sends it as the
 *       response body. The xrootd_export_* functions each read one region of
 *       *shm and emit its HELP/TYPE/counter lines via the writer.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "metrics.h"

/* Location config — the `xrootd_metrics on;` flag plus the `xrootd_health on;`
 * flag (phase-47 W2: a tiny liveness/readiness endpoint co-located in this
 * module so it needs no new .so).  Both default off (NGX_CONF_UNSET). */
typedef struct {
    ngx_flag_t  enable;   /* xrootd_metrics — Prometheus exporter   */
    ngx_flag_t  health;   /* xrootd_health  — /healthz JSON probe   */
} ngx_http_xrootd_metrics_loc_conf_t;

extern ngx_module_t ngx_http_xrootd_metrics_module;

/* Buffer chain writer for Prometheus text output. */
#define METRICS_BUF_SIZE  65536

/* Grow-only buffered writer: mw_printf/mw_emit_* append text into a chain of
 * METRICS_BUF_SIZE buffers (pool-allocated), starting a new buffer when the
 * current tail fills. The completed chain becomes the /metrics response body. */
typedef struct {
    ngx_pool_t   *pool;
    ngx_chain_t  *head;
    ngx_chain_t  *tail;
    u_char       *pos;   /* current write cursor in tail buffer        */
    u_char       *last;  /* one-past-end pointer for the tail buffer   */
    size_t        total; /* total bytes emitted across the whole chain */
} metrics_writer_t;

/* writer.c */
extern const char *xrootd_http_status_names[XROOTD_HTTP_NSTATUS];
extern const char *xrootd_http_range_result_names[3];

/* Initialise *mw and allocate its first METRICS_BUF_SIZE buffer from `pool`
 * (pool not owned — caller's request pool). Must be called before any
 * mw_printf/mw_emit_*. Returns NGX_OK, or NGX_ERROR if buffer alloc fails. */
ngx_int_t  mw_init(metrics_writer_t *mw, ngx_pool_t *pool);

/* Append printf-formatted text to the chain, rolling over to a fresh buffer if
 * the current tail can't hold the output (a single line must fit in one empty
 * METRICS_BUF_SIZE buffer). Returns NGX_OK, or NGX_ERROR on encoding failure or
 * a line that overflows even an empty buffer. NOTE: the mw_emit_* helpers ignore
 * this return, so an over-long single line is silently dropped from output. */
ngx_int_t  mw_printf(metrics_writer_t *mw, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Emit one single-label counter family: a HELP/TYPE banner for `name` then `n`
 * rows `name{label_key="names[i]"} value`. `counters` is read atomically
 * (lock-free load, not mutated); `names` and `counters` must both have >= n
 * elements and stay live for the call. No return (errors swallowed via mw_printf). */
void       mw_emit_labeled(metrics_writer_t *mw, const char *name,
    const char *help, const char *label_key, const char * const *names,
    ngx_uint_t n, ngx_atomic_t *counters);

/* Emit one unlabelled counter family: HELP/TYPE banner plus a single
 * `name value` line. `counter` is read atomically (lock-free load, not mutated). */
void       mw_emit_scalar(metrics_writer_t *mw, const char *name,
    const char *help, ngx_atomic_t *counter);

/* Emit per-zone KV-cache counters (hits/misses/evictions/entries/capacity) for
 * every configured KV zone, labelled by operator-chosen zone name. Reads each
 * zone's stats snapshot; emits nothing when no zones are configured. Module-
 * global state — takes no shm argument. */
void       xrootd_kv_metrics_emit(metrics_writer_t *mw);

/* Seal the chain: trim the tail buffer to the written length and mark it
 * last_buf, making mw->head a complete response body. Call exactly once after
 * all output; no further mw_printf/mw_emit_* afterwards. */
void       mw_finish(metrics_writer_t *mw);

/* stream.c */
/* Top-level /metrics exporter: emits the native-stream families AND fans out to
 * every other subsystem exporter below (cache/proxy/tracking/unified/webdav/s3/
 * cluster/ratelimit/mirror), so the handler only needs this one call. `shm` is
 * the per-worker metrics SHM (borrowed, read-only). Counters read lock-free;
 * output is eventually consistent (no global snapshot lock). */
void  xrootd_export_prometheus_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);
/* Emit read-through/write-through cache families (occupancy, evictions,
 * thresholds), one {port,auth} row per active server slot. Re-stats each cache
 * root via statvfs(2) at scrape time; skips inactive/cache-disabled slots. */
void  xrootd_export_stream_cache_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);
/* Emit transparent-proxy families (connect/auth/op/byte counters), aggregate
 * per server plus a per-upstream row for each labelled upstream slot. */
void  xrootd_export_stream_proxy_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);
/* Emit VO and unique-user tracking families from the bounded SHM LRU tables
 * (per-VO bytes/requests, VO overflow, unique-user current/total/evictions).
 * VO label is the truncated VO name; users are FNV-1a-hashed (no DNs as labels). */
void  xrootd_export_stream_tracking_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);
/* Emit the cross-protocol unified families (xrootd_io_*, xrootd_cache_*,
 * xrootd_auth_total, xrootd_tpc_*). Latency histogram buckets are stored
 * non-cumulative in SHM and cumulated here at scrape time; also folds legacy
 * per-server stream counters into the stream-proto rows. */
void  xrootd_export_unified_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);

/* webdav.c */
/* Emit all WebDAV counter families from shm->webdav (per-method requests and
 * method x status responses, auth outcomes, bytes, range/PUT modes, PROPFIND
 * depth, HTTP-TPC, CORS, credential delegation). Labels are fixed enums only. */
void  xrootd_export_webdav_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);

/* s3.c */
/* Emit all S3-endpoint counter families from shm->s3 (requests, method x status
 * responses, auth, bytes, range/PUT modes, events, ListObjectsV2 stats). */
void  xrootd_export_s3_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);

/* stream.c — Phase 34 SciTags packet-marking aggregate counters (flows started/
 * ended, firefly sent/dropped, flow-label set/failed, unmapped opens). */
void  xrootd_export_pmark_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);

/* frm/metrics.c — phase-35 FRM tape-stage counters (stage requests/dedup/
 * success/fail-by-reason, in-flight gauge, evict/migrate/purge, async
 * waitresp/asynresp, and the coarse seconds stage-latency histogram). */
void  xrootd_export_frm_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);

/* cluster.c — reads registry SHM directly, no shm argument needed */
/* Emit per-server cluster gauges (space/load/heartbeat-age/blacklist) plus
 * health-check counters from a locked snapshot of the registry SHM. Emits
 * nothing (not even the count gauge) when no registry zone exists, i.e. unless
 * running in manager/redirector mode. */
void  xrootd_export_cluster_metrics(metrics_writer_t *mw);

/* ratelimit.c — Phase 25 advanced rate-limit aggregate counters */
/* Emit the four low-cardinality rate-limiter aggregate counters (throttled,
 * evictions, zone-full errors). No-op if `shm` is NULL. Per-principal detail is
 * exposed only via the dashboard API, never here. */
void  xrootd_export_ratelimit_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);

/* handler.c */
/* /metrics HTTP content handler. Returns NGX_DECLINED when the location's
 * `xrootd_metrics` flag is off, NGX_HTTP_NOT_ALLOWED for non-GET/HEAD, 500 if
 * the writer can't init; otherwise builds the Prometheus body in the request
 * pool and returns ngx_http_output_filter()'s rc. Reads SHM only (no mutation);
 * emits an informational comment body when no stream zone is configured. */
ngx_int_t  ngx_http_xrootd_metrics_handler(ngx_http_request_t *r);

/* health.c — content handler for `xrootd_health on;` (phase-47 W2).  Serves
 * GET/HEAD /healthz as a small JSON liveness document (always 200 while the
 * worker is accepting connections); `?verbose` adds cheap, non-secret
 * readiness signals (metrics SHM mapped, worker pid, nginx version).  Reads
 * only process/global state — never the request body and never any secret. */
ngx_int_t  ngx_http_xrootd_health_handler(ngx_http_request_t *r);

/* tracking.c — per-VO traffic and unique user identity counting. */
/* Atomically add `bytes_tx`/`bytes_rx` and a request to the SHM slot for
 * NUL-terminated `vo_name` (copied, truncated to XROOTD_VO_NAME_LEN-1). A new VO
 * takes a free slot; if the table is full, overflow_total is bumped and slot 0 is
 * reused. Returns NGX_OK, or NGX_ERROR if shm/vo_name is NULL or vo_name empty.
 * Hot-path mutator (write side), not an exporter. */
ngx_int_t  xrootd_track_vo_activity(ngx_xrootd_metrics_t *shm, const char *vo_name,
    size_t bytes_tx, size_t bytes_rx);
/* Record a session for the user identified by FNV-1a hash of (`identity`,
 * `identity_len`) — `identity` is borrowed, hashed, never stored verbatim
 * (INVARIANT #8). Bumps the existing slot's session count, or claims a free slot
 * (LRU-evicts slot 0, bumping evictions_total, when full). Returns NGX_OK, or
 * NGX_ERROR if shm/identity is NULL or identity_len is 0. */
ngx_int_t  xrootd_track_unique_user(ngx_xrootd_metrics_t *shm, const char *identity,
    size_t identity_len);

#endif /* NGX_XROOTD_METRICS_INTERNAL_H */
