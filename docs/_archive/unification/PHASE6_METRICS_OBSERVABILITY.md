# Phase 6: Metrics & Observability Unification - Implementation Plan

**Status:** PLANNING  
**Phase:** 6 of 6 (Protocol Unification)  
**Depends On:** Phase 3 (VFS Operations), Phase 4 (Cache Unification), Phase 5 (TPC Unification)  
**Estimated Effort:** 8-12 hours  
**Risk Level:** MEDIUM (additive changes; existing metrics remain until cutover)  
**Target:** Op-centric Prometheus metric model; unified structured access log; single dashboard view

---

## Executive Summary

This is the final phase and it is largely additive. Phases 1–5 push all meaningful work through shared layers. Phase 6 harvests the observability payoff: because all I/O now flows through the VFS layer and all identities are `xrootd_identity_t`, a single instrumentation point captures throughput, latency, cache effectiveness, and authentication method across every protocol simultaneously.

Currently metrics are siloed:

| Metric | Stream | WebDAV | S3 |
|:---|:---|:---|:---|
| Bytes sent | `src/metrics/stream.c` | `src/metrics/webdav.c` | `src/metrics/s3.c` |
| Request count | `src/metrics/stream.c` | `src/metrics/webdav.c` | `src/metrics/s3.c` |
| Cache hits | `src/metrics/stream_cache.c` | Not recorded | Not recorded |
| TPC bytes | Not recorded | `src/webdav/metrics.c` (partial) | N/A |
| Auth method | Not recorded | Not recorded | Not recorded |

After Phase 6:
- One Prometheus query shows total read throughput across all protocols.
- A single access log line contains protocol, auth method, op, path, bytes, duration, and cache status.
- The dashboard displays all protocols in one transfer table.

---

## Current State Analysis

### Existing Metric Infrastructure (`src/metrics/`)

| File | Purpose |
|:---|:---|
| `metrics.h` | Metric slot enum and public API |
| `metrics_internal.h` | Per-worker metric array |
| `metrics_macros.h` | `XROOTD_PROXY_METRIC_INC(op, status)` macro |
| `stream.c` | Stream-specific metric export |
| `stream_cache.c` | Stream cache hit/miss metrics |
| `stream_proxy.c` | Stream proxy metric export |
| `stream_tracking.c` | Per-stream byte tracking |
| `webdav.c` | WebDAV metric export |
| `s3.c` | S3 metric export |
| `tracking.c` | General tracking helpers |
| `handler.c` | `/metrics` HTTP endpoint handler |
| `writer.c` | Prometheus text format writer |
| `http_common.h` | Shared HTTP helpers for metrics endpoint |
| `module.c` | nginx module registration |
| `config.c` | Config parsing |

The metric slot enum in `metrics.h` contains separate slots per protocol:

```c
// Current (protocol-centric):
XROOTD_METRIC_STREAM_BYTES_TX,
XROOTD_METRIC_STREAM_READS,
XROOTD_METRIC_WEBDAV_BYTES_TX,
XROOTD_METRIC_WEBDAV_GETS,
XROOTD_METRIC_S3_BYTES_TX,
XROOTD_METRIC_S3_GET_OBJECTS,
...
```

A single Prometheus query cannot sum read throughput across all protocols without manual label juggling.

### Dashboard (`src/dashboard/`)

`src/dashboard/transfer_table.c` tracks in-progress stream transfers. HTTP transfers (`src/dashboard/http_tracking.c`) use a separate table. S3 has no dashboard integration.

---

## Target Architecture

### Op-Centric Metric Model

Replace protocol-centric slots with op-centric slots labeled by protocol:

```c
// Target (op-centric with protocol label):
XROOTD_METRIC_IO_BYTES_READ,       // label: proto=[stream|webdav|s3]
XROOTD_METRIC_IO_BYTES_WRITTEN,    // label: proto=[stream|webdav|s3]
XROOTD_METRIC_IO_OPS_TOTAL,        // label: proto, op=[read|write|stat|delete|mkdir|rename]
XROOTD_METRIC_IO_OPS_ERRORS,       // label: proto, op, error=[not_found|forbidden|io_error|...]
XROOTD_METRIC_IO_LATENCY_USEC,     // label: proto, op (histogram)
XROOTD_METRIC_CACHE_HITS,          // label: proto
XROOTD_METRIC_CACHE_MISSES,        // label: proto
XROOTD_METRIC_CACHE_BYTES_EVICTED,
XROOTD_METRIC_AUTH_TOTAL,          // label: proto, method=[gsi|token|sss|s3key|none]
XROOTD_METRIC_AUTH_FAILURES,       // label: proto, method
XROOTD_METRIC_TPC_TRANSFERS,       // label: proto=[stream|webdav], direction=[push|pull]
XROOTD_METRIC_TPC_BYTES,           // label: proto, direction
XROOTD_METRIC_TPC_ERRORS,          // label: proto, direction, error
XROOTD_METRIC_CONNECTIONS_ACTIVE,  // label: proto
XROOTD_METRIC_CONNECTIONS_TOTAL,   // label: proto
```

### Metric Label Architecture

Labels are **low-cardinality only** (per AGENTS.md invariant #8 — no paths, no bucket names, no UUIDs). The full label set for `xrootd_io_ops_total`:

```
xrootd_io_ops_total{proto="stream", op="read"}
xrootd_io_ops_total{proto="webdav", op="read"}
xrootd_io_ops_total{proto="s3",     op="read"}
xrootd_io_ops_total{proto="stream", op="write"}
...
```

Maximum label combinations: 3 proto × 7 ops = 21 time series (vs the current unbounded approach).

### Implementation: `src/metrics/unified.h`

```c
#ifndef XROOTD_METRICS_UNIFIED_H
#define XROOTD_METRICS_UNIFIED_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef enum {
    XROOTD_PROTO_STREAM = 0,
    XROOTD_PROTO_WEBDAV = 1,
    XROOTD_PROTO_S3     = 2,
    XROOTD_PROTO_COUNT  = 3
} xrootd_proto_t;

typedef enum {
    XROOTD_OP_READ   = 0,
    XROOTD_OP_WRITE  = 1,
    XROOTD_OP_STAT   = 2,
    XROOTD_OP_DELETE = 3,
    XROOTD_OP_MKDIR  = 4,
    XROOTD_OP_RENAME = 5,
    XROOTD_OP_DIRLIST= 6,
    XROOTD_OP_COUNT  = 7
} xrootd_op_t;

typedef enum {
    XROOTD_ERR_NONE      = 0,
    XROOTD_ERR_NOT_FOUND = 1,
    XROOTD_ERR_FORBIDDEN = 2,
    XROOTD_ERR_IO        = 3,
    XROOTD_ERR_OTHER     = 4,
    XROOTD_ERR_COUNT     = 5
} xrootd_err_class_t;

/*
 * Record completion of one I/O operation.
 * Called by xrootd_vfs_read/write/stat/etc. (Phase 3).
 */
void xrootd_metric_op_done(xrootd_proto_t proto,
                            xrootd_op_t op,
                            size_t bytes,
                            ngx_msec_t latency_usec,
                            xrootd_err_class_t err);

/*
 * Record cache hit or miss.
 * Called by src/fs/vfs_open.c (Phase 3/4).
 */
void xrootd_metric_cache_result(xrootd_proto_t proto,
                                 unsigned int hit,
                                 size_t bytes_evicted);

/*
 * Record authentication outcome.
 * Called by src/session/login.c and src/webdav/auth_*.c (Phase 2).
 */
void xrootd_metric_auth(xrootd_proto_t proto,
                         ngx_uint_t auth_method,   /* XROOTD_AUTHN_* */
                         unsigned int success);

/*
 * Record TPC transfer outcome.
 * Called by src/tpc/done.c and src/webdav/tpc_thread.c (Phase 5).
 */
void xrootd_metric_tpc(xrootd_proto_t proto,
                        unsigned int is_push,
                        size_t bytes,
                        xrootd_err_class_t err);

#endif /* XROOTD_METRICS_UNIFIED_H */
```

### Implementation: `src/metrics/unified.c`

Implements the four functions above. Each translates its typed arguments into the appropriate slot index in the existing per-worker metric array and calls `xrootd_metric_inc()` / `xrootd_metric_add()` (existing internal API). No new SHM or atomic operations needed — the existing per-worker aggregation mechanism is reused.

---

## Prometheus Output Changes

### Before (protocol-centric, current output)

```
xrootd_stream_bytes_tx 1234567
xrootd_webdav_bytes_tx 891234
xrootd_s3_bytes_tx 456789
```

### After (op-centric with labels)

```
# HELP xrootd_io_bytes_read Total bytes read, by protocol
# TYPE xrootd_io_bytes_read counter
xrootd_io_bytes_read{proto="stream"} 1234567
xrootd_io_bytes_read{proto="webdav"} 891234
xrootd_io_bytes_read{proto="s3"} 456789

# HELP xrootd_io_ops_total Total I/O operations completed, by protocol and operation
# TYPE xrootd_io_ops_total counter
xrootd_io_ops_total{proto="stream",op="read",status="ok"} 8821
xrootd_io_ops_total{proto="webdav",op="read",status="ok"} 3410
xrootd_io_ops_total{proto="s3",    op="read",status="ok"} 1205
xrootd_io_ops_total{proto="stream",op="read",status="not_found"} 12

# HELP xrootd_cache_hits_total Cache hits by protocol
# TYPE xrootd_cache_hits_total counter
xrootd_cache_hits_total{proto="stream"} 5500
xrootd_cache_hits_total{proto="webdav"} 2100
xrootd_cache_hits_total{proto="s3"} 800

# HELP xrootd_auth_total Authentication attempts by protocol and method
# TYPE xrootd_auth_total counter
xrootd_auth_total{proto="stream",method="gsi",status="ok"} 1200
xrootd_auth_total{proto="webdav",method="token",status="ok"} 890
xrootd_auth_total{proto="s3",method="s3key",status="ok"} 450
```

Single Prometheus query for total read throughput:

```promql
sum(rate(xrootd_io_bytes_read[5m]))
```

---

## Structured Access Log

### New Log Format

Each protocol currently writes to a separate access log with a different format. After Phase 6, all protocols write to a **single structured log** (`xrootd_access.log`) in JSON-Lines format:

```json
{
  "ts": 1749081234.456,
  "proto": "stream",
  "remote": "192.168.1.10",
  "op": "read",
  "path": "/store/data/run3/file001.root",
  "bytes": 4194304,
  "offset": 0,
  "latency_ms": 12,
  "status": "ok",
  "from_cache": true,
  "auth_method": "token",
  "subject": "atlas-prod-001",
  "tpc": false
}
```

Protocol-specific fields (e.g., kXR request ID, HTTP status code) are written to their existing per-protocol logs; this unified log is for cross-protocol analysis only.

### Log Emission Point

Emitted from `src/fs/vfs_read.c`, `src/fs/vfs_write.c`, and other VFS operations at completion — after the metric is recorded. Implemented as a thin call:

```c
// src/fs/vfs_internal.h:
void xrootd_access_log_emit(const xrootd_vfs_ctx_t *ctx,
                             xrootd_op_t op,
                             const xrootd_vfs_io_result_t *result,
                             xrootd_err_class_t err);
```

`src/metrics/access_log.c` (new file) implements this function. It formats the JSON line and writes to the configured log file via `ngx_log_error()` with a dedicated log channel.

---

## Dashboard Unification

`src/dashboard/` currently has two transfer tables: `transfer_table.c` (stream) and `http_tracking.c` (WebDAV). Phase 5 added the TPC registry. Phase 6 consolidates:

### Single Dashboard Transfer Table

`src/dashboard/transfer_table.c` is extended to hold entries from all protocols. Each entry gains a `protocol` field matching `xrootd_proto_t`. The dashboard HTML page (`src/dashboard/page.c`) renders a single table with a "Protocol" column.

`src/dashboard/http_tracking.c` is refactored to call the unified `transfer_table.c` instead of maintaining its own list.

### Dashboard API Changes

```c
// Extended entry type (src/dashboard/dashboard_tracking.h):
typedef struct {
    uint64_t         id;
    xrootd_proto_t   protocol;         // NEW
    ngx_str_t        path;
    off_t            bytes_total;
    off_t            bytes_done;
    time_t           started_at;
    ngx_str_t        remote_addr;
    ngx_str_t        auth_subject;     // NEW (from identity->subject)
} xrootd_dashboard_entry_t;
```

---

## Migration: Legacy Metric Slots

The old protocol-centric slots (`XROOTD_METRIC_STREAM_BYTES_TX` etc.) are **kept** for one release cycle alongside the new op-centric slots. The `writer.c` Prometheus output includes both old and new metrics with a deprecation comment:

```
# DEPRECATED: use xrootd_io_bytes_read{proto="stream"} instead
xrootd_stream_bytes_tx 1234567
```

Removal of legacy slots is a follow-up PR after consumers (Grafana dashboards, alerting rules) are migrated.

---

## File Inventory

### New files
| File | Purpose |
|:---|:---|
| `src/metrics/unified.h` | Op-centric metric API |
| `src/metrics/unified.c` | Implementation of unified metric helpers |
| `src/metrics/access_log.c` | JSON-Lines structured access log emitter |
| `src/metrics/access_log.h` | Public header |

### Modified files
| File | Change |
|:---|:---|
| `src/metrics/metrics.h` | Add new op-centric slot enum entries |
| `src/metrics/writer.c` | Emit new labeled metrics; keep legacy slots with deprecation comments |
| `src/metrics/stream.c` | Replace direct slot writes with `xrootd_metric_op_done()` calls |
| `src/metrics/webdav.c` | Replace direct slot writes with `xrootd_metric_op_done()` calls |
| `src/metrics/s3.c` | Replace direct slot writes with `xrootd_metric_op_done()` calls |
| `src/metrics/stream_cache.c` | Replace with `xrootd_metric_cache_result()` calls |
| `src/fs/vfs_read.c` | Call `xrootd_metric_op_done()` + `xrootd_access_log_emit()` |
| `src/fs/vfs_write.c` | Call `xrootd_metric_op_done()` + `xrootd_access_log_emit()` |
| `src/fs/vfs_stat.c` | Call `xrootd_metric_op_done()` |
| `src/dashboard/transfer_table.c` | Add `protocol` and `auth_subject` fields |
| `src/dashboard/http_tracking.c` | Delegate to unified `transfer_table.c` |
| `src/dashboard/page.c` | Render "Protocol" column; show auth subject |
| `src/config/config.h` | Add `src/metrics/unified.c`, `src/metrics/access_log.c` to `NGX_ADDON_SRCS` |

---

## Testing Strategy

### Metric Correctness Tests (`tests/test_metrics.py`)

1. **Read via stream** → `xrootd_io_bytes_read{proto="stream"}` increments by file size.
2. **Read via WebDAV** → `xrootd_io_bytes_read{proto="webdav"}` increments.
3. **Read via S3** → `xrootd_io_bytes_read{proto="s3"}` increments.
4. **Cache hit via WebDAV** → `xrootd_cache_hits_total{proto="webdav"}` increments.
5. **Auth failure** → `xrootd_auth_total{...,status="fail"}` increments.
6. **Total sum** → `sum(xrootd_io_bytes_read)` equals sum of individual protocol counters.
7. **Legacy slots** → Old `xrootd_stream_bytes_tx` still present in `/metrics` output.

### Access Log Tests

1. Stream read → JSON line with `"proto":"stream"`, correct `bytes`, `from_cache`.
2. WebDAV GET → JSON line with `"proto":"webdav"`, `auth_method` from identity.
3. S3 GetObject → JSON line with `"proto":"s3"`, `subject` = access key ID.
4. Error path → JSON line with `"status":"not_found"` on 404.
5. Log contains no full paths in `subject` field (low-cardinality check).

### Dashboard Tests

1. Stream transfer appears in dashboard with "stream" in Protocol column.
2. WebDAV transfer appears with "webdav" and auth subject.
3. TPC transfer (Phase 5) appears with correct protocol.
4. Completed transfers disappear from table.

### Grafana / PromQL Validation

Run the following queries against the test server and verify non-zero results:

```promql
# Total read throughput (all protocols)
sum(rate(xrootd_io_bytes_read[1m]))

# Cache hit ratio per protocol
xrootd_cache_hits_total / (xrootd_cache_hits_total + xrootd_cache_misses_total)

# Error rate by operation
rate(xrootd_io_ops_total{status!="ok"}[5m])

# Auth method breakdown
sum by (method) (xrootd_auth_total{status="ok"})
```

---

## Risk Assessment

| Risk | Mitigation |
|:---|:---|
| Legacy Grafana dashboards break | Legacy metric slots preserved; document migration path |
| Access log volume too high | Log is async via nginx log channel; configurable log level; can be disabled |
| Latency histogram bucket overflow | Use power-of-two buckets with reasonable max (60s); overflow goes to `+Inf` bucket |
| Dashboard entry count unbounded | Cap at 1000 active entries; oldest completed entries evicted first |
| `auth_subject` in access log leaks PII | Subject is a JWT `sub` claim or access key ID — both are identifiers, not PII; configurable via `xrootd_access_log_include_subject off` |

---

## Completion Criteria

- [ ] `src/metrics/unified.h` and `unified.c` exist with four public functions
- [ ] All protocol metric files call unified API — no direct slot writes
- [ ] VFS layer emits metrics for every op (read, write, stat, delete, mkdir, rename)
- [ ] `/metrics` output contains new op-centric metrics with `proto` labels
- [ ] Legacy protocol-centric metrics still present with deprecation comment
- [ ] JSON-Lines access log emitted for all three protocols
- [ ] Dashboard shows all protocols in single transfer table
- [ ] Metric correctness tests pass (7 tests)
- [ ] PromQL sum query returns correct total across all protocols
- [ ] `make -j$(nproc)` clean with no warnings

---

## Project Completion Summary

With Phase 6 complete, the full unification project achieves:

| Concern | Before | After |
|:---|:---|:---|
| Path resolution | 2 resolvers (stream + HTTP) | 1 resolver (`src/path/unified.c`) |
| Identity/Auth | 3 structs, 3 auth flows | 1 `xrootd_identity_t`, 4 auth backends |
| File I/O | 3 open/read/write implementations | 1 VFS layer (`src/fs/`) |
| Cache | Stream-only | All protocols, transparent in VFS |
| TPC credential/auth | 2 independent paths | 1 common layer (`src/tpc/common/`) |
| Metrics | 3 siloed namespaces | 1 op-centric model with protocol labels |
| Access log | 3 different formats | 1 JSON-Lines unified log |
| Dashboard | 2 tables (stream + HTTP) | 1 table, all protocols |
