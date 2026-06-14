# metrics — shared-memory counters and the Prometheus `/metrics` exporter

## Overview

This subsystem is the single observability spine for nginx-xrootd. Every
protocol surface — native XRootD (`root://`) on the stream side, WebDAV/HTTPS,
the S3-compatible REST endpoint, the CMS cluster registry, the transparent
XRootD proxy, the read-through/write-through cache, traffic mirroring, and the
rate limiter — writes counters into **one** shared-memory object,
`ngx_xrootd_metrics_t`, and a separate HTTP module reads that object back out as
Prometheus text-exposition output on `/metrics`. There is no per-handler scrape
logic and no lock on the hot path: handlers do an `ngx_atomic_fetch_add` into a
fixed slot; the exporter reads the same slots eventually-consistently.

The design is deliberately split into two nginx modules that share this one
header (`metrics.h`). The **stream module** (`ngx_stream_xrootd_module`) creates
and zeroes the shared zone at config time (`config.c`) and compiles the
write-side helpers (`tracking.c`, `unified.c`, `access_log.c`). The **HTTP
metrics module** (`ngx_http_xrootd_metrics_module`, defined in `module.c`)
attaches the `xrootd_metrics` location directive and compiles the read-side
exporters (`stream.c`, `webdav.c`, `s3.c`, `cluster.c`, `ratelimit.c`,
`stream_cache.c`, `stream_proxy.c`, `stream_tracking.c`, `writer.c`,
`handler.c`). The two modules communicate only through the global
`ngx_shm_zone_t *ngx_xrootd_shm_zone` and the numeric slot ABI in `metrics.h` —
the stream side records by slot index, the exporter maps the index back to a
label string. The two must stay in sync.

In the request lifecycle this subsystem is touched twice. On the way *in*,
completed operations call increment macros (`XROOTD_SRV_METRIC_INC`,
`XROOTD_WEBDAV_METRIC_INC`, `XROOTD_S3_METRIC_INC`, `XROOTD_PROXY_METRIC_INC`)
or the protocol-neutral `xrootd_metric_op_done()` / `xrootd_metric_auth()` /
`xrootd_metric_tpc()` functions from `unified.c`. On the way *out*, an operator
scrapes the dedicated metrics listener (default `:9100`) and
`ngx_http_xrootd_metrics_handler()` walks the whole zone and emits it.

A hard, repeated invariant runs through every file here: **Prometheus label
values are low-cardinality enums only.** Paths, bucket names, object keys, DNs,
token subjects, and S3 access keys never become label values. Per-VO and
per-user views are made safe with bounded LRU tables and FNV-1a hashing
(`tracking.c`); free-form identity ends up in the JSON access log
(`access_log.c`), never on a counter label.

## Files

| File | Responsibility |
|---|---|
| `metrics.h` | The shared-memory ABI. Defines `ngx_xrootd_metrics_t` (root SHM object) and its sub-structs (`ngx_xrootd_srv_metrics_t` per-listener, `ngx_xrootd_webdav_metrics_t`, `ngx_xrootd_s3_metrics_t`, `ngx_xrootd_proxy_metrics_t` + per-upstream slice, `ngx_xrootd_unified_metrics_t`, VO/user tracking tables), all `XROOTD_OP_*` / `XROOTD_WEBDAV_*` / `XROOTD_S3_*` slot constants, cache-line alignment macro, and `extern ngx_xrootd_shm_zone`. Included by both modules. |
| `unified.h` | Protocol-neutral enums (`xrootd_proto_t`, `xrootd_metric_op_t`, `xrootd_err_class_t`, auth/TPC slots, latency-bucket count) and the public `xrootd_metric_*` write API used cross-protocol. |
| `metrics_internal.h` | Module-private types: location config (`ngx_http_xrootd_metrics_loc_conf_t`), the `metrics_writer_t` buffer-chain writer, and every cross-file exporter/writer prototype. |
| `metrics_macros.h` | The increment macros (`XROOTD_ATOMIC_INC/DEC/ADD`, `XROOTD_SRV_/WEBDAV_/S3_/PROXY_METRIC_INC/ADD`, per-upstream `XROOTD_PROXY_UP_*`) plus the `xrootd_metrics_shared()` accessor with its `NULL`/sentinel-`1` guard. |
| `http_common.h` | `xrootd_http_status_class()` — maps an HTTP status code to the six `XROOTD_HTTP_STATUS_*` buckets. Single authoritative inline shared by WebDAV and S3 callers. |
| `access_log.h` | Prototype for `xrootd_access_log_emit()` — the structured JSON access-log line. |
| `config.c` | Stream-side setup: `xrootd_configure_metrics()` adds the `xrootd_metrics` SHM zone (`sizeof(ngx_xrootd_metrics_t)` + one page) and assigns each enabled listener a deterministic `metrics_slot`; `ngx_xrootd_metrics_shm_init()` zeroes a fresh mapping but preserves counters across reloads. |
| `module.c` | Defines `ngx_http_xrootd_metrics_module`: the `xrootd_metrics on;` location directive, its create/merge loc-conf, and binding of the content handler. |
| `handler.c` | `ngx_http_xrootd_metrics_handler()` — the `/metrics` content handler. Owns the `ngx_xrootd_shm_zone` global definition; restricts to GET/HEAD, discards body, drives the writer through every exporter, sets `text/plain; version=0.0.4`. |
| `writer.c` | `metrics_writer_t` growable buffer-chain (`mw_init`/`mw_printf`/`mw_finish`) and reusable emit helpers (`mw_emit_labeled`, `mw_emit_scalar`); also `xrootd_kv_metrics_emit()` for per-zone KV cache/rate-limit stats and the shared `xrootd_http_status_names[]`/`xrootd_http_range_result_names[]` tables. |
| `stream.c` | `xrootd_op_names[]` (the slot→label ABI table) and `xrootd_export_prometheus_metrics()` — the top-level exporter: native stream counters (connections, bytes by IP version, wire frames, per-op ok/error, xfer-heap budget, session-registry, depth violations, mirror) and it chains every other exporter. |
| `stream_cache.c` | `xrootd_export_stream_cache_metrics()` — read-through cache occupancy (live `statvfs` via `xrootd_fs_usage_stat`), eviction counters, and write-through flush health gauges/counters. |
| `stream_proxy.c` | `xrootd_export_stream_proxy_metrics()` — transparent-proxy upstream counters (connect/auth/open/read/write/close/reconnect/path-op/wait), emitted as an aggregate row plus one row per named upstream slice. |
| `stream_tracking.c` | `xrootd_export_stream_tracking_metrics()` — per-VO bytes/requests, VO overflow, unique-user gauges, and per-user (hashed) session counts from the bounded LRU tables. |
| `webdav.c` | `xrootd_export_webdav_metrics()` — WebDAV counter families (requests/responses by method×status, auth result, range mode, PUT body mode, PROPFIND depth, HTTP-TPC pull/push/cred, CORS) with their label tables. |
| `s3.c` | `xrootd_export_s3_metrics()` — S3-compatible counter families (requests/responses, SigV4 auth outcomes, range, PUT body mode, diagnostic events, ListObjectsV2 pagination) with their label tables. |
| `cluster.c` | `xrootd_export_cluster_metrics()` — reads the **manager registry** SHM (not the per-worker zone) via `xrootd_srv_snapshot()` for per-server free-space/utilisation/last-seen/blacklist gauges, plus aggregate health-check counters. |
| `ratelimit.c` | `xrootd_export_ratelimit_metrics()` — the four aggregate rate-limiter counters (throttled http/stream, LRU evictions, zone-full errors). Per-principal detail is dashboard-only. |
| `unified.c` | The protocol-neutral write API (`xrootd_metric_op_done`/`_cache_result`/`_auth`/`_tpc`) and `xrootd_export_unified_metrics()`; folds legacy stream/webdav/s3 counters into the unified `proto`-labeled families and emits the latency histogram. Also the enum→string and `errno`/HTTP-status→error-class mappers. |
| `access_log.c` | `xrootd_access_log_emit()` — emits one JSON access-log line per VFS op (ts, proto, op, path, bytes, latency, status, from_cache, auth method, subject) with `\uXXXX` escaping; this is where free-form identity/path safely lives. |
| `tracking.c` | `xrootd_track_vo_activity()` and `xrootd_track_unique_user()` — maintain the bounded VO and unique-user LRU tables (FNV-1a identity hashing, overflow/eviction accounting) so high-cardinality identity never reaches a label. |

## Key types & data structures

- **`ngx_xrootd_metrics_t`** (`metrics.h`) — the root SHM object stored in
  `ngx_xrootd_shm_zone->data`. Holds a fixed `servers[XROOTD_METRICS_MAX_SERVERS]`
  array, the singleton `webdav`/`s3`/`unified` blocks, cluster health-check and
  mirror/rate-limit/session-registry scalars, and the `vo_global` / `user_tracking`
  LRU tables. Fixed-size so indexing needs no allocation once workers run.
- **`ngx_xrootd_srv_metrics_t`** — per-listener block. Connection/byte/wire
  counters, the cache-line-aligned `op_ok[XROOTD_NOPS]` / `op_err[XROOTD_NOPS]`
  hot arrays (aligned to stop false-sharing between cores), cache/write-through
  health, transfer-heap budget gauges, and the listener identity (`port`, `auth`,
  `cache_root`) written once at startup before workers fork.
- **`XROOTD_OP_*` constants + `xrootd_op_names[]`** — the numeric slot ABI.
  Stream handlers bump `op_ok[slot]`/`op_err[slot]`; `stream.c` turns the slot
  back into the `op=` label. Note `XROOTD_OP_QUERY_CKSUM` and `QUERY_SPACE`
  intentionally alias slot 17. `XROOTD_NOPS` (37) sizes both arrays and the name
  table.
- **`ngx_xrootd_unified_metrics_t`** + **`xrootd_proto_t` / `xrootd_metric_op_t`
  / `xrootd_err_class_t`** (`unified.h`) — the Phase-6 protocol-labeled view:
  per-`[proto][op][err]` op counts, a non-cumulative latency histogram
  (`XROOTD_IO_LATENCY_BUCKETS`), and `[proto][method][status]` auth and
  `[proto][direction][err]` TPC families.
- **`ngx_xrootd_proxy_metrics_t` / `ngx_xrootd_proxy_upstream_metrics_t`** —
  proxy aggregate plus up to `XROOTD_PROXY_MAX_UPSTREAMS` per-upstream slices,
  each with a `label[]` ("host:port") written once at first connect.
- **`ngx_xrootd_vo_global_t` / `ngx_xrootd_user_global_t`** — bounded LRU
  tracking tables (`XROOTD_VO_MAX_TRACKED`, `XROOTD_USERS_MAX_TRACKED`); users
  are stored as a 32-bit FNV-1a hash, never as a string.
- **`metrics_writer_t`** (`metrics_internal.h`) — a chain of 64 KiB nginx
  buffers that grows on overflow and ends with `last_buf=1`, fed straight to
  `ngx_http_output_filter`.

## Control & data flow

**Setup.** During stream postconfiguration the stream module calls
`xrootd_configure_metrics()` (`config.c`), which creates the `xrootd_metrics`
shared zone, registers `ngx_xrootd_metrics_shm_init`, and assigns one slot per
enabled listener. The HTTP metrics module is independent: its only job at config
time is to bind `ngx_http_xrootd_metrics_handler` wherever `xrootd_metrics on;`
appears.

**Write path (entering this subsystem).** Handlers across the tree increment
counters without ever calling into this directory's `.c` files directly — they
use the macros in `metrics_macros.h`. Stream ops carry a cached
`ctx->metrics` pointer (the assigned slot) and use `XROOTD_SRV_METRIC_INC`;
WebDAV/S3 use the `xrootd_metrics_shared()`-guarded `XROOTD_WEBDAV_/S3_METRIC_INC`;
the proxy uses `XROOTD_PROXY_METRIC_INC` / `XROOTD_PROXY_UP_INC`. Cross-protocol
op/auth/TPC accounting goes through the `xrootd_metric_*()` functions in
`unified.c`. VFS-level ops additionally call `xrootd_track_vo_activity()` /
`xrootd_track_unique_user()` (`tracking.c`) and `xrootd_access_log_emit()`
(`access_log.c`).

**Read path (the scrape).** `ngx_http_xrootd_metrics_handler()` (`handler.c`)
inits a `metrics_writer_t`, then `xrootd_export_prometheus_metrics()` (`stream.c`)
emits the native stream block and fans out to
`xrootd_export_stream_cache_metrics` → `unified` → `stream_proxy` →
`stream_tracking` → `webdav` → `s3` → `cluster` → `ratelimit`, and finally the
handler emits `xrootd_kv_metrics_emit()` (KV zones). All reads use
`ngx_atomic_fetch_add(..., 0)`.

**Calls out to siblings.** `cluster.c` reads the manager registry SHM
(`../manager/registry.h`, `xrootd_srv_snapshot`) — see [../manager/README.md](../manager/README.md)
and [../cms/README.md](../cms/README.md) for how that registry is populated.
`stream_cache.c` reports on the [../cache/README.md](../cache/README.md) read-through/
write-through subsystem via `../compat/fs_usage.h`. `unified.c` and `access_log.c`
consume identity from `../types/identity.h`, and `writer.c` reads KV stats from
`../shm/kv.h`. The op slots correspond to handlers in
[../read/README.md](../read/README.md) and [../write/README.md](../write/README.md);
async completions that bump counters originate in [../aio/README.md](../aio/README.md);
path-confinement rejections feed `path_depth_violations_total` from
[../path/README.md](../path/README.md).

## Invariants, security & gotchas

- **Low-cardinality labels are a security boundary, not a style choice.** No
  path, bucket, object key, DN, token subject, or S3 access key may ever be a
  Prometheus label value (`metrics.h:151`, `s3.c`, repeated in every exporter).
  High-cardinality identity is bounded (VO/user LRU in `tracking.c`) or hashed
  (`user_sessions_total{hash=...}` in `stream_tracking.c`) or routed to the JSON
  access log instead. Per-IP-version byte counters exist precisely to avoid a
  per-client-address label explosion.
- **The slot table is a binary ABI between two modules.** `XROOTD_OP_*` in
  `metrics.h` and `xrootd_op_names[]` in `stream.c` must stay index-aligned or
  every `op=` label silently shifts. Same rule for the WebDAV/S3 enum tables.
- **Reload-safe SHM.** `ngx_xrootd_metrics_shm_init()` (`config.c:71`) zeroes
  only a *fresh* mapping; on reload nginx hands back the existing `data` and live
  counters are preserved. The `data == (void *) 1` sentinel distinguishes
  first-setup from reuse; `xrootd_metrics_shared()` treats both `NULL` and `1` as
  "not ready" so increments before init are no-ops, not crashes.
- **Eventual consistency, by design.** Each counter is read atomically, but
  different lines in one scrape may observe slightly different instants — there is
  no global lock. Do not assume cross-counter consistency within a single scrape.
- **Lock-free writes; identity fields written pre-fork.** Counters are
  `ngx_atomic_t`. The non-atomic identity fields (`port`, `auth`, `cache_root`,
  and each upstream `label[]`) are written exactly once before any reader can
  observe them, so they need no synchronisation.
- **Non-cumulative latency histogram.** `xrootd_metric_op_done()` (`unified.c:200`)
  increments only the single bucket a sample lands in (bounding the hot path to 3
  atomics), and `xrootd_export_unified_metrics()` accumulates buckets at scrape
  time so the emitted `le` buckets stay Prometheus-cumulative and `+Inf` equals
  count.
- **`mw_printf` is `vsnprintf`-based.** It does not understand nginx `%V`; render
  an `ngx_str_t` with `%.*s` and an `(int)` length (`writer.c:186`). It is also
  not on the wire hot path — it runs only during a scrape, in the request pool.
- **`cluster.c` reads a different zone.** Unlike every other exporter it reads
  the manager registry SHM, not the per-worker metrics zone, and returns early if
  `xrootd_srv_shm_zone == NULL`. Its `server=` label is the one place a
  host:port string appears — acceptable because cluster membership is bounded and
  operator-controlled.
- **Legacy counters are deprecated, not removed.** `stream.c`/`webdav.c`/`s3.c`
  still emit `xrootd_bytes_*`/`xrootd_webdav_bytes_*`/`xrootd_s3_bytes_*` with a
  `# DEPRECATED:` comment pointing at the unified `xrootd_io_bytes_*{proto=...}`
  family; `unified.c` folds the legacy values into the unified output so dashboards
  can migrate without double-counting confusion.
- **VO/user LRU wrap reuses slot 0.** When a tracking table fills,
  `tracking.c` increments `overflow_total`/`evictions_total` and recycles slot 0
  rather than failing — counts after overflow are approximate by construction.

## Entry points / extending

- **New native (stream) op counter:** add an `XROOTD_OP_*` constant and bump
  `XROOTD_NOPS` in `metrics.h`, add the matching string to `xrootd_op_names[]`
  in `stream.c` (same index!), then `XROOTD_SRV_METRIC_INC(ctx, op_ok[SLOT])` /
  `op_err[SLOT]` at the handler call site.
- **New WebDAV/S3 counter family:** add the slot enum + `N*` count and an
  `ngx_atomic_t` field/array to the relevant struct in `metrics.h`, add the
  label-string table and an `mw_emit_labeled`/`mw_emit_scalar` call in `webdav.c`
  / `s3.c`, and increment with `XROOTD_WEBDAV_METRIC_INC` / `XROOTD_S3_METRIC_INC`.
- **New protocol-neutral metric:** prefer the unified API — add a field to
  `ngx_xrootd_unified_metrics_t`, a writer in `unified.c`, and an export loop in
  `xrootd_export_unified_metrics()`. Call from any protocol via the
  `xrootd_metric_*()` functions.
- **New scalar/aggregate (mirror/rate-limit/health style):** add an
  `ngx_atomic_t` to `ngx_xrootd_metrics_t`, increment it anywhere with the SHM
  accessor, and emit it from the appropriate exporter (`stream.c`, `cluster.c`,
  or `ratelimit.c`).
- **Add the endpoint to a server:** `location /metrics { xrootd_metrics on; }`
  on a listener (commonly a dedicated `:9100` server). The handler declines
  (`NGX_DECLINED`) when the flag is off, so it can be toggled without a 404.

## See also

- [../README.md](../README.md) — master subsystem index
- [../manager/README.md](../manager/README.md), [../cms/README.md](../cms/README.md) — the cluster registry `cluster.c` reads
- [../cache/README.md](../cache/README.md) — read-through/write-through counters surfaced by `stream_cache.c`
- [../read/README.md](../read/README.md), [../write/README.md](../write/README.md), [../aio/README.md](../aio/README.md) — handlers/async completions that drive the op slots
- [../path/README.md](../path/README.md) — confinement layer feeding `path_depth_violations_total`
- [../webdav/README.md](../webdav/README.md), [../s3/README.md](../s3/README.md), [../dashboard/README.md](../dashboard/README.md) — protocol surfaces and the richer (high-cardinality) dashboard API
