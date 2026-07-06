# Metrics Overview

All Prometheus metrics exported by BriX-Cache, organized by protocol layer — native XRootD stream, WebDAV, and S3.

---

## Where each counter family fires

Metrics are emitted at fixed points along the connection → request → data-plane
pipeline. This map shows which family increments at each stage:

```text
  TCP accept            handshake/auth         operation            data plane
  ──────────            ──────────────         ─────────            ──────────
  ┌──────────────┐  ┌──────────────────┐  ┌────────────────┐  ┌──────────────────┐
  │ connections_ │  │ requests_total   │  │ requests_total │  │ bytes_rx/tx_total│
  │  total ▲     │  │  {op=login/auth} │  │  {op,status}   │  │ bytes_root_*     │
  │ connections_ │  │ webdav_auth_total│  │ webdav_requests│  │ bytes_*_ipv4/6   │
  │  active ▲▼   │  │ s3_auth_total    │  │ s3_requests    │  │ vo_bytes_*       │
  └──────┬───────┘  └────────┬─────────┘  └───────┬────────┘  └────────┬─────────┘
         │                   │                    │                    │
         ▼                   ▼                    ▼                    ▼
   per-conn, by          per-identity         per-operation       per-byte, split by
   {port,auth}           unique_users_*       counters &          proto / IP-version /
                         user_sessions        status_class        VO; cache_* on fills
  ──────────────────────────────────────────────────────────────────────────────────
  wire_bytes_rx/tx_total, stream_*_frames, write_stalls  ← low-level, every socket op

  Label discipline (INVARIANT #8): only low-cardinality labels —
  {port, auth, op, status, method, status_class}. Never paths, DNs, buckets,
  keys, or UUIDs. VO is capped at 32 entries; user identity is hashed + LRU-512.
```

---

## Stream Layer Metrics

### Connection Counters

#### `brix_connections_total`

Total TCP connections accepted since the nginx process started. Never decreases.

Labels: `port`, `auth`

```
brix_connections_total{port="1094",auth="anon"} 1042
brix_connections_total{port="1095",auth="gsi"} 17
```

#### `brix_connections_active`

Number of XRootD connections currently open. Goes up when a client connects, down when it disconnects.

Labels: `port`, `auth`

```
brix_connections_active{port="1094",auth="anon"} 4
brix_connections_active{port="1095",auth="gsi"} 1
```

### Byte Counters

#### `brix_bytes_rx_total`

Total bytes received from clients (i.e. uploaded data). Counts only file data payloads, not protocol overhead.

Labels: `port`, `auth`

```
brix_bytes_rx_total{port="1094",auth="anon"} 5368709120
```

#### `brix_bytes_tx_total`

Total bytes sent to clients (i.e. downloaded data). Counts only file data, not protocol overhead.

Labels: `port`, `auth`

```
brix_bytes_tx_total{port="1094",auth="anon"} 107374182400
```

### Native Stream Wire Counters

Low-level counters for debugging protocol framing, socket back-pressure, and wire overhead. These count native XRootD stream behavior, not WebDAV HTTP traffic.

Labels: `port`, `auth`

Metrics:

- `brix_wire_bytes_rx_total` - raw socket bytes received
- `brix_wire_bytes_tx_total` - raw socket bytes sent
- `brix_stream_request_frames_total` - parsed XRootD request headers
- `brix_stream_request_payload_bytes_total` - declared request payload bytes
- `brix_stream_oversized_payloads_total` - requests rejected for excessive payload length
- `brix_stream_response_frames_total` - response send attempts
- `brix_stream_response_write_stalls_total` - sends that waited for socket writability
- `brix_stream_response_write_errors_total` - send/send_chain failures

```
brix_wire_bytes_rx_total{port="1094",auth="anon"} 8209232
brix_stream_response_write_stalls_total{port="1094",auth="anon"} 14
```

### Per-Protocol Byte Counters (Extended)

Separates root:// data transfer from WebDAV and S3 at the stream layer:

Metrics:
- `brix_bytes_root_rx_total` — bytes received via root:// protocol only
- `brix_bytes_root_tx_total` — bytes sent via root:// protocol only

```
brix_bytes_root_rx_total{port="1094",auth="gsi"} 5368709120
brix_bytes_root_tx_total{port="1094",auth="gsi"} 107374182400
```

### Per-IP-Version Byte Counters (Extended)

Tracks IPv4 vs IPv6 traffic separately without adding per-client IP as a Prometheus label.

**Native XRootD stream layer:**
```
brix_bytes_rx_ipv4_total{port="1094",auth="gsi"} 5368709120
brix_bytes_tx_ipv4_total{port="1094",auth="gsi"} 107374182400
brix_bytes_rx_ipv6_total{port="1094",auth="gsi"} 0
brix_bytes_tx_ipv6_total{port="1094",auth="gsi"} 0
```

See [extended-metrics.md](./extended-metrics.md) for WebDAV and S3 IP-version counters.

---

## Cache Metrics

### `brix_cache_occupancy_ratio`

Current `statvfs()` filesystem occupancy ratio for `brix_cache_export`.

Labels: `port`, `auth`

```
brix_cache_occupancy_ratio{port="1094",auth="anon"} 0.734218
```

### `brix_cache_eviction_threshold_ratio`

Configured cache eviction high-water mark.

Labels: `port`, `auth`

```
brix_cache_eviction_threshold_ratio{port="1094",auth="anon"} 0.900000
```

### `brix_cache_bytes`

Current cache filesystem bytes, split by state.

Labels: `port`, `auth`, `state`

```
brix_cache_bytes{port="1094",auth="anon",state="total"} 214748364800
brix_cache_bytes{port="1094",auth="anon",state="used"} 157672816640
brix_cache_bytes{port="1094",auth="anon",state="available"} 57075548160
```

### `brix_cache_evictions_total`

Total regular cached files unlinked by cache eviction.

Labels: `port`, `auth`

```
brix_cache_evictions_total{port="1094",auth="anon"} 17
```

### `brix_cache_evicted_bytes_total`

Total bytes reclaimed by cache eviction, using each evicted file's size at scan time.

Labels: `port`, `auth`

```
brix_cache_evicted_bytes_total{port="1094",auth="anon"} 549755813888
```

### `brix_cache_eviction_errors_total`

Total best-effort eviction maintenance errors, such as scan, stat, or unlink failures.

Labels: `port`, `auth`

```
brix_cache_eviction_errors_total{port="1094",auth="anon"} 1
```

### `brix_cache_dirty_reaped_total`

Cache files removed by the stale-dirty reaper, broken down by **why** via the
`reason` label. The reaper scans the unified cache-state root
(`brix_cache_state_root`, defaulting to `brix_cache_export`), shared by the
**read-through and write-through caches**, so this counter covers both. Unlike the
eviction counters (gated on the read-through cache being enabled) it is reported
for **any active server with a cache-state root** — the same `in_use`-only gate as
the write-through `wt_*` families.

The reason is derived per file from its `.cinfo` write-back state:

| `reason` | Meaning | Data loss? |
|---|---|---|
| `abandoned` | Un-flushed dirty data aged past `brix_cache_dirty_max_age` and was **never** written back (`flush_gen == 0`). | **Yes** — full |
| `incomplete` | Aged dirty data on a file that **had** a prior successful write-back (`flush_gen > 0`) and was re-dirtied; only the trailing dirty episode is discarded. | Partial |
| `completed` | A **clean**, fully written-back staging copy (`flush_gen > 0`) reclaimed once its last flush aged out — bytes are safely on the origin. A read-through fill (`flush_gen == 0`, clean) is left for occupancy-driven eviction. | No |

A non-zero `abandoned`/`incomplete` rate means write-back data is being discarded
before it reaches the origin/backend (origin unreachable, flush failing, or
`brix_cache_dirty_max_age` too short) — pair it with
`brix_wt_flushes_total{result="error"}`. A `completed` rate is benign cleanup.

Labels: `port`, `auth`, `reason`

```
brix_cache_dirty_reaped_total{port="1094",auth="anon",reason="abandoned"} 3
brix_cache_dirty_reaped_total{port="1094",auth="anon",reason="incomplete"} 0
brix_cache_dirty_reaped_total{port="1094",auth="anon",reason="completed"} 12
```

---

## Request Metrics

### `brix_requests_total`

Total XRootD requests completed, broken down by operation type and outcome.

Labels: `port`, `auth`, `op`, `status`

```
brix_requests_total{port="1094",auth="anon",op="login",status="ok"} 1042
brix_requests_total{port="1094",auth="anon",op="open_rd",status="ok"} 8314
brix_requests_total{port="1094",auth="anon",op="read",status="ok"} 41570
brix_requests_total{port="1094",auth="anon",op="close",status="ok"} 8314
brix_requests_total{port="1094",auth="anon",op="open_rd",status="error"} 12
```

Operations tracked (`op` label values): `login`, `auth`, `stat`, `open_rd`, `open_wr`, `read`, `write`, `sync`, `close`, `dirlist`, `mkdir`, `rmdir`, `rm`, `mv`, `chmod`, `truncate`, `ping`, `query_cksum`, `query_space`, `readv`, `pgread`, `writev`, `locate`, `statx`, `fattr`, `query_stats`, `query_xattr`, `query_finfo`, `query_fsinfo`, `set`, `query_visa`, `query_opaque`, `query_opaquf`, `query_opaqug`, `query_ckscan`, `clone`, `chkpoint`

`kXR_pgwrite` is currently accounted under the `write` slot because it shares the write-family metric path.

Error series (`status="error"`) are omitted from the output when the count is zero — this keeps the scrape output short when errors are rare.

---

## WebDAV Counters

WebDAV counters are global to the nginx instance and intentionally avoid path, DN, token subject, and Origin labels.

Metrics:

- `brix_webdav_requests_total{method}` - requests by method
- `brix_webdav_responses_total{method,status_class}` - responses by method and HTTP status class
- `brix_webdav_auth_total{result}` - auth outcomes (`none`, `cert_ok`, `token_ok`, `anonymous_fallback`, `rejected`)
- `brix_webdav_bytes_rx_total` - bytes accepted into WebDAV writes
- `brix_webdav_bytes_tx_total` - bytes sent by WebDAV GET and PROPFIND
- `brix_webdav_range_requests_total{result}` - full, partial, or unsatisfied GET ranges
- `brix_webdav_put_bodies_total{mode}` - empty, memory, spooled, or threaded PUT bodies
- `brix_webdav_fd_cache_total{event}` - per-connection fd-cache hit/miss/insert/update/evict/stale
- `brix_webdav_propfind_depth_total{depth}` - PROPFIND depth buckets
- `brix_webdav_propfind_entries_total` - PROPFIND response entries emitted
- `brix_webdav_tpc_total{event}` - HTTP-TPC pull/curl/commit outcomes
- `brix_webdav_cors_total{event}` - CORS allowed/denied/preflight/no-origin decisions

```
brix_webdav_requests_total{method="GET"} 1297
brix_webdav_responses_total{method="GET",status_class="2xx"} 1294
brix_webdav_cors_total{event="preflight"} 22
```

### WebDAV IP-Version Counters (Extended)

WebDAV also tracks IPv4 vs IPv6 traffic separately:

```
brix_webdav_bytes_rx_ipv4_total 5368709120
brix_webdav_bytes_tx_ipv4_total 107374182400
brix_webdav_bytes_rx_ipv6_total 0
brix_webdav_bytes_tx_ipv6_total 0
```

See [extended-metrics.md](./extended-metrics.md) for full details.

---

## S3-Compatible Counters

S3-compatible counters are global to the nginx instance and intentionally avoid bucket, object key, access-key, principal, and other client-controlled labels. They cover the path-style REST subset implemented under `src/protocols/s3/`.

Metrics:

- `brix_s3_requests_total{method}` - requests by operation (`GET`, `HEAD`, `PUT`, `DELETE`, `LIST`, `OTHER`)
- `brix_s3_responses_total{method,status_class}` - responses by operation and HTTP status class
- `brix_s3_auth_total{result}` - auth outcomes (`anonymous`, `sigv4_ok`, `missing`, `malformed`, `bad_access_key`, `bad_date`, `signature_mismatch`, `internal_error`)
- `brix_s3_bytes_rx_total` - bytes accepted into successful PUT writes
- `brix_s3_bytes_tx_total` - bytes emitted by GET, ListObjectsV2, and XML error responses
- `brix_s3_range_requests_total{result}` - full, partial, or unsatisfied GET ranges
- `brix_s3_put_bodies_total{mode}` - empty, memory, spooled, or mixed PUT bodies
- `brix_s3_events_total{event}` - low-cardinality diagnostics such as invalid URI, access denied, missing key, write disabled, method not allowed, internal error, directory sentinel, or idempotent delete-missing
- `brix_s3_list_contents_total` - ListObjectsV2 `<Contents>` entries emitted
- `brix_s3_list_common_prefixes_total` - ListObjectsV2 `<CommonPrefixes>` entries emitted
- `brix_s3_list_truncated_total` - ListObjectsV2 responses with a continuation token

```
brix_s3_requests_total{method="GET"} 834
brix_s3_responses_total{method="GET",status_class="2xx"} 831
brix_s3_range_requests_total{result="partial"} 42
brix_s3_auth_total{result="sigv4_ok"} 1204
```

### S3 IP-Version Counters (Extended)

S3 also tracks IPv4 vs IPv6 traffic separately:

```
brix_s3_bytes_rx_ipv4_total 5368709120
brix_s3_bytes_tx_ipv4_total 107374182400
brix_s3_bytes_rx_ipv6_total 0
brix_s3_bytes_tx_ipv6_total 0
```

See [extended-metrics.md](./extended-metrics.md) for full details.

---

## Per-VO Traffic Tracking (Extended)

Groups data transfer by virtual organisation. VO names are truncated to 15 characters for storage efficiency. The table supports up to 32 VOs simultaneously; excess VOs increment an overflow counter and evict the oldest entry (LRU policy).

Metrics:
- `brix_vo_bytes_tx_total{vo="..."}` — bytes sent to clients from this VO's users
- `brix_vo_bytes_rx_total{vo="..."}` — bytes received from this VO's users  
- `brix_vo_requests_total{vo="..."}` — request count for this VO

```
brix_vo_bytes_tx_total{vo="cms"} 1234567890
brix_vo_bytes_tx_total{vo="atlas"} 9876543210
brix_vo_requests_total{vo="cms"} 54321
```

See [extended-metrics.md](./extended-metrics.md) for configuration notes and full details.

---

## Unique User Identity Tracking (Extended)

Counts distinct authenticated users since process start. Users are identified by hashing their DN (GSI) or token sub claim via FNV-1a 32-bit hash before lookup. The table supports up to 512 tracked identities simultaneously; excess entries evict the oldest slot using LRU policy.

Metrics:
- `brix_unique_users_current` — currently tracked unique users (bounded by table size)
- `brix_unique_users_total` — lifetime unique users seen (never decreases)
- `brix_user_evictions_total` — slots recycled when table is full
- `brix_user_sessions_total{hash=...}` — sessions per hashed identity

```
brix_unique_users_current 42
brix_unique_users_total 1873
brix_user_evictions_total 156
brix_user_sessions_total{hash=a1b2c3d4} 5
```

See [extended-metrics.md](./extended-metrics.md) for configuration notes and full details.

---

## Sample Output

Complete sample of Prometheus metrics text output:

```
# HELP brix_connections_total Total TCP connections accepted since process start.
# TYPE brix_connections_total counter
brix_connections_total{port="1094",auth="anon"} 42
brix_connections_total{port="1095",auth="gsi"} 7
# HELP brix_connections_active Currently open XRootD connections.
# TYPE brix_connections_active gauge
brix_connections_active{port="1094",auth="anon"} 3
brix_connections_active{port="1095",auth="gsi"} 0
# HELP brix_bytes_rx_total Bytes received from clients (write payloads).
# TYPE brix_bytes_rx_total counter
brix_bytes_rx_total{port="1094",auth="anon"} 12582912
# HELP brix_bytes_tx_total Bytes sent to clients (read data).
# TYPE brix_bytes_tx_total counter
brix_bytes_tx_total{port="1094",auth="anon"} 4194304
# HELP brix_cache_occupancy_ratio Filesystem occupancy ratio for brix_cache_export.
# TYPE brix_cache_occupancy_ratio gauge
brix_cache_occupancy_ratio{port="1094",auth="anon"} 0.734218
# HELP brix_cache_eviction_threshold_ratio Configured cache eviction high-water occupancy ratio.
# TYPE brix_cache_eviction_threshold_ratio gauge
brix_cache_eviction_threshold_ratio{port="1094",auth="anon"} 0.900000
# HELP brix_cache_bytes Cache filesystem bytes by state.
# TYPE brix_cache_bytes gauge
brix_cache_bytes{port="1094",auth="anon",state="total"} 214748364800
brix_cache_bytes{port="1094",auth="anon",state="used"} 157672816640
brix_cache_bytes{port="1094",auth="anon",state="available"} 57075548160
# HELP brix_cache_evictions_total Files evicted from brix_cache_export.
# TYPE brix_cache_evictions_total counter
brix_cache_evictions_total{port="1094",auth="anon"} 17
# HELP brix_cache_evicted_bytes_total Bytes reclaimed by cache eviction.
# TYPE brix_cache_evicted_bytes_total counter
brix_cache_evicted_bytes_total{port="1094",auth="anon"} 549755813888
# HELP brix_cache_eviction_errors_total Cache eviction maintenance errors.
# TYPE brix_cache_eviction_errors_total counter
brix_cache_eviction_errors_total{port="1094",auth="anon"} 1
# HELP brix_requests_total XRootD requests completed, by operation and status.
# TYPE brix_requests_total counter
brix_requests_total{port="1094",auth="anon",op="login",status="ok"} 42
brix_requests_total{port="1094",auth="anon",op="open_wr",status="ok"} 18
brix_requests_total{port="1094",auth="anon",op="write",status="ok"} 18
brix_requests_total{port="1094",auth="anon",op="close",status="ok"} 35
```

---

## Next Steps

- See [extended-metrics.md](./extended-metrics.md) for protocol separation, IP version tracking, VO and user analytics
- See [promql-examples.md](./promql-examples.md) for ready-to-use PromQL queries
- See [metrics-analysis.md](./metrics-analysis.md) for interpretation guidance and alerting rules
