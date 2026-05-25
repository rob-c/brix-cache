# Metrics Overview

All Prometheus metrics exported by nginx-xrootd, organized by protocol layer — native XRootD stream, WebDAV, and S3.

---

## Stream Layer Metrics

### Connection Counters

#### `xrootd_connections_total`

Total TCP connections accepted since the nginx process started. Never decreases.

Labels: `port`, `auth`

```
xrootd_connections_total{port="1094",auth="anon"} 1042
xrootd_connections_total{port="1095",auth="gsi"} 17
```

#### `xrootd_connections_active`

Number of XRootD connections currently open. Goes up when a client connects, down when it disconnects.

Labels: `port`, `auth`

```
xrootd_connections_active{port="1094",auth="anon"} 4
xrootd_connections_active{port="1095",auth="gsi"} 1
```

### Byte Counters

#### `xrootd_bytes_rx_total`

Total bytes received from clients (i.e. uploaded data). Counts only file data payloads, not protocol overhead.

Labels: `port`, `auth`

```
xrootd_bytes_rx_total{port="1094",auth="anon"} 5368709120
```

#### `xrootd_bytes_tx_total`

Total bytes sent to clients (i.e. downloaded data). Counts only file data, not protocol overhead.

Labels: `port`, `auth`

```
xrootd_bytes_tx_total{port="1094",auth="anon"} 107374182400
```

### Native Stream Wire Counters

Low-level counters for debugging protocol framing, socket back-pressure, and wire overhead. These count native XRootD stream behavior, not WebDAV HTTP traffic.

Labels: `port`, `auth`

Metrics:

- `xrootd_wire_bytes_rx_total` - raw socket bytes received
- `xrootd_wire_bytes_tx_total` - raw socket bytes sent
- `xrootd_stream_request_frames_total` - parsed XRootD request headers
- `xrootd_stream_request_payload_bytes_total` - declared request payload bytes
- `xrootd_stream_oversized_payloads_total` - requests rejected for excessive payload length
- `xrootd_stream_response_frames_total` - response send attempts
- `xrootd_stream_response_write_stalls_total` - sends that waited for socket writability
- `xrootd_stream_response_write_errors_total` - send/send_chain failures

```
xrootd_wire_bytes_rx_total{port="1094",auth="anon"} 8209232
xrootd_stream_response_write_stalls_total{port="1094",auth="anon"} 14
```

### Per-Protocol Byte Counters (Extended)

Separates root:// data transfer from WebDAV and S3 at the stream layer:

Metrics:
- `xrootd_bytes_root_rx_total` — bytes received via root:// protocol only
- `xrootd_bytes_root_tx_total` — bytes sent via root:// protocol only

```
xrootd_bytes_root_rx_total{port="1094",auth="gsi"} 5368709120
xrootd_bytes_root_tx_total{port="1094",auth="gsi"} 107374182400
```

### Per-IP-Version Byte Counters (Extended)

Tracks IPv4 vs IPv6 traffic separately without adding per-client IP as a Prometheus label.

**Native XRootD stream layer:**
```
xrootd_bytes_rx_ipv4_total{port="1094",auth="gsi"} 5368709120
xrootd_bytes_tx_ipv4_total{port="1094",auth="gsi"} 107374182400
xrootd_bytes_rx_ipv6_total{port="1094",auth="gsi"} 0
xrootd_bytes_tx_ipv6_total{port="1094",auth="gsi"} 0
```

See [extended-metrics.md](./extended-metrics.md) for WebDAV and S3 IP-version counters.

---

## Cache Metrics

### `xrootd_cache_occupancy_ratio`

Current `statvfs()` filesystem occupancy ratio for `xrootd_cache_root`.

Labels: `port`, `auth`

```
xrootd_cache_occupancy_ratio{port="1094",auth="anon"} 0.734218
```

### `xrootd_cache_eviction_threshold_ratio`

Configured cache eviction high-water mark.

Labels: `port`, `auth`

```
xrootd_cache_eviction_threshold_ratio{port="1094",auth="anon"} 0.900000
```

### `xrootd_cache_bytes`

Current cache filesystem bytes, split by state.

Labels: `port`, `auth`, `state`

```
xrootd_cache_bytes{port="1094",auth="anon",state="total"} 214748364800
xrootd_cache_bytes{port="1094",auth="anon",state="used"} 157672816640
xrootd_cache_bytes{port="1094",auth="anon",state="available"} 57075548160
```

### `xrootd_cache_evictions_total`

Total regular cached files unlinked by cache eviction.

Labels: `port`, `auth`

```
xrootd_cache_evictions_total{port="1094",auth="anon"} 17
```

### `xrootd_cache_evicted_bytes_total`

Total bytes reclaimed by cache eviction, using each evicted file's size at scan time.

Labels: `port`, `auth`

```
xrootd_cache_evicted_bytes_total{port="1094",auth="anon"} 549755813888
```

### `xrootd_cache_eviction_errors_total`

Total best-effort eviction maintenance errors, such as scan, stat, or unlink failures.

Labels: `port`, `auth`

```
xrootd_cache_eviction_errors_total{port="1094",auth="anon"} 1
```

---

## Request Metrics

### `xrootd_requests_total`

Total XRootD requests completed, broken down by operation type and outcome.

Labels: `port`, `auth`, `op`, `status`

```
xrootd_requests_total{port="1094",auth="anon",op="login",status="ok"} 1042
xrootd_requests_total{port="1094",auth="anon",op="open_rd",status="ok"} 8314
xrootd_requests_total{port="1094",auth="anon",op="read",status="ok"} 41570
xrootd_requests_total{port="1094",auth="anon",op="close",status="ok"} 8314
xrootd_requests_total{port="1094",auth="anon",op="open_rd",status="error"} 12
```

Operations tracked (`op` label values): `login`, `auth`, `stat`, `open_rd`, `open_wr`, `read`, `write`, `sync`, `close`, `dirlist`, `mkdir`, `rmdir`, `rm`, `mv`, `chmod`, `truncate`, `ping`, `query_cksum`, `query_space`, `readv`, `pgread`, `writev`, `locate`, `statx`, `fattr`, `query_stats`, `query_xattr`, `query_finfo`, `query_fsinfo`, `set`, `query_visa`, `query_opaque`, `query_opaquf`, `query_opaqug`, `query_ckscan`, `clone`, `chkpoint`

`kXR_pgwrite` is currently accounted under the `write` slot because it shares the write-family metric path.

Error series (`status="error"`) are omitted from the output when the count is zero — this keeps the scrape output short when errors are rare.

---

## WebDAV Counters

WebDAV counters are global to the nginx instance and intentionally avoid path, DN, token subject, and Origin labels.

Metrics:

- `xrootd_webdav_requests_total{method}` - requests by method
- `xrootd_webdav_responses_total{method,status_class}` - responses by method and HTTP status class
- `xrootd_webdav_auth_total{result}` - auth outcomes (`none`, `cert_ok`, `token_ok`, `anonymous_fallback`, `rejected`)
- `xrootd_webdav_bytes_rx_total` - bytes accepted into WebDAV writes
- `xrootd_webdav_bytes_tx_total` - bytes sent by WebDAV GET and PROPFIND
- `xrootd_webdav_range_requests_total{result}` - full, partial, or unsatisfied GET ranges
- `xrootd_webdav_put_bodies_total{mode}` - empty, memory, spooled, or threaded PUT bodies
- `xrootd_webdav_fd_cache_total{event}` - per-connection fd-cache hit/miss/insert/update/evict/stale
- `xrootd_webdav_propfind_depth_total{depth}` - PROPFIND depth buckets
- `xrootd_webdav_propfind_entries_total` - PROPFIND response entries emitted
- `xrootd_webdav_tpc_total{event}` - HTTP-TPC pull/curl/commit outcomes
- `xrootd_webdav_cors_total{event}` - CORS allowed/denied/preflight/no-origin decisions

```
xrootd_webdav_requests_total{method="GET"} 1297
xrootd_webdav_responses_total{method="GET",status_class="2xx"} 1294
xrootd_webdav_cors_total{event="preflight"} 22
```

### WebDAV IP-Version Counters (Extended)

WebDAV also tracks IPv4 vs IPv6 traffic separately:

```
xrootd_webdav_bytes_rx_ipv4_total 5368709120
xrootd_webdav_bytes_tx_ipv4_total 107374182400
xrootd_webdav_bytes_rx_ipv6_total 0
xrootd_webdav_bytes_tx_ipv6_total 0
```

See [extended-metrics.md](./extended-metrics.md) for full details.

---

## S3-Compatible Counters

S3-compatible counters are global to the nginx instance and intentionally avoid bucket, object key, access-key, principal, and other client-controlled labels. They cover the path-style REST subset implemented under `src/s3/`.

Metrics:

- `xrootd_s3_requests_total{method}` - requests by operation (`GET`, `HEAD`, `PUT`, `DELETE`, `LIST`, `OTHER`)
- `xrootd_s3_responses_total{method,status_class}` - responses by operation and HTTP status class
- `xrootd_s3_auth_total{result}` - auth outcomes (`anonymous`, `sigv4_ok`, `missing`, `malformed`, `bad_access_key`, `bad_date`, `signature_mismatch`, `internal_error`)
- `xrootd_s3_bytes_rx_total` - bytes accepted into successful PUT writes
- `xrootd_s3_bytes_tx_total` - bytes emitted by GET, ListObjectsV2, and XML error responses
- `xrootd_s3_range_requests_total{result}` - full, partial, or unsatisfied GET ranges
- `xrootd_s3_put_bodies_total{mode}` - empty, memory, spooled, or mixed PUT bodies
- `xrootd_s3_events_total{event}` - low-cardinality diagnostics such as invalid URI, access denied, missing key, write disabled, method not allowed, internal error, directory sentinel, or idempotent delete-missing
- `xrootd_s3_list_contents_total` - ListObjectsV2 `<Contents>` entries emitted
- `xrootd_s3_list_common_prefixes_total` - ListObjectsV2 `<CommonPrefixes>` entries emitted
- `xrootd_s3_list_truncated_total` - ListObjectsV2 responses with a continuation token

```
xrootd_s3_requests_total{method="GET"} 834
xrootd_s3_responses_total{method="GET",status_class="2xx"} 831
xrootd_s3_range_requests_total{result="partial"} 42
xrootd_s3_auth_total{result="sigv4_ok"} 1204
```

### S3 IP-Version Counters (Extended)

S3 also tracks IPv4 vs IPv6 traffic separately:

```
xrootd_s3_bytes_rx_ipv4_total 5368709120
xrootd_s3_bytes_tx_ipv4_total 107374182400
xrootd_s3_bytes_rx_ipv6_total 0
xrootd_s3_bytes_tx_ipv6_total 0
```

See [extended-metrics.md](./extended-metrics.md) for full details.

---

## Per-VO Traffic Tracking (Extended)

Groups data transfer by virtual organisation. VO names are truncated to 15 characters for storage efficiency. The table supports up to 32 VOs simultaneously; excess VOs increment an overflow counter and evict the oldest entry (LRU policy).

Metrics:
- `xrootd_vo_bytes_tx_total{vo="..."}` — bytes sent to clients from this VO's users
- `xrootd_vo_bytes_rx_total{vo="..."}` — bytes received from this VO's users  
- `xrootd_vo_requests_total{vo="..."}` — request count for this VO

```
xrootd_vo_bytes_tx_total{vo="cms"} 1234567890
xrootd_vo_bytes_tx_total{vo="atlas"} 9876543210
xrootd_vo_requests_total{vo="cms"} 54321
```

See [extended-metrics.md](./extended-metrics.md) for configuration notes and full details.

---

## Unique User Identity Tracking (Extended)

Counts distinct authenticated users since process start. Users are identified by hashing their DN (GSI) or token sub claim via FNV-1a 32-bit hash before lookup. The table supports up to 512 tracked identities simultaneously; excess entries evict the oldest slot using LRU policy.

Metrics:
- `xrootd_unique_users_current` — currently tracked unique users (bounded by table size)
- `xrootd_unique_users_total` — lifetime unique users seen (never decreases)
- `xrootd_user_evictions_total` — slots recycled when table is full
- `xrootd_user_sessions_total{hash=...}` — sessions per hashed identity

```
xrootd_unique_users_current 42
xrootd_unique_users_total 1873
xrootd_user_evictions_total 156
xrootd_user_sessions_total{hash=a1b2c3d4} 5
```

See [extended-metrics.md](./extended-metrics.md) for configuration notes and full details.

---

## Sample Output

Complete sample of Prometheus metrics text output:

```
# HELP xrootd_connections_total Total TCP connections accepted since process start.
# TYPE xrootd_connections_total counter
xrootd_connections_total{port="1094",auth="anon"} 42
xrootd_connections_total{port="1095",auth="gsi"} 7
# HELP xrootd_connections_active Currently open XRootD connections.
# TYPE xrootd_connections_active gauge
xrootd_connections_active{port="1094",auth="anon"} 3
xrootd_connections_active{port="1095",auth="gsi"} 0
# HELP xrootd_bytes_rx_total Bytes received from clients (write payloads).
# TYPE xrootd_bytes_rx_total counter
xrootd_bytes_rx_total{port="1094",auth="anon"} 12582912
# HELP xrootd_bytes_tx_total Bytes sent to clients (read data).
# TYPE xrootd_bytes_tx_total counter
xrootd_bytes_tx_total{port="1094",auth="anon"} 4194304
# HELP xrootd_cache_occupancy_ratio Filesystem occupancy ratio for xrootd_cache_root.
# TYPE xrootd_cache_occupancy_ratio gauge
xrootd_cache_occupancy_ratio{port="1094",auth="anon"} 0.734218
# HELP xrootd_cache_eviction_threshold_ratio Configured cache eviction high-water occupancy ratio.
# TYPE xrootd_cache_eviction_threshold_ratio gauge
xrootd_cache_eviction_threshold_ratio{port="1094",auth="anon"} 0.900000
# HELP xrootd_cache_bytes Cache filesystem bytes by state.
# TYPE xrootd_cache_bytes gauge
xrootd_cache_bytes{port="1094",auth="anon",state="total"} 214748364800
xrootd_cache_bytes{port="1094",auth="anon",state="used"} 157672816640
xrootd_cache_bytes{port="1094",auth="anon",state="available"} 57075548160
# HELP xrootd_cache_evictions_total Files evicted from xrootd_cache_root.
# TYPE xrootd_cache_evictions_total counter
xrootd_cache_evictions_total{port="1094",auth="anon"} 17
# HELP xrootd_cache_evicted_bytes_total Bytes reclaimed by cache eviction.
# TYPE xrootd_cache_evicted_bytes_total counter
xrootd_cache_evicted_bytes_total{port="1094",auth="anon"} 549755813888
# HELP xrootd_cache_eviction_errors_total Cache eviction maintenance errors.
# TYPE xrootd_cache_eviction_errors_total counter
xrootd_cache_eviction_errors_total{port="1094",auth="anon"} 1
# HELP xrootd_requests_total XRootD requests completed, by operation and status.
# TYPE xrootd_requests_total counter
xrootd_requests_total{port="1094",auth="anon",op="login",status="ok"} 42
xrootd_requests_total{port="1094",auth="anon",op="open_wr",status="ok"} 18
xrootd_requests_total{port="1094",auth="anon",op="write",status="ok"} 18
xrootd_requests_total{port="1094",auth="anon",op="close",status="ok"} 35
```

---

## Next Steps

- See [extended-metrics.md](./extended-metrics.md) for protocol separation, IP version tracking, VO and user analytics
- See [promql-examples.md](./promql-examples.md) for ready-to-use PromQL queries
- See [metrics-analysis.md](./metrics-analysis.md) for interpretation guidance and alerting rules
