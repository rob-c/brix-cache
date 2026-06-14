# Metrics Analysis: Health Checks and Alerting

How to read the key metric groups, what healthy values look like, and what changes signal a problem. Assumes Prometheus `rate()` and `irate()` over a 15s or 30s scrape interval.

---

## Connection Health

```promql
# Connection acceptance rate
rate(xrootd_connections_total[5m])

# Live connections (should be stable, not monotonically growing)
xrootd_connections_active

# Auth failures as a fraction of logins
rate(xrootd_requests_total{op="auth",status="error"}[5m])
  / rate(xrootd_requests_total{op="login",status="ok"}[5m])
```

**What to watch:**

- `xrootd_connections_active` growing without bound means connections are not being closed. Caused by client-side `xrdcp` hangs, long-running jobs holding file handles, or upstream redirect loops that keep secondaries alive.
- A spike in `xrootd_connections_total` rate with no corresponding increase in `xrootd_requests_total{op="open_rd"}` rate means clients are connecting and immediately disconnecting — usually an auth failure or a misconfigured client that cannot finish the login sequence.
- `xrootd_requests_total{op="auth",status="error"}` increasing is the first signal of an expired CA bundle, a rotated CRL that invalidates a VO's credentials, or a JWKS fetch failure for token auth.

---

## Throughput

```promql
# Read throughput in bytes/s (file data only, not protocol overhead)
rate(xrootd_bytes_tx_total[1m])

# Write throughput in bytes/s
rate(xrootd_bytes_rx_total[1m])

# WebDAV GET throughput
rate(xrootd_webdav_bytes_tx_total[1m])

# S3 GET throughput
rate(xrootd_s3_bytes_tx_total[1m])
```

`xrootd_bytes_tx_total` covers native `kXR_read`, `kXR_readv`, and `kXR_pgread` data payloads. `xrootd_wire_bytes_tx_total` includes protocol framing on top. The gap between the two grows with small-read workloads (many headers, little data) and shrinks toward zero for large sequential reads.

**Normal range:** For large file sequential reads over a 10 Gbps link you should see `xrootd_bytes_tx_total` rate approaching 1–1.2 GB/s per worker. If you are significantly below that on a dedicated machine, look at:

1. `xrootd_stream_response_write_stalls_total` rate — a high stall rate means the kernel socket buffer is full and the server is waiting for the client. Caused by slow clients, high network RTT, or undersized TCP receive windows.
2. The `CLOSE` verb in access logs — look for throughputs well below the line rate across many files. Combined with high stall counts, this points to client-side bottlenecks or network congestion.
3. `pgread` vs `read` split — `kXR_pgread` builds per-page CRC32c in memory, which costs CPU. A workload driven entirely by `pgread` will saturate CPU before the NIC.

---

## Read Operation Mix

```promql
# Vector read fraction (usually from ROOT branch I/O)
rate(xrootd_requests_total{op="readv"}[5m])
  / rate(xrootd_requests_total{op=~"read|readv|pgread"}[5m])

# Paged read fraction (data-integrity path)
rate(xrootd_requests_total{op="pgread"}[5m])
  / rate(xrootd_requests_total{op=~"read|readv|pgread"}[5m])
```

**Interpretation:**

- A high `readv` fraction (>50%) is normal for ROOT TTree analysis jobs, which use vector reads to fetch multiple branches per event in a single round trip. Each `kXR_readv` request counts as one entry in `xrootd_requests_total` but transfers the same data as several `kXR_read` calls.
- A high `pgread` fraction means clients are requesting per-page CRC32c verification. This is correct for integrity-sensitive transfers but costs CPU on the server. If you see unexpected CPU pressure alongside high `pgread` rates, this is likely the cause.

---

## Error Rates by Operation

```promql
# Open errors (file not found, permissions)
rate(xrootd_requests_total{op="open_rd",status="error"}[5m])

# Read errors (I/O errors on already-open handles)
rate(xrootd_requests_total{op="read",status="error"}[5m])

# Write errors
rate(xrootd_requests_total{op="write",status="error"}[5m])
```

**What to watch:**

- `open_rd` errors that are a small, stable fraction of opens (1–5%) are normal — clients probe for files that may not exist. A sudden jump in `open_rd` errors usually means a path mapping change or a namespace operation that removed files clients expected to find.
- `read` errors on open handles indicate underlying I/O problems: disk errors, NFS stale file handles, or filesystem corruption. Any non-zero `read` error rate warrants immediate investigation. Check `dmesg` and storage health.
- `write` errors combined with low `sync` counts can indicate a disk-full condition: writes appear to succeed (buffered), but `fsync` fails. Check `xrootd_cache_occupancy_ratio` and filesystem free space on the data volume.

---

## Cache Occupancy and Eviction

```promql
# How full the cache filesystem is
xrootd_cache_occupancy_ratio

# Eviction rate (files/s being removed)
rate(xrootd_cache_evictions_total[5m])

# Rate of bytes being reclaimed
rate(xrootd_cache_evicted_bytes_total[5m])

# Eviction failures (scan/unlink errors)
rate(xrootd_cache_eviction_errors_total[5m])
```

**Normal behavior:** `xrootd_cache_occupancy_ratio` should oscillate below `xrootd_cache_eviction_threshold_ratio`. Evictions fire when occupancy crosses the threshold; afterwards occupancy drops and evictions stop. Continuous evictions mean the cache is too small for the working set or the fill rate exceeds the eviction rate.

**Warning signs:**

- `xrootd_cache_occupancy_ratio` at or above the threshold with `xrootd_cache_evictions_total` not increasing means eviction is failing. Check `xrootd_cache_eviction_errors_total` — filesystem permission errors, full inodes, or a stale mount point can stall eviction silently.
- `xrootd_cache_eviction_errors_total` non-zero: the eviction scanner failed to stat or unlink a candidate file. One or two errors on startup are normal. A continuously growing count means the cache directory has entries the server cannot remove.
- Cache occupancy at 100% with write errors in native or WebDAV logs is the disk-full scenario. The cache fill throttle does not help once the filesystem is completely full.

---

## WebDAV Health

```promql
# WebDAV error rate by method
rate(xrootd_webdav_responses_total{status_class="4xx"}[5m])
rate(xrootd_webdav_responses_total{status_class="5xx"}[5m])

# Auth outcome distribution
xrootd_webdav_auth_total{result="cert_ok"}
xrootd_webdav_auth_total{result="token_ok"}
xrootd_webdav_auth_total{result="anonymous_fallback"}
xrootd_webdav_auth_total{result="rejected"}

# PUT body handling — are uploads being spooled to disk?
xrootd_webdav_put_bodies_total{mode="spooled"}
xrootd_webdav_put_bodies_total{mode="threaded"}
```

**Interpretation:**

- `xrootd_webdav_auth_total{result="rejected"}` increasing means credentials are being presented but failing verification. For proxy-cert deployments this typically means an expired user proxy or a CA/CRL store issue. For token deployments it often means a JWKS key rotation that the server has not yet picked up.
- `xrootd_webdav_auth_total{result="anonymous_fallback"}` higher than expected means clients that should be authenticating are failing silently. Compare with `rejected` — if both are low and `anonymous_fallback` is high, clients may not be sending credentials at all.
- `xrootd_webdav_put_bodies_total{mode="spooled"}` means nginx had to buffer the PUT body to a temp file before the handler could read it. This happens when the client sends a `Content-Length` header that nginx's built-in body handling cannot satisfy in memory. For large file uploads this is expected; for small uploads it may indicate a client not sending the `Expect: 100-continue` header.
- `xrootd_webdav_fd_cache_total{event="stale"}` increasing means the fd cache is returning stale entries (a file was replaced between opens on the same keepalive connection). A small number is normal after MOVE or overwrite operations. A sustained rate means the same path is being written and read rapidly on the same connection.

---

## WebDAV TPC (Third-Party Copy)

```promql
# TPC pull success rate
rate(xrootd_webdav_tpc_total{event="pull_success"}[5m])
  / rate(xrootd_webdav_tpc_total{event="pull_started"}[5m])

# curl error rate
rate(xrootd_webdav_tpc_total{event="curl_error"}[5m])
```

A `pull_success / pull_started` ratio below 1.0 means TPC transfers are failing before completing. `curl_error` is the most common failure mode — check server-side TLS configuration for the remote endpoint, network connectivity, and whether the source server requires authentication. `commit_error` (a separate event slot) means the curl transfer succeeded but the local rename into place failed, usually a full filesystem.

---

## S3 Endpoint Health

```promql
# S3 auth failure distribution
xrootd_s3_auth_total{result="signature_mismatch"}
xrootd_s3_auth_total{result="bad_access_key"}
xrootd_s3_auth_total{result="bad_date"}

# S3 4xx and 5xx rates
rate(xrootd_s3_responses_total{status_class="4xx"}[5m])
rate(xrootd_s3_responses_total{status_class="5xx"}[5m])

# ListObjects pagination
rate(xrootd_s3_list_truncated_total[5m])
```

**Interpretation:**

- `signature_mismatch` means credentials are valid (key was found) but the request signature does not match. Usually a client-side clock skew (`bad_date` accompanies it) or a client that is computing the canonical request incorrectly. Check that both client and server are NTP-synchronized.
- `bad_access_key` means the `access_key_id` in the `Authorization` header does not match any configured key. A rotation of server-side keys without updating clients causes a spike here.
- `xrootd_s3_events_total{event="invalid_uri"}` non-zero means S3 clients are sending requests the module cannot route: unknown bucket, malformed path, or a path that resolves outside the configured export root.
- High `xrootd_s3_list_truncated_total` rate means clients are paginating through large directories. This is not an error, but it indicates a directory listing workload that may be expensive; each continuation is a separate directory scan.

---

## Wire Framing Diagnostics

```promql
# Stall rate — server waiting for socket writability
rate(xrootd_stream_response_write_stalls_total[1m])

# Send error rate
rate(xrootd_stream_response_write_errors_total[1m])

# Oversized payload rejections
rate(xrootd_stream_oversized_payloads_total[1m])
```

**What to watch:**

- `write_stalls` rate growing with `bytes_tx` rate staying flat means the server is producing data faster than the network or client can consume it. For wide-area transfers this is normal. For local-area transfers it suggests a client processing bottleneck or a receive-window tuning issue.
- `write_errors` non-zero means `send()` or `send_chain()` returned a hard error, usually because the client closed the connection mid-transfer. A small number is expected in production (clients can die); a high rate suggests network instability.
- `oversized_payloads` non-zero means a client sent a request with a declared payload length larger than the server's configured limit. This is a protocol violation and the connection is dropped. In production this usually indicates a buggy client or a fuzzer.

---

## Useful Prometheus Alerting Rules

The examples below use `for: 5m` to avoid alerting on transient spikes.

```yaml
groups:
  - name: xrootd
    rules:
      - alert: XRootDHighReadErrors
        expr: |
          rate(xrootd_requests_total{op="read",status="error"}[5m]) > 0.1
        for: 5m
        annotations:
          summary: "Sustained read errors — check storage health"

      - alert: XRootDAuthFailures
        expr: |
          rate(xrootd_requests_total{op="auth",status="error"}[5m]) > 0.05
        for: 5m
        annotations:
          summary: "GSI/token auth failures — check CA bundle or JWKS"

      - alert: XRootDCacheNearFull
        expr: |
          xrootd_cache_occupancy_ratio
            > xrootd_cache_eviction_threshold_ratio * 1.05
        for: 5m
        annotations:
          summary: "Cache above eviction threshold — eviction may be stalled"

      - alert: XRootDEvictionErrors
        expr: |
          rate(xrootd_cache_eviction_errors_total[5m]) > 0.01
        for: 5m
        annotations:
          summary: "Cache eviction errors — check filesystem permissions"

      - alert: XRootDWebDAVRejected
        expr: |
          rate(xrootd_webdav_auth_total{result="rejected"}[5m]) > 0.1
        for: 5m
        annotations:
          summary: "WebDAV credentials rejected — check proxy cert or token config"
```

---

## Extended Metrics Alerting (Per-VO, Users, IP Version)

### VO tracking table full:
```promql
xrootd_vo_overflow_total > 0
```

### User tracking table full:
```promql
xrootd_user_evictions_total > 0
```

### Unusual user growth spike (>10 new users/hour):
```promql
increase(xrootd_unique_users_total[3600]) - increase(xrootd_user_evictions_total[3600]) > 10
```

### High IPv6 traffic threshold (warning if >5%):
```promql
(
  sum(rate(xrootd_bytes_tx_ipv6_total[5m])) + sum(rate(xrootd_webdav_bytes_tx_ipv6_total[5m])))
/ (
    sum(rate(xrootd_bytes_tx_ipv4_total[5m])) + sum(rate(xrootd_bytes_tx_ipv6_total[5m])))
  + sum(rate(xrootd_webdav_bytes_tx_ipv4_total[5m])) + sum(rate(xrootd_webdav_bytes_tx_ipv6_total[5m])))
)) * 100 > 5
```

---

## Next Steps

- See [metrics-overview.md](./metrics-overview.md) for complete metric catalog
- See [extended-metrics.md](./extended-metrics.md) for protocol separation, IP version tracking, VO and user analytics
- See [promql-examples.md](./promql-examples.md) for detailed query examples
