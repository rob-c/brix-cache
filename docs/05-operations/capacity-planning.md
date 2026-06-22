# Capacity Planning

How to size an nginx-xrootd gateway: workers, connections, file descriptors,
the async thread pool, shared-memory zones, and the transfer memory budget.
Numbers below are starting points — measure with the
[Grafana dashboard](../08-metrics-monitoring/monitoring-guide.md)
(`contrib/grafana-dashboard.json`) and adjust.

## Workers & connections

```nginx
worker_processes  auto;          # one per core is the default starting point
worker_rlimit_nofile 1048576;    # must exceed worker_connections * (peers+files)
events { worker_connections 65536; }
```

- **`worker_processes auto`** maps to the core count. The data plane is event-driven,
  so you rarely need more workers than cores; add cores rather than workers.
- **`worker_connections`** bounds *concurrent sockets per worker*. Each proxied/TPC/
  cluster transfer uses an upstream socket too, so budget ~2 connections per active
  transfer in proxy/cluster topologies.
- **`worker_rlimit_nofile`** must be larger than `worker_connections` plus the open
  file handles per connection. root:// gives each connection up to 256 file handles
  (`src/connection/fd_table.c`), so an FD-starved worker shows up as failed `open`s.
  Watch `xrootd_connections_active` against your `worker_connections` ceiling.

## Async thread pool

Blocking disk work (large reads/writes, `copy_file_range`, aws-chunked decode,
multipart assembly, checksum scans) is offloaded off the event loop to a thread
pool so latency for other clients stays flat. Declare it at the top level:

```nginx
thread_pool default threads=32 max_queue=65536;
```

- **`threads`** ≈ the number of concurrent blocking IO operations you want in flight.
  Start at ~2× cores for spinning disk, lower for NVMe (which finishes fast enough
  that the offload overhead dominates). If `max_queue` is hit, requests error — raise
  `threads` or `max_queue`.
- The S3 and WebDAV write paths resolve this pool lazily; if it is **absent**, writes
  fall back to running synchronously on the event loop (correct, but it serialises
  large uploads). Always declare a `thread_pool` on a write-serving gateway.

## Shared-memory zones

Several subsystems keep cross-worker state in nginx SHM zones (metrics, session
registry, rate-limit buckets, KV zones, FRM queue cache, cluster registry).
Sizing notes:

- The **metrics** zone is fixed-shape and small; it does not grow with traffic.
- **Rate-limit** and **KV** zones are LRU and sized by directive — size them to the
  number of distinct keys (VO/issuer/IP/DN, or KV entries) you expect to track.
  `xrootd_kv_entries{zone}` / `xrootd_kv_capacity{zone}` and the
  `xrootd_*_eviction_total` / `xrootd_*_full_errors_total` counters tell you when a
  zone is too small (evictions climbing, or full-errors > 0).
- The **session registry** has an LRU reaper; `xrootd_session_registry_full_total`
  and `xrootd_session_evict_total` rising together mean the cap is too low for your
  concurrent-session count.

## Transfer memory budget

To keep resident memory bounded on many-large-transfer workloads, the data plane
uses windowed read/write and an explicit byte budget rather than buffering whole
objects. Signals:

- `xrootd_xfer_heap_bytes` / `xrootd_xfer_heap_high_water_bytes` — current and peak
  transfer scratch memory.
- `xrootd_budget_waits_total` — how often a transfer waited for budget. A steadily
  climbing rate means concurrency is being throttled by the budget; this is the
  backpressure working as intended. Add memory/raise the budget only if latency
  suffers and the host has headroom.

## Read cache (optional)

If `xrootd_cache` is enabled, size it to your hot working set:

- `xrootd_cache_occupancy_ratio` near 1.0 with a low
  `xrootd_cache_hits_total / (hits+misses)` ratio ⇒ the cache is too small or the
  working set is not cacheable.
- `xrootd_cache_evictions_total` climbing ⇒ churn; grow the cache or raise
  `xrootd_cache_max_file_size` selectivity.

## A sizing worksheet

1. **Peak concurrent transfers** `C` (from `xrootd_connections_active` at peak).
2. `worker_connections ≥ C × (1 + upstreams_per_transfer)` with headroom.
3. `worker_rlimit_nofile ≥ worker_connections × avg_fds_per_conn`.
4. `thread_pool threads ≈` peak concurrent **blocking IO** ops (≤ `C`, usually far less).
5. Size each LRU SHM zone to its distinct-key count; confirm `*_eviction_total`/
   `*_full_errors_total` stay flat at peak.
6. Confirm `xrootd_budget_waits_total` rate is acceptable; if not, add RAM/budget.

See also: [Troubleshooting](troubleshooting.md) ·
[Performance Benchmarks](performance-benchmarks.md) ·
[Monitoring Guide](../08-metrics-monitoring/monitoring-guide.md)
