# Metrics Overview

All Prometheus metrics exported by BriX-Cache, organized by protocol layer — native
XRootD stream, WebDAV, S3, the cvmfs cache plane, and the GridFTP gateway.

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
  ──────────────────────────────────────────────────────────────────────────────────
  io_ops_total, io_bytes_read/written, io_latency_seconds, auth_total, tpc_*
    ← the unified {proto=...} view, written by ALL FIVE planes
      (stream · webdav · s3 · cvmfs · gridftp) into the one process-wide zone

  Label discipline (INVARIANT #8): only low-cardinality labels —
  {proto, port, auth, op, status, method, status_class}. Never paths, DNs,
  buckets, keys, or UUIDs. VO is capped at 32 entries; user identity is
  hashed + LRU-1024 (1024-entry bounded table).
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

#### `brix_io_bytes_written`

Total bytes received from clients (i.e. uploaded data). Counts only file data payloads, not protocol overhead.

Labels: `proto`

```
brix_io_bytes_written{proto="stream"} 5368709120
```

#### `brix_io_bytes_read`

Total bytes sent to clients (i.e. downloaded data). Counts only file data, not protocol overhead.

Labels: `proto`

```
brix_io_bytes_read{proto="stream"} 107374182400
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

### Per-protocol byte counters

The two canonical families above distinguish all five planes through `proto`.
Use `proto="stream"` for root://, `webdav` for WebDAV, `s3` for S3-compatible,
`cvmfs` for CVMFS and `gridftp` for GridFTP.

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

## Cluster Membership Metrics (CMS / AAA federation)

When `brix_cms_manager` is set, the node dials its redirector and registers
upward. These three families answer the only question a federation operator
actually asks during an incident — *is this site still in the cluster?* — from
the node's own `/metrics`, without shell access to the manager.

```
brix_cms_logins_total 4
brix_cms_connect_failures_total 37
brix_cms_registered_links 1
```

| Metric | Type | Meaning |
| --- | --- | --- |
| `brix_cms_logins_total` | counter | LOGIN frames this node sent upward. Increments once per successful join, so a rising value with a flat `registered_links` means the node is flapping. |
| `brix_cms_connect_failures_total` | counter | Upward dials that were torn down before LOGIN ever went out — refused, unreachable, or past the connect deadline. |
| `brix_cms_registered_links` | **gauge** | Upward links currently logged in. **`0` means this node is out of the cluster** and the redirector will stop sending it clients. |

The outbound CMS client runs on worker 0 only (stock `cmsd` admits one
connection per SID), so the gauge has a single writer and needs no
per-worker aggregation. It is decremented in the link teardown path, which
is also where a never-logged-in dial is counted as a failure: on loopback — and
on any path where the peer resets rather than dropping — a refused dial
surfaces on the **read** side (`recv()` returning `ECONNREFUSED`), not at
`ngx_event_connect_peer()`, so teardown is the one funnel every failed join
passes through exactly once.

Useful alerts:

```promql
# This site has fallen out of the federation.
brix_cms_registered_links == 0

# Joined but not staying joined — link is flapping, not down.
rate(brix_cms_logins_total[15m]) > 0 and brix_cms_registered_links == 0

# Redirector unreachable; backoff is working if this rises slowly, not linearly.
rate(brix_cms_connect_failures_total[5m]) > 0
```

Retry is exponential with jitter (6 s initial, capped at 60 s and at 10×
`brix_cms_interval`), so a sustained outage produces a handful of failures per
minute — not hundreds. A steep `connect_failures` slope is itself the signal
that backoff has regressed to a hot loop.

Coverage: `tests/test_cms_aaa_join_noise.py` drives join, outage, rejoin and
hostile-redirector cases across an impaired link and asserts on all three
families.

### Manager-side: `brix_cms_locate_coalesced_total`

The three families above are emitted by a **node** about its link upward. This
one is emitted by a **manager** about work it did not have to do.

```
brix_cms_locate_coalesced_total 812
```

| Metric | Type | Meaning |
| --- | --- | --- |
| `brix_cms_locate_coalesced_total` | counter | Dynamic-locate requests that rode a `kYR_state` window already in flight for the same path instead of opening one of their own. Requires `brix_cms_coalesce on`; stays at `0` otherwise. |

Read it against the locate rate, not on its own. A high *ratio* is the feature
working — a popular path being opened by many clients at once costs one probe
wave rather than N. A ratio near zero under load means the arrivals are not
actually colliding (distinct paths, or a `brix_cms_locate_window` too short for
a second client to arrive inside it), so the directive is buying nothing.

```promql
# Probe waves saved, as a share of dynamic locates served.
rate(brix_cms_locate_coalesced_total[5m])
```

Two things it deliberately does not count: a `kXR_refresh` locate, which must
never coalesce because refresh exists to bypass an in-flight answer, and a
collision across worker processes — parking is per worker, so on an N-worker
manager the ceiling is per-worker collisions, not global ones.

### Manager-side: the cluster registry and health-check families

A **manager** (`brix_manager_mode on`) also exports what it knows about its
members, from the shared-memory registry every worker reads. Emitted whenever
the registry zone exists, member or not; a manager with no data server yet
still exposes the count gauge and the four health-check counters.

```
brix_cluster_servers_registered 2
brix_cluster_server_free_megabytes{server="ds1.example:1094"} 812000
brix_cluster_server_utilization_percent{server="ds1.example:1094"} 37
brix_cluster_server_last_seen_seconds{server="ds1.example:1094"} 1.4
brix_cluster_server_blacklisted{server="ds1.example:1094"} 0
brix_cluster_server_disconnect_total{server="ds1.example:1094"} 0
brix_cluster_hc_probes_total 140
brix_cluster_hc_pass_total 140
brix_cluster_hc_fail_total 0
brix_cluster_hc_blacklist_total 0
```

| Metric | Type | Meaning |
| --- | --- | --- |
| `brix_cluster_servers_registered` | gauge | Members in this manager's registry — its own tier only; a sub-manager's leaves are counted by the sub-manager, not by the meta above it. |
| `brix_cluster_server_*{server="host:port"}` | gauge / counter | One row per member: reported free space and utilisation, seconds since its last heartbeat, whether it is blacklisted right now, and `disconnect_total` — the CMS link drops charged to it. |
| `brix_cluster_hc_probes_total`, `_pass_total`, `_fail_total`, `_blacklist_total` | counter | Active health-check outcomes, **aggregate only** — no per-server label, by INVARIANT 8 (low-cardinality labels). Per-server health is on the dashboard snapshot API. |

The `server` label is bounded by the registry's slot count, not by clients.

**Reset semantics.** A member's CMS link dropping sets `blacklisted` to 1 and
bumps `disconnect_total`; when the member registers again, `brix_srv_register`
rebuilds its row ("clear any prior blacklist on reconnect") and both read 0.
That is the counter reset Prometheus allows after a restart of the thing
counted — `rate()` and `increase()` handle it — and a re-register is never
charged as a second disconnect. A failure at one tier is never charged to the
tier above: the meta's row for a sub-manager does not move when that
sub-manager's leaf drops.

Coverage: `tests/test_release20_cms_metrics.py` (three-tier tree: ownership,
drop and re-register, tier isolation) and `tests/test_release20_health_metrics.py`
(the hc family declared and moving, emitted before the first member, no
per-server label).

---

## Cache Metrics

### `brix_cache_occupancy_ratio`

Current occupancy ratio, from the cache store's own capacity report
(`brix_cstore_freespace`) first — for `brix_cache_store ram:<size>` that is the
configured cap against resident bytes plus in-flight fill reservations, per
worker — and from a `statvfs()` of the legacy `brix_cache_export` root only when
the store has no report of its own.

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

Current cache bytes, split by state, from the cache store's own capacity
report — a `ram:` store answers its configured cap (`total`), resident bytes
plus in-flight fill reservations (`used`) and the remainder (`available`); a
store with no report of its own falls back to the filesystem of the legacy
`brix_cache_export` root. Every export with a `brix_cache_store` gets the row
(since 2.0 — before, only `brix_cache on` did), from the export's first
accepted TCP connection on (the slot is published at accept time, before any
handshake — a readiness probe is enough).

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
| `completed` | A **clean**, fully written-back staging copy (`flush_gen > 0`) reclaimed once its last flush aged out — bytes are safely on the origin. | No |
| `cold` | A **clean read-through fill** (`flush_gen == 0`) untouched for longer than `brix_cache_cold_max_age`, purged regardless of occupancy. Off unless that directive is set; without it a clean read-fill is left for occupancy-driven eviction. | No — re-fetchable |

A non-zero `abandoned`/`incomplete` rate means write-back data is being discarded
before it reaches the origin/backend (origin unreachable, flush failing, or
`brix_cache_dirty_max_age` too short) — pair it with
`brix_wt_flushes_total{result="error"}`. A `completed` rate is benign cleanup,
and so is `cold`: a rising `cold` rate simply means the working set is smaller
than the cache and objects are ageing out on schedule. If `cold` is high while
hit rate drops, `brix_cache_cold_max_age` is shorter than the real re-access
interval.

A removal the reaper cannot complete is **not** counted here — it logs
`cache reaper could not remove "<path>" (left in place)` at error level
instead, so a stuck store shows up as a log signal rather than as phantom
counter progress.

Labels: `port`, `auth`, `reason`

```
brix_cache_dirty_reaped_total{port="1094",auth="anon",reason="abandoned"} 3
brix_cache_dirty_reaped_total{port="1094",auth="anon",reason="incomplete"} 0
brix_cache_dirty_reaped_total{port="1094",auth="anon",reason="completed"} 12
brix_cache_dirty_reaped_total{port="1094",auth="anon",reason="cold"} 41
```

### `brix_cache_prefetch_jobs_total` / `brix_cache_prefetch_blocks_total` / `brix_cache_prefetch_failures_total`

Background block prefetch (`brix_cache_prefetch` +
`brix_cache_prefetch_window` on a slice cache): jobs posted, blocks filled by
those jobs, and jobs that failed (origin/cache open or fill error — the
foreground serving path is unaffected). **Process-wide, unlabeled** — the
detached thread-pool jobs carry no per-server context (same shape as the
watermark group). Sole owner: `src/fs/backend/cache/sd_cache_prefetch.c`
(Pattern 6). `jobs_total` increments at post time on the event loop;
`blocks_total`/`failures_total` at job completion. A rising `failures_total`
with a healthy origin usually means cache-volume permission or space trouble.

```
brix_cache_prefetch_jobs_total 42
brix_cache_prefetch_blocks_total 168
brix_cache_prefetch_failures_total 0
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

- `brix_webdav_requests_total{method}` - requests by method (`OPTIONS`, `HEAD`, `GET`, `PUT`, `DELETE`, `MKCOL`, `COPY`, `PROPFIND`, `MOVE`, `OTHER`; MOVE has been first-class since the 2026-08 conformance pass — it previously folded into `OTHER`)
- `brix_webdav_responses_total{method,status_class}` - responses by method and HTTP status class
- `brix_webdav_auth_total{result}` - auth outcomes (`none`, `cert_ok`, `token_ok`, `anonymous_fallback`, `rejected`)
- `brix_io_bytes_written{proto="webdav"}` - bytes accepted into WebDAV writes
- `brix_io_bytes_read{proto="webdav"}` - bytes sent by WebDAV GET and PROPFIND
- `brix_webdav_range_requests_total{result}` - full, partial, or unsatisfied GET ranges
- `brix_webdav_put_bodies_total{mode}` - empty, memory, spooled, or threaded PUT bodies
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
- `brix_io_bytes_written{proto="s3"}` - bytes accepted into successful PUT writes
- `brix_io_bytes_read{proto="s3"}` - bytes emitted by GET, ListObjectsV2, and XML error responses
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

Counts distinct authenticated users since process start. Users are identified by hashing their DN (GSI) or token sub claim via FNV-1a 32-bit hash before lookup. The table supports up to 1024 tracked identities simultaneously; excess entries evict the oldest slot using LRU policy.

Metrics:
- `brix_unique_users_current` — currently tracked unique users (bounded by table size)
- `brix_unique_users_total` — lifetime unique users seen (never decreases)
- `brix_user_evictions_total` — slots recycled when table is full
- `brix_user_sessions_total{hash=...}` — sessions per hashed identity

```
brix_unique_users_current 42
brix_unique_users_total 1873
brix_user_evictions_total 156
brix_user_sessions_total{hash="a1b2c3d4"} 5
```

See [extended-metrics.md](./extended-metrics.md) for configuration notes and full details.

---

## Unified Protocol-Labeled Metrics

The `brix_io_*`, `brix_auth_total` and `brix_tpc_*` families are the
protocol-neutral view: one label vocabulary shared by **every** protocol plane
the module speaks. The metrics zone is process-wide, so one `/metrics` location
exports all of them no matter which planes are configured on which listeners —
a `stream {}` gateway and an HTTP `server {}` in the same nginx write into the
same counters, and a single scrape covers the whole process.

### The `proto` label values

**All protocols are inside the metrics zone.** The label set is generated from
the single protocol declaration in `src/core/types/proto_list.h`, so it cannot
drift from the code:

| `proto` | Plane | Wire scheme(s) | nginx side |
|---------|-------|----------------|------------|
| `stream` | Native XRootD | `root://`, `roots://` | `stream {}` |
| `webdav` | WebDAV / HTTP | `davs://`, `https://`, `http://` | `http {}` |
| `s3` | S3-compatible REST | path-style REST | `http {}` |
| `cvmfs` | cvmfs site cache | `cvmfs://` | `http {}` |
| `gridftp` | GridFTP gateway | `gsiftp://` | `stream {}` |

`stream` and `root` are frozen historical names for the same native plane: the
metric label is `stream`, the dashboard display name is `root`. The list is
**append-only** — the enum values persist in shared memory as small ints, so
rows are never reordered or removed.

Series are emitted for the full label cross product, so every `proto` appears in
every family even when that plane carries no traffic: an unconfigured protocol
reads `0`, it does not vanish. Alerting rules can reference `{proto="gridftp"}`
without an `absent()` guard.

### Families

| Family | Type | Labels |
|--------|------|--------|
| `brix_io_ops_total` | counter | `proto`, `op`, `status` |
| `brix_io_bytes_read` | counter | `proto` |
| `brix_io_bytes_written` | counter | `proto` |
| `brix_io_latency_seconds` | histogram | `proto`, `op` (+ `le` on `_bucket`) |
| `brix_auth_total` | counter | `proto`, `method`, `status` |
| `brix_tpc_transfers_total` | counter | `proto`, `direction`, `status` |
| `brix_tpc_bytes_total` | counter | `proto`, `direction` |
| `brix_tpc_gsi_delegated_total` | counter | `result` |

The same five `proto` values also label the cache-outcome and credential-gate
families, which iterate the identical protocol list:

| Family | Type | Labels |
|--------|------|--------|
| `brix_cache_requests_total` | counter | `proto`, `cache_status` |
| `brix_cache_bytes_evicted_total` | counter | `proto` |
| `brix_cred_select_user_total` / `_fallback_total` / `_deny_total` | counter | `proto` |
| `brix_cred_deleg_total` | counter | `proto`, `mode`, `outcome` |
| `brix_cred_deleg_fail_total` | counter | `proto`, `reason` |
| `brix_vfs_mutation_denied_total` | counter | `proto`, `op`, `reason` |
| `brix_vfs_spill_bytes_total` / `brix_vfs_spill_refused_total` | counter | `proto` |
| `brix_vfs_spill_active` | gauge | *(none — process-wide)* |
| `brix_vfs_lock_refused_total` | counter | `proto` |
| `brix_vfs_precond_failed_total` | counter | `kind` |
| `brix_vfs_precond_advisory_total` | counter | `driver` |
| `brix_vfs_recall_total` | counter | `result` |
| `brix_vfs_evict_bytes_total` | counter | `driver` |
| `brix_vfs_bulk_delete_batches_total` / `brix_vfs_bulk_delete_keys_total` | counter | `driver` |

Label values (closed sets — INVARIANT #8):

- `op` — `read`, `write`, `stat`, `delete`, `mkdir`, `rename`, `dirlist`,
  `tpc`, `xattr`, `copy`
- `status` (I/O and TPC) — `ok`, `not_found`, `forbidden`, `io_error`, `other`
- `method` — `none`, `gsi`, `token`, `sss`, `s3key`, `unix`, `krb5`, `host`,
  `pwd`; `status` on `brix_auth_total` is `ok` or `fail`
- `direction` — `pull`, `push`
- `result` (delegation) — `ok`, `expired`, `absent`
- `op` on `brix_vfs_mutation_denied_total` — the closed VFS mutation
  vocabulary `open`, `write`, `truncate`, `sync`, `mkdir`, `remove`, `rename`,
  `copy`, `setattr`, `xattr`, `publish`; `reason` is always `read_only`
- `kind` on `brix_vfs_precond_failed_total` — `absent`, `etag`, `meta`
- `result` on `brix_vfs_recall_total` — `queued`, `joined`, `online`, `error`
- `driver` — the fixed storage-driver id table (`brix_fs_id_name`, bounded by
  `BRIX_FS_ID_COUNT`), never an instance or export name
- `le` — the eight finite microsecond bounds `1000`, `5000`, `10000`, `50000`,
  `100000`, `500000`, `1000000`, `5000000`, plus `+Inf`

`brix_io_bytes_read`/`_written` fold the older per-protocol wire ledgers in at
scrape time for `stream`, `webdav` and `s3` (see
[Per-Protocol Byte Counters](#per-protocol-byte-counters-extended)); `cvmfs` and
`gridftp` have no legacy ledger and book their bytes directly. Which layer owns
each row is fixed — see the single-owner rule below.

```
brix_io_ops_total{proto="stream",op="read",status="ok"}      14302
brix_io_ops_total{proto="webdav",op="read",status="ok"}       8871
brix_io_ops_total{proto="s3",op="write",status="ok"}          1204
brix_io_ops_total{proto="cvmfs",op="read",status="ok"}       36510
brix_io_ops_total{proto="gridftp",op="read",status="ok"}      6120
brix_io_bytes_read{proto="gridftp"}                    92341760512
brix_io_bytes_written{proto="gridftp"}                 44002181120
brix_io_latency_seconds_count{proto="gridftp",op="write"}      418
brix_auth_total{proto="gridftp",method="gsi",status="ok"}      377
brix_vfs_mutation_denied_total{proto="webdav",op="write",reason="read_only"}  12
```

`brix_vfs_mutation_denied_total` is booked by the VFS mutation-policy kernel
(phase-105, `src/fs/vfs/vfs_policy.c`), once per refused mutation, at the
moment the endpoint policy answers `EROFS` — before any backend lookup,
capability probe or credential selection. A non-zero rate on an export you
believe is writable means the endpoint merged to read-only; a non-zero rate on
a deliberately read-only export is the gate working, and the `op` label says
which family of write the client is attempting. The counter is never bumped
for an authorization failure, which stays `EACCES`/`brix_auth_total`.

The three `brix_vfs_spill_*` families are the phase-107 C1 writer's
reorder-spill telemetry (`src/fs/vfs/vfs_writer_spill.c`): `_bytes_total`
counts bytes absorbed into the local scratch when a client writes
out-of-order against a staged-only backend, `_refused_total` counts reordered
uploads the spill could not serve (no `brix_vfs_spill_path`/`brix_stage_dir`
configured, `brix_vfs_spill_max` exceeded, an overlapping extent, or a
coverage hole at commit), and `_active` is the process-wide gauge of spill
scratches currently open. A rising `_refused_total` with `_bytes_total` flat
means clients reorder here but no scratch is configured — the fix is a
directive, not a client change. No path, export or size ever becomes a label
(INVARIANT #8).

`brix_vfs_lock_refused_total` is the phase-107 C7 cross-protocol lock gate's
ledger (`brix_vfs_require_unlocked` in `src/fs/vfs/vfs_lock_gate.c`): one
observation per mutation that arrived under a live, unexpired WebDAV lock whose
token the caller did not present. Under `brix_lock_enforcement strict` each
observation is a refusal the client saw (`kXR_FileLocked` / 423 / S3 409
`OperationAborted` / GridFTP 450); under `advisory` the same observation counts
a breach that was warned to the error log and allowed through — so a non-zero
rate during an `advisory` migration window is the exact traffic that will start
refusing when the export moves to `strict`. Expired locks never book here (the
gate treats them as absent), and the lock token never appears in any label or
log line. The `proto` label says which plane's clients are colliding with the
locks; `proto="webdav"` rows are unusual since the WebDAV edge check normally
refuses first.

The `brix_vfs_precond_*` pair is the phase-107 C6 conditional-publish ledger
(observer `brix_vfs_precond_refused_observe` in `src/fs/vfs/vfs_staged.c`,
called from every commit/copy failure path and from the HTTP edge's own
RFC 9110 refusals). `_failed_total{kind}` counts every refused publish
precondition — `absent` is a lost If-None-Match create race, `etag`/`meta` a
lost If-Match overwrite race — each surfaced to the client as 412 / typed kXR
error rather than a silent overwrite (the errno contract is what classifies:
`EEXIST` is only ever the ABSENT verdict, `ECANCELED` only a MATCH one).
`_advisory_total{driver}` is the honesty subset: those refusals whose verdict
came from a *non-atomic* probe (a stat-then-act window, or an edge check ahead
of a backend that can't enforce natively) rather than an atomic
compare-and-act at the storage. The ratio to watch is `_advisory_total`
against `_failed_total`: a rising advisory share on a driver that enforces
natively (http If-Match, s3 conditional PUT) means the capability probe is
degrading the verdict, not that clients changed behavior.

`brix_vfs_recall_total{result}` and `brix_vfs_evict_bytes_total{driver}` are
the phase-107 C2 nearline lifecycle pair: `queued` vs `joined` is the recall
registry's dedup ratio (a `joined` recall attached to an in-flight stage
instead of issuing a second one), `online` means the object needed no recall,
and `error` is a failed bring-online. Evicted bytes are labelled by the
dispatching driver, separating a cache reclaim from a nearline release. The
`brix_vfs_bulk_delete_*` pair (phase-107 C4) counts batch-delete dispatches:
`keys_total / batches_total` is the achieved batching factor — a ratio near 1
on an S3 export means the bulk plane is not engaging and deletes are paying
one round-trip per key.

---

## Accounting Ownership & Accuracy Invariants

Verified end-to-end by the conformance suite (`tests/test_cachemx_*.py` — 2070
tests across 24 files driving real transfers over root://, WebDAV
(plain/TLS/token/cert), S3 (anonymous/SigV4), and cmsd redirection, asserting
exact per-request counter deltas). Beyond the per-plane flow suites it pins:
the complete 196-family catalogue (name + type, drift-checked in both
directions — `test_cachemx_catalog.py`), every family's HELP text
(`test_cachemx_help_text.py`, snapshot in `tests/_cachemx_catalog_data.py`)
and label-key schema incl. strict exposition-format residue checking
(`test_cachemx_label_schema.py`, schema pinned from the C emitters in
`tests/_cachemx_catalog_schema.py`; 26 families are CONDITIONAL — HELP/TYPE
always exposed, sample rows only under subsystem traffic), MOVE/rename
accounting incl. the full WebDAV precondition error ladder
(`test_cachemx_move_rename.py`), the namespace-method edges
(MKCOL/HEAD/PROPFIND/DELETE/OPTIONS/Range windows —
`test_cachemx_namespace_methods.py`, re-proven per authenticated plane with
1:1 auth-row coupling in `test_cachemx_http_method_planes.py`), Range-window
byte-exactness incl. clamps, suffix/open-ended forms, 416s and the
malformed-Range regression pin (`test_cachemx_range_windows.py`),
byte-exactness across a 1 B – 64 KiB size ladder per flow
(`test_cachemx_accuracy_matrix.py`) extended to the 3 B – 1 MiB chunked
regime (`test_cachemx_size_ladder_ext.py`), repetition linearity (N ops move
every counter by exactly N× — `test_cachemx_repetition.py`), multi-op
lifecycle algebra and cross-dialect cache-hit accounting
(`test_cachemx_sequences.py`), auth-result edges and the hashed
user-session identity pins (`test_cachemx_auth_matrix.py`), and cross-plane
ledger isolation plus requests==responses conservation
(`test_cachemx_ownership.py`). A per-family grid layer (traffic burst over
every plane, then structural checks parametrized across the full catalogue —
shared parser in `tests/_cachemx_grid.py`) adds: HELP-before-TYPE-before-
sample ordering, duplicate-series rejection, finite/non-negative sample
values and counter monotonicity across two traffic-separated scrapes
(`test_cachemx_family_grid.py`); per-key label-value grammars (`port`, `le`,
`status_class` incl. the `other` overflow class, `hash`, enum-shaped keys)
plus full histogram invariants — cumulative buckets, `+Inf` == `_count`,
finite `_sum` (`test_cachemx_family_semantics.py`). Three credential-route
grids complete the matrix: GET/PUT byte-exactness across dav/davs+bearer/
davsg+cert/s3/s3sig at three sizes and all four stream security planes at
two (`test_cachemx_plane_size_grid.py`); per-plane wire-ledger ok/error
splits for mv/rm/rmdir/mkdir/absent-read — pinning the deliberate stock-
parity idempotence of mkdir-over-existing (EEXIST tolerated, do_Mkdir) and
rmdir-of-absent (ENOENT tolerated, do_Rmdir), which book **ok** rows, not
errors (`test_cachemx_stream_wire_errors.py`); and N-op linearity per
credential route (`test_cachemx_linearity_grid.py`).

**Single-owner rule.** Every unified `brix_io_*` row is booked by exactly one layer
(see [metrics-bug-patterns.md](./metrics-bug-patterns.md) Pattern 6 for the owner
table and the double-count bugs this rule closed):

- WebDAV/S3 READ + WRITE ops and latency: the protocol response path, once per
  request, with full-request latency. Bytes come from the per-protocol rx/tx wire
  ledgers at scrape time.
- Stream (root://) READ + WRITE ops: the per-server wire-ledger fold. These carry
  **no latency observations** — `brix_io_latency_seconds{proto="stream",op="read"}`
  staying at zero under pure streaming reads is correct, not a bug.
- GridFTP (gsiftp://) READ + WRITE ops, latency and `brix_io_bytes_*`:
  `brix_ftp_ev_metric_xfer()` at transfer completion
  (`src/protocols/gridftp/ev/ftp_ev_metrics.c`). The gateway has no wire ledger to
  fold, so unlike stream it books its own bytes — derived from the data-channel
  offsets, not counted a second time in the pump. Transfers refused before a data
  channel opened (read-only export, denied path, absent file) are counted without
  a latency sample, so a refusal cannot falsify the lowest bucket.
- cvmfs (`cvmfs://`) data plane: the dedicated `brix_cvmfs_bytes_served_total`
  family (bytes by cache disposition) plus `brix_cache_requests_total` under
  `proto="cvmfs"`, split by `cache_status`. The plane deliberately books
  **no** unified `op="read"` row — a transparent public cache serves the same
  object from cache, origin fill, or bundle, and the cvmfs families are the
  authoritative split. Its unified rows come from the VFS observer.
- Response offloading (`brix_io_offload_total{proto="stream"}`): the read-family
  offload dispatch (`brix_{read,readv,pgread}_try_offload`), once per reply routed
  over a bound secondary data channel (§1.1 pathid response offloading). The
  series is absent until the first offload, so it never perturbs a scrape from a
  deployment where no client requests offloading.
- Namespace ops (stat/delete/mkdir/rename/dirlist, all protocols): the VFS
  observer, with per-call latency. This is why the gridftp seam books only the
  data plane — SIZE/MDTM/MLST/MKD/DELE/LIST over gsiftp are already metered
  inside `brix_vfs_*` under `proto="gridftp"`.
- Per-backend `brix_storage_io_bytes_*`: the VFS/staged-commit layer (books the
  committed object size exactly once per publish).

**Eviction accounting is a three-family split:**

1. Policy-engine purges: `brix_cache_evictions_total` / `brix_cache_evicted_bytes_total`
   per cache instance (exact file count and byte sum of purged objects).
2. Watermark reaper trims: the same instance families, driven by occupancy
   watermarks.
3. Protocol-driven evictions (rm/DELETE/rename-over-cached/write-open-over-cached):
   the per-protocol evicted-bytes family, booking the exact cached size of the
   displaced copy. These do NOT move the per-instance eviction families.

**`brix_cache_eviction_threshold_ratio` is policy-engine-only**: it has no sample
under watermark-based trimming, even when an eviction threshold is configured on
the instance. Absence of this gauge is the expected exposition for
watermark-managed caches.

**Auth accounting is singular**: each request books exactly one auth-result row
(e.g. all eight `brix_s3_auth_total` result labels sum to +1 per request; a WebDAV
`optional`-auth plane books `anonymous_fallback` for credential-less requests).

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
# HELP brix_io_bytes_written Total bytes written to storage, by protocol.
# TYPE brix_io_bytes_written counter
brix_io_bytes_written{proto="stream"} 12582912
# HELP brix_io_bytes_read Total bytes read from storage, by protocol.
# TYPE brix_io_bytes_read counter
brix_io_bytes_read{proto="stream"} 4194304
# HELP brix_cache_occupancy_ratio Cache store occupancy ratio for brix_cache_export (the cache store's own capacity, or the legacy root's filesystem).
# TYPE brix_cache_occupancy_ratio gauge
brix_cache_occupancy_ratio{port="1094",auth="anon"} 0.734218
# HELP brix_cache_eviction_threshold_ratio Configured cache eviction high-water occupancy ratio.
# TYPE brix_cache_eviction_threshold_ratio gauge
brix_cache_eviction_threshold_ratio{port="1094",auth="anon"} 0.900000
# HELP brix_cache_bytes Cache store bytes by state (the cache store's own capacity, or the legacy root's filesystem).
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

## Complete Family Index

Every metric family this module can export — all 240 of them — with its
Prometheus type and the exact `# HELP` text it emits. The sections above explain
the families operators tune against (label vocabularies, ownership rules, worked
examples); this index exists so that no exported family is undocumented, and so
that a scrape can be read end to end without reaching for the source.

The rows are the calibrated catalogue the conformance suite already pins against
a live scrape — `tests/test_cachemx_catalog.py` for the type,
`tests/test_cachemx_help_text.py` for the HELP text. A family added, renamed or
retyped without a row here fails
`tests/test_release20_surface_pins.py::test_the_family_reference_covers_every_exported_family`,
so this index cannot silently fall behind the exporter.

Reading the table: a family whose subsystem is not configured still emits its
HELP/TYPE header and reads `0` rather than vanishing, so alerting rules need no
`absent()` guard; every label vocabulary is a closed, low-cardinality set
(INVARIANT #8) — no path, export name, user, token or size is ever a label
value; and every latency family is in **seconds** (the microsecond aliases were
removed in 2.0).

### Access control (NSS/DNS helpers) — `brix_acc_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_acc_dns_pending_fallback_total` | counter | Times an XrdAcc host-rule decision fell back to the numeric peer because the reverse-DNS answer was still pending. |
| `brix_acc_nss_breaker_open_total` | counter | Times the XrdAcc NSS group-lookup circuit breaker tripped open. |

### Authentication — `brix_auth_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_auth_l1_hits_total` | counter | Auth-gate verdicts served from the per-worker L1 cache (no SHM lock). |
| `brix_auth_l1_misses_total` | counter | Auth-gate L1 misses that fell through to the SHM L2 or full evaluation. |
| `brix_auth_total` | counter | Authentication attempts by protocol, method, and status. |

### Cache tier — `brix_cache_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_cache_bytes` | gauge | Cache store bytes by state (the cache store's own capacity, or the legacy root's filesystem). |
| `brix_cache_bytes_evicted_total` | counter | Cache bytes evicted, by protocol. |
| `brix_cache_dirty_reaped_total` | counter | Cache files reaped by the stale-dirty reaper, by reason (abandoned/incomplete = write-back discarded; completed = finished staging reclaimed). |
| `brix_cache_evicted_bytes_total` | counter | Bytes reclaimed by cache eviction. |
| `brix_cache_eviction_errors_total` | counter | Cache eviction maintenance errors. |
| `brix_cache_eviction_threshold_ratio` | gauge | Configured cache eviction high-water occupancy ratio. |
| `brix_cache_evictions_total` | counter | Files evicted from brix_cache_export. |
| `brix_cache_occupancy_ratio` | gauge | Cache store occupancy ratio for brix_cache_export (the cache store's own capacity, or the legacy root's filesystem). |
| `brix_cache_prefetch_blocks_total` | counter | Cache blocks filled by background prefetch. |
| `brix_cache_prefetch_failures_total` | counter | Background cache prefetch jobs that failed. |
| `brix_cache_prefetch_jobs_total` | counter | Background cache prefetch jobs posted. |
| `brix_cache_requests_total` | counter | Cache lookups by protocol and disposition (HIT/MISS — the $brix_cache_status vocabulary). |
| `brix_cache_usage_ratio` | gauge | Cache filesystem occupancy (0-1). |
| `brix_cache_watermark_evicted_bytes_total` | counter | Bytes reaped by the watermark reaper. |
| `brix_cache_watermark_evicted_files_total` | counter | Files reaped by the watermark reaper. |
| `brix_cache_watermark_purges_total` | counter | Watermark reaper purge runs that reclaimed space. |

### CernVM-FS plane — `brix_cvmfs_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_cvmfs_bytes_served_total` | counter | bytes served to clients by cache disposition |
| `brix_cvmfs_fill_failures_total` | counter | fills that failed definitively |
| `brix_cvmfs_fills_total` | counter | origin fills published to the cache |
| `brix_cvmfs_negative_hits_total` | counter | 404s absorbed by the per-worker negative cache |
| `brix_cvmfs_origin_bytes_total` | counter | bytes pulled from the Stratum-1 origins (WAN in) |
| `brix_cvmfs_origin_failovers_total` | counter | read attempts that failed over to the next-ranked origin |
| `brix_cvmfs_repo_bytes_served_total` | counter | bytes served per repository by cache disposition |
| `brix_cvmfs_repo_cache_hits_total` | counter | requests served from the local store per repository |
| `brix_cvmfs_repo_cache_misses_total` | counter | requests that needed an origin fill per repository |
| `brix_cvmfs_repo_files_accessed_total` | counter | CAS objects served (hit or fill) per repository |
| `brix_cvmfs_repo_fill_failures_total` | counter | fills that failed definitively per repository |
| `brix_cvmfs_repo_fills_total` | counter | origin fills published per repository |
| `brix_cvmfs_repo_negative_hits_total` | counter | 404s absorbed by the negative cache per repository |
| `brix_cvmfs_repo_origin_bytes_total` | counter | bytes pulled from the Stratum-1 origins per repository (WAN in) |
| `brix_cvmfs_repo_requests_total` | counter | requests per repository by traffic class |
| `brix_cvmfs_repo_verify_failures_total` | counter | CAS verify mismatches per repository |
| `brix_cvmfs_requests_total` | counter | CVMFS requests by traffic class |
| `brix_cvmfs_upstream_failovers_total` | counter | fills served by a non-primary endpoint per upstream Stratum-1 |
| `brix_cvmfs_upstream_fill_duration_seconds` | histogram | origin fill duration per upstream |
| `brix_cvmfs_upstream_fill_failures_total` | counter | origin fill attempts that failed per upstream Stratum-1 |
| `brix_cvmfs_upstream_fills_total` | counter | origin fills that published per upstream Stratum-1 |
| `brix_cvmfs_upstream_origin_bytes_total` | counter | bytes pulled per upstream Stratum-1 (WAN in) |
| `brix_cvmfs_upstream_requests_total` | counter | origin fill attempts per upstream Stratum-1 |
| `brix_cvmfs_verify_failures_total` | counter | CAS verify mismatches (fill quarantined, never admitted) |

### Cluster registry — `brix_cluster_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_cluster_hc_blacklist_total` | counter | Servers blacklisted by health checking. |
| `brix_cluster_hc_fail_total` | counter | Health-check probes that failed or timed out. |
| `brix_cluster_hc_pass_total` | counter | Health-check probes that passed. |
| `brix_cluster_hc_probes_total` | counter | Active health-check probes started. |
| `brix_cluster_servers_registered` | gauge | Number of data servers currently in the cluster registry. |

### CMS / AAA federation — `brix_cms_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_cms_cap_rejections_total` | counter | CMS server connections refused by the global or per-IP admission cap. |
| `brix_cms_connect_failures_total` | counter | Upward CMS dials that never became a logged-in link (refused/unreachable/deadline). |
| `brix_cms_frame_yields_total` | counter | CMS read loops that yielded the worker after the per-wakeup frame cap. |
| `brix_cms_idle_closes_total` | counter | CMS server connections reaped by the post-login idle watchdog. |
| `brix_cms_locate_coalesced_total` | counter | Locates parked on a kYR_state wave already in flight for the same path. |
| `brix_cms_login_timeouts_total` | counter | CMS server connections closed for not completing LOGIN before the deadline. |
| `brix_cms_logins_total` | counter | CMS LOGIN frames this node sent to its upstream manager (federation joins). |
| `brix_cms_read_timeouts_total` | counter | CMS client reconnects after the manager went silent past the read timeout. |
| `brix_cms_registered_links` | gauge | Upward CMS links currently logged in (0 = this node is OUT of the cluster). |

### Configuration — `brix_config_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_config_generation` | gauge | Config loads since master start (steps on each reload). |

### Connections — `brix_connections_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_connections_active` | gauge | Currently open XRootD connections. |
| `brix_connections_total` | counter | Total TCP connections accepted since process start. |

### Credential selection and delegation — `brix_cred_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_cred_deleg_fail_total` | counter | Delegation-gate failures by protocol and reason (closed vocabulary). |
| `brix_cred_deleg_total` | counter | Delegation-gate terminal outcomes, by protocol, configured delegation mode, and outcome. |
| `brix_cred_select_deny_total` | counter | Request rejected at the credential gate (EACCES; fallback_deny=1), by protocol. |
| `brix_cred_select_fallback_total` | counter | Service-credential fallback allowed (no/expired user cred or driver incapable; fallback_deny=0), by protocol. |
| `brix_cred_select_user_total` | counter | Per-user backend credential selected and used, by protocol. |

### CSI page tagstore — `brix_csi_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_csi_scrub_mismatch_total` | counter | At-rest data blocks whose on-disk bytes failed CRC32c re-verification during the background CSI scrub (brix_csi_scrub_interval). A rising value is silent storage rot; 0 unless a scrub is armed. |

### Export registry — `brix_registry_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_registry_full_total` | counter | Server registrations dropped because the registry was at capacity. |

### Forwarding proxy — `brix_proxy_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_proxy_abandoned_handles_total` | counter | Upstream file handles freed on client disconnect without an explicit close. |
| `brix_proxy_closes_total` | counter | kXR_close requests forwarded to upstream. |
| `brix_proxy_open_errors_total` | counter | kXR_open requests forwarded to upstream that failed. |
| `brix_proxy_opens_total` | counter | kXR_open requests forwarded to upstream that succeeded. |
| `brix_proxy_path_op_errors_total` | counter | Path-based mutation operations that received an error from upstream. |
| `brix_proxy_path_ops_total` | counter | Path-based mutation operations (rm/mkdir/rmdir/mv/chmod/truncate) that succeeded. |
| `brix_proxy_read_bytes_total` | counter | Bytes relayed from upstream to client via proxy. |
| `brix_proxy_reads_total` | counter | kXR_read/pgread/readv requests forwarded to upstream. |
| `brix_proxy_reconnects_total` | counter | Upstream reconnect attempts after idle connection drop. |
| `brix_proxy_upstream_auth_errors_total` | counter | Upstream login or token authentication failures. |
| `brix_proxy_upstream_connect_errors_total` | counter | Upstream TCP connect or TLS handshake failures. |
| `brix_proxy_upstream_connects_total` | counter | Successful upstream TCP (or TLS) connects. |
| `brix_proxy_wait_responses_total` | counter | kXR_wait responses from upstream that were absorbed and retried transparently. |
| `brix_proxy_write_bytes_total` | counter | Bytes forwarded from client to upstream via proxy. |
| `brix_proxy_writes_total` | counter | kXR_write/pgwrite/writev requests forwarded to upstream. |

### FRM / tape staging — `brix_frm_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_frm_asynresp_total` | counter | Async stage completions delivered via kXR_attn(asynresp). |
| `brix_frm_cmsd_have_total` | counter | Now-resident paths registered with the manager (cmsd Have). |
| `brix_frm_dedup_hits_total` | counter | Stage opens collapsed onto an already in-flight recall. |
| `brix_frm_evict_total` | counter | kXR_evict / Tape-REST release marks applied. |
| `brix_frm_in_flight` | gauge | Stage requests currently QUEUED or STAGING. |
| `brix_frm_migrate_total` | counter | Category-2 migrate-out attempts (scaffolding). |
| `brix_frm_purge_total` | counter | Online-buffer copies released by the tape purge engine (phase-115 W3.2). |
| `brix_frm_reject_inflight_total` | counter | Stage requests refused because the queue was at max_inflight. |
| `brix_frm_requests_total` | counter | Tape stage requests admitted to the FRM durable queue. |
| `brix_frm_stage_fail_total` | counter | Recalls that failed, by coarse reason. |
| `brix_frm_stage_latency_seconds` | histogram | Tape recall latency in seconds. |
| `brix_frm_stage_success_total` | counter | Recalls that completed and brought the file online. |
| `brix_frm_waitresp_total` | counter | Async stalled opens parked with kXR_waitresp. |

### Legacy byte ledgers — `brix_bytes_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_bytes_rx_ipv4_total` | counter | Bytes received from IPv4 clients (stream layer). |
| `brix_bytes_rx_ipv6_total` | counter | Bytes received from IPv6 clients (stream layer). |
| `brix_bytes_tx_ipv4_total` | counter | Bytes sent to IPv4 clients (stream layer). |
| `brix_bytes_tx_ipv6_total` | counter | Bytes sent to IPv6 clients (stream layer). |

### Native stream plane — `brix_stream_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_stream_connections_rejected_total` | counter | Connections refused at accept because the listener was at brix_max_connections. |
| `brix_stream_handshake_timeouts_total` | counter | Connections dropped because the pre-auth handshake stalled past brix_handshake_timeout. |
| `brix_stream_io_uring_active` | gauge | 1 if a worker fronting this listener has used the io_uring backend. |
| `brix_stream_io_uring_fallback_total` | counter | Mapped disk ops that fell back to the thread pool because io_uring was full or runtime-disabled. |
| `brix_stream_io_uring_ops_total` | counter | Mapped disk ops (read/write/single-group readv/writev) submitted via the io_uring backend. |
| `brix_stream_oversized_payloads_total` | counter | Native XRootD requests rejected because their payload was too large. |
| `brix_stream_read_pdu_timeouts_total` | counter | Connections dropped because an incomplete request PDU stalled past brix_read_timeout. |
| `brix_stream_request_frames_total` | counter | Native XRootD request headers parsed by the stream module. |
| `brix_stream_request_payload_bytes_total` | counter | Declared native XRootD request payload bytes parsed by the stream module. |
| `brix_stream_response_frames_total` | counter | Native XRootD response send attempts. |
| `brix_stream_response_write_errors_total` | counter | Native XRootD response send or send_chain failures. |
| `brix_stream_response_write_stalls_total` | counter | Native XRootD response sends that had to wait for socket writability. |
| `brix_stream_send_drain_timeouts_total` | counter | Connections dropped because the response drain stalled past brix_send_timeout. |
| `brix_stream_tpc_egress_refused_total` | counter | TPC pulls refused because the requested source host was not on brix_tpc_source_allow (server-side request-forgery control). 0 unless brix_tpc_source_guard is on. |

### Native wire counters — `brix_wire_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_wire_bytes_rx_total` | counter | Raw socket bytes received from native XRootD clients. |
| `brix_wire_bytes_tx_total` | counter | Raw socket bytes sent to native XRootD clients. |

### OCI registry mirror — `brix_oci_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_oci_delegate_total` | counter | delegated-pull authorization proofs by disposition (D16) |
| `brix_oci_fill_bytes_total` | counter | bytes pulled from the upstream registry (WAN in) |
| `brix_oci_requests_total` | counter | OCI distribution requests by surface, traffic class and outcome |
| `brix_oci_token_fetch_total` | counter | upstream Bearer-token acquisitions by disposition |
| `brix_oci_upstream_errors_total` | counter | upstream registry error responses by status bucket |
| `brix_oci_verify_fail_total` | counter | fills whose bytes did not hash to the digest the request named (quarantined, never admitted) |

### OCSP stapling — `brix_ocsp_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_ocsp_timeouts_total` | counter | OCSP fetches that hit the socket deadline (connect/handshake/read). |

### Packet marking (SciTag) — `brix_pmark_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_pmark_firefly_dropped_total` | counter | Firefly UDP datagrams dropped on sendto error (fail-open). |
| `brix_pmark_firefly_sent_total` | counter | Firefly UDP datagrams sent successfully. |
| `brix_pmark_flowlabel_failed_total` | counter | IPv6 flow-label setsockopt refusals (kernel/permission; fail-open). |
| `brix_pmark_flowlabel_set_total` | counter | IPv6 flow labels stamped on connections. |
| `brix_pmark_flows_ended_total` | counter | SciTags flows that emitted an end firefly. |
| `brix_pmark_flows_started_total` | counter | SciTags flows that mapped to (experiment,activity) and were marked. |
| `brix_pmark_map_unresolved_total` | counter | Opens with packet marking enabled but no (experiment,activity) mapping. |

### Path resolution — `brix_path_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_path_depth_violations_total` | counter | Requests rejected because path depth exceeded BRIX_MAX_WALK_DEPTH. Prevents CPU exhaustion from malicious symlink traversal chains or deep nesting. |

### Per-user accounting — `brix_user_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_user_evictions_total` | counter | User identity slots evicted from the tracking table. |
| `brix_user_sessions_total` | gauge | Sessions per tracked user identity. Sum across all entries equals total authenticated sessions. |

### Per-VO accounting — `brix_vo_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_vo_bytes_rx_total` | counter | Bytes received from clients grouped by virtual organisation. VO names are truncated to 15 characters. |
| `brix_vo_bytes_tx_total` | counter | Bytes sent to clients grouped by virtual organisation. VO names are truncated to 15 characters; the metric family has one entry per VO. |
| `brix_vo_overflow_total` | counter | VO entries that exceeded the tracking limit and were evicted. |
| `brix_vo_requests_total` | counter | Requests grouped by virtual organisation. VO names are truncated. |

### Rate limiting — `brix_rate_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_rate_limit_eviction_total` | counter | LRU node evictions from rate-limit shared-memory zones. |
| `brix_rate_limit_throttled_total` | counter | Requests throttled by the advanced rate limiter. |
| `brix_rate_limit_zone_full_errors_total` | counter | Allocation failures in rate-limit shared-memory zones. |

### Read budget — `brix_budget_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_budget_waits_total` | counter | Reads deferred with kXR_wait because they would exceed brix_memory_budget. |

### Requests — `brix_requests_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_requests_total` | counter | XRootD requests completed, by operation and status. |

### RPM mirror — `brix_rpm_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_rpm_prefetch_fail_total` | counter | warm repodata fills the origin did not serve (the client pays the miss it would have paid anyway) |
| `brix_rpm_prefetch_total` | counter | repodata objects (primary, filelists) warmed into the cache after a new repomd.xml named them, before any client asked |
| `brix_rpm_requests_total` | counter | RPM repository mirror requests by object class and outcome |
| `brix_rpm_verify_fail_total` | counter | repodata fills whose bytes did not hash to the checksum their own name carries (quarantined, never admitted) |

### Runtime DNS — `brix_dns_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_dns_bridge_requests_total` | counter | Blocking resolutions handed to the event loop by a thread-pool caller (this worker). |
| `brix_dns_bridge_timeouts_total` | counter | Bridge crossings that timed out waiting for the event loop and fell back to libc. |
| `brix_dns_cache_entries` | gauge | Live entries in the per-worker forward-DNS cache. |
| `brix_dns_cache_hits_total` | counter | Positive forward-DNS cache hits. |
| `brix_dns_cache_misses_total` | counter | forward-DNS cache misses (a query followed). |
| `brix_dns_cache_negative_hits_total` | counter | Negative forward-DNS cache hits (no query sent). |
| `brix_dns_failures_total` | counter | Failed runtime resolution attempts of registered targets (this worker). |
| `brix_dns_lookups_total` | counter | Completed runtime DNS queries by outcome (this worker; cache hits excluded). |
| `brix_dns_resolutions_total` | counter | Successful runtime resolutions of registered targets (this worker). |
| `brix_dns_reverse_cache_entries` | gauge | Live entries in the per-worker reverse-DNS cache. |
| `brix_dns_reverse_cache_hits_total` | counter | Positive reverse-DNS cache hits. |
| `brix_dns_reverse_cache_misses_total` | counter | reverse-DNS cache misses (a query followed). |
| `brix_dns_reverse_cache_negative_hits_total` | counter | Negative reverse-DNS cache hits (no query sent). |
| `brix_dns_targets` | gauge | Runtime-DNS targets registered from the configuration, by state (this worker's view). |

### S3 plane — `brix_s3_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_s3_auth_total` | counter | S3 SigV4 or anonymous authentication outcomes. |
| `brix_s3_bytes_rx_ipv4_total` | counter | Bytes received from IPv4 clients via S3-compatible PUT. |
| `brix_s3_bytes_rx_ipv6_total` | counter | Bytes received from IPv6 clients via S3-compatible PUT. |
| `brix_s3_bytes_tx_ipv4_total` | counter | Bytes sent to IPv4 clients via S3-compatible GET. |
| `brix_s3_bytes_tx_ipv6_total` | counter | Bytes sent to IPv6 clients via S3-compatible GET. |
| `brix_s3_events_total` | counter | Low-cardinality S3-compatible endpoint diagnostic events. |
| `brix_s3_list_common_prefixes_total` | counter | S3 ListObjectsV2 CommonPrefixes entries emitted. |
| `brix_s3_list_contents_total` | counter | S3 ListObjectsV2 Contents entries emitted. |
| `brix_s3_list_truncated_total` | counter | S3 ListObjectsV2 responses that returned a continuation token. |
| `brix_s3_put_bodies_total` | counter | S3-compatible PUT body storage modes observed after successful writes. |
| `brix_s3_range_requests_total` | counter | S3-compatible GET range handling outcomes. |
| `brix_s3_requests_total` | counter | S3-compatible endpoint requests received, by operation. |
| `brix_s3_responses_total` | counter | S3-compatible endpoint responses by operation and HTTP status class. |

### Sessions — `brix_session_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_session_evict_total` | counter | Idle sessions reaped (LRU) to admit a new login under table pressure. |
| `brix_session_registry_full_total` | counter | Logins rejected because the session table was full and nothing was reapable. |
| `brix_session_src_cap_evict_total` | counter | Own-LRU sessions recycled because one identity hit the per-source soft cap. |

### SSI plane — `brix_ssi_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_ssi_alerts_pushed_total` | counter | XrdSsi out-of-band alerts pushed to clients. |
| `brix_ssi_attn_push_failures_total` | counter | XrdSsi kXR_attn pushes that failed to queue. |
| `brix_ssi_errors_total` | counter | XrdSsi error responses. |
| `brix_ssi_requests_total` | counter | XrdSsi requests dispatched. |

### Storage backends and exports — `brix_storage_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_storage_backend_info` | gauge | Composed storage stack per export (source backend, origin, auth, stage); value always 1. |
| `brix_storage_bytes_available` | gauge | Backend export filesystem bytes available. |
| `brix_storage_bytes_total` | gauge | Backend export filesystem size in bytes (local backends). |
| `brix_storage_bytes_used` | gauge | Backend export filesystem bytes used. |
| `brix_storage_io_bytes_read` | counter | Bytes read by each storage backend driver. |
| `brix_storage_io_bytes_written` | counter | Bytes written by each storage backend driver. |
| `brix_storage_occupancy_ratio` | gauge | Backend export filesystem occupancy (0-1). |

### Stratum cvmfs — `brix_scvmfs_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_scvmfs_requests_total` | counter | requests admitted by the scvmfs security preamble (EXPERIMENTAL) |

### Third-party copy — `brix_tpc_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_tpc_bytes_total` | counter | Successful third-party-copy bytes. |
| `brix_tpc_gsi_delegated_total` | counter | Outbound TPC GSI proxy-delegation credential-selection outcomes. |
| `brix_tpc_transfers_total` | counter | Third-party-copy transfer outcomes. |

### Traffic mirroring — `brix_mirror_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_mirror_divergence_total` | counter | Shadow status differed from the primary. |
| `brix_mirror_dropped_total` | counter | Requests skipped by the mirror sampling/filter. |
| `brix_mirror_errors_total` | counter | Mirror requests that failed to reach the shadow. |
| `brix_mirror_requests_total` | counter | Mirror requests the shadow answered. |

### Transfer engine — `brix_xfer_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_xfer_heap_bytes` | gauge | Bytes currently held in per-connection transfer scratch buffers. |
| `brix_xfer_heap_high_water_bytes` | gauge | Peak transfer-heap bytes observed since start. |

### Unified protocol-labeled I/O — `brix_io_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_io_bytes_read` | counter | Total bytes read from storage, by protocol. |
| `brix_io_bytes_written` | counter | Total bytes written to storage, by protocol. |
| `brix_io_latency_seconds` | histogram | I/O operation latency in seconds. |
| `brix_io_offload_total` | counter | Read-family responses (read/readv/pgread) routed over a bound secondary data channel (pathid response offloading). |
| `brix_io_ops_total` | counter | I/O operations completed, by protocol, operation, and status. |
| `brix_io_slowop_threshold_usec` | gauge | Armed slow-op latency threshold in microseconds (0 = classifier disabled). |
| `brix_io_slowop_total` | counter | Completed I/O ops whose latency met or exceeded brix_io_slowop_threshold_usec. |

### Unique identities — `brix_unique_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_unique_users_current` | gauge | Currently tracked unique user identities (bounded LRU, max 1024). Users are identified by DN or token sub via FNV-1a hash. |
| `brix_unique_users_total` | counter | Lifetime unique user identities seen since process start. Never decremented. |

### VFS policy and lifecycle — `brix_vfs_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_vfs_authz_backstop_total` | counter | VFS authorization-backstop evaluations, by protocol and result (agree|edge_missing|no_rules|unbound). |
| `brix_vfs_bulk_delete_batches_total` | counter | unlink_many batches flushed, by leaf driver. |
| `brix_vfs_bulk_delete_keys_total` | counter | Keys removed via the batch delete path, by leaf driver. |
| `brix_vfs_domain_mutation_total` | counter | Service-storage mutations passed by the typed domain assert, by storage domain and operation. |
| `brix_vfs_evict_bytes_total` | counter | Bytes reclaimed by the VFS evict verb, by dispatching driver. |
| `brix_vfs_lock_refused_total` | counter | Mutations arriving under a live foreign lock (refused in strict enforcement, warned through in advisory), by protocol. |
| `brix_vfs_mutation_denied_total` | counter | Export mutations refused by the VFS read-only policy, by protocol and operation. |
| `brix_vfs_precond_advisory_total` | counter | Precondition refusals decided non-atomically (check-then-act), by driver. |
| `brix_vfs_precond_failed_total` | counter | Publish preconditions refused (412), by kind. |
| `brix_vfs_recall_total` | counter | Nearline recall (prestage) outcomes, by result class. |
| `brix_vfs_spill_active` | gauge | Writer spill scratches currently open. |
| `brix_vfs_spill_bytes_total` | counter | Bytes absorbed into the writer's out-of-order spill scratch, by protocol. |
| `brix_vfs_spill_refused_total` | counter | Reordered uploads the spill could not serve (no scratch, capacity, overlap, or coverage hole), by protocol. |

### WebDAV plane — `brix_webdav_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_webdav_auth_total` | counter | WebDAV authentication outcomes. |
| `brix_webdav_bytes_rx_ipv4_total` | counter | Bytes received from IPv4 clients via WebDAV PUT. |
| `brix_webdav_bytes_rx_ipv6_total` | counter | Bytes received from IPv6 clients via WebDAV PUT. |
| `brix_webdav_bytes_tx_ipv4_total` | counter | Bytes sent to IPv4 clients via WebDAV GET and PROPFIND. |
| `brix_webdav_bytes_tx_ipv6_total` | counter | Bytes sent to IPv6 clients via WebDAV GET and PROPFIND. |
| `brix_webdav_cors_total` | counter | WebDAV CORS request/header decisions. |
| `brix_webdav_propfind_depth_total` | counter | WebDAV PROPFIND requests by Depth header bucket. |
| `brix_webdav_propfind_entries_total` | counter | WebDAV PROPFIND response entries emitted. |
| `brix_webdav_put_bodies_total` | counter | WebDAV PUT body storage modes. |
| `brix_webdav_range_requests_total` | counter | WebDAV GET range handling outcomes. |
| `brix_webdav_requests_total` | counter | WebDAV requests received, by HTTP/WebDAV method. |
| `brix_webdav_responses_total` | counter | WebDAV responses by method and HTTP status class. |
| `brix_webdav_tpc_cred_total` | counter | WebDAV HTTP-TPC OAuth2/OIDC credential delegation events. |
| `brix_webdav_tpc_total` | counter | WebDAV HTTP-TPC COPY pull, push, and helper events. |

### Write-through / write-back staging — `brix_wt_*`

| Family | Type | Exported HELP |
|---|---|---|
| `brix_wt_dirty_handles` | gauge | Open write-through handles with unflushed dirty data. |
| `brix_wt_flush_bytes_total` | counter | Bytes mirrored to origin by successful write-through flushes. |
| `brix_wt_flush_pending` | gauge | Write-through flush tasks currently pending completion. |
| `brix_wt_flushes_total` | counter | Write-through flush completions by result. |
| `brix_wt_stage_throttled_total` | counter | Writes shed by staging backpressure, by action. |
| `brix_wt_stage_usage_ratio` | gauge | Write-back staging filesystem occupancy (0-1). |
---

## Next Steps

- See [extended-metrics.md](./extended-metrics.md) for protocol separation, IP version tracking, VO and user analytics
- See [promql-examples.md](./promql-examples.md) for ready-to-use PromQL queries
- See [metrics-analysis.md](./metrics-analysis.md) for interpretation guidance and alerting rules
