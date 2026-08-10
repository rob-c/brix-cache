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
  io_ops_total, io_bytes_read/written, io_latency_usec, auth_total, tpc_*
    ← the unified {proto=...} view, written by ALL FIVE planes
      (stream · webdav · s3 · cvmfs · gridftp) into the one process-wide zone

  Label discipline (INVARIANT #8): only low-cardinality labels —
  {proto, port, auth, op, status, method, status_class}. Never paths, DNs,
  buckets, keys, or UUIDs. VO is capped at 32 entries; user identity is
  hashed + LRU-512.
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
- `brix_webdav_bytes_rx_total` - bytes accepted into WebDAV writes
- `brix_webdav_bytes_tx_total` - bytes sent by WebDAV GET and PROPFIND
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
| `brix_io_latency_usec` | histogram | `proto`, `op` (+ `le` on `_bucket`) |
| `brix_auth_total` | counter | `proto`, `method`, `status` |
| `brix_tpc_transfers_total` | counter | `proto`, `direction`, `status` |
| `brix_tpc_bytes_total` | counter | `proto`, `direction` |
| `brix_tpc_gsi_delegated_total` | counter | `result` |

The same five `proto` values also label the cache-outcome and credential-gate
families, which iterate the identical protocol list:

| Family | Type | Labels |
|--------|------|--------|
| `brix_cache_hits_total` / `brix_cache_misses_total` | counter | `proto` |
| `brix_cache_bytes_evicted_total` | counter | `proto` |
| `brix_cred_select_user_total` / `_fallback_total` / `_deny_total` | counter | `proto` |
| `brix_cred_deleg_total` | counter | `proto`, `mode`, `outcome` |
| `brix_cred_deleg_fail_total` | counter | `proto`, `reason` |

Label values (closed sets — INVARIANT #8):

- `op` — `read`, `write`, `stat`, `delete`, `mkdir`, `rename`, `dirlist`,
  `tpc`, `xattr`, `copy`
- `status` (I/O and TPC) — `ok`, `not_found`, `forbidden`, `io_error`, `other`
- `method` — `none`, `gsi`, `token`, `sss`, `s3key`, `unix`, `krb5`, `host`,
  `pwd`; `status` on `brix_auth_total` is `ok` or `fail`
- `direction` — `pull`, `push`
- `result` (delegation) — `ok`, `expired`, `absent`
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
brix_io_latency_usec_count{proto="gridftp",op="write"}         418
brix_auth_total{proto="gridftp",method="gsi",status="ok"}      377
```

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
  **no latency observations** — `brix_io_latency_usec{proto="stream",op="read"}`
  staying at zero under pure streaming reads is correct, not a bug.
- GridFTP (gsiftp://) READ + WRITE ops, latency and `brix_io_bytes_*`:
  `brix_ftp_ev_metric_xfer()` at transfer completion
  (`src/protocols/gridftp/ev/ftp_ev_metrics.c`). The gateway has no wire ledger to
  fold, so unlike stream it books its own bytes — derived from the data-channel
  offsets, not counted a second time in the pump. Transfers refused before a data
  channel opened (read-only export, denied path, absent file) are counted without
  a latency sample, so a refusal cannot falsify the lowest bucket.
- cvmfs (`cvmfs://`) data plane: the dedicated `brix_cvmfs_bytes_served_total`
  family (bytes by cache disposition) plus `brix_cache_hits_total` /
  `brix_cache_misses_total` under `proto="cvmfs"`. The plane deliberately books
  **no** unified `op="read"` row — a transparent public cache serves the same
  object from cache, origin fill, or bundle, and the cvmfs families are the
  authoritative split. Its unified rows come from the VFS observer.
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
