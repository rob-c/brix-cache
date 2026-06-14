# Dashboard Feature Implementation Plan

This plan turns
[`dashboard-feature-ideas.md`](../08-metrics-monitoring/dashboard-feature-ideas.md)
into an implementation roadmap. It covers all proposed dashboard additions and
keeps the current design constraints intact: display-only by default, bounded
shared memory, low-cardinality Prometheus labels, and no duplicated path/auth
logic.

## Current Baseline

The dashboard today is a small HTTP module under `src/dashboard/`:

| Area | Current implementation |
|---|---|
| HTTP routing | `src/dashboard/module.c` routes `/xrootd/`, `/xrootd/login`, and `/xrootd/transfers`. |
| Auth | `src/dashboard/auth.c` supports one plaintext `xrootd_dashboard_password` and a signed cookie. |
| Page | `src/dashboard/page.c` embeds a single HTML/JS page that polls every 2 seconds. |
| JSON | `src/dashboard/api.c` emits active transfer rows and aggregate totals. |
| Transfer table | `src/dashboard/dashboard.h` and `transfer_table.c` define a fixed 512-slot shared-memory table. |
| Native tracking | `src/read/open_resolved_file.c`, `src/read/read.c`, `src/write/write.c`, `src/read/close.c`, and `src/connection/disconnect.c` allocate, update, and free slots for native XRootD file handles. |
| Metrics source | `src/metrics/metrics.h` stores stream, WebDAV, and S3 counters in `ngx_xrootd_shm_zone`. |

The current transfer JSON can represent `root`, `webdav`, and `s3`, but only
native stream file handles are wired into the live slot lifecycle.

## Implementation Rules

- Use existing helpers for path resolution, auth, metrics, locks, HTTP body
  handling, and file response building.
- Do not add paths, identities, bucket names, object keys, transfer IDs, or URLs
  as Prometheus labels.
- A dashboard failure must not fail a data transfer. Full table, event overflow,
  and JSON truncation are observability degradation, not data-path errors.
- Shared-memory structures must stay bounded and have explicit capacities.
- Add tests in the success, error, and security-negative pattern for every
  feature slice.
- Keep `/xrootd/transfers` backward-compatible until a documented API version
  replaces it.

## Proposed File Map

| File | Purpose |
|---|---|
| `src/dashboard/dashboard.h` | Add slot fields, event/history structs, helper declarations. |
| `src/dashboard/transfer_table.c` | Extend alloc/update/free APIs and state/rate helpers. |
| `src/dashboard/http_tracking.c` | New request-pool cleanup helper for WebDAV/S3/TPC active slots. |
| `src/dashboard/events.c` | New bounded recent event ring. |
| `src/dashboard/history.c` | New bounded aggregate history sampler. |
| `src/dashboard/api.c` | Add versioned snapshot, detail, events, history, cluster, and cache JSON. |
| `src/dashboard/page.c` | Add filters, detail drawer, summary panels, sparklines, snapshot export, and accessibility improvements. |
| `src/dashboard/auth.c` | Add configurable cookie path, TTL directive support, users file auth, and audit events. |
| `src/dashboard/module.c` | Add directives and route new API endpoints. |
| `src/webdav/get.c`, `src/webdav/put.c`, `src/webdav/tpc.c`, `src/webdav/tpc_marker.c` | Wire WebDAV and HTTP-TPC transfer slot lifecycle. |
| `src/s3/object.c`, `src/s3/put.c`, `src/s3/multipart*.c` | Wire S3 transfer slot lifecycle. |
| `src/manager/registry.h`, `src/manager/registry.c` | Add safe snapshot/export helper for cluster view. |
| `src/metrics/stream_cache.c`, `src/metrics/metrics.h` | Reuse cache counters and add minimal WT counters if missing. |
| `tests/test_dashboard.py` | New dashboard API, auth, UI JSON, and security tests. |
| Existing protocol tests | Add protocol-specific dashboard assertions where the data path already exists. |

New dashboard source files must also be added to the nginx module source lists
in `config`. Stream-visible files such as `events.c` and `history.c` belong
with the stream module sources if stream workers write to them; HTTP-only files
belong with the `ngx_http_xrootd_dashboard_module` source list.

## Shared-Memory Layout

Keep the current `xrootd_dashboard` transfer table if possible, and add new
zones for non-transfer data. This minimizes changes to existing call sites.

| Zone | Type | Capacity |
|---|---|---|
| `xrootd_dashboard` | `xrootd_transfer_table_t` | 512 active transfers |
| `xrootd_dashboard_events` | `xrootd_dashboard_event_table_t` | 512 recent events |
| `xrootd_dashboard_history` | `xrootd_dashboard_history_t` | 30 minutes at 5-second buckets |
| Existing `xrootd_metrics` | `ngx_xrootd_metrics_t` | Existing counters |
| Existing manager registry | `xrootd_srv_table_t` | Configured registry slots |

If `xrootd_transfer_slot_t` grows enough to make nginx reload behavior awkward,
use a versioned zone name such as `xrootd_dashboard_v2` or add a `magic`,
`schema_version`, and `struct_size` header and reinitialize old layouts.

Suggested transfer slot expansion:

```c
#define XROOTD_DASHBOARD_OP_LEN       32
#define XROOTD_DASHBOARD_REASON_LEN   96
#define XROOTD_DASHBOARD_HOST_LEN    128
#define XROOTD_DASHBOARD_VO_LEN       32

#define XROOTD_XFER_STATE_ACTIVE   1
#define XROOTD_XFER_STATE_IDLE     2
#define XROOTD_XFER_STATE_STALLED  3
#define XROOTD_XFER_STATE_CLOSING  4
#define XROOTD_XFER_STATE_ERROR    5

typedef struct {
    ngx_atomic_t  in_use;
    uint32_t      serial;
    u_char        sessid[16];
    ngx_pid_t     worker_pid;

    char          client_ip[XROOTD_DASHBOARD_IP_LEN];
    char          identity[XROOTD_DASHBOARD_IDENTITY_LEN];
    char          vo[XROOTD_DASHBOARD_VO_LEN];
    char          path[XROOTD_DASHBOARD_PATH_LEN];
    char          op[XROOTD_DASHBOARD_OP_LEN];

    uint8_t       direction;
    uint8_t       proto;
    uint8_t       state;
    uint8_t       flags;

    ngx_atomic_t  bytes;
    ngx_atomic_t  bytes_last_sample;
    ngx_atomic_t  instant_bps;
    int64_t       expected_bytes;
    int64_t       start_ms;
    ngx_atomic_t  last_ms;
    ngx_atomic_t  state_since_ms;

    ngx_atomic_t  read_ops;
    ngx_atomic_t  write_ops;
    ngx_atomic_t  sync_ops;
    ngx_atomic_t  close_ops;

    char          last_error[XROOTD_DASHBOARD_REASON_LEN];

    char          tpc_remote_host[XROOTD_DASHBOARD_HOST_LEN];
    char          tpc_remote_path_hint[XROOTD_DASHBOARD_PATH_LEN];
    int           tpc_remote_status;
    int           tpc_curl_exit;
} xrootd_transfer_slot_t;
```

Add helper APIs instead of open-coding field writes:

```c
int xrootd_transfer_slot_alloc_ex(...);
void xrootd_transfer_slot_update_bytes(...);
void xrootd_transfer_slot_set_state(...);
void xrootd_transfer_slot_set_error(...);
void xrootd_transfer_slot_set_tpc_remote(...);
void xrootd_transfer_slot_count_op(...);
```

The old `xrootd_transfer_slot_alloc()` and `xrootd_transfer_slot_update()` can
remain as wrappers so native stream call sites can migrate gradually.

## API Shape

Keep `/xrootd/transfers` as the compatibility endpoint. Add versioned endpoints
under `/xrootd/api/v1/`:

| Endpoint | Purpose |
|---|---|
| `/xrootd/transfers` | Compatibility alias for active transfers. |
| `/xrootd/api/v1/snapshot` | Full dashboard payload: transfers, totals, protocol summaries, cache, cluster, events, and history metadata. |
| `/xrootd/api/v1/transfers` | Active transfer list. |
| `/xrootd/api/v1/transfers/<id>` | Detail for one transfer serial. |
| `/xrootd/api/v1/events` | Recent sanitized event ring. |
| `/xrootd/api/v1/history` | Bounded dashboard time-series buckets. |
| `/xrootd/api/v1/cluster` | Manager registry snapshot. |
| `/xrootd/api/v1/cache` | Cache/write-through health snapshot. |

All endpoints require the same dashboard auth as `/xrootd/transfers`.

Base snapshot schema:

```json
{
  "schema": "xrootd-dashboard.v1",
  "server_ms": 1760000000000,
  "limits": {
    "max_active_transfers": 512,
    "max_recent_events": 512,
    "history_bucket_seconds": 5
  },
  "active_transfers": [],
  "protocols": {},
  "cache": {},
  "cluster": {},
  "events": [],
  "history": {},
  "totals": {}
}
```

Transfer row schema:

```json
{
  "id": 42,
  "worker_pid": 1234,
  "client": "192.0.2.10",
  "identity": "/DC=org/DC=example/CN=User",
  "vo": "atlas",
  "path": "/store/data/file.root",
  "protocol": "root",
  "direction": "read",
  "op": "read",
  "state": "active",
  "bytes": 1048576,
  "expected_bytes": 10737418240,
  "instant_bps": 125000000,
  "avg_bps": 94000000,
  "idle_ms": 240,
  "start_ms": 1760000000000,
  "last_ms": 1760000000240,
  "last_error": ""
}
```

## Feature 1: Protocol-Complete Active Transfers

### Goal

Show active native XRootD, WebDAV, S3, and HTTP-TPC operations in one transfer
table.

### Common HTTP Tracking Helper

Add `src/dashboard/http_tracking.c` with a request-pool cleanup pattern:

```c
typedef struct {
    int                      slot;
    xrootd_transfer_table_t *table;
    ngx_http_request_t      *r;
} xrootd_dashboard_http_track_t;

int xrootd_dashboard_http_start(ngx_http_request_t *r,
    const char *path, uint8_t proto, uint8_t direction,
    const char *op, int64_t expected_bytes);

void xrootd_dashboard_http_add(ngx_http_request_t *r, ngx_atomic_int_t bytes);
void xrootd_dashboard_http_state(ngx_http_request_t *r, uint8_t state);
void xrootd_dashboard_http_error(ngx_http_request_t *r, const char *reason);
void xrootd_dashboard_http_finish(ngx_http_request_t *r);
```

Implementation details:

- Store the tracking context with `ngx_http_set_ctx` only if it does not
  collide with each HTTP protocol module context. If collision is likely, store
  the pointer in a pool cleanup record only and expose lookup helpers through a
  tiny request note list.
- Register a pool cleanup so aborted HTTP requests free the slot.
- Use `r->connection->addr_text` for client address.
- Use WebDAV `ngx_http_xrootd_webdav_req_ctx_t.dn` or `"anonymous"` for
  identity. For S3, use the access key ID only if configured and sanitized; do
  not expose secret material.
- Call `xrootd_transfer_slot_free()` from explicit finish paths and make the
  cleanup idempotent by setting `slot = -1`.

### WebDAV GET

Touchpoints:

- `src/webdav/get.c`
- shared sendfile helper `src/compat/http_file_response.c`

Implementation:

1. After path resolution, file open, stat, range parsing, and header
   preparation succeed, call `xrootd_dashboard_http_start()` with:
   - proto `XROOTD_XFER_PROTO_WEBDAV`
   - direction `XROOTD_XFER_DIR_READ`
   - op `"GET"`
   - expected bytes `send_len`
2. If `xrootd_http_send_file_range()` returns success and not `header_only`,
   call `xrootd_dashboard_http_add(r, send_len)`.
3. Let request-pool cleanup free the slot after send completion.
4. On error after slot allocation, call `xrootd_dashboard_http_error()` and
   `xrootd_dashboard_http_finish()`.

Limitation: file-backed sendfile completion is not currently reported chunk by
chunk. First milestone can count the full `send_len` once the response chain is
queued; later work can add an output-filter-based progress hook.

### WebDAV PUT

Touchpoints:

- `src/webdav/put.c`
- `src/compat/http_body.c`

Implementation:

1. After path resolution and successful write open, call start with:
   - proto `webdav`
   - direction `write`
   - op `"PUT"`
   - expected bytes from `xrootd_http_body_summary()`
2. In synchronous memory/spooled writes, call `xrootd_dashboard_http_add()` after
   each buffer write if the shared body helper is enhanced, or once after the
   full helper returns in the first milestone.
3. In thread-pool writes, store `slot` in `webdav_put_aio_t`, update bytes in
   `webdav_put_aio_done()`, then finish.
4. On write error, set state `error`, record a sanitized reason, then finish.

Better shared helper: add an optional progress callback to
`xrootd_http_body_write_to_fd()`:

```c
typedef void (*xrootd_http_body_progress_pt)(void *data, size_t nbytes);
```

Use it from both WebDAV PUT and S3 PUT.

### WebDAV HTTP-TPC

Touchpoints:

- `src/webdav/tpc.c`
- `src/webdav/tpc_curl.c`
- `src/webdav/tpc_marker.c`
- `src/webdav/tpc_headers.c`

Implementation:

1. Allocate a slot before starting pull or push work:
   - proto `webdav`
   - direction `tpc`
   - op `"TPC_PULL"` or `"TPC_PUSH"`
2. Store sanitized remote host and path hint:
   - parse `Source` for pull and `Destination` for push
   - keep scheme and host
   - keep path basename or first safe path prefix only
   - drop query strings and credentials
3. For marker-mode pull, update bytes from temp-file `stat()` in
   `tpc_marker_poll()`.
4. For marker-mode push, update final bytes from `push_file_size`; interim
   progress can remain 0 until curl progress callbacks are available.
5. For non-marker curl mode, update final bytes after curl success.
6. Record curl exit and remote HTTP status in `tpc_curl.c`; if libcurl does not
   expose all fields yet, extend the return type from `ngx_int_t` to a small
   result struct.
7. Finish on commit success, rollback, timeout, request cleanup, or child kill.

### S3 GET

Touchpoints:

- `src/s3/object.c`

Implementation mirrors WebDAV GET:

1. After open, stat, range parse, and headers succeed, start a slot with:
   - proto `s3`
   - direction `read`
   - op `"GetObject"`
   - expected bytes `send_len`
2. Add bytes after `xrootd_http_send_file_range()` succeeds.
3. Pool cleanup closes the active row.

### S3 PUT

Touchpoints:

- `src/s3/put.c`
- `src/s3/multipart*.c`
- `src/compat/http_body.c`

Implementation:

1. For regular `PutObject`, start after staged file open succeeds.
2. Use the body progress callback, or update once after body write returns.
3. In thread-pool write path, carry the slot in `s3_put_aio_t`.
4. Finish only after staged commit succeeds; mark error on abort.
5. For directory sentinel objects, either skip tracking or track as a zero-byte
   `write` with op `"PutObjectSentinel"`.
6. For multipart upload:
   - track `UploadPart` body writes
   - optionally track `CompleteMultipartUpload` as a short metadata operation
   - do not expose upload IDs unless redacted or truncated

### Tests

Add tests in `tests/test_dashboard.py` and protocol-specific files:

- WebDAV GET appears in `/xrootd/transfers` during a throttled download.
- WebDAV PUT appears and frees its slot after completion.
- S3 GET/PUT appear with `protocol == "s3"` and sanitized identity.
- HTTP-TPC pull/push expose `direction == "tpc"` and redacted remote endpoint.
- Aborted HTTP request frees the slot.
- Table full does not fail the transfer.

## Feature 2: Stalled and Slow Transfer Detection

### Goal

Expose state directly in JSON so operators do not infer stalled transfers from
browser-only byte deltas.

### Data Model

Add to `xrootd_transfer_slot_t`:

- `state`
- `state_since_ms`
- `bytes_last_sample`
- `instant_bps`
- `last_error`

### State Rules

| State | Set when |
|---|---|
| `active` | Slot allocated or bytes moved recently. |
| `idle` | No bytes moved for `idle_threshold_ms`, but below stalled threshold. |
| `stalled` | No bytes moved for `stalled_threshold_ms`. |
| `closing` | Close/commit/cleanup is running. |
| `error` | Operation failed or cleanup detected failure. |

Add dashboard directives:

```nginx
xrootd_dashboard_idle_threshold 5s;
xrootd_dashboard_stalled_threshold 60s;
```

Implementation can begin with constants in `api.c`, then promote to directives.

### Rate Calculation

Do rate calculation in the JSON exporter or in a periodic sampler:

- First milestone: compute `avg_bps = bytes * 1000 / (now_ms - start_ms)` and
  `idle_ms = now_ms - last_ms` in `api.c`.
- Better version: `history.c` or a lightweight sampler updates `instant_bps`
  from `bytes - bytes_last_sample`.

### Tests

- Active transfer includes `avg_bps`, `idle_ms`, and `state`.
- Artificial stale slot becomes `stalled` in JSON.
- Error path exposes a sanitized `last_error`, not raw token/header data.

## Feature 3: Filters, Search, and Stable Sorting

### Goal

Make the embedded dashboard usable when many transfers are active.

### UI Work

Modify `src/dashboard/page.c`:

- Add filter controls for protocol, direction, and state.
- Add text search across path, identity, client, and transfer ID.
- Add sort controls for rate, bytes, age, idle time, protocol, and client.
- Preserve selected sort and filters in `localStorage`.
- Keep row identity stable by transfer `id`.

Implementation detail: the backend does not need query parameters for the first
version. Fetch all rows, filter in JavaScript, and keep API simple.

### Tests

The current test suite is mostly protocol/API focused. Add lightweight HTML/API
assertions:

- Page contains filter control IDs.
- JavaScript can parse a fixture payload and sort deterministically. This can be
  tested by extracting pure JS helpers only if the page is split from the C
  string; otherwise test via Playwright only when a browser fixture exists.

## Feature 4: Transfer Detail View

### Goal

Let an operator inspect one transfer without cluttering the main table.

### Backend

Add `/xrootd/api/v1/transfers/<id>`.

Implementation:

1. Parse `<id>` as a decimal `uint32_t`.
2. Scan transfer slots for matching `serial`.
3. Return 404 if missing or already freed.
4. Include the row fields plus detail-only fields:
   - worker PID
   - session ID hash, not raw session ID
   - operation counters
   - lock state
   - TPC sanitized remote summary
   - range start/end if available
   - open flags if available

Avoid exposing full raw session IDs, bearer tokens, query strings, or credential
headers.

### Frontend

Add a drawer or side panel in `page.c`:

- Clicking a row opens detail.
- Poll detail while the row remains active.
- Preserve keyboard accessibility: Enter/Space opens, Escape closes.

### Tests

- Existing active transfer detail returns 200.
- Missing transfer detail returns 404.
- Detail redacts TPC query strings and credentials.

## Feature 5: Recent Error Ring

### Goal

Show the last bounded set of operationally relevant events on the dashboard.

### Shared Memory

New `src/dashboard/events.c` and declarations in `dashboard.h`:

```c
#define XROOTD_DASHBOARD_MAX_EVENTS 512
#define XROOTD_DASHBOARD_EVENT_MSG_LEN 160

typedef enum {
    XROOTD_DASH_EVENT_AUTH = 1,
    XROOTD_DASH_EVENT_NAMESPACE,
    XROOTD_DASH_EVENT_IO,
    XROOTD_DASH_EVENT_TPC,
    XROOTD_DASH_EVENT_DASHBOARD
} xrootd_dashboard_event_class_e;

typedef struct {
    ngx_atomic_t  sequence;
    int64_t       time_ms;
    uint8_t       class_id;
    uint8_t       proto;
    uint16_t      status;
    char          message[XROOTD_DASHBOARD_EVENT_MSG_LEN];
    char          path_hint[128];
} xrootd_dashboard_event_t;
```

Use a spinlock for append. A lock-free event ring is possible, but a short lock
on error paths is simpler and acceptable.

### Event Producers

Add event calls at these sites:

- `src/dashboard/auth.c`: login success/failure, cookie reject.
- WebDAV auth failures in `src/webdav/auth_cert.c` and `auth_token.c`.
- S3 SigV4 failure classes in `src/s3/auth.c`.
- namespace errors in WebDAV/S3/root mutation paths.
- I/O errors in read/write/PUT/GET/TPC paths.
- dashboard table full, stale slot cleanup, and JSON truncation in
  `src/dashboard/api.c` and `transfer_table.c`.

Every event message must be sanitized and bounded.

### API/UI

- Add `/xrootd/api/v1/events`.
- Add an "Recent Events" panel with class, time, protocol, status, message.
- Include events in `/snapshot`.

### Tests

- Failed dashboard login creates an auth event.
- Failed WebDAV path access creates namespace event without raw token data.
- Event ring wraps without crashing and preserves sequence order.

## Feature 6: Protocol Summary Cards

### Goal

Show one compact operational card each for native XRootD, WebDAV, S3, and TPC.

### Data Sources

Use existing `ngx_xrootd_metrics_t` and the active transfer table:

| Card field | Source |
|---|---|
| active transfers | scan `xrootd_transfer_table_t` by proto/direction |
| current ingress/egress | history sampler or transfer instant rates |
| lifetime bytes | `servers[].bytes_*`, `webdav.bytes_*`, `s3.bytes_*` |
| request success/error | `servers[].op_ok/op_err`, `webdav.responses_total`, `s3.responses_total` |
| auth failures | `servers[].op_err[XROOTD_OP_AUTH]`, `webdav.auth_total`, `s3.auth_total` |
| top current error | recent event ring by protocol |

### API

Add to snapshot:

```json
"protocols": {
  "root": {"active": 4, "ingress_bps": 0, "egress_bps": 125000000},
  "webdav": {"active": 2, "ingress_bps": 30000000, "egress_bps": 8000000},
  "s3": {"active": 1, "ingress_bps": 0, "egress_bps": 12000000},
  "tpc": {"active": 1, "ingress_bps": 0, "egress_bps": 0}
}
```

### Tests

- Snapshot includes all protocol keys when metrics zone exists.
- Empty server returns zeros, not missing fields.
- Error counters remain coarse and do not include paths or identities.

## Feature 7: Cache and Write-Through Health

### Goal

Expose cache occupancy and WT flush health in the dashboard.

### Cache Sources

Existing sources:

- `ngx_xrootd_srv_metrics_t.cache_enabled`
- `cache_eviction_threshold`
- `cache_root`
- `cache_evictions_total`
- `cache_evicted_bytes_total`
- `cache_eviction_errors_total`
- `src/metrics/stream_cache.c` already computes `statvfs()`

Implement a dashboard helper that reuses the `statvfs()` logic or moves it into
a shared helper so metrics export and dashboard JSON do not diverge.

### Write-Through Sources

Existing handle fields:

- `wt_enabled`
- `wt_policy`
- `wt_dirty_offset`
- `wt_bytes_written`
- `wt_flush_pending`

Missing global counters should be added to `ngx_xrootd_srv_metrics_t`:

```c
ngx_atomic_t  wt_dirty_handles;
ngx_atomic_t  wt_flush_pending;
ngx_atomic_t  wt_flush_success_total;
ngx_atomic_t  wt_flush_error_total;
ngx_atomic_t  wt_flush_bytes_total;
```

Update in:

- `src/read/open_resolved_file.c`
- `src/write/write.c`
- `src/write/pgwrite.c`
- `src/read/close.c`
- `src/cache/writethrough_flush.c`

### API/UI

Add `/xrootd/api/v1/cache`:

```json
{
  "enabled": true,
  "occupancy_ratio": 0.72,
  "eviction_threshold_ratio": 0.90,
  "evictions_total": 12,
  "eviction_errors_total": 0,
  "write_through": {
    "enabled": true,
    "dirty_handles": 2,
    "flush_pending": 1,
    "flush_errors_total": 0
  }
}
```

### Tests

- Cache-disabled listener returns `enabled: false`.
- Cache-enabled fixture returns occupancy and threshold fields.
- Simulated WT flush failure increments event/counter and appears in snapshot.

## Feature 8: Manager and Cluster Health

### Goal

Show registered data servers and redirector health for manager-mode deployments.

### Backend

Add a safe snapshot helper to `src/manager/registry.c`:

```c
typedef struct {
    char        host[256];
    uint16_t    port;
    char        paths[XROOTD_SRV_MAX_PATHS];
    uint32_t    free_mb;
    uint32_t    util_pct;
    ngx_msec_t  last_seen;
} xrootd_srv_snapshot_entry_t;

ngx_uint_t xrootd_srv_snapshot(xrootd_srv_snapshot_entry_t *out,
    ngx_uint_t max_entries, ngx_msec_t now);
```

The helper should hold the registry lock only while copying fixed-size entries
into caller-owned memory.

### API/UI

Add `/xrootd/api/v1/cluster`:

- registered server count
- host, port, paths
- free MB, utilization percent
- heartbeat age
- stale flag based on configurable threshold
- optional path lookup result for `?path=/store/foo&write=0`

Add directive:

```nginx
xrootd_dashboard_cluster_stale_after 90s;
```

### Tests

- Empty registry returns an empty array.
- Registered test server appears with heartbeat age.
- Path lookup query does not allow path traversal or unbounded strings.

## Feature 9: HTTP-TPC Progress View

### Goal

Make third-party copy operations diagnosable without reading logs.

### Data Model

Extend transfer slot or add a companion TPC detail table:

- mode: pull or push
- redacted remote host
- redacted path hint
- bytes committed locally
- remote HTTP status
- curl exit code
- credential mode: none, bearer, oauth2, x509 summary only
- timeout seconds
- retry count if retries are added later
- commit state: staging, curl_done, committing, committed, rollback, failed
- last performance marker time and bytes

### Curl Result Struct

Replace `ngx_int_t` only returns from TPC curl helpers with:

```c
typedef struct {
    ngx_int_t  rc;
    long       http_status;
    int        curl_code;
    off_t      bytes_transferred;
    char       error[96];
} webdav_tpc_result_t;
```

Keep wrapper functions if needed to preserve existing call sites during
migration.

### Tests

- Pull success shows mode `pull`, commit `committed`, and final bytes.
- Push failure shows mode `push`, curl code, and redacted remote.
- Credential material never appears in JSON.

## Feature 10: Configurable Session Settings

### Goal

Expose dashboard cookie lifetime and path without hard-coding `/xrootd`.

### Directives

Add to `src/dashboard/module.c` and `dashboard_http.h`:

```nginx
xrootd_dashboard_session_ttl 8h;
xrootd_dashboard_cookie_path /xrootd;
```

Implementation notes:

- Store TTL as seconds or milliseconds consistently. The existing
  `session_ttl` field is seconds.
- Parse nginx time values with `ngx_parse_time()`.
- Default TTL remains 28800 seconds.
- Default cookie path remains `/xrootd` for compatibility.
- Reject cookie paths that are empty, lack a leading slash, include control
  characters, or include `;`.
- Update login redirect construction to use the configured path.
- Update page JavaScript fetch paths or inject a tiny config object into the
  page with the configured base path.

### Tests

- Custom TTL accepts fresh cookies and rejects expired cookies.
- Custom cookie path emits `Set-Cookie: Path=<path>`.
- Invalid cookie path fails `nginx -t`.

## Feature 11: Multiple Admin Users

### Goal

Replace the single shared plaintext password path with an optional users file.

### Directive

```nginx
xrootd_dashboard_users /etc/nginx/xrootd-dashboard.htpasswd;
```

Config behavior:

- `xrootd_dashboard_password` keeps working for simple deployments.
- If `xrootd_dashboard_users` is set, reject simultaneous
  `xrootd_dashboard_password` unless a compatibility decision is made
  explicitly.
- Validate the file is readable during `nginx -t`.

### File Format

Start with an htpasswd-like format:

```text
alice:$2y$...
bob:$2y$...
```

Implementation choices:

- Prefer existing system `crypt(3)` support if available.
- If portability is a concern, use OpenSSL EVP PBKDF2 with a module-specific
  format instead of adding a large password-hash dependency.
- Load users at config time into an array owned by `cf->pool`.

### Auth Changes

- Login form adds username.
- Cookie payload includes username and timestamp.
- HMAC covers username, timestamp, and a server-side secret derived from the
  configured password hash or random startup key.
- Event ring records login success/failure by username, but never logs
  passwords.

### Tests

- Valid user/password logs in.
- Wrong password fails and records an auth event.
- Unknown user response is indistinguishable from wrong password.
- Cookie tampering is rejected.

## Feature 12: Audit Trail

### Goal

Record dashboard access and security-relevant events without leaking secrets.

### Event Classes

Use the recent event ring:

- login success
- login failure
- expired cookie
- malformed cookie
- API 401/403
- users file parse failure during config validation

### Tests

- Failed login produces one auth event.
- Cookie with invalid HMAC produces one auth event.
- Event messages do not contain password, cookie value, bearer token, or
  Authorization header.

## Feature 13: Versioned JSON

### Goal

Make dashboard JSON stable for the embedded page and external tooling.

### Implementation

- Add `"schema": "xrootd-dashboard.v1"` to all versioned endpoints.
- Add `"server_ms"` and `"limits"` consistently.
- Keep old `/xrootd/transfers` response shape until callers are migrated.
- Consider `?compat=0` or `/api/v1/transfers` for the richer shape.

### Tests

- Snapshot includes schema.
- Existing `/xrootd/transfers` tests still pass.
- Unknown endpoint under `/xrootd/api/v1/` returns 404 JSON or standard 404,
  but does not fall through to the HTML page.

## Feature 14: Bounded History

### Goal

Provide short dashboard sparklines without embedding Prometheus.

### Shared Memory

Add `src/dashboard/history.c`:

```c
#define XROOTD_DASHBOARD_HISTORY_BUCKETS 360
#define XROOTD_DASHBOARD_HISTORY_INTERVAL_MS 5000

typedef struct {
    int64_t       bucket_start_ms;
    ngx_atomic_t  active_root;
    ngx_atomic_t  active_webdav;
    ngx_atomic_t  active_s3;
    ngx_atomic_t  bytes_rx;
    ngx_atomic_t  bytes_tx;
    ngx_atomic_t  errors;
    ngx_atomic_t  auth_failures;
    ngx_atomic_t  write_stalls;
    uint32_t      cache_occupancy_ppm;
} xrootd_dashboard_history_bucket_t;
```

Sampling approach:

- Lazy sampling in `api.c` when dashboard is polled is simplest.
- A timer-based sampler would require worker lifecycle hooks and is more
  invasive.
- On each snapshot request, advance buckets based on `ngx_current_msec`, copy
  deltas from metrics counters, and scan active slots.

### API/UI

- Add history arrays to `/snapshot`.
- Render compact sparklines for ingress, egress, active transfers, and errors.

### Tests

- History buckets advance across synthetic timestamps.
- Ring wrap preserves bounded length.
- Missing metrics zone returns empty or zero history safely.

## Feature 15: Snapshot Export

### Goal

Let operators capture a sanitized incident snapshot from the browser.

### Frontend

In `page.c`:

- Add an export button.
- Use the last fetched snapshot object.
- Remove or redact optional sensitive fields based on a client-side allowlist.
- Create a `Blob` with JSON and trigger a browser download.

### Backend

No backend is required for the first version if `/snapshot` already returns all
data. If server-side redaction modes are added later, support:

```text
/xrootd/api/v1/snapshot?redact=strong
```

### Tests

- Snapshot JSON omits raw credential material.
- Export button is present in the HTML.
- Redaction helper removes query strings from TPC URLs.

## Feature 16: Accessibility and Mobile Layout

### Goal

Make the embedded dashboard usable for keyboard users and small screens.

### UI Requirements

- Use semantic table markup with captions or accessible labels.
- Use text labels as well as color for `active`, `idle`, `stalled`, and
  `error`.
- Add visible focus states for filters, buttons, and rows.
- Support `prefers-reduced-motion`.
- Collapse low-priority columns on narrow screens.
- Ensure long paths and identities truncate with title text, not layout breakage.

### Tests

- HTML contains labels for controls.
- No essential control is mouse-only.
- Mobile viewport screenshot test if Playwright is available in the test stack.

## Routing Changes

Current routing in `src/dashboard/module.c` uses suffix checks. Replace it with
clear prefix/exact matching:

```c
if (uri == base || uri == base + "/") page;
if (uri == base + "/login") login;
if (uri == base + "/transfers") compatibility transfers;
if (uri starts base + "/api/v1/") api router;
else 404;
```

This avoids accidentally serving the dashboard page for unknown API paths.

## Documentation Updates

Update these docs as features land:

- `docs/08-metrics-monitoring/monitoring-guide.md`
- `docs/08-metrics-monitoring/dashboard-feature-ideas.md`
- `docs/03-configuration/directives.md`
- `docs/09-developer-guide/test-coverage-map.md`
- `README.md` only for major user-visible dashboard changes

Do not document directives before they are implemented.

## Testing Plan

Minimum new file:

- `tests/test_dashboard.py`

Recommended coverage:

| Feature | Tests |
|---|---|
| API auth | no cookie, bad cookie, valid login, expired cookie |
| Versioned JSON | schema, limits, backward-compatible `/xrootd/transfers` |
| WebDAV active rows | GET, PUT, abort cleanup |
| S3 active rows | GET, PUT, auth redaction |
| TPC rows | pull success, push failure, remote redaction |
| Event ring | append, wrap, sanitized strings |
| Protocol cards | empty metrics, populated metrics, no high-card labels |
| Cache panel | disabled, enabled, statvfs failure |
| Cluster panel | empty, registered server, stale heartbeat |
| Users file | valid login, wrong password, malformed file |
| UI HTML | controls present, detail panel present, export button present |

Run order:

```bash
PYTHONPATH=tests pytest tests/test_dashboard.py -v
PYTHONPATH=tests pytest tests/test_http_webdav.py tests/test_s3.py -k dashboard -v
PYTHONPATH=tests pytest tests/test_webdav_tpc.py -k dashboard -v
PYTHONPATH=tests pytest tests/test_manager_mode.py -k dashboard -v
PYTHONPATH=tests pytest tests/ -v --tb=short
```

Also run:

```bash
make -j$(nproc)
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf
```

## Milestones

### Milestone 0: API foundation

- [x] Add API v1 router.
- [x] Add schema metadata.
- [x] Keep compatibility endpoint.
- [x] Add JSON helper functions and endpoint tests.

### Milestone 1: WebDAV active transfer tracking

- [x] Add HTTP tracking helper.
- [x] Wire WebDAV GET and PUT.
- [x] Add state, idle, and average rate fields.
- [x] Add filters in page.

### Milestone 2: S3 and HTTP-TPC tracking

- [x] Wire S3 GET/PUT and multipart upload parts.
- [x] Wire WebDAV TPC pull/push and marker mode.
- [x] Add TPC redaction helpers and progress/result fields.

### Milestone 3: Dashboard triage views

- [x] Add detail endpoint and panel.
- [x] Add recent event ring.
- [x] Add protocol summary cards.

### Milestone 4: Operational panels

- [x] Add cache/write-through JSON and UI.
- [x] Add manager registry snapshot and cluster UI.
- [x] Add bounded history and sparklines.

### Milestone 5: Security and polish

- [x] Add configurable TTL and cookie path.
- [x] Add users file support.
- [x] Add audit events.
- [x] Add snapshot export.
- [x] Improve accessibility and mobile layout.

## Rollout Notes

- Start with additive JSON fields. Avoid removing or renaming existing fields.
- Feature-gate risky panels with data availability, not config flags: if a zone
  or registry is absent, return empty JSON and hide the panel.
- Treat UI work as progressive enhancement. The JSON API should remain useful
  without the embedded page.
- Keep every string copied into shared memory bounded and explicitly
  NUL-terminated.
- Prefer one small protocol slice at a time. WebDAV GET/PUT tracking is the
  best first data-path milestone because the active file transfer behavior is
  easy to observe and already shares helpers with S3.
