# dashboard — live HTTPS transfer monitor + REST admin write API

## Overview

The `dashboard` subsystem is a self-contained operator console served over the
HTTP module at `/xrootd/`. It gives a site operator real-time visibility into
every active transfer (who, which file, which protocol, how many bytes, how
fast), plus a recent-events ring buffer, rolling history sparkline, cache
health, and CMS cluster state — and, since Phase 23, a guarded REST API that
*mutates* runtime state (register/drain data servers, add/drain dynamic WebDAV
proxy backends). It exists so operators can replace the XRootD monitoring
daemons with the same nginx process that serves data, with no external
collector required.

The subsystem spans **both nginx module worlds**, which is the single most
important fact about its layout. The data producers run inside the **stream**
module: stream workers (and HTTP method handlers, via `http_tracking.c`) write
into three shared-memory zones — the active-transfer table, the event ring
buffer, and the history ring. The consumers run inside a dedicated **HTTP**
module (`ngx_http_xrootd_dashboard_module`): when a request hits a location
that has `xrootd_dashboard on`, the content handler renders the HTML page,
serves JSON snapshots, handles login, or dispatches admin writes. The two sides
never share a request context — they communicate only through SHM — so the
headers are deliberately split: stream-visible types live in `dashboard.h`,
HTTP-only declarations in `dashboard_http.h`.

In the request lifecycle, dashboard tracking is a *side effect* of the four
data lifecycles, not part of any of them. A `root://` open calls
`xrootd_transfer_slot_alloc()`, each read/write calls
`xrootd_transfer_slot_update()`, close/disconnect frees the slot; a WebDAV or S3
request does the equivalent through the `xrootd_dashboard_http_*` helpers in
`http_tracking.c`, which attach a pool-cleanup so the slot is always freed when
the request ends. Tracking failures are silent (table full → transfer proceeds
untracked): the dashboard is display-only and must never affect data movement.

The dashboard is **firewalled-admin-only by design**. It exposes client
identities, file paths, and IP addresses, and the page password lives in
`nginx.conf` in plaintext; the module provides no IP-level access control for
the *page* (the operator must restrict the location via nginx `allow`/`deny` or
a firewall). The Phase 23 *admin write API* is separately and more strictly
guarded (CIDR allowlist and/or bearer secret, fail-closed).

## Files

The build compiles these in two groups (see `config`): the **stream** group
(`config.c`, `transfer_table.c`, `events.c`, `history.c`) registers and feeds
the SHM zones; the **HTTP** group (`module.c`, `auth.c`, `api.c`,
`api_admin.c`, `http_tracking.c`, `page.c`) serves requests.

| File | Responsibility |
|---|---|
| `dashboard.h` | Stream-visible public API + all SHM struct/enum/constant definitions (`xrootd_transfer_slot_t`, `_table_t`, event table, history ring); slot-operation and event/history prototypes. Included via the umbrella `ngx_xrootd_module.h`. Must compile in stream context (no `ngx_http_request_t`). |
| `dashboard_http.h` | HTTP-only declarations: the `ngx_module_t`, the per-location config `ngx_http_xrootd_dashboard_loc_conf_t`, the API-endpoint enum, and the four content-handler + `check_auth` prototypes. Included only by `module.c`/`auth.c`/`api.c`/`page.c`. |
| `dashboard_tracking.h` | HTTP-side tracking helpers (`xrootd_dashboard_http_start[_identity]`, `_add`, `_state`, `_error`, `_tpc_remote`, `_finish`) that other HTTP handlers (WebDAV/S3/TPC) call to populate a transfer slot. |
| `api_admin.h` | Phase 23 admin write API surface: `xrootd_admin_dispatch()` plus the three directive setters. |
| `config.c` | **(stream)** Registers the three SHM zones (`xrootd_dashboard_v2`, `_events`, `_history`) during stream postconfiguration; sets the `(void*)1` first-startup sentinel; owns the global `ngx_shm_zone_t *` pointers. |
| `transfer_table.c` | **(stream)** Owns the active-transfer table: the slot-alloc mutex, the SHM init callback, and all slot operations (alloc/update/state/error/tpc/count-op/free/free-all-for-session). Stale-slot GC contract documented here. |
| `events.c` | **(stream)** Event ring buffer: `xrootd_dashboard_event_add()` (sequenced, mutex-guarded, control-char-sanitised) and `xrootd_dashboard_events_snapshot()`. |
| `history.c` | **(stream)** Rolling history ring: `xrootd_dashboard_history_sample()` aggregates current transfer counts + cumulative metrics into the current 5 s bucket; `xrootd_dashboard_history_snapshot()` reads them back oldest→newest. |
| `module.c` | **(http)** Module definition, directives (`xrootd_dashboard`, `_password`, `_session_ttl`, `_cookie_path`, `_users`, `_idle/_stalled/_cluster_stale` thresholds, plus the Phase 23 `xrootd_admin_*`), loc-conf create/merge, and the URI dispatcher `…_main_handler` that routes `/xrootd/*` to page/login/api/admin handlers. |
| `auth.c` | **(http)** Single-admin-or-user-file cookie auth (`xrd_dashboard=<hmac>.<ts>[.<user>]`, HMAC-SHA256, constant-time compare, TTL), the login form (GET) + verify (async POST body), bcrypt/`crypt()` and plaintext password support, and `Set-Cookie` issuance. |
| `api.c` | **(http)** Endpoint routing + name/format helpers (`dashboard_*_name`, `avg_bps`, `session_hash`), `send_json`, anon-allow gate, and the `…_api_handler` dispatcher. *(Phase 38: split.)* |
| `api_transfers.c` | **(http)** Live-transfer model: `build_transfer_object`/`_rows`, TPC registry, and the v1 transfers + per-id detail builders. *(Phase 38 split of `api.c`.)* |
| `api_snapshot.c` | **(http)** Top-level snapshot assembly: totals/protocols collect + build, events/history/cache/cluster fill, and the v1 snapshot wiring. *(Phase 38 split of `api.c`.)* |
| `api_ratelimit.c` | **(http)** The v1 ratelimit view + the not-found/truncated responses. *(Phase 38 split of `api.c`.)* |
| `api_cvmfs.c` | **(http)** The cvmfs:// site-cache view (`/api/v1/cvmfs` + the snapshot's `cvmfs` section): aggregate counters, hit/fill/origin byte split, and the bounded per-repo/per-upstream slot tables (READY + lowest-index-dup rules mirror `metrics/cvmfs.c`; names redacted for anonymous viewers). |
| `dashboard_api_internal.h` | Private split contract shared by `api*.c` (the totals/protocols structs + de-`static`'d builder prototypes). |
| `api_admin.c` | **(http)** Admin write API: dispatch, auth (CIDR/bearer/require-both), async body reader, input validation, structured audit log. *(Phase 38: split.)* |
| `api_admin_cluster.c` | **(http)** Cluster registry write endpoints (`register`/`drain`/`delete`/`undrain` + server-URI parse). *(Phase 38 split of `api_admin.c`.)* |
| `api_admin_proxy.c` | **(http)** Dynamic proxy-pool write endpoints (`add`/`list`/`one` + proxy-URI parse + host allow-list). *(Phase 38 split of `api_admin.c`.)* |
| `api_admin_config.c` | **(http)** Runtime config writes: io_uring killswitch + the `allow`/`secret`/`proxy_allow` directive setters. *(Phase 38 split of `api_admin.c`.)* |
| `dashboard_api_admin_internal.h` | Private split contract shared by `api_admin*.c`. |
| `http_tracking.c` | **(http)** Bridges HTTP requests to the stream-owned transfer table: allocates a slot on `…_http_start`, stores it in module ctx, registers a pool cleanup that frees the slot, redacts TPC URLs (strips userinfo + query). |
| `page.c` | **(http)** The embedded single-file HTML/CSS/JS dashboard UI (polls `/api/v1/snapshot` every 2 s) and its handler, which redirects to `/xrootd/login` when unauthenticated. |
| `noop.c` | Weak fallback stubs for every public dashboard symbol, returning "untracked"/empty. Lets the HTTP dashboard module link in a build without the stream module. **Not referenced by the current `config`** (both groups are compiled), but kept so the API stays linkable standalone. |

## Key types & data structures

All live in `dashboard.h` and reside in shared memory; `ngx_shmtx_sh_t lock`
is always the first field of each root table (an `ngx_shmtx_create()`
requirement, identical to the session/metrics registries).

- **`xrootd_transfer_slot_t`** — one active transfer. Mixes lock-written fields
  (`in_use`, identity/path/op strings, `serial`, `sessid`, `start_ms`) with
  lock-free atomics updated during I/O (`bytes`, `last_ms`, `state_since_ms`,
  `read/write/sync/close_ops`, `instant_bps`). Carries protocol/direction/state
  tags (`XROOTD_XFER_PROTO_*`, `_DIR_*`, `_STATE_*`) and TPC remote-endpoint
  fields. `serial` is a monotonic ID so the JS can detect row churn and address
  a transfer at `/api/v1/transfers/{id}`.
- **`xrootd_transfer_table_t`** — the active-transfer table: `lock`,
  `next_serial`, and a fixed `slots[XROOTD_DASHBOARD_MAX_TRANSFERS]` (512).
- **`xrootd_dashboard_event_t` / `_event_table_t`** — a sequenced event
  (`class_id` ∈ `xrootd_dashboard_event_class_e`, proto, status, message,
  redacted `path_hint`) in a 512-entry ring indexed by `(seq-1) % MAX_EVENTS`.
- **`xrootd_dashboard_history_bucket_t` / `_history_t`** — 360 buckets of 5 s
  each (30 min). Each bucket holds active counts per protocol and cumulative
  byte/error/auth-failure snapshots; `last_bucket_start_ms` drives rollover.
- **`ngx_http_xrootd_dashboard_loc_conf_t`** (`dashboard_http.h`) — per-location
  config: enable flag, page password / `users` array, session TTL, cookie path,
  idle/stalled/cluster-stale thresholds, and the Phase 23 admin fields
  (`admin_allow` CIDR list, `admin_secret`, `admin_require_both`,
  `admin_proxy_allow`).
- **`xrootd_dashboard_api_endpoint_e`** (`dashboard_http.h`) — the routed
  endpoint, set by `module.c`'s dispatcher and consumed by the `api.c` switch.

## Control & data flow

**Producer side (writes into SHM):**
`../config/postconfiguration.c` calls `xrootd_configure_dashboard()`
(`config.c`) to register the three zones against `ngx_stream_xrootd_module`.
At runtime, stream op handlers in `../read/` and `../write/` call the
`xrootd_transfer_slot_*` functions in `transfer_table.c`; HTTP handlers in
`../webdav/` and `../s3/` call the `xrootd_dashboard_http_*` wrappers in
`http_tracking.c`, which in turn call the same slot functions. Errors and
notable actions anywhere call `xrootd_dashboard_event_add()` (`events.c`).
`history.c` reads both the transfer table and the metrics SHM
(`../metrics/`) to fill the current bucket — it is driven lazily from the API
handler (`xrootd_dashboard_history_sample()` is called on each API hit).

**Consumer side (reads SHM, serves HTTP):** a request to a
`xrootd_dashboard on` location enters `ngx_http_xrootd_dashboard_main_handler`
(`module.c`), which routes by URI. Page → `page.c` (auth-gated, else 302 to
login). Login → `auth.c`. JSON → `api.c` (`check_auth` → GET/HEAD →
`history.sample` → collect totals → build the requested endpoint with jansson →
`json_dumpb` into a pool buffer → memory-backed `b->memory=1` chain). Admin →
`xrootd_admin_dispatch` (`api_admin.c`).

**Outbound dependencies** beyond siblings already named: `api.c` reads the
TPC SHM registry (`../tpc/`), the manager/CMS server registry (`../manager/`),
filesystem usage (`../compat/fs_usage.h`), and rate-limit zones
(`../ratelimit/`). `api_admin.c` writes the manager registry (`../manager/`)
and the dynamic proxy pool (`../webdav/proxy_pool.h`), and parses bearer tokens
via `../compat/http_headers.h`. Auth uses OpenSSL HMAC/`CRYPTO_memcmp` directly
(not `../crypto/`).

## Invariants, security & gotchas

- **Two compilation contexts, one SHM bridge.** `dashboard.h` must stay free of
  `ngx_http_request_t`; HTTP-only types belong in `dashboard_http.h`
  (`dashboard_http.h:6-14`). Producers run in stream workers, consumers in HTTP
  workers; they share *only* the three SHM zones, never a request ctx.
- **SHM zone sentinel.** `config.c` sets `shm_zone->data = (void*)1` before
  first map; every reader must treat `NULL` and `(void*)1` as "not ready"
  (see the triple-guard in `api.c:151-156`, `history.c:108-111`). The init
  callbacks distinguish first-startup (`data==NULL`, zero + create mutex) from
  reload (`data!=NULL`, re-create mutex, **preserve in-flight slots**) —
  `transfer_table.c:31-63`.
- **Lock discipline.** The slot-alloc mutex is held only for the O(512) free
  scan and the final `in_use=1` publish (written *last* so lock-free readers
  never see a half-built slot — `transfer_table.c:131`). Byte/timestamp updates
  and single-slot free are lock-free (`ngx_atomic_fetch_add`, `ngx_atomic_cmp_set`).
  Disconnect cleanup (`_free_all_for_session`) re-takes the mutex.
- **Tolerated torn reads + memory barrier.** The JSON exporter scans lock-free
  and accepts eventual consistency. `dashboard_build_transfer_object`
  (`api.c:305`) issues `ngx_memory_barrier()` and copies every volatile field
  into stack locals before any jansson call — preserve this block.
- **Fail-open tracking, never block I/O.** A full table returns `-1` and the
  transfer proceeds untracked (`transfer_table.c:101-106`); all `_http_*`
  helpers no-op when no slot is attached. HTTP slot freeing is guaranteed by a
  `ngx_pool_cleanup_add` handler (`http_tracking.c:96-106`), so dropped clients
  don't leak slots.
- **Stale-slot GC, two layers.** The doc contract names a 60 s sweep; the live
  code GC threshold is `STALE_GC_MS = 600000` (10 min) applied during the API
  scan (`api.c:24,415-422`). Session-disconnect and pool cleanup are the primary
  reclaim paths; the scan GC is the backstop.
- **TLS-safe responses.** All HTML/JSON responses use memory-backed buffers
  (`b->memory = 1`, `b->last_buf = 1`) — correct for the davs:// TLS path; the
  dashboard never uses file-backed/sendfile buffers.
- **Auth is fail-closed and constant-time.** Cookie verification recomputes the
  HMAC and compares with `CRYPTO_memcmp` (`auth.c:429`); TTL and a +60 s
  clock-skew bound are enforced (`auth.c:488`). No page password configured ⇒
  open access (`auth.c:314`) — intentional, documented as firewall-gated.
- **Admin API is separately, strictly guarded.** Disabled (403) unless
  `xrootd_admin_allow` or `xrootd_admin_secret` is set
  (`api_admin.c:175`); `require_both` ANDs CIDR + bearer. Inputs are
  **whitelist-validated and rejected, never sanitised** (`admin_validate_hostname`
  /`_paths`/`_url`). Secrets are read from file at config time, must be
  ≥ 16 bytes (`ADMIN_SECRET_MIN`), and the transient stack copy is
  `OPENSSL_cleanse`d. Dynamic proxy backends are SSRF-guarded by
  `xrootd_admin_proxy_allow` (`admin_url_host_allowed`). Every write is
  audit-logged via `admin_audit()` (a structured `ngx_log` line, distinct from
  the dashboard event ring).
- **Low-cardinality / redaction.** Event `path_hint` and TPC remote URLs are
  redacted: `dashboard_event_copy` strips control bytes and stops at `?`/`#`;
  `dashboard_redact_url` (`http_tracking.c:210`) drops `user:pass@` userinfo and
  the query string, keeping only host + basename. `session_hash` is exposed, not
  the raw `sessid`.
- **`addr_text` is not NUL-terminated.** `http_tracking.c` must copy
  `r->connection->addr_text` into a bounded buffer before handing it to the
  `ngx_cpystrn`-based slot copier (Phase 27 / Valgrind finding,
  `http_tracking.c:31-57`).
- **Login POST is async.** `ngx_http_xrootd_dashboard_login_handler` returns
  `NGX_DONE` and finalizes inside the body callback; it issues a 302 via
  `headers_out.location` rather than `send_header` alone, because a bare
  `send_header` in a body callback leaves headers unflushed (`auth.c:682-710`).

## Entry points / extending

- **Add a read JSON endpoint:** add a value to `xrootd_dashboard_api_endpoint_e`
  (`dashboard_http.h`) → route its URI in `…_main_handler` (`module.c`) → add a
  `dashboard_build_v1_*` builder and a `case` in
  `ngx_http_xrootd_dashboard_api_handler` (`api.c`). Build the body with jansson
  leaf builders; return through `dashboard_send_json` (it owns/decrefs `root`).
- **Add a tracked field:** add the field to `xrootd_transfer_slot_t`
  (`dashboard.h`), set it under the alloc mutex in
  `xrootd_transfer_slot_alloc_ex` or via a new lock-free setter in
  `transfer_table.c`, and emit it in `dashboard_build_transfer_object`
  (`api.c`). Keep `noop.c` in sync if you add a new public function.
- **Add an admin write op:** add a handler in `api_admin.c`, route it in
  `xrootd_admin_dispatch` (gated on method), whitelist-validate every input,
  call `admin_audit()`, and (for body-bearing ops) go through
  `xrootd_admin_read_body`.
- **Add a directive:** declare the field in
  `ngx_http_xrootd_dashboard_loc_conf_t` (`dashboard_http.h`), add an
  `ngx_command_t` + setter in `module.c`, and merge it in
  `…_merge_loc_conf` — no `./configure` needed (no new source file).

## See also

- `../metrics/README.md` — the metrics SHM that `api.c`/`history.c` aggregate.
- `../manager/README.md` — CMS server registry read by `/api/v1/cluster` and
  written by the admin API.
- `../tpc/README.md` — third-party-copy registry surfaced as `tpc_transfers`.
- `../webdav/README.md` — dynamic proxy pool managed by the admin API; WebDAV
  handlers that call the `http_tracking.c` helpers.
- `../ratelimit/README.md` — zones surfaced by `/api/v1/ratelimit`.
- `../config/README.md` — postconfiguration that registers the SHM zones.
- `../README.md` — master subsystem index.

## VFS export browser (`xrootd_dashboard_vfs_browse on`)

Admin-auth-only, read-only, **off by default** (it exposes stored user
data through the dashboard). Three endpoints, every operation routed
through `xrootd_vfs_*` — so the listing is the export's LOGICAL
namespace for ANY backend the registry composed (a pblock export shows
its files, not `catalog.db` + packed blobs; posix/ceph/xroot the same):

    GET /xrootd/api/v1/vfs                       export census (root, backend, origin)
    GET /xrootd/api/v1/vfs/files?export=&path=   JSON directory listing (name/type/size/mtime)
    GET /xrootd/api/v1/vfs/download?export=&path= stream one file (shared VFS serve pipeline:
                                                  ranges, pblock sendfile gate, TLS buffer rule)

The Files tab in the UI grows a Source selector: the host tree
(`xrootd_dashboard_browse_root`, raw-POSIX — logs/spool) plus one entry
per registered export. NOTE: an export registers by NAMING its backend
(`xrootd_*_storage_backend posix|pblock|…`); a location that relies on
the implicit posix default is served as before but does not appear in
the census. The vctx binds with allow_write=0 — the browser cannot
write; ?path= must be absolute and ".."-free, and the VFS re-confines
every open at the kernel (openat2 RESOLVE_IN_ROOT).
