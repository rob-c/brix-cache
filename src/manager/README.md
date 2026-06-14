# manager — Cluster / redirector control plane (server registry, redirect cache, active health checks)

## Overview

This subsystem is the control plane that lets `nginx-xrootd` act as an **XRootD redirector / CMS sub-manager**, not just a leaf data server. When `xrootd_manager_mode` is on, the node does not serve files itself — it tracks the fleet of child data servers and answers client `kXR_locate` / `kXR_open` requests with a `kXR_redirect` to the best-fit server for the requested path. All of the cross-worker state needed to make that decision lives here.

The core is the **shared-memory server registry** (`registry.c`): a fixed-capacity, spinlock-protected table that every worker process maps. Child data servers announce themselves through the CMS management protocol (`../cms/`), which calls `xrootd_srv_register()` on login and `xrootd_srv_update_load()` on each heartbeat; the registry records each server's host/port, exported path prefixes, free space, and utilisation. The selection helpers (`xrootd_srv_select`, `xrootd_srv_locate_all`) then perform longest-prefix path matching plus a load/space policy to pick a target, and are called directly from the stream protocol handlers in `../read/` (`open_request.c`, `locate.c`) and `../cms/recv.c`.

Three supporting tables round out the plane. The **redirect-collapse cache** (`redir_cache.c`) memoises resolved `path → (host,port)` redirects with a TTL so a busy manager can answer repeat opens/locates from memory instead of re-running CMS resolution — required when `kXR_collapseRedir` is advertised. The **pending-locate table** (`pending.c`) correlates an async `kXR_locate` a worker forwards to its upstream CMS manager with the eventual `kXR_select` reply that arrives later on the CMS socket, so the suspended client session can be woken with the answer. **Active health checks** (`health_check.c`) are an opt-in per-worker timer that opens a real short-lived XRootD probe connection to each registered server and blacklists hung-but-connected nodes that the passive CMS-disconnect signal would miss.

Everything here is configured once at startup (`../config/postconfiguration.c` calls the `*_configure*` functions; `../config/process.c` starts the health-check timer in `init_process`) and is shared across all nginx workers via dedicated `ngx_shm_zone_t` regions, each guarded by a single `ngx_shmtx_t` spinlock that is held only for in-memory scans — never across I/O.

## Files

| File | Responsibility |
|---|---|
| `registry.h` | Public registry API + the `xrootd_srv_entry_t` / `xrootd_srv_table_t` / `xrootd_srv_snapshot_entry_t` types; capacity constants (`XROOTD_SRV_REGISTRY_SLOTS`, `XROOTD_SRV_MAX_PATHS`). |
| `registry.c` | The shared-memory server table and all its operations: zone init/configure, `xrootd_srv_register` / `_update_load` / `_unregister`, path-prefix matcher `srv_path_matches`, server selection `xrootd_srv_select` (read=least-loaded / write=most-free), `xrootd_srv_locate_all` (lateral-redirect listing), blacklist/undrain, health-check slot helpers (`_hc_claim/_pass/_fail`), `tried/triedrc` retry-exhaustion logic, per-path deregistration, aggregate-space and snapshot exporters. |
| `redir_cache.h` | Redirect-collapse cache API + `XROOTD_REDIR_CACHE_SLOTS` default. |
| `redir_cache.c` | FNV-1a-hashed, bounded-probe open-addressing cache in SHM: `xrootd_redir_cache_lookup` / `_insert` with TTL expiry, free/expired-slot reuse, and soonest-to-expire eviction within the probe window. |
| `pending.h` | Pending-locate table API + the `xrootd_pending_locate_t` / `xrootd_pending_table_t` types; `XROOTD_PENDING_LOCATE_SLOTS` (32). |
| `pending.c` | SHM table of in-flight `kXR_locate` requests keyed by `(streamid, worker_pid)`: `xrootd_pending_insert` (with expiry reaping), `xrootd_pending_lookup` (returns **locked**), `xrootd_pending_unlock`, `xrootd_pending_remove`. |
| `health_check.h` | Active health-check API (`xrootd_hc_manager_start`) + probe-type constants (`XROOTD_HC_TYPE_PING` / `_STAT`). |
| `health_check.c` | Self-contained async XRootD probe client (handshake → protocol → login → `kXR_ping`/`kXR_stat "/"`) plus the per-worker scan timer that claims one due registry slot per interval and reports pass/fail back to the registry. |

## Key types & data structures

- **`xrootd_srv_entry_t`** (`registry.h`) — one registered data server: `host[256]`, `port`, colon-delimited `paths[XROOTD_SRV_MAX_PATHS]`, `free_mb`, `util_pct`, `last_seen`, `in_use`, plus availability state (`blacklisted_until`, `error_count`) and health-check state (`hc_next_check`, `hc_last_ok`, `hc_fail_count`, `hc_in_progress`).
- **`xrootd_srv_table_t`** (`registry.h`) — the registry itself: `ngx_shmtx_sh_t lock` (must be first, required by `ngx_shmtx_create`), runtime `capacity`, and a C99 flexible `slots[]` array of `capacity` entries.
- **`xrootd_srv_snapshot_entry_t`** (`registry.h`) — lock-free copy of an entry returned by `xrootd_srv_snapshot()` for the dashboard / metrics exporters, so they can format output without holding the spinlock.
- **`xrootd_redir_cache_entry_t` / `xrootd_redir_cache_t`** (`redir_cache.c`, file-private) — cache slot (`path[256]` key, `host[128]`, `port`, `in_use`, `expires`) and the SHM header (`lock`, `capacity`, flexible `entries[]`). Probing is bounded by `XROOTD_REDIR_PROBE_MAX` (32) slots from `hash(path) % capacity`.
- **`xrootd_pending_locate_t` / `xrootd_pending_table_t`** (`pending.h`) — correlation slot for an outstanding locate: CMS `streamid`, owning `worker_pid`, the waiting client's `conn_fd` + `conn_number` generation guard, the original 2-byte `client_streamid`, `expires`, and the `redir_host`/`redir_port` filled in by `../cms/recv.c` when `kXR_select` returns.
- **`xrootd_hc_ctx_t` / `xrootd_hc_mgr_t`** (`health_check.c`, file-private) — per-probe connection state machine (`xrootd_hc_phase_t`: HANDSHAKE → PROTOCOL → LOGIN → PROBE) and the per-worker scan-timer manager holding the cycle, server conf, and scan interval.

## Control & data flow

**Registration / heartbeat (write side):** `../cms/server_recv.c` (CMS server handler) accepts a child data server's CMS login → `xrootd_srv_register()`; subsequent heartbeats call `xrootd_srv_update_load()`; `xrootd_cms_srv_close()` on disconnect calls `xrootd_srv_blacklist()` (entry preserved for fast reconnect, skipped by selection until the window expires).

**Client redirect (read side):** a stream `kXR_open` reaches `../read/open_request.c`. In manager mode it (1) checks `xrootd_manager_tried_exhausted()` to honour the `tried/triedrc` retry protocol and answer `kXR_NotFound` once the client has visited every candidate; (2) consults `xrootd_redir_cache_lookup()`; (3) on a miss calls `xrootd_srv_select()` and, on success, caches the result via `xrootd_redir_cache_insert()` and emits a redirect; (4) when resolution must be delegated upward, `xrootd_pending_insert()` parks the client and a `kXR_locate` is forwarded to the upstream CMS via `../cms/send.c`. `../read/locate.c` follows the same cache → select → pending sequence and can return the full server set via `xrootd_srv_locate_all()` (lateral redirect). When `../cms/recv.c` receives the upstream `kXR_select`, it `xrootd_pending_lookup()`s the slot, writes the redirect host/port, wakes the waiting connection, and `xrootd_pending_remove()`s the slot.

**Health checks:** `../config/process.c` (`init_process`) calls `xrootd_hc_manager_start()` per enabled server block; the timer periodically `xrootd_srv_hc_claim()`s exactly one due server (cross-worker exclusivity via `hc_in_progress`), `xrootd_hc_start()` runs an async probe built on `../upstream/bootstrap.c` framing, and the verdict feeds `xrootd_srv_hc_pass()` / `xrootd_srv_hc_fail()`.

**Calls out to:** `../cms/` (registration/heartbeat producers, `kXR_select` consumer), `../read/` (`open_request.c`, `locate.c`, `stat.c`), `../config/` (zone setup + timer start), `../upstream/` (`xrootd_upstream_build_bootstrap` reused by the probe), `../compat/net_target.h` (`xrootd_net_host_chars_valid`) and `../compat/shm_slots.h` (free-slot/expiry helpers), `../metrics/` (`registry_full_total`, `hc_*` counters), and is read by `../dashboard/` (`api.c`, `api_admin.c` via `xrootd_srv_snapshot`/`xrootd_srv_undrain`), `../metrics/cluster.c`, and `../cache/` (`evict_policy.c`, `thread.c` via `xrootd_srv_unregister_path`).

## Invariants, security & gotchas

- **Single store choke point for host strings.** `xrootd_srv_register()` rejects any host that fails `xrootd_net_host_chars_valid()` (`registry.c:209`) *before* it enters the table. This is deliberate: every redirect-emitting path (`xrootd_srv_select`, `xrootd_srv_locate_all`) reads these strings straight into the `"S<r|w>host:port"` wire reply a client parses, so validating once at the store prevents control-byte / scheme injection downstream.
- **Spinlock held for scans only.** Every public function takes `xrootd_srv_mutex` / `xrootd_redir_mutex` / `xrootd_pending_mutex` for the duration of an in-memory slot scan and releases it before doing anything else — never across I/O. The one intentional exception is `xrootd_pending_lookup()`, which returns **still holding the lock** so the caller can read `redir_host`/`redir_port`; that caller **must** call `xrootd_pending_unlock()` (`pending.h`, `pending.c:180`).
- **Uninitialised-zone guard.** Each table accessor (`srv_table`, `redir_cache`, `pending_table`) returns NULL when `shm_zone->data` is NULL or the `(void *) 1` configure-time sentinel, and every API treats NULL as a no-op / miss. Calling these before postconfiguration is safe but inert.
- **Selection policy & path matching.** `srv_path_matches()` does longest-prefix matching over colon-delimited tokens with a literal `"/"` token matching everything; `xrootd_srv_select()` picks **lowest `util_pct`** for reads and **highest `free_mb`** for writes, skipping `in_use==0` and currently-blacklisted slots.
- **Blacklist provenance matters.** `xrootd_srv_hc_pass()` clears a blacklist **only** when it was health-check-induced (`hc_fail_count > 0`); it never clears a CMS-disconnect blacklist (`registry.c:686`). `xrootd_srv_register()` clears blacklist + error_count on a clean reconnect; admin `xrootd_srv_undrain()` clears all of blacklist/error/hc-fail state.
- **Capacity is fail-soft.** A full registry **drops** new registrations (logs a warning + bumps `registry_full_total`) rather than evicting; existing servers keep serving. Raise `xrootd_registry_slots`. The redirect cache and pending table instead evict (soonest-to-expire / reaped-expired) within their bounded windows.
- **Cross-worker correlation keys.** Pending entries are keyed by `(streamid, worker_pid)` because each worker maintains its own CMS socket and streamid space; the `conn_number` field is a generation guard so a recycled fd is not mistaken for the original waiter.
- **Health-probe quirks (`health_check.c`).** Probe response bodies are bounded at 4096 bytes; a server that answers `kXR_authmore` (wants creds) or `kXR_gotoTLS` (wants TLS) is treated as **alive**, since the probe carries no credentials and no TLS — the goal is liveness, not full auth. `streamid` `0,2` tags a frame as a health request. A single `hc_timeout_ms` deadline timer fails hung-but-connected servers. Exactly one worker probes a given server per interval via the `hc_in_progress` claim flag.
- **No-realloc SHM layout.** All tables are sized at configure time (`sizeof(header) + slots * sizeof(entry) + ngx_pagesize`) and never grow; `redir_cache.c` keeps a vestigial `next_slot` field only to preserve the on-disk SHM layout.

## Entry points / extending

- **Add a registry field:** extend `xrootd_srv_entry_t` (and, if it must be exported, `xrootd_srv_snapshot_entry_t`) in `registry.h`, populate it under the spinlock in `xrootd_srv_register`/`_update_load`, copy it in `xrootd_srv_snapshot`, and surface it in `../dashboard/api.c` / `../metrics/cluster.c`. Bump nothing else — the zone size is derived from `sizeof(xrootd_srv_entry_t)`.
- **Change selection policy:** edit the `for_write` branch in `xrootd_srv_select()` (and mirror any prefix-matching change in `srv_path_matches`, which is shared by `_select`, `_count_matching`, and `_locate_all`).
- **Add a config knob (slots/TTL/HC tunables):** declare the field in `../config/config.h`, register the directive, then wire it into the relevant `*_configure*` call in `../config/postconfiguration.c` (registry/redir-cache/pending) or the timer in `../config/process.c` (health check) — no top-level zone change needed for existing tables.
- **Add a health-probe type:** add a constant in `health_check.h`, build the request in `xrootd_hc_send_probe()`, and handle its reply in the `XRD_HC_PROBE` case of `xrootd_hc_dispatch()`.

## See also

- `../cms/README.md` — CMS management protocol: the producer of registration/heartbeat events and the consumer of `kXR_select` redirects.
- `../read/README.md` — `open_request.c` / `locate.c` / `stat.c`: the stream handlers that call `xrootd_srv_select` / `_locate_all` / the redirect cache / pending table.
- `../upstream/README.md` — `xrootd_upstream_build_bootstrap`, reused by the health-check probe.
- `../session/README.md` — the session registry, built on the same SHM-table + spinlock pattern.
- `../dashboard/README.md` and `../metrics/README.md` — consumers of `xrootd_srv_snapshot` / `xrootd_srv_undrain` and the cluster/health counters.
- `../config/README.md` — where these zones are configured and the health-check timer is started.
- `../README.md` — master subsystem index.
