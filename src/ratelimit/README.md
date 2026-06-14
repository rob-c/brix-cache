# ratelimit — identity-aware leaky-bucket rate, bandwidth & concurrency limiting (Phase 25)

## Overview

This subsystem is a second, richer rate limiter than the coarse per-IP/per-DN
token bucket of the Phase 20 `xrootd_rate_limit` directive. It enforces
**request-rate**, **bandwidth**, and **concurrency** (in-flight) limits keyed on
XRootD-specific *identity dimensions* — VO group, token issuer, client IP, GSI
subject DN, or storage-volume path prefix — so a Tier-1 gateway can express
policies the stock nginx limiter cannot, e.g. "ATLAS VO: 500 r/s, burst 800" or
"`/store/tape`: 50 MiB/s aggregate" or "max 16 concurrent connections per VO".

It works identically across both data planes. On the **stream** plane
(`root://`/`roots://`) a dispatch gate runs before each data-plane opcode
handler and answers a throttled client with `kXR_wait(seconds)`, leaving the
connection open to retry. On the **HTTP/WebDAV** plane an `NGX_HTTP_ACCESS_PHASE`
handler answers a throttled client with `429 Too Many Requests` + `Retry-After`.
Bandwidth is charged *after* the response is sent (in the stream read/write
handlers and in the HTTP log phase), so throttling reacts to real bytes moved,
not declared content length.

State lives in one or more named nginx shared-memory slab zones
(`xrootd_rate_limit_zone`). Each zone holds an rbtree of per-principal
leaky-bucket nodes plus an LRU queue for O(1) eviction when the zone fills —
the same structure as `ngx_http_limit_req_module`. A single shared SHM tag is
used for every zone, so the *same zone name* declared in both an `http{}` block
and a `stream{}` block resolves to **one** shared zone, giving cross-plane
principal accounting (a VO's `root://` and `davs://` traffic share one bucket).

The limiter is **fail-open**: any internal failure (zone not yet attached, slab
exhausted after eviction) returns `NGX_OK`/allow, because availability beats
strict enforcement on a storage gateway. Throttle/eviction/exhaustion counts
are exported to Prometheus and a live snapshot feeds the dashboard. The naming
note matters: this is the `xrootd_rate_limit_zone` / `_rule` / `_bandwidth` /
`_concurrency` family — unrelated to and unchanged by the Phase 20
`xrootd_rate_limit` directive.

## Files

| File | Responsibility |
|---|---|
| `ratelimit.h` | Public API + all data structures: `xrootd_rl_key_type_t` enum, `xrootd_rl_node_t` (per-principal bucket), `xrootd_rl_shctx_t` (shared rbtree+LRU), `xrootd_rl_zone_t` (zone handle), `xrootd_rl_rule_t` (one configured rule), `xrootd_rl_snapshot_entry_t` (dashboard row). Declares the zone/core/key/HTTP/stream entry points and documents the `× 1000` request-unit convention. |
| `ratelimit.c` | Leaky-bucket core. `xrootd_rl_check` (request rate), `xrootd_rl_bw_check` (bandwidth pre-check) + `xrootd_rl_charge_bytes` (post-send charge), `xrootd_rl_conc_acquire`/`_release` (W7 in-flight cap), `xrootd_rl_snapshot` (dashboard rows, sorted by throttle count). All take `shpool->mutex` internally. |
| `ratelimit_zone.c` | SHM zone lifecycle: FNV-1a32 `xrootd_rl_hash`, rbtree insert/lookup, LRU eviction, slab alloc. `xrootd_rl_zone_add`/`_get`/`_zones_all` (config-time registry of up to 16 zones), `xrootd_rl_lookup_locked`/`_create_locked` (node CRUD; caller holds `shpool->mutex`), `xrootd_rl_init_zone` (zone-init callback with reload inheritance). |
| `ratelimit_keys.c` | Identity → `"<type>:<value>"` key string for both planes (`xrootd_rl_key_stream`, `xrootd_rl_key_http`), DN hashing (`rl_key_dn_hash`), directive value parsers (`rl_parse_key`/`_req_rate`/`_bw_rate`/`_size`), and the directive setters (`xrootd_rl_zone_directive`, `_rule_directive`, `_bw_directive`, `_conc_directive`) shared by the HTTP and stream command tables via a single `rl_add_rule` builder. |
| `ratelimit_http.c` | HTTP/WebDAV enforcement. `xrootd_rl_http_access_handler` (ACCESS phase: per-rule rate/bandwidth/concurrency check → 429 via `rl_reject`), `xrootd_rl_http_log_handler` (LOG phase: charge bytes, release concurrency slot). |
| `ratelimit_stream.c` | XRootD stream enforcement. `xrootd_rl_stream_gate` (per-opcode gate → `kXR_wait`), `xrootd_rl_charge_ctx` (post-send byte charge), `xrootd_rl_release_ctx` (release per-connection concurrency slot on disconnect). Carries the opcode allowlist (`rl_op_rate_limited`), the path-bearing check (`rl_op_path_bearing`), and per-ctx key caching. |

## Key types & data structures

- **`xrootd_rl_key_type_t`** (`ratelimit.h`) — the five identity dimensions:
  `VO`, `ISSUER`, `IP`, `DN`, `VOLUME` (path-prefix match on `key_match`).
- **`xrootd_rl_node_t`** — one slab-allocated per-principal bucket. `node.key`
  is the FNV-1a32 hash of the key string (rbtree ties broken by `key_str`
  bytes); carries `req_excess` (request bucket, stored ×1000 so a 1-request
  charge is 1000 units and millisecond-granular drain stays integer),
  `bw_excess` (bytes, ×1), `in_flight` (W7 concurrency counter), cumulative
  `req_total`/`bytes_total`/`throttle_count`, `last` (ms of last update), an LRU
  `queue` link, and a flexible `key_str[1]` tail (`len` bytes follow). Lives
  inside the SHM zone.
- **`xrootd_rl_shctx_t`** — the shared `{rbtree, sentinel, queue}` at the head
  of the slab pool; `queue` head = most-recently-used.
- **`xrootd_rl_zone_t`** — runtime handle (resolved at config time): `sh`
  (shared ctx, set in the zone init callback), `shpool`, `shm_zone`, `name`,
  `size`. Up to `XROOTD_RL_MAX_ZONES` (16) tracked in a static registry in
  `ratelimit_zone.c`.
- **`xrootd_rl_rule_t`** — one configured rule: `key_type` + `key_match`
  (VOLUME prefix), `req_rate` (r/s ×1000) / `req_burst` (requests, not ×1000),
  `bw_rate` (B/s) / `bw_burst` (bytes), `req_conc` (W7 cap), `nodelay` flag, and
  the resolved `zone` pointer. A rule may carry rate, bandwidth, concurrency, or
  any combination; `rl_add_rule` defaults `req_burst` to 1 and `bw_burst` to one
  second of `bw_rate` when omitted.
- **`xrootd_rl_snapshot_entry_t`** — flat dashboard row copied out under the
  zone lock then sorted by `throttle_count` descending (insertion sort, small N).

Per-connection / per-request state lives **outside** this subsystem on
`xrootd_ctx_t` (stream, `../types/context.h`: `rl_bw_rule`/`rl_bw_key`,
`rl_conc_rule`/`rl_conc_key`, and the `rl_key_cache[XROOTD_RL_RULE_CACHE_MAX]`
+ `rl_key_cache_valid` bitmask) and on the WebDAV request ctx (HTTP:
`rl_bw_rule`/`rl_key_str`, `rl_conc_rule`/`rl_conc_key`).
`XROOTD_RL_RULE_CACHE_MAX` is defined as 8 in `../types/tunables.h`.

## Directive reference (configuration surface)

Declared once at config time; setters live in `ratelimit_keys.c`, registered in
both `../stream/module.c` and `../webdav/module.c`.

```nginx
# 1. Declare a shared zone (size clamped up to 64 KiB minimum). Same NAME in
#    http{} and stream{} = one cross-plane zone.
xrootd_rate_limit_zone   zone=vo_limits:10m;

# 2. Request-rate rule (req/s). burst defaults to 1; nodelay = reject now
#    instead of kXR_wait/Retry-After.
xrootd_rate_limit_rule   zone=vo_limits key=vo rate=500r/s burst=800 [nodelay];

# 3. Bandwidth rule (bytes/s, k|m|g suffix). burst defaults to 1s of rate.
xrootd_bandwidth_limit   zone=vo_limits key=volume:/store/tape rate=50m/s burst=100m;

# 4. Concurrency / in-flight cap (W7).
xrootd_concurrency_limit zone=vo_limits key=vo limit=16;
```

`key=` accepts `vo | issuer | ip | dn | volume:<prefix>`; `zone=`, `key=`, and
`rate=`/`limit=` are required (a zone unknown at rule-parse time is a hard config
error).

## Control & data flow

**Config time.** `xrootd_rate_limit_zone` (setter `xrootd_rl_zone_directive`)
declares an SHM slab zone via `xrootd_rl_zone_add` → `ngx_shared_memory_add`
under the shared tag. `xrootd_rate_limit_rule` / `xrootd_bandwidth_limit` /
`xrootd_concurrency_limit` push `xrootd_rl_rule_t`s into a rules array stored at
`cmd->offset` in the loc-conf (WebDAV) or srv-conf (stream); one `rl_add_rule`
implementation serves both planes. Source files are listed in `config`
(`NGX_ADDON_SRCS`).

**Stream plane.** `../handshake/dispatch.c` (`dispatch.c:64`) calls
`xrootd_rl_stream_gate` *after* login/proxy checks and *before* the data-plane
opcode handler. The gate limits only data-plane opcodes (`kXR_open`, `kXR_read`,
`kXR_readv`, `kXR_pgread`, `kXR_write`, `kXR_writev`, `kXR_pgwrite`,
`kXR_dirlist`, `kXR_locate`) — stat/statx/ping/close/sync/login/auth are never
limited so keepalive and health checks are unaffected. It derives the key
(caching identity-stable keys on the ctx to avoid per-read re-hashing), runs the
rate → bandwidth → concurrency checks, and on throttle returns
`xrootd_send_wait` (see `../response/`). It stashes the matched bandwidth
rule/key on the ctx; the read (`../read/read.c:191`, `../read/pgread.c:292`) and
write (`../write/write.c:149`, `../write/pgwrite.c:303`) handlers call
`xrootd_rl_charge_ctx` after sending bytes. The connection-lifetime concurrency
slot is released by `xrootd_rl_release_ctx` from `../connection/disconnect.c:291`
(`xrootd_on_disconnect`).

**HTTP/WebDAV plane.** `../webdav/postconfig.c` registers
`xrootd_rl_http_access_handler` (ACCESS phase, after the auth handler so
identity is populated) and `xrootd_rl_http_log_handler` (LOG phase). The access
handler reads identity from the WebDAV request ctx, resolves the request path
lazily (only when a VOLUME rule exists, via
`ngx_http_xrootd_webdav_resolve_path`, see `../path/`), runs the three checks,
and returns `429` on throttle. It stashes the bandwidth rule/key and the W7
concurrency rule/key on the request ctx; the log handler charges the response
size (`content_length_n`, falling back to `connection->sent - header_size`) and
releases the concurrency slot exactly once.

**Observability.** Counters increment via the local `XROOTD_RL_METRIC_INC`
macro into the metrics SHM (`../metrics/metrics.h`): `rl_throttled_http_total`,
`rl_throttled_stream_total`, `rl_eviction_total`, `rl_zone_full_errors`. They
are exported by `../metrics/ratelimit.c` (`xrootd_export_ratelimit_metrics`) and
the live per-principal snapshot is served at `/xrootd/api/v1/ratelimit`
(`../dashboard/module.c:446`) by `../dashboard/api.c`
(`dashboard_build_v1_ratelimit` → `xrootd_rl_snapshot`).

## Invariants, security & gotchas

- **Fail-open by design.** Every check returns allow (`NGX_OK`) on zone-not-
  attached or slab-exhausted-after-eviction (`ratelimit.c:30-46`, `98-113`,
  `216`). The limiter never denies otherwise-authorised access on internal
  failure — availability over strict enforcement.
- **Anonymous principals fall back to IP** (`ratelimit_keys.c`). VO/ISSUER/DN
  keys with no identity degrade to `ip:<addr>`, so unauthenticated bulk clients
  are always subject to at least an IP-keyed rule (Phase 25 invariant 5,
  fail-closed coverage). DN is never used raw — it is FNV-hashed into
  `dn:<8 hex>` (`rl_key_dn_hash`) to bound key length and avoid leaking the DN.
- **Low-cardinality keys only.** Keys are dimension prefixes
  (`vo:` / `iss:` / `ip:` / `dn:<hash>` / `vol:<prefix>`), never raw paths,
  buckets, or UUIDs — consistent with the project's metric-label rule. The
  whole key is capped at `XROOTD_RL_KEY_LEN` (128 bytes).
- **All node access holds `zone->shpool->mutex`.** The `*_locked` helpers
  *require* the caller to hold it; lookup also moves the node to the LRU head.
  Never cache a node pointer across the lock — the LRU reaper may free it. W7
  release deliberately re-looks-up under the lock and tolerates a missing node
  (`ratelimit.c:144-156`).
- **Drained-excess write-back is load-bearing.** On a *throttled* request the
  code persists the drained excess (without the `+1000` charge) **and** advances
  the clock together (`ratelimit.c:72-74`). Skipping this would peg the bucket
  against a stale excess so it never drains under sustained load and serve rate
  collapses — see the in-code comment.
- **Bandwidth is charged after the fact, in two phases.** A cheap pre-check at
  dispatch/access time rejects only if the bucket is *already* overflowing
  (charges nothing); the real byte count is charged post-send. The HTTP charge
  happens in the LOG phase, not a body filter, because the WebDAV file-serve
  path uses thread-pool/sendfile that does not reliably traverse a chained body
  filter (`ratelimit_http.c:142-145`).
- **W7 concurrency slot pairing differs by plane.** HTTP reserves **one slot
  per request**, released in the LOG phase (which runs for every finalized
  request including errors/aborts, so it never leaks). Stream holds **one slot
  for the connection's lifetime**, acquired on the first matching rule and
  released exactly once in `xrootd_on_disconnect` — so the stream cap is
  concurrent-connections-per-principal, not per-request.
- **Cross-plane zone sharing via the shared tag.** Same NAME in `http{}` and
  `stream{}` = one zone (`ratelimit_zone.c` file header). Zone size is clamped
  to `XROOTD_RL_MIN_SIZE` (64 KiB); a zone-not-found at rule parse time is a
  hard config error. Reload inherits the already-initialised shared structure
  (`xrootd_rl_init_zone`), so live buckets survive `nginx -s reload`.
- **VOLUME rules are path-dependent and uncacheable.** Stream key caching skips
  VOLUME rules and rules beyond `XROOTD_RL_RULE_CACHE_MAX`; the gate only copies
  the request payload path when a VOLUME rule exists (Phase 33 C4 hot-path
  optimisation, `ratelimit_stream.c:95-106`). Only path-bearing opcodes
  (`kXR_open`/`kXR_dirlist`/`kXR_locate`) expose a usable path; handle-bearing
  read/write ops do not. A VOLUME prefix miss returns `NGX_DECLINED` so the rule
  simply does not apply.
- **Subrequests inherit the parent verdict** — the HTTP access handler returns
  `NGX_DECLINED` for `r != r->main` (`ratelimit_http.c:56`); the log handler is
  likewise a no-op for subrequests.

## Entry points / extending

- **Add a key dimension:** extend `xrootd_rl_key_type_t` (`ratelimit.h`), add a
  `case` in both `xrootd_rl_key_stream` and `xrootd_rl_key_http`
  (`ratelimit_keys.c`) with an IP fallback for the unauthenticated case, and add
  the type string to `rl_parse_key`.
- **Add a directive:** add a setter in `ratelimit_keys.c` (model on
  `rl_add_rule` / `xrootd_rl_conc_directive`) and register it in *both*
  `../stream/module.c` and `../webdav/module.c` command tables with the rules
  array `offset`.
- **Add a metric:** add an `ngx_atomic_t rl_*` field in `../metrics/metrics.h`,
  bump it with `XROOTD_RL_METRIC_INC(field)`, and export it in
  `../metrics/ratelimit.c`.
- **Limit a new stream opcode:** add it to `rl_op_rate_limited` (and
  `rl_op_path_bearing` if its payload starts with the path) in
  `ratelimit_stream.c`.

## See also

- `../handshake/README.md` — stream dispatcher that invokes the gate (`dispatch.c:64`)
- `../webdav/README.md` — HTTP method router + access/log phase registration (`postconfig.c`)
- `../read/README.md`, `../write/README.md` — call `xrootd_rl_charge_ctx` after sending bytes
- `../response/README.md` — `xrootd_send_wait` (kXR_wait framing)
- `../path/README.md` — `resolve_path` used for VOLUME-rule path matching
- `../connection/README.md` — `xrootd_on_disconnect` releases the stream concurrency slot
- `../metrics/README.md` — Prometheus export of the throttle/eviction counters
- `../dashboard/README.md` — `/xrootd/api/v1/ratelimit` snapshot endpoint
- `../types/README.md` — `xrootd_ctx_t` rate-limit fields + `tunables.h`
- `../README.md` — master subsystem index
