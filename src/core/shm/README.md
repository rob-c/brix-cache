# shm — generic cross-worker key/value store and token-bucket rate limiter in nginx shared memory

## Overview

nginx runs N independent worker processes that share nothing by default, yet
several nginx-xrootd features need state that is consistent *across* workers: a
JWT/bearer validation result cached so the next request to any worker skips the
expensive crypto, an auth-decision cache shared between the stream and HTTP
planes, and a rate limit that must count a client's requests no matter which
worker accepted them. This subsystem provides the one primitive all of those
build on — a fixed-capacity, open-addressed hash table laid out in a single
nginx **shared-memory zone** (`ngx_shm_zone_t`), guarded by a per-zone spinlock —
plus a thin token-bucket limiter layered on top of it.

`shm/kv.*` is the generic store. It treats keys and values as opaque byte
buffers bounded by per-zone `key=`/`val=` maxima fixed at configuration time, so
one zone implementation serves any consumer that picks a key encoding and a value
struct. Zones are declared once in the `http{}` or `stream{}` main block with the
`xrootd_kv_zone` directive and then resolved by name by feature directives. Every
configured zone is recorded in a module-wide registry so consumer directives can
look one up (`xrootd_kv_find`) and the Prometheus exporter can iterate them all.

`shm/rate_limit.*` is the first typed wrapper: a best-effort token-bucket
admission test whose per-identity state (token count + last-refill timestamp)
lives as a 16-byte KV value, keyed by authenticated DN (stream/GSI, post-auth)
or by client IP (HTTP, before identity is known). It runs synchronously at
admission time — `NGX_OK` admits, `NGX_DECLINED` rejects — and adds no I/O or
allocation to the request path.

This subsystem sits *beside* the request lifecycle rather than inside any one
protocol handler: it is shared infrastructure (peer of `compat`, `crypto`, and
`metrics`). Its consumers are the token cache
([../token/token_cache.c](../token/token_cache.c)), the auth-result cache
([../path/auth_cache.c](../path/auth_cache.c) / `auth_gate.c`), the GSI/stream
rate-limit entry point ([../gsi/auth.c](../gsi/auth.c)), the HTTP rate-limit
entry point (`../webdav/access.c`), and the metrics writer
([../metrics/writer.c](../metrics/writer.c)) which exports each zone's counters.

## Files

| File | Responsibility |
|---|---|
| `kv.h` | Public API + the process-local `xrootd_kv_t` handle and the `xrootd_kv_stats_t` snapshot type. Declares `xrootd_kv_configure/get/set/delete/stats`, the zone-registry accessors (`xrootd_kv_find`, `xrootd_kv_zone_count`, `xrootd_kv_zone_get`), and the `xrootd_kv_zone_directive` setter. Intentionally depends only on `<ngx_config.h>`/`<ngx_core.h>` so it can be embedded in per-module config structs without an `ngx_xrootd_module.h` include cycle. |
| `kv.c` | The store implementation: shared-segment layout (`xrootd_kv_header_t` + a flat array of `xrootd_kv_entry_t`), FNV-1a 64-bit hashing, linear-probing get/set/delete with backward-shift (tombstone-free) deletion, lazy TTL expiry, the module-level `xrootd_kv_zones[]` registry, zone init/attach on (re)load (`xrootd_kv_init_zone`), and the `xrootd_kv_zone` directive parser. |
| `rate_limit.h` | `xrootd_rate_limit_conf_t` (per-conf settings: resolved zone handle, rate, burst, key-by-DN-or-IP) and the `xrootd_rate_limit_check` / `xrootd_rate_limit_directive` declarations. |
| `rate_limit.c` | Token-bucket logic: derive the `"rl:"`-prefixed key, read the bucket from the KV zone, refill proportional to elapsed time, decrement-and-store with an idle-eviction TTL; plus the `xrootd_rate_limit` directive parser. |

## Key types & data structures

- **`xrootd_kv_t`** (`kv.h`) — the *process-local* handle. Allocated from the
  config pool, persists for the process lifetime, and is pointed at by consumer
  conf fields. Holds the zone name (used as the Prometheus `zone="..."` label),
  the `ngx_shm_zone_t *`, a per-process `ngx_shmtx_t` handle to the shared lock,
  and the configured `size`/`key_max`/`val_max`. The actual shared state lives at
  `kv->zone->shm.addr`, *not* in this struct.
- **`xrootd_kv_header_t`** (`kv.c`, shared) — the first object in the zone's
  segment. Its `ngx_shmtx_sh_t lock` **must be the first member** because
  `ngx_shmtx_create` takes the address of the header as the lock target. Also
  holds the live `count`, the `hits`/`misses`/`evictions` counters, and the
  layout parameters `capacity` (power of two)/`key_max`/`val_max`.
- **`xrootd_kv_entry_t`** (`kv.c`, shared) — one bucket. Stores the 64-bit FNV-1a
  `hash`, `key_len` (`0` means the slot is free — there is no separate occupancy
  flag), `val_len`, and `expires` (an `ngx_current_msec` deadline; `0` = never).
  The key bytes (`key_max` wide) and value bytes (`val_max` wide) follow the
  struct inline, so the per-entry **stride** is
  `sizeof(entry) + key_max + val_max`.
- **`xrootd_kv_stats_t`** (`kv.h`) — a snapshot of `hits`/`misses`/`evictions`/
  `count`/`capacity` taken under the lock and returned to the (lock-free) caller
  for Prometheus export.
- **`xrootd_rate_limit_conf_t`** (`rate_limit.h`) — per-location/per-server
  limiter settings: the resolved `xrootd_kv_t *kv` (NULL = disabled), `rate`
  (sustained req/s), `burst` (bucket capacity), and `key_ip` (0 = key by DN,
  1 = key by client IP).
- **`xrootd_rl_val_t`** (`rate_limit.c`, the KV value) — `{ uint32_t tokens;
  ngx_msec_t last_refill; }`, 16 bytes, stored under a `"rl:" + id` key.

## Control & data flow

**Configuration time.** `xrootd_kv_zone <name> <size> key=<bytes> val=<bytes>;`
is parsed by `xrootd_kv_zone_directive`, valid in either the `http{}` or
`stream{}` main block (it picks `&ngx_http_xrootd_webdav_module` or
`&ngx_stream_xrootd_module` from `cf->cmd_type`). Both directive tables register
it (`webdav/module.c:685`, `stream/module.c:960`). The setter allocates an
`xrootd_kv_t` from `cf->pool` and calls `xrootd_kv_configure`, which registers the
segment via `ngx_shared_memory_add`, sets the `init` callback to
`xrootd_kv_init_zone`, and appends to the module-wide `xrootd_kv_zones[]`
registry (cap `XROOTD_KV_MAX_ZONES` = 16; size clamped up to `XROOTD_KV_MIN_SIZE`
= 64 KiB). Feature directives such as `xrootd_rate_limit`, `xrootd_token_cache`,
and `xrootd_auth_cache` then run *after* and resolve their zone by name with
`xrootd_kv_find`, each validating that the zone's `val_max` (and where relevant
`key_max >= 32`) is large enough for their value struct — failing config if not.

**Zone init / reload.** `xrootd_kv_init_zone` runs when nginx maps the segment.
On a fresh segment it zeroes the header, creates the spinlock, computes
`capacity` as the largest power of two of entries that fit (so
`hash & (capacity-1)` selects the home bucket with no modulo), and records the
layout. On reload or attach-to-existing (`okv != NULL || shm.exists`) it only
re-creates this process's handle to the already-initialized shared lock — it does
**not** re-lay-out live data.

**Runtime data path.** Consumers call `xrootd_kv_get`/`xrootd_kv_set`/
`xrootd_kv_delete` directly. Each op takes the zone spinlock, performs a single
bounded linear-probe sequence (capped at `capacity/2` probes), and releases it;
there is no I/O or allocation inside the critical section. `get` lazily evicts an
entry it finds expired and reports a miss. Token caching
([../token/token_cache.c](../token/token_cache.c)) keys by a 32-byte token
fingerprint and stores the whole `xrootd_token_claims_t`, with a TTL derived from
the token's own `exp` and capped at `XROOTD_TOKEN_CACHE_MAX_TTL_MS` (5 min);
auth caching ([../path/auth_cache.c](../path/auth_cache.c)) stores
`xrootd_auth_cache_val_t` with a short configured TTL (default 30 s).

`xrootd_rate_limit_check` is called at admission: it loads the bucket (defaulting
to a full bucket if absent), refills by elapsed time, and either
decrements-and-admits (`NGX_OK`) or rejects (`NGX_DECLINED`). Callers turn
`NGX_DECLINED` into the appropriate protocol response — stream `kXR_wait` from
[../gsi/auth.c](../gsi/auth.c) (keyed by authenticated DN), HTTP 429 from
`../webdav/access.c` (keyed by client IP). (The richer leaky-bucket / bandwidth /
concurrency limiter lives in [../ratelimit/](../ratelimit/); this
`shm/rate_limit.c` is the simple per-request token-bucket variant.)

**Export.** [../metrics/writer.c](../metrics/writer.c) (`xrootd_kv_metrics_emit`)
iterates `xrootd_kv_zone_count()` / `xrootd_kv_zone_get(i)`, calls
`xrootd_kv_stats`, and emits `xrootd_kv_hits_total{zone="..."}` and its siblings.

## Invariants, security & gotchas

- **Lock-first layout is load-bearing.** `xrootd_kv_header_t.lock`
  (`ngx_shmtx_sh_t`) must remain the first member (`kv.c:30`); `ngx_shmtx_create`
  takes the address of the header as the lock. Reordering it silently corrupts
  locking.
- **0.5 load-factor cap, by design.** `xrootd_kv_set` refuses to insert a *new*
  key once `count >= capacity/2` (`kv.c:319`), and every op probes at most
  `capacity/2` slots. This bounds worst-case probe length and keeps the table a
  cache, not a guaranteed store — a full zone fails `set` with `NGX_ERROR`;
  callers must treat caching as best-effort and re-derive on miss. **Sizing a
  zone for K live entries therefore needs roughly 2×K capacity worth of bytes.**
- **No background sweeper — expiry is lazy.** A TTL'd entry is only reclaimed when
  a `get`/probe lands on it (`kv.c:262`). An expired entry still occupies a slot
  (and counts against the load factor) until something touches it. The rate
  limiter mitigates this by writing an idle-eviction TTL so abandoned buckets age
  out the next time their slot is probed.
- **Tombstone-free deletion.** Removal uses Knuth Algorithm R backward-shift
  (`xrootd_kv_remove_at`, `kv.c:119`) so probe chains stay contiguous — there are
  no tombstones to degrade lookups over time. `xrootd_kv_should_shift` encodes the
  cyclic-interval test deciding whether a following entry may legally fill the
  hole; this is the subtle part — do not "simplify" it.
- **Best-effort across-worker counting.** `xrootd_rate_limit_check` does a
  separate `get` then `set` (two lock acquisitions), so under high concurrency a
  small over-admission is possible (`rate_limit.h:5`). This is intentional and
  acceptable for throttling; do not assume exact accounting.
- **Truncation, not error, on oversized reads.** `xrootd_kv_get` copies
  `min(val_len, *out_len)` and updates `*out_len`; a too-small output buffer
  silently truncates. `set` *rejects* (`NGX_ERROR`) keys/values exceeding the zone
  maxima rather than truncating.
- **Refill keeps fractional remainder.** When elapsed time has not yet produced a
  whole token, `last_refill` is left untouched (`rate_limit.c:100-109`) so the
  fraction accumulates across calls instead of being discarded each check.
- **Low-cardinality metric labels only.** Zones are labeled by name; the rate
  limiter keys by DN or IP internally, but those identities never become metric
  labels — keep it that way (project invariant: no paths/DNs/UUIDs in labels).
- **Header is intentionally lightweight.** `kv.h` includes only nginx core
  headers (not `ngx_xrootd_module.h`) so it can be embedded in `types/config.h`
  and `webdav/webdav.h` without an include cycle (`kv.h:24`). Keep stream/http
  symbols out of it; `kv.c` itself pulls the full `ngx_xrootd_module.h`.

## Entry points / extending

- **Add a new KV-backed feature (a typed wrapper):** define your value struct,
  pick a key encoding (prefix it like `rate_limit.c`'s `"rl:"` to avoid colliding
  with other consumers sharing a zone), add a directive setter that resolves the
  zone with `xrootd_kv_find` and validates `kv->val_max >= sizeof(your_val)`
  (see `xrootd_token_cache_directive` / `xrootd_auth_cache_directive` / this
  subsystem's `xrootd_rate_limit_directive` as templates), then use
  `xrootd_kv_get`/`xrootd_kv_set` on the hot path. Store the resolved
  `xrootd_kv_t *` in your module conf.
- **Register the source file:** any new `.c` in this directory must be added to
  `NGX_ADDON_SRCS` in the top-level `config` file (where `src/core/shm/kv.c` and
  `src/core/shm/rate_limit.c` already appear) and rebuilt with `./configure`.
- **Add a directive to an existing wrapper:** wire it through the module's
  `ngx_command_t` table in `webdav/module.c` / `stream/module.c` (which already
  register `xrootd_kv_zone` and `xrootd_rate_limit`), then parse it in the
  corresponding `_directive` setter.
- **Expose per-zone stats:** they are already exported automatically by
  `xrootd_kv_metrics_emit` in [../metrics/writer.c](../metrics/writer.c) for every
  registered zone — no per-feature wiring needed.

## See also

- [../token/README.md](../token/README.md) — JWT/bearer validation cache built on a KV zone.
- [../path/README.md](../path/README.md) — auth-result cache (`auth_cache.c`/`auth_gate.c`) built on a KV zone.
- [../ratelimit/README.md](../ratelimit/README.md) — the full leaky-bucket / bandwidth / concurrency limiter (this dir is the simple token-bucket variant).
- [../metrics/README.md](../metrics/README.md) — Prometheus exporter that emits per-zone KV counters.
- [../config/README.md](../config/README.md) — directive parsing and conf-merge conventions.
- [../README.md](../README.md) — master subsystem index.
