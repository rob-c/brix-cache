# cvmfs — the cvmfs:// site cache (+ experimental scvmfs:// TLS variant)

## Overview

A CVMFS site cache: clients (Frontier/CVMFS HTTP clients, or the native
brixMount cvmfs client) hit an `brix_cvmfs`-enabled location, and the
server proxies + caches content-addressed objects from upstream stratum
origins. The server side is a transparent byte proxy — CVMFS semantics
(catalogs, signatures) live in the client; here the job is fast, resilient,
verified object delivery.

`module.c` owns the config lifecycle and installs the location handler;
`handler.c` is the request entry point. A request passes `secure.c`
(transport + client-authz gate) then `gate.c` (access restriction), is
classified (`classify.h`), and is forwarded by `geo.c` to an upstream
chosen by measured RTT ranking (`geo_answer.c`), with haversine
distance + stable argsort (`origin_geo.c`) as the geographic prior and a
repeating per-worker probe timer (`origin_probe.c`) keeping latencies
fresh. `upstreams.c` maps each `(host, port)` upstream to a synthetic VFS
backend export, so fills flow through the standard cache tier
(`src/protocols/shared/http_cache_fill.c` — coalescing + hold timers) and
objects are verified content-addressed (`src/fs/cache/verify.c`,
cvmfs-cas).

Operational resilience: stall detection (connect + low-speed timeouts),
force-primary retry, stale-if-error serving, and single-line operational
logging of fill/origin/client events (retry / recovered / hold-expired /
client-gone / degraded / absorbed-404).

## Files

| File | Responsibility |
|---|---|
| `module.c` | config lifecycle (create/merge loc_conf), directive table, handler install |
| `handler.c` | request entry point for every `brix_cvmfs` location |
| `secure.c` | transport + client-authz gate (runs before the cvmfs gate) |
| `gate.c` | access restriction: first step of the dedicated handler |
| `classify.h` | request classification constants |
| `request.c` | absolute-form request-line handling |
| `geo.c` | forward the classified request (with query string) to the chosen upstream |
| `geo_answer.c` | measured-RTT upstream ranking (port-guard 80/443/8000) |
| `origin_geo.c` / `origin_geo.h` | haversine great-circle distance + stable argsort |
| `origin_probe.c` | repeating per-worker timer measuring origin latencies |
| `upstreams.c` | map (host, port) → synthetic VFS backend export |
| `cvmfs.h` | loc-conf + request-ctx types; handler/gate/geo APIs |

## Invariants, security & gotchas

1. Objects are content-addressed: cache verification (cvmfs-cas) must pass
   before a fill is served — a hash mismatch is a fill failure, never a
   serve.
2. Config-parse NOTICE logs are dropped (`cf->log` = ERR) — use WARN for
   anything an operator must see at startup.
3. A broken upstream connection mid-fill maps to the right client error
   (EIO ≠ ENOENT — a torn connection must not become a 404).
4. Storage directives are the unified `brix_export`/`brix_cache_store`
   family owned by `src/core/config/http_common.c` — nothing cvmfs-private.

## See also

- [../shared/](../shared/) — `http_cache_fill.c`, the coalescing fill engine
- [../../fs/cache/](../../fs/cache/) — verify.c (cvmfs-cas) and the cache tier
- [../../../docs/04-protocols/](../../../docs/04-protocols/) — protocol-level docs
