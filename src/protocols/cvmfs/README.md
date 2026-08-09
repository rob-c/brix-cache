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

### Other files

| File | Responsibility |
|---|---|
| `attest.c` | since this proxy VERIFIES every CAS byte it serves (phase-85 F1), it can attest exactly which content hashes a job consumed. |
| `bundle.c` | POST /cvmfs/<repo>/.cvmfs-bundle (gated brix_cvmfs_bundle, default off): the body is a newline-separated want-list of repo-relative CAS paths ("data/<2hex>/<hex>[sfx]"); the response streams every CACHE-RESIDENT member b. |
| `cvmfs_module_build.c` | The two functions that run only when a location has brix_cvmfs on: - brix_cvmfs_reject_unsupported — EMERG at config load for storage grammar cvmfs cannot honour (staging, CAS slicing, explicit writes). |
| `cvmfs_module_georank.c` | The config-parse-time helpers that turn geographic directives into backend origin ranks and allow-list state: 1. |
| `cvmfs_module_internal.h` | Declares the handful of former-static entry points that the cvmfs module's directive table, config-merge orchestrator, and export-build step call across the translation units they were split into (module.c ↔ cvmfs_module. |
| `cvmfs_module_merge.c` | The four per-concern merge-field helpers and the orchestrator that sequences them: - cvmfs_merge_preamble — adopt unified directives, merge enable, pre-seed the CAS verify default, run the shared common.* merge. |
| `delta.c` | a CAS data GET carrying `X-Brix-Delta-Base: <40-hex>` (the sha1 of a CAS object the client already holds — typically the revision-N catalog while fetching the N+1 catalog) may be answered as a zstd DELTA of the target ag. |
| `dict.c` | GET/HEAD /cvmfs/<repo>/.cvmfs-dict/(current\|<40-hex id>) (gated brix_cvmfs_dict, default off): lazily train a zstd dictionary per worker from a bounded sample of this repo's CACHE-RESIDENT CAS objects and serve it with i. |
| `directives_core.h` | cvmfs core directives (scvmfs:// secure layer, manifest/negative TTL, quarantine, upstream allow/max, trace, per-protocol tier) #included into ngx_http_brix_cvmfs_commands[] in cvmfs/module.c (compiler concatenates; sett. |
| `directives_resilience.h` | cvmfs origin resilience directives (origin selection/geo-coords, upstream stall detection + force-through retry, server-side geo answering) #included into ngx_http_brix_cvmfs_commands[] in cvmfs/module.c (compiler concat. |
| `handler_finalize.c` | the pool-cleanup observer handler.c registers on every request, plus its edge helpers: session-log close-out, the optional one-line client trace, and the T16 fill/hit metric accounting — all keyed off the FINAL response. |
| `learn.c` | a passive per-worker Markov model of CAS access sequences ("a GET of X on this connection is followed by Y"), and an advisory prewarm that fills the predicted successors through the cache-fill seam before they are reques. |
| `scrub.c` | a repeating worker-0 timer walks the cvmfs cache store in bounded windows and re-runs the cvmfs-cas verify (name-hash == byte-hash) on resident CAS objects; a mismatch is evicted so the next access re-fills verified from. |
| `secure_internal.h` | cvmfs/secure_internal.h — shared seam between secure.c and secure_x509.c. |
| `secure_x509.c` | The `brix_scvmfs_authz x509` and `authz voms` back-ends — locate the end-entity cert behind any RFC 3820 proxy chain, glob-gate its subject DN (brix_scvmfs_x509_dn), and, in VOMS mode, glob-gate the extracted VO/FQAN set. |
| `swarm.c` | generalizes the phase-85 F8 sibling mesh from a static brix_cache_peers ring to gossip-maintained membership: every node serves its member view at /cvmfs/.swarm/roster, periodically pulls a random member's roster (the pu. |
| `swarm_gossip.c` | the bounded plain-socket roster probe (thread pool), the live-ring rebuild + publish, the gossip lifecycle timers, and the per-worker init that arms them. |
| `swarm_internal.h` | the membership types, per-process registration/context tables, and former-static entry points shared between swarm.c (registration, membership core, roster wire format, roster endpoint) and swarm_gossip.c (probe thread t. |
| `virtual.c` | brix_cvmfs_virtual_repo <virtual-fqrn> <member-fqrn>.. |

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

- [../shared/](../shared/) — `src/protocols/shared/http_cache_fill.c`, the coalescing fill engine
- [../../fs/cache/](../../fs/cache/) — src/fs/cache/verify.c (cvmfs-cas) and the cache tier
- [../../../docs/04-protocols/](../../../docs/04-protocols/) — protocol-level docs
