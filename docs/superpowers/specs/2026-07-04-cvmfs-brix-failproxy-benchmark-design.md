# CVMFS-brix vs stock cvmfs2 — failproxy resilience benchmark (design)

**Date:** 2026-07-04
**Goal:** measure whether cvmfs-brix pulls 100 real atlas.cern.ch files more reliably/faster
than the stock cvmfs2 client as HTTP-level fault rate (loss / reorder / stall) rises.

## Environment (probed)
- atlas.cern.ch reachable: CERN S1 + Cloudflare mirror `http://s1cern-cvmfs.openhtc.io` (200).
- Stock `/usr/bin/cvmfs2` + `cvmfs_config` + `mount.cvmfs` installed; `cern.ch` key on disk.
- atlas root catalog magic = `789c` → **zlib** (brix `object.c` handles it).
- **No sudo** → no `tc netem`; fault injection is **userspace** (failproxy).

## Topology
`client → failproxy (fault injection) → atlas S1 (openhtc.io mirror)`. Both clients use the
same failproxy as their HTTP proxy, cold cache each run, same 100 real atlas file paths.

## Component 1 — `tests/cvmfs/failproxy.py`
Userspace forward proxy (GET-absolute + CONNECT) relaying to atlas, injecting per-response at a
configurable rate:
- **loss:** truncate response / reset connection mid-stream,
- **reorder/corrupt:** reorder or flip response-body bytes,
- **stall:** trickle bytes / pause (throttle).
Probabilistic per response (retries eventually get a clean copy). Logs faults + request count.

## Component 2 — `tests/run_cvmfs_bench.sh`
- **Phase 0 (feasibility gates):** mount atlas cleanly (no proxy) with BOTH clients; confirm
  brix reads real atlas (fix gaps — the agreed path) and stock cvmfs2 mounts unprivileged
  (custom `CVMFS_CACHE_BASE`, no autofs). Enumerate 100 real file paths (small files).
- **Phase 1 (sweep):** fault ∈ {0,5,10,20,30,40%} × {loss,reorder,stall}; per cell, cold-cache
  each client, point at the failproxy, read the 100 files, record wall-time / success count /
  bytes / retries.
- **Report:** table + summary — the degradation curve for each client; the crossover where brix
  holds up better.

## Metrics
success rate (all 100 arrived?), wall-clock, retry/failover count. Both clients hash-verify
(content-addressed), so the differentiator is recovery behaviour (brix per-mirror retries +
fresh-connection + failover vs stock).

## Caveats (built in)
- Userspace HTTP faults, not L3 netem — a fair stand-in for a bad middlebox (the real scenario).
- brix real-atlas fidelity unproven until Phase 0; gaps get fixed (agreed) before benchmarking.
