# Unified Caching Layer — Design Spec

**Date:** 2026-06-29
**Status:** Approved for planning
**Builds on:** [unified cache state engine (.cinfo v3)](2026-06-28-unified-cache-state-engine-design.md), [cache storage on a driver](2026-06-29-cache-storage-on-a-driver-design.md), the SD driver seam (`src/fs/backend/sd.h`), `src/fs/cache/`, `src/ratelimit/`, `src/metrics/unified.c`.

## Goal

Turn `src/fs/cache/` into a single, origin-agnostic caching layer: a **read-through + caching** front for remote `root://`, `s3://`, and `http(s)://` (WebDAV) filesystems, with a **watermark-driven LRU reaper** (background timer, dedicated Prometheus metrics) and **two-tier backpressure** that throttles incoming writes when the write-back staging area fills.

## The unifying idea

Two earlier phases already made the **local cache storage** an SD instance (`xrootd_sd_instance_t`). This work makes the **remote origin** an SD instance too. Once both sides of the cache are SD instances, the cache collapses to **driver→driver copies**:

- **Read-through fill** = `remote_origin->pread` → `cache_storage->staged_write` → `staged_commit`. Origin-agnostic; replaces today's scheme-switch (`root://` via `origin_protocol.c`, `http(s)` via `http_transport.c`, GSI via `xrdcp`-exec) inside `fetch.c`.
- **Write-back flush** = `cache_storage->pread` → origin. Already built and FRM-journaled; **kept as-is** this cycle. Converging the flush onto a writable remote driver is an explicit non-goal here (see Non-goals).

That is the "fold both ways": one driver seam underneath, one caching layer on top, whether a plane is local or remote.

## Global constraints (copied from the repo rules)

- **No `goto`** in `src/`, `shared/`, `client/`; early-return + helper decomposition.
- **Functional/modular:** one responsibility per function, explicit state (no new globals), table/descriptor-driven dispatch over branch ladders.
- **All data byte I/O routes through `src/fs/backend/` via the SD driver seam** — no raw libc disk calls in the cache data path. The remote origin is itself an SD driver, so origin reads obey the same rule.
- **3 tests per change:** success + error + security-negative.
- New `.c` files register in the top-level `./config` (then `rm -rf objs && ./configure && make`).
- New concepts ship with docs + tests in the same change.
- The operator drives all git commits.

---

## Component B — Watermark-driven LRU reaper *(built first)*

### What exists
`evict_policy.c` already does a **two-pass LRU, oldest-first** purge keyed on `statvfs` occupancy, driver-aware after Phase 2 (`collect_dir` enumerates via `inst->driver->opendir/readdir/stat`; dirty write-back files are skipped). It is triggered **reactively, on fill**, against a single `cache_eviction_threshold` (ppm). There is no proactive timer, no high/low hysteresis, and no dedicated eviction metric.

### What changes
1. **High/low watermark with hysteresis.** Add `xrootd_cache_high_watermark` and `xrootd_cache_low_watermark` (percent, 1–99, `high > low`). A purge starts only when occupancy `> high` and runs until occupancy `≤ low`. `cache_eviction_threshold` remains accepted and maps to `high` (with `low = high − 5%` if `low` is unset) for back-compat.
2. **Background reaper timer.** A per-worker timer (template: the existing stale-dirty reaper in `cache_reap.c` + its `process.c` arming) calls the watermark purge every `xrootd_cache_reap_interval` (default 60s), independent of fills. The on-fill check (`evict_if_needed`) stays as a fast safety net for burst fills between ticks.
3. **Cross-worker coordination.** Only one worker may purge the shared cache tree at a time: a `flock`-held reap-lockfile under the state root plus small per-worker startup jitter prevents a stampede. A worker that cannot take the lock skips the tick.
4. **Fullness sampler (shared infra).** A tiny helper `xrootd_cache_fs_usage_cached(root, ttl_ms, *ratio)` wraps `statvfs` with a short per-worker TTL cache so neither the timer nor Component C calls `statvfs` per-operation.

### New files / touch points
- `src/fs/cache/reap_watermark.c` (+ prototypes in `cache_internal.h`): `xrootd_cache_watermark_purge(conf, log)` — sample → if over high, loop `evict_one` oldest-first until `≤ low` or no candidates — and the timer handler. (`evict_candidates.c`/`evict_policy.c` provide the reusable collection/sort/`evict_one` already.)
- `src/fs/cache/fs_usage.c` (+ header): the TTL-cached `statvfs` sampler, shared with Component C.
- `process.c`: arm the reaper timer per worker (gated on a cache + watermarks configured).
- `src/core/config/` + `src/stream/module.c`: directives `xrootd_cache_high_watermark`, `xrootd_cache_low_watermark`, `xrootd_cache_reap_interval`; merge + EMERG validation (`0 < low < high < 100`).

### Metrics (the "unique XCache-style" family) — `src/metrics/unified.c`
- `xrootd_cache_usage_ratio` — **gauge**, current cache_root occupancy (0–1).
- `xrootd_cache_evicted_bytes_total{reason}` — **counter**, `reason="watermark"` for proactive purges, `reason="fill"` for the on-fill safety net.
- `xrootd_cache_evicted_files_total{reason}` — **counter**.
- `xrootd_cache_purge_runs_total` — **counter**, one per purge that did work.

Labels stay low-cardinality (no paths/keys), per the metrics invariant.

### Tests
- **Success:** fill a cache past `high`; assert the timer purges oldest-first to `≤ low`, newest files survive, and `evicted_bytes_total{reason="watermark"}` + `usage_ratio` move correctly.
- **Error:** a `statvfs` failure / unreadable cache dir degrades to a logged WARN, no crash, no spurious purge.
- **Security-negative:** a **dirty** write-back file over the watermark is **never** reaped (write-back durability beats space reclamation); purge confined to cache_root (no escape via symlink).

---

## Component C — Staging-fullness backpressure *(built second)*

### What exists
`src/ratelimit/` can already shed stream (`kXR_wait`) and HTTP (`429`) load via `ratelimit_stream.c` / `ratelimit_http.c` + `reservation.c`. Phase 2 added the write-back **staging** SD instance (`cache_wt_stage_root`). Nothing connects staging fullness to admission.

### What changes
1. **Fullness signal = `statvfs` on the stage filesystem** (chosen), via the same `xrootd_cache_fs_usage_cached` sampler (short TTL → not per-open).
2. **Two-tier admission gate.** New `xrootd_wt_stage_admit(conf)` → `XROOTD_WT_ADMIT_{ALLOW,WAIT,REJECT}`:
   - occupancy `< low` → **ALLOW**.
   - `low ≤ occupancy < high` (soft band) → **WAIT** (backpressure).
   - occupancy `≥ high` → **REJECT** until it drains below `low` (hysteresis).
3. **Enforcement at write-open only — reads always flow.**
   - `root://`: in `src/read/open_resolved_file.c` on the `is_write` path — `WAIT` → `kXR_wait` (server-directed retry delay); `REJECT` → `kXR_Overloaded`.
   - WebDAV/S3 `PUT`: in the respective PUT handlers — `WAIT` → `503` with `Retry-After`; `REJECT` → `429`.
   - The gate runs **before** a staging temp/object is created, so a rejected write never consumes staging space.

### New files / touch points
- `src/fs/cache/stage_admit.c` (+ prototypes): `xrootd_wt_stage_admit()` + the action enum; pure decision over the sampler + conf.
- `src/read/open_resolved_file.c`, WebDAV `put.c`, S3 `put.c`: call the gate on write-open/PUT, map the verdict to the protocol-correct response.
- `src/core/config/` + `src/stream/module.c` (+ WebDAV/S3 directive plumbing where the cache is configured): `xrootd_wt_stage_high_watermark`, `xrootd_wt_stage_low_watermark`; merge + EMERG validation. No-op unless a staging root is configured.

### Metrics — `src/metrics/unified.c`
- `xrootd_wt_stage_usage_ratio` — **gauge**, staging occupancy (0–1).
- `xrootd_wt_stage_throttled_total{action="wait|reject"}` — **counter**.

### Tests
- **Success:** drive staging across `low` then `high`; assert ALLOW → `kXR_wait`/`503` → `kXR_Overloaded`/`429`, and recovery to ALLOW once drained below `low`; assert the counters.
- **Error:** a `statvfs` failure fails **open** (ALLOW) with a WARN — a monitoring fault must not wedge all writes.
- **Security-negative:** **reads are never throttled** by staging fullness; a rejected write created **no** staging artifact.

---

## Component A — Remote-origin driver *(built last; the larger refactor)*

### What changes
Introduce a read-only **remote SD driver** so the cache origin is an `xrootd_sd_instance_t`, and rewrite `fetch.c`'s fill as a driver→driver copy.

1. **New driver** `src/fs/backend/sd_remote.c` — `xrootd_sd_driver_t name="remote"`, `caps = XROOTD_SD_CAP_RANGE_READ` only (no `CAP_FD`/`SENDFILE`/write caps → it can never be mistaken for a writable export primary; the write vtable slots are `NULL`). Implements `init/cleanup`, `open`, `close`, `pread` (+ optional `preadv`), `fstat`, `stat`, and optionally `opendir/readdir/closedir` (deferred — listing-cache is a follow-on). The instance holds the parsed origin URL + credentials; `open` returns an `xrootd_sd_obj_t` carrying the per-fetch transport handle.
2. **Scheme dispatch to transports.** The driver picks a transport by URL scheme:
   - `root://` / `roots://` → wrap the existing `src/fs/cache/origin/origin_protocol.c` XRootD wire client.
   - `http://` / `https://` / `davs://` → wrap the existing `src/fs/cache/origin/http_transport.c` (libcurl).
   - `s3://` → **new** `src/fs/cache/origin/s3_transport.c` (libcurl + **SigV4 reused from `shared/xrdproto`**). This is the only missing protocol.
3. **`fetch.c` becomes origin-agnostic.** The whole-file/slice fill opens the remote object via the origin instance and `pread`s into the Phase-2 staged-write sink (`cache_storage->staged_write` → `staged_commit`), keeping commit-then-verify-checksum-then-evict-on-mismatch. The GSI `xrdcp`-exec path is retained only as a fallback for an origin the in-process transports cannot authenticate (documented), not as a primary route.
4. **Config.** Extend `xrootd_cache_origin` to accept a full URL (`root://`, `s3://`, `https://`); a bare `host:port` stays back-compat (implies `root://`). Reuse `cache_origin_tls`/bearer/GSI knobs; add `xrootd_cache_origin_s3_{access_key,secret_key,region}` (and `_endpoint` for non-AWS). Credentials load via the existing credfile-hardening helpers.
5. **Threading.** The remote driver's blocking ops run **only** in the existing thread-pool fill worker (matching today's blocking origin I/O); they are never called on the event loop.

### New files / touch points
- `src/fs/backend/sd_remote.c` + registration in the driver registry; `./config`.
- `src/fs/cache/origin/s3_transport.{c,h}` + `./config`.
- `fetch.c` / `slice_fill.c`: replace the scheme-switch with the origin-instance copy.
- `src/core/config/` + directive plumbing for the origin URL + S3 creds.

### Metrics — `src/metrics/unified.c`
- `xrootd_cache_origin_fetch_bytes_total{scheme}` — **counter** (`scheme="root|s3|http"`).
- `xrootd_cache_origin_fetch_errors_total{scheme}` — **counter**.

### Tests
- **Success:** S3-origin fill byte-exact (multi-part object), and `root://` + `http(s)` parity through the unified driver path (existing origin tests must stay green).
- **Error:** origin not-found → `kXR_NotFound`/404 mapped correctly; mid-fetch origin error aborts the staged write (no partial committed entry).
- **Security-negative:** the remote driver rejects being used as a writable export primary (write slots `NULL` → capability check); S3 SigV4 credentials never appear in logs (sanitized); origin TLS verification honored.

---

## Non-goals (this cycle)

- Converging the **write-back flush** onto a writable remote driver — the flush stays on its current FRM-journaled origin-client path. (Follow-on once the read-side remote driver is proven.)
- A **listing cache** (remote `opendir/readdir`) — the remote driver may stub these initially.
- Cross-node / shared-cache coordination beyond the single-host `flock` reap lock.
- Changing the on-disk `.cinfo`/`.meta` formats.

## Architecture summary

```
            ┌──────────────────────────── cache layer (src/fs/cache/) ───────────────────────────┐
 client ──▶ │  read:  remote_origin->pread  ──▶  cache_storage->staged_write ──▶ staged_commit │ ──▶ client
            │  write: client ──▶ cache_storage (primary)  ──▶ stage copy ──▶ origin (FRM flush) │
            │                                                                                   │
            │  reaper timer ─▶ watermark_purge(cache_root)      [B]                             │
            │  write-open ───▶ stage_admit(stage_root)          [C]                             │
            └──────────────────────────────────┬────────────────────────────────────────────────┘
                                                ▼
          SD driver seam (src/fs/backend/):  posix | block(pblock) | remote(root/s3/http) [A]
                                                ▲
                      shared fs_usage sampler (statvfs + TTL)  ── feeds B and C
```

## Sequencing

**B → C → A.** B and C are small, high-operational-value, and build directly on finished Phase-2 plumbing; A is the larger refactor and goes last. Each phase is independently shippable and independently tested. The shared `fs_usage` sampler is introduced in B and reused by C.

## Validation gate (per phase)

Unit harnesses (cinfo 81 / cache_admit 11 / cache_storage) stay green; the cache pytest group + pblock/cache e2e stay green; the VFS seam guard stays green; each phase adds its own success/error/security-negative tests and metric assertions.
