# Unified Caching Layer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `src/fs/cache/` an origin-agnostic caching layer (root/s3/http remote origins) with a watermark-driven LRU reaper (background timer + dedicated metrics) and two-tier staging backpressure on writes.

**Architecture:** Both the local cache storage and the remote origin are SD instances (`xrootd_sd_instance_t`); the cache is driver→driver copies. A shared `statvfs`+TTL fullness sampler feeds the reaper (cache_root) and the staging gate (stage_root).

**Tech Stack:** nginx C module, SD driver seam (`src/fs/backend/sd.h`), libcurl (http/s3 transports), `shared/xrdproto` SigV4, nginx event timers, SHM metrics (`src/observability/metrics/unified.c`).

## Global Constraints

- **No `goto`** anywhere in `src/`/`shared/`/`client/`; early-return + helper decomposition.
- **Functional/modular:** one job per function, explicit state (no new globals beyond the existing per-worker timer pattern), table/descriptor dispatch over branch ladders.
- **All cache data byte I/O routes through the SD driver seam** — the remote origin is an SD driver too.
- **3 tests per change:** success + error + security-negative.
- New `.c` files register in the top-level `./config`, then `rm -rf objs && ./configure && make`.
- Metric labels stay low-cardinality (no paths/keys/UUIDs).
- The operator drives all git commits — no git operations.
- Watermarks are **percent** (1–99, `high > low`); `xrootd_cache_fs_usage` reports `occupancy_ppm` (0–1000000), so `pct → ppm = pct*10000`.

---

# Phase B — Watermark-driven LRU reaper

**Interfaces produced:**
- `xrootd_cache_fs_usage_sampled(const char *root, ngx_msec_t ttl, xrootd_cache_fs_usage_t *out)` — TTL-cached `statvfs` (per-worker).
- `ngx_uint_t xrootd_cache_watermark_purge(ngx_stream_xrootd_srv_conf_t *conf, ngx_log_t *log)` — purge oldest-first from `> high` to `≤ low`; returns files evicted.
- Config fields: `cache_high_watermark`, `cache_low_watermark` (ppm), `cache_reap_interval` (sec).

### Task B1: Shared TTL fullness sampler

**Files:**
- Create: `src/fs/cache/fs_usage.c`
- Modify: `src/fs/cache/evict_internal.h` (declare `xrootd_cache_fs_usage_sampled`)
- Modify: `./config` (register `fs_usage.c`)
- Test: `tests/c/test_fs_usage.c`, `tests/c/run_fs_usage_tests.sh`

- [ ] **Step 1: Failing unit test.** Two calls within `ttl` return the same cached snapshot (one `statvfs`); a call after `ttl` re-samples. Use a tiny injectable clock or a 0-ms ttl to force re-sample. Assert `occupancy_ppm` is in `[0,1000000]` for `/tmp`.
- [ ] **Step 2:** Run `tests/c/run_fs_usage_tests.sh` → FAIL (symbol missing).
- [ ] **Step 3: Implement.** Per-worker static cache keyed by `root` string (small fixed table, ≤8 roots) holding `{root, last_ms, usage}`. On call: if `now - last_ms < ttl` and root matches → return cached; else `xrootd_cache_fs_usage(root,&u)` + stamp. Pure libc + `ngx_current_msec`. No allocation.
- [ ] **Step 4:** Run the harness → PASS.

### Task B2: Watermark config directives

**Files:**
- Modify: `src/core/types/config.h` (`cache_high_watermark`, `cache_low_watermark`, `cache_reap_interval` — `ngx_uint_t`, `NGX_CONF_UNSET_UINT`)
- Modify: `src/stream/module.c` (3 `ngx_command_t`: `xrootd_cache_high_watermark`, `_low_watermark` as percent parsers → store ppm; `xrootd_cache_reap_interval` seconds)
- Modify: `src/core/config/server_conf.c` (init UNSET; merge with defaults: high=`cache_eviction_threshold` if set else 900000 ppm, low=high−50000, interval=60)
- Modify: `src/core/config/runtime_server.c` (EMERG validation: `0 < low < high < 1000000`)

- [ ] **Step 1: Failing config test.** A `nginx -t` config fixture with `low ≥ high` must fail with the EMERG message; a valid one must pass. (Shell: write conf, run `objs/nginx -t`, assert exit/stderr.)
- [ ] **Step 2:** Run → FAIL (directive unknown).
- [ ] **Step 3: Implement** the percent→ppm parsers (reuse the `_eviction_threshold` ppm parser shape in `directives.c`), merge defaults, and the validation block. Back-compat: when only `cache_eviction_threshold` is set, derive watermarks from it.
- [ ] **Step 4:** Run → PASS. `./configure` only if a new top-level block (none here) — incremental `make`.

### Task B3: Watermark purge core (refactor eviction to a conf-based target loop)

**Files:**
- Create: `src/fs/cache/reap_watermark.c`
- Modify: `src/fs/cache/evict_policy.c` — extract the list-build + two-pass loop into `xrootd_cache_purge_to_target(conf, ctx_or_null, protect_path, target_ppm, log, *files, *bytes)`; `evict_if_needed` becomes a thin caller (`target = threshold`).
- Modify: `src/fs/cache/evict_internal.h` (declare the core + the ctx-optional metric path)
- Modify: `./config`
- Test: `tests/run_cache_watermark.sh`

- [ ] **Step 1: Failing e2e.** Self-spawn one nginx with a small `cache_root` on a tmpfs-ish dir; fill N files past `high`; invoke a purge (call the timer path via a short interval) and assert occupancy drops to `≤ low`, the **oldest** files are gone and the **newest** survive.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3: Implement.**
  - Refactor `evict_one`/`evict_if_needed`: the metric add must work without a fill task. Replace `xrootd_cache_metric_add(t->ctx, …)` in the core with a `conf`-based atomic add on `conf->cache_*` counters (the per-server atomics already exist); the on-fill caller passes its conf.
  - `xrootd_cache_watermark_purge(conf, log)`: sample via `xrootd_cache_fs_usage_sampled(cache_root, 1000ms)`; if `occupancy_ppm ≤ high` return 0; take the existing `try_evict_lock` (cross-worker `flock`); re-sample; `purge_to_target(conf, NULL, NULL, low, …)`; unlock; return files evicted. Dirty files already skipped by `collect_dir`.
- [ ] **Step 4:** Run → PASS.

### Task B4: Background reaper timer

**Files:**
- Modify: `src/core/config/process.c` (add `xrootd_cache_watermark_timer` per worker, mirroring `xrootd_cache_reap_handler`; arm on cache + watermarks configured; re-arm at `cache_reap_interval`)
- Modify: `src/fs/cache/reap_watermark.h` (handler prototype)

- [ ] **Step 1: Failing e2e** (extends B3): without manually invoking, the **timer alone** drives a too-full cache to `≤ low` within ~2 intervals.
- [ ] **Step 2:** Run → FAIL (no timer).
- [ ] **Step 3: Implement** the timer handler (`ev->data = xcf`; call `xrootd_cache_watermark_purge`; re-arm). Add small per-worker jitter on first arm so workers don't all fire together.
- [ ] **Step 4:** Run → PASS.

### Task B5: Dedicated Prometheus metrics

**Files:**
- Modify: `src/observability/metrics/unified.c` + `unified.h` (+ the SHM struct): `cache_usage_ratio` (gauge, set by the timer), `cache_evicted_bytes_total{reason}`, `cache_evicted_files_total{reason}`, `cache_purge_runs_total`.
- Modify: `reap_watermark.c` / `evict_policy.c` to emit them (`reason="watermark"` vs `"fill"`).

- [ ] **Step 1: Failing test.** Scrape `/metrics` after a purge; assert `xrootd_cache_evicted_bytes_total{reason="watermark"} > 0` and `xrootd_cache_usage_ratio` within `[0,1]`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3: Implement** the SHM fields + HELP/TYPE emitters (mirror the existing `cache_bytes_evicted` block) + the set/inc calls. Gauge set each timer tick.
- [ ] **Step 4:** Run → PASS.

### Task B6: Phase-B regression + docs

- [ ] Update `src/fs/cache/README.md` (reaper section: watermark + timer + metrics).
- [ ] Run: `tests/c/run_cinfo_tests.sh`, `tests/c/run_fs_usage_tests.sh`, `tests/run_cache_reaper.sh`, `tests/run_cache_watermark.sh`, the cache pytest group, the seam guard. All green.

---

# Phase C — Staging-fullness backpressure

**Interfaces produced:**
- `typedef enum { XROOTD_WT_ADMIT_ALLOW, _WAIT, _REJECT } xrootd_wt_admit_t;`
- `xrootd_wt_admit_t xrootd_wt_stage_admit(const ngx_stream_xrootd_srv_conf_t *conf);`
- Config: `wt_stage_high_watermark`, `wt_stage_low_watermark` (ppm).

### Task C1: Staging watermark config

**Files:** `src/core/types/config.h`, `src/stream/module.c`, `src/core/config/server_conf.c`, `src/core/config/runtime_server.c` (validate `0<low<high<1e6`; no-op unless `cache_wt_stage_root` set).

- [ ] Failing `nginx -t` test (low≥high fails) → implement percent→ppm + merge + validate → PASS.

### Task C2: Admission decision

**Files:**
- Create: `src/fs/cache/stage_admit.c` (+ enum/proto in a header), `./config`
- Test: `tests/c/test_stage_admit.c`, `tests/c/run_stage_admit_tests.sh`

- [ ] **Step 1: Failing unit test** over a stubbed sampler: `<low→ALLOW`, `[low,high)→WAIT`, `≥high→REJECT`; a `statvfs` error → ALLOW (fail-open).
- [ ] **Step 2:** FAIL.
- [ ] **Step 3: Implement** `xrootd_wt_stage_admit` over `xrootd_cache_fs_usage_sampled(cache_wt_stage_root, 1000ms)`; return ALLOW when no staging root configured.
- [ ] **Step 4:** PASS.

### Task C3: Enforce at write-open (root://)

**Files:** `src/read/open_resolved_file.c` (is_write path, before staging temp/object creation).

- [ ] **Step 1: Failing e2e.** With staging pre-filled past high, a `root://` write-open returns `kXR_Overloaded`; in the soft band returns `kXR_wait`; reads still succeed.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3: Implement:** call `xrootd_wt_stage_admit` only when `conf->wt_enable` and a write open; map `WAIT→kXR_wait` (use the existing wait helper), `REJECT→kXR_Overloaded`. Place before `xrootd_alloc_fhandle`.
- [ ] **Step 4:** PASS.

### Task C4: Enforce at PUT (WebDAV + S3)

**Files:** `src/webdav/put.c`, `src/s3/put.c` (before staging).

- [ ] Failing e2e (HTTP PUT → `503 Retry-After` in soft band, `429` above high; GET unaffected) → implement → PASS.

### Task C5: Metrics + docs

**Files:** `src/observability/metrics/unified.c`/`.h`: `wt_stage_usage_ratio` gauge, `wt_stage_throttled_total{action}`; set gauge from the admit sampler. `src/fs/cache/README.md` write-through section.

- [ ] Failing `/metrics` assertion → implement → PASS. Phase-C regression green.

---

# Phase A — Remote-origin driver

**Interfaces produced:**
- `sd_remote` driver (`xrootd_sd_driver_t name="remote"`, `caps=XROOTD_SD_CAP_RANGE_READ`), built from a parsed origin URL.
- `src/fs/cache/origin/s3_transport.{c,h}`: `s3_open/read/stat/close` (libcurl + SigV4).
- `xrootd_cache_origin` accepts a full URL; `xrootd_cache_origin_s3_{access_key,secret_key,region,endpoint}`.

### Task A1: S3 transport

**Files:** Create `src/fs/cache/origin/s3_transport.{c,h}`; `./config`. Test: `tests/run_cache_s3_origin.sh` (front a local S3 endpoint — the module's own S3 server on 9001 — as origin).

- [ ] **Step 1: Failing e2e.** Cache node with `xrootd_cache_origin s3://…` fills byte-exact from an object PUT to the S3 origin. → FAIL → implement libcurl GET + range + SigV4 (reuse `shared/xrdproto` `xrootd_sigv4_*`), HEAD for stat → PASS.
- [ ] **Step 2:** Error: object-not-found → `kXR_NotFound`/404; SigV4 creds never logged.

### Task A2: `sd_remote` driver

**Files:** Create `src/fs/backend/sd_remote.c`; register in the driver registry; `./config`.

- [ ] **Step 1: Failing unit test.** `sd_remote` reports `caps==CAP_RANGE_READ`, write slots `NULL`; `open`+`pread`+`stat` against a stub transport return expected bytes/size; a capability check rejects it as a writable primary.
- [ ] **Step 2:** FAIL → implement init(parse URL→transport), open/close/pread/fstat/stat dispatching by scheme to `origin_protocol`/`http_transport`/`s3_transport` → PASS.

### Task A3: Origin URL config + `fetch.c` rewrite

**Files:** `src/fs/cache/origin_*`, `fetch.c`, `slice_fill.c`; config plumbing for the URL + S3 creds.

- [ ] **Step 1: Failing e2e.** Existing `root://` + `http(s)` origin tests stay green through the unified driver path; `fetch.c` opens the origin instance and `pread`s into the staged-write sink (commit-then-verify retained). GSI `xrdcp`-exec retained as documented fallback.
- [ ] **Step 2:** FAIL → implement the origin-instance copy; keep the scheme→transport mapping inside `sd_remote` → PASS.
- [ ] **Step 3:** Metrics `cache_origin_fetch_bytes_total{scheme}` / `_errors_total{scheme}`.

### Task A4: Phase-A regression + docs

- [ ] `src/fs/cache/README.md` origin section; full cache + pblock + origin e2e + seam guard green; `xrootd_cache_origin_fetch_*` scrape asserts.

---

## Self-review notes

- **Spec coverage:** B (watermark+timer+metrics+dirty-skip), C (two-tier statvfs gate, reads exempt, fail-open), A (remote driver root/s3/http, URL config) all mapped.
- **Type consistency:** watermarks stored as ppm everywhere; `xrootd_wt_admit_t` used in C2/C3/C4; `xrootd_cache_fs_usage_sampled` introduced in B1, reused in C2.
- **Back-compat:** `cache_eviction_threshold` retained (maps to high); bare `host:port` origin retained (implies root://); GSI exec retained as fallback.
