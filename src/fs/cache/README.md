# `src/fs/cache/` — XCache-style read-through cache and write-through origin mirroring

## Overview

This subsystem turns a data server into a **caching gateway** in front of a remote
XRootD origin. It implements two complementary halves:

- **Read-through cache (XCache):** when a client opens a file for reading and the
  byte range (or whole file) is not yet local, a thread-pool worker connects to the
  export's registered source backend (`brix_storage_backend root://…` — the
  phase-64 §14 replacement for the retired `brix_cache_origin` model), speaks the
  XRootD wire protocol as a client, downloads the data into the local cache tree,
  and then serves it from disk. Subsequent opens hit the local copy with no origin round-trip. Two fill
  granularities exist: **whole-file** (`fetch.c`, the historical path) and
  fixed-size **slices** (phase-64 §6.5: the tier grammar's
  `brix_cache_slice_size`, served by the composed `sd_cache` partial path in
  `src/fs/backend/cache/` — random reads fetch only the touched windows).
- **Write-through mirroring:** when write-through is enabled, files written locally
  are mirrored back to an origin (`brix_wt_origin` or the cache origin) at
  `kXR_sync`/`kXR_close` time, either synchronously or on a thread-pool worker.
  Policy (allow/deny prefixes, size limits) is decided **once at open time** and
  cached on the file handle.

Both halves share one **unified persistence-state engine**: the per-file `.cinfo`
record (v3) carries the read side's block-present bitmap AND file-level write-back
state (dirty extent, `dirty_since`, `flush_gen`, `last_flush`, `bytes_flushed`).
The read fill marks blocks present; a write-through flush marks the file dirty
before mirroring and clean on success; **eviction never reclaims a dirty file**;
and a per-worker **stale-dirty reaper** removes write-back staging dirty longer
than `brix_cache_dirty_max_age` (default 7 days) so an abandoned flush cannot
leak disk indefinitely. A single shared **admission filter** (`cache_admit.c`)
gives read-caching and write-through the same prefix/size/regex policy shape.

It exists so that nginx-xrootd can act as a regional cache/proxy node in a grid
storage federation without re-downloading hot data, and so that an edge node can
absorb writes and propagate them upstream asynchronously. It sits **below** the
protocol handlers: the stream `kXR_open` read path (`src/protocols/root/read/open_cache.c`) calls
in, the VFS open path
(`src/fs/vfs/vfs_open.c`) calls `brix_cache_open()` for hits, and the write path
(`src/protocols/root/write/sync.c`, `src/protocols/root/read/close.c`) calls the write-through flush entry points.
The HTTP plane (WebDAV/S3) shares only the lightweight readiness/slice helpers via
`cache_http.h`.

Everything that touches the origin runs in an **nginx thread-pool worker**, not on
the event loop: the origin protocol (`io.c`, `origin_*.c`) uses blocking
socket/TLS I/O with `poll()` timeouts. Completion callbacks
(`brix_cache_fill_done`, `brix_wt_flush_done`) run back on the single-threaded
event loop to resume the client and emit metrics. The cache namespace is a
**separate directory tree** (`cache_root`) from the export root, with its own
confinement model (see Invariants). `noop.c` is a stub implementation used only
when the full cache is excluded from the build; the live build (see repo-root
`config`) compiles the real sources.

## Files

### Read-through entry points & lifecycle
| File | Responsibility |
|---|---|
| `open_or_fill.c` | Public stream entry `brix_cache_open_or_fill()`: cache-hit → open directly; miss → allocate `brix_cache_fill_t`, post whole-file fill task, put client in `XRD_ST_AIO`. |
| `thread.c` | Whole-file fill worker `brix_cache_fill_thread` (ensure parent → evict → lock → fetch → evict → unlock) and the event-loop completion `brix_cache_fill_done` (redirect on admission decline / send error / open cached file / re-register in manager mode). |
| `fetch.c` | `brix_cache_fetch_origin()`: whole-file download into `.part`, admission filter (size + include-regex), `fsync`, atomic `rename` to the cache path, write `.meta` sidecar. |
| `open.c` | VFS-layer cache hit: `brix_cache_open()` (open the cached fd if meta validates), `brix_cache_path_for_resolved()` (map export-root path → cache-root path), `brix_cache_record_access()` (bump atime for LRU). |

### Cache store adapter & state (phase-64)
| File | Responsibility |
|---|---|
| `cstore.c` / `cstore.h` (+ `cstore_scan.c`) | The cache's **one storage adapter** (phase-64 §6.1): turns a generic SD instance (the cache_store tier — posix, pblock, s3, a roots:// cache server, …) into the small operation set the read cache needs — fill sink open/write/commit/abort, serve open/pread, evict, cinfo load/store, scan, freespace. Every policy module (admit/evict/reap/verify) drives the store through THIS adapter, never a driver directly (review gate G5). `cstore_scan.c` holds the recursive store-key scan used by eviction/reaping. Slice/partial fills are served by the composed `sd_cache` tier driver (`src/fs/backend/cache/`). |
| `cinfo_l1.c` / `cinfo_l1.h` | Per-worker write-through **L1 cache over cinfo records**: malloc-owned FNV-1a hash over an MRU-at-head LRU (O(1) get/put/drop, bounded, evicts the tail). No nginx pool, so it is safe on the cache fill worker thread. |
| `fill_retry.c` / `fill_retry.h` | Upstream-outcome classification + deadline'd jittered-exponential backoff for **never-drop fills** (phase-68 T20): retry-vs-definitive per attempt, bounded by the client-hold deadline while a client is parked and by the detached-fill max-life after. Absorbs origin trouble instead of re-emitting it (a CVMFS client would otherwise mark the proxy failed and escalate). |
| `gcas.c` / `gcas.h` | CVMFS CAS dedup: after a cas-verified fill commits, hard-link the per-repo cache object to a canonical repo-agnostic name (`/.gcas/<2hex>/<hex><sfx>`, one inode across N repos); eviction unlinks the canonical once it is the last remaining name. |
| `cinfo.c` / `cinfo.h` | The unified per-file state record `<cachefile>.cinfo` (**v3**): the read-side block-present **bitmap** PLUS file-level write-back state. `mark_dirty`/`mark_clean`/`dirty_extent` (flock RMW that preserves the present bitmap) drive the dirty flag + extent + `dirty_since`/`flush_gen`/`last_flush`/`bytes_flushed`; a legacy **v2** sidecar is read as present-only/clean (no cache cold-start on upgrade). Originally Phase-58 §9 — XrdPfc cinfo's state vector in this module's versioned format. Fixed header (origin validity + access stats + optional origin digest) followed by `ceil(size/block_size)` bits, one per slice granule, set as windows are fetched. `brix_cache_cinfo_record_block()` is the record-keeping entry point: an `flock(2)`-serialised read-modify-write so concurrent slice fills never lose each other's bits, with a validity reset when the origin file's size/mtime changes. Plus `load`/`store` (header verbatim + appended bitmap; a short/garbage sidecar loads as `NGX_DECLINED` → "nothing recorded", so a torn write is always safe), pure bit ops (`mark_block`/`block_present`/`present_count`/`refresh_flags` → COMPLETE/PARTIAL), and `from_meta` migration. Records cache contents durably; does not (yet) change how reads are served. Unit-tested standalone (`tests/c/test_cinfo.c`). |

### Origin protocol client (thread-pool, blocking)
| File | Responsibility |
|---|---|
| `origin_connection.c` | DNS resolve + non-blocking `connect()` with `poll()` timeout, `SO_RCVTIMEO`/`SO_SNDTIMEO`, optional TLS handshake (CA verify + SNI). `brix_cache_origin_close()` is the symmetric teardown. |
| `origin_protocol.c` (+ `origin_protocol_bootstrap.c`, `origin_write.c`, `origin_ns.c`) | XRootD client framing consumed by the `sd_xroot` source driver (`src/fs/backend/xroot/`): `_bootstrap` (handshake + `kXR_protocol` + `kXR_login`), `_open` (read open with `kXR_retstat` to learn size), `_read_chunk`; `origin_write.c` splits out the write surface (`_open_write` update+delete+mkpath, chunked `_write_chunk`, `_truncate`, `_sync`, `_close_file`, plus the cache-sink writer used to mirror a staged file back to the origin); `origin_ns.c` the namespace surface (`kXR_mv`/`kXR_rm`/`kXR_fattr` against the origin); `_query_checksum` (`kXR_Qcksum`) feeds checksum-on-fill. E2E: `tests/test_cmd_cache_xroot_origin.py`. |
| `origin_auth.c` / `origin_auth_gsi.c` | **In-process root:// origin auth**: `origin_auth.c` frames `kXR_auth` and runs the single-round **ztn** (bearer TokenResp blob from the export's named `brix_credential` token / forwarded token) and **sss** exchanges; `origin_auth_gsi.c` runs the full two-round XrdSecgsi handshake (certreq → verify server cert → cert response → final) with the shared handshake kernel (`src/auth/gsi/gsi_core.h`), loading the named `brix_credential` x509 proxy (attached via `brix_storage_credential`) as the client credential. Called from `brix_cache_origin_bootstrap()`. |
| `origin_response.c` | `brix_cache_read_response()` (read `ServerResponseHdr` + bounded body, NUL-terminate) and `brix_cache_set_origin_error()` (preserve the origin's exact `kXR_*` code + message). |
| `io.c` | Blocking `send`/`recv-exact`/`fd-write-all` loops handling SSL `WANT_READ/WANT_WRITE`, `EINTR`, and EOF→`EPIPE`/`ECONNRESET`. |

### Integrity (checksum-on-fill)
| File | Responsibility |
|---|---|
| `verify.h` / `verify.c` | Transport-agnostic checksum-on-fill: `brix_cache_verify_part()` recomputes a completed `.part`'s content checksum (shared `brix_checksum_hex_name_fd` kernel) and compares it to the digest the origin advertised, BEFORE the atomic rename — so a corrupted/truncated transfer never becomes a served entry. Policy `brix_cache_verify off\|best-effort\|require` (default **best-effort**, fail-closed): verify when a digest is available, commit-unverified when none is, never serve a proven-bad file. A verified digest is persisted into the `.meta` sidecar (`cks_alg`/`cks_hex`). The origin's digest comes from `kXR_Qcksum` for `root://` (`brix_cache_origin_query_checksum` in `origin_protocol.c`) and, in later phases, a `Digest` header for HTTP/Pelican origins. |
| `origin/transport.h` | Origin-transport seam (vtable `brix_cache_transport_t` + `brix_cache_origin_url_parse`) decoupling the fill engine from the origin wire protocol, so HTTP and Pelican origins reuse one fill loop and one verify path. The `xroot://` driver is the historical `origin_*.c`; HTTP/Pelican drivers land in `origin/`. |
| `origin/s3_transport.{c,h}` (+ `origin/s3_transport_setup.c`) | The server-side libcurl implementation of `brix_s3_transport_t` (`../backend/s3/sd_s3_transport.h`) — one synchronous request + response accessors — **injected into the shared `sd_s3` and `sd_http` source drivers** so the cache fronts S3 (`s3://`) and HTTP(S)/WebDAV (`http://`/`https://`/`davs://`) origins by reusing the driver code verbatim (SigV4 / HEAD / Range-GET), no protocol code duplicated. Since phase-64 §14 there is no per-scheme dispatch here: a remote origin is simply the export's registered source backend (`src/fs/backend/{s3,http,xroot,remote}/`), filled through the one cstore spine. `s3_transport_setup.c` carries operator policy + per-thread curl-handle lifecycle. |
| `origin/pelican_register.{c,h}` | **Pelican cache advertisement** (publisher role): when `brix_cache_advertise on`, a per-worker timer (armed in `init_process`) offloads to the cache thread pool a periodic (≥60s) `POST <director>/api/v1.0/director/registerCache` of an `OriginAdvertiseV2` JSON document, authenticated with a short-lived ES256 advertise JWT (scope `pelican.advertise`) minted by `src/auth/token/jwt_sign.c`. Directives: `brix_cache_advertise` + `brix_cache_advertise_{key,interval,namespace,data_url,web_url,sitename,issuer}`. **Prerequisite:** the cache's public key must be registered with the federation **registry** out of band (the registry handshake is an operator step, not performed here). |
| `../../token/jwt_sign.{c,h}` | **ES256 JWT minting** (`brix_jwt_sign_es256` + `brix_jwt_load_ec_key`) — the codebase's only JWT-signing path (verification lives in `src/auth/token/signature.c`). Used solely by the Pelican advertise token; the DER→P1363 conversion is the exact inverse of `brix_token_verify_es256`. |

### Cache filesystem bookkeeping
| File | Responsibility |
|---|---|
| `lock.c` | Per-file fill serialization: `brix_cache_try_lock` (`O_CREAT\|O_EXCL` sentinel) + `brix_cache_wait_or_lock` (poll loop: file-ready / claim lock / `kXR_FileLocked` timeout). |
| `paths.c` | `brix_cache_append_suffix`, `brix_cache_meta_path` (`.meta`), `brix_cache_ensure_parent` (recursive mkdir), `brix_cache_file_ready` (3-state stat: 1 ready / 0 miss / -1 error), and the state-engine path helpers `brix_cache_state_root` (explicit `brix_cache_state_root`, else `cache_root`, else NULL) + `brix_cache_state_path` (resolved export path → the `.cinfo`-bearing state-tree path). |
| `meta.c` / `meta.h` | `.meta` sidecar (origin mtime/size/etag) read/write/derive; used to detect a cached copy gone stale vs. the origin. |
| `errors.c` | `brix_cache_set_error` / `brix_cache_set_syserror`: record `result`/`xrd_error`/`sys_errno`/`err_msg` on the fill task for the done callback. |

### Eviction
| File | Responsibility |
|---|---|
| `evict_policy.c` | The eviction engine `brix_cache_purge_to_target(conf, ctx_or_NULL, c_or_NULL, protect, target_ppm, …)` — collect → qsort → **two-pass LRU** (large-file pass then oldest-first pass) to a target occupancy — decoupled from any fill task so BOTH the on-fill safety net (`brix_cache_evict_if_needed`, a thin caller targeting `cache_eviction_threshold`) and the proactive watermark reaper drive it. `ctx`/`c` are optional (the timer passes NULL). |
| `evict_candidates.c` | Helpers: `statvfs` occupancy (ppm), eviction sentinel lock (with stale-lock reclaim), recursive dir scan with skip-list + same-device guard, overflow-checked candidate growth (Phase 27 F9/W1), LRU comparator, free. **Skip-list excludes `*.part`/`*.lock`/`.meta`/`.cinfo`** — a `.cinfo` is cache STATE (dirty/present-bitmap), never a candidate; evicting one would orphan its data file's write-back-dirty protection. |
| `reap_watermark.c` | **Proactive watermark reaper** `brix_cache_watermark_purge()`: when cache_root occupancy crosses `cache_high_watermark`, take the cross-worker lock and `purge_to_target()` down to `cache_low_watermark` (hysteresis), oldest-first, dirty-skipping. Plus the self-rearming per-worker timer (`brix_cache_watermark_timer_handler`, armed in `src/core/config/process.c` at `cache_reap_interval`). Publishes the dedicated metrics (gauge `brix_cache_usage_ratio`; counters `brix_cache_watermark_{purges,evicted_files,evicted_bytes}_total`). A `statvfs` error is logged and skipped (fail-safe). E2E: `tests/test_cmd_cache_watermark.py`. |
| `cache_fs_sampler.{c,h}` | TTL-cached `statvfs` sampler `brix_cache_fs_usage_sampled()` (pure freshness predicate `brix_cache_sample_fresh` in the header) so the reaper tick and the staging gate don't `statvfs` per call. Unit test `tests/c/test_fs_usage.c` (C-unit lane). |
| `evict_internal.h` | Eviction structs (`evict_candidate_t`, `evict_list_t`, `fs_usage_t`), the `brix_cache_metric_add` macro, the sampler + `purge_to_target` prototypes. |

The watermark directives (`brix_cache_high_watermark`, `brix_cache_low_watermark` as `0.9`/`90%`, `brix_cache_reap_interval` in seconds) live in `directives.c` (shared parser `brix_conf_set_cache_watermark`) + `src/protocols/root/stream/module.c`; `cache_eviction_threshold` remains the on-fill safety net and the default for HIGH. Validation (`0 < low < high < 1.0`): `src/core/config/runtime_server.c`. Config test: `tests/test_cmd_cache_watermark_config.py`.

### Unified state engine & parity
| File | Responsibility |
|---|---|
| `cache_admit.c` / `cache_admit.h` | The shared admission filter `brix_cache_admit()` (deny-prefix precedence → allow whitelist → size cap with include-regex bypass; `is_new` skips the size cap; fail-closed on NULL). Lifted out of the write-through decision so read-caching (`fetch.c`) and write-through (`writethrough_decision.c`) share one matcher. Unit-tested standalone (`tests/c/test_cache_admit.c`). |
| `cache_reap.c` / `cache_reap.h` | The stale-dirty reaper `brix_cache_reap_dirty()`: a recursive same-device scan of the state root that **unconditionally** removes any data file whose `.cinfo` has been DIRTY longer than `brix_cache_dirty_max_age` (data + `.cinfo`/`.meta` sidecars), with a `WARN` per file. Armed as a per-worker hourly timer in `src/core/config/process.c` (first tick 5 s), independent of occupancy. E2E: `tests/test_cmd_cache_reaper.py`. |

### Write-through
| File | Responsibility |
|---|---|
| `writethrough_decision.c` | Default policy engine `brix_wt_default_decide()` (now delegates the size/prefix/regex match to the shared `brix_cache_admit()`; resolves the size via `stat` then returns `DENY`/`ALLOW_ASYNC`) and `brix_cache_should_writethrough()` (evaluated at open). Mirrors `XrdPfcDecision`. |
| *(flush engine — moved, phase-64 §11)* | The flush engine itself no longer lives here: `brix_wt_flush_on_close` (`src/protocols/root/read/close.c`) submits a **FLUSH** through the one async-staging engine `brix_stage_submit()` (`src/fs/xfer/stage_engine.c`, with its durable journal/scheduler/restart-reconcile splits `stage_engine_{journal,scheduler,reconcile}.c`), and the write-stage decorator's write-back object (`src/fs/backend/stage/sd_stage_wb.c`) buffers random-access writes on the stage store and flushes whole objects to the backend. The dirty/clean cinfo hooks and counters ride the same path (`writethrough_metrics.h`). |
| `writethrough_decision.h` | Decision enum (`DENY`/`ALLOW_SYNC`/`ALLOW_ASYNC`), callback signature, prefix/config structs, prototypes. |
| `writethrough.h` | One-line interface: `brix_cache_should_writethrough()` over a `brix_vfs_ctx_t`. |
| `writethrough_metrics.h` | Header-only inline metric helpers: dirty/clean marking on the handle, pending/success/error counters, byte totals. |
| `stage_admit.{c,h}` | **Two-tier write-back-staging backpressure.** `brix_wt_stage_admit(conf)` samples the staging filesystem (`cache_wt_stage_root`, via the TTL `cache_fs_sampler`) and returns ALLOW / WAIT / REJECT from the pure band `brix_wt_stage_decide(occ, low, high)` (in the header, unit-tested by `tests/c/test_stage_admit.c` (C-unit lane)). Enforced at the **root:// write-open** (`src/protocols/root/read/open_resolved_file.c`, `is_write && wt_enable`, before any handle/temp allocation): soft band `[low,high)` → `kXR_wait` (the client retries; `BRIX_WT_STAGE_WAIT_SECS`), hard cap `≥high` → `kXR_Overloaded`. **Reads are never throttled** (staging is filled only by root:// write-through — `brix_wt_flush_on_close` from `src/protocols/root/read/close.c`; WebDAV/S3 PUT do not stage, so there is no PUT gate). **Fails open** (ALLOW) on a statvfs fault. Directives `brix_wt_stage_{high,low}_watermark` (shared parser, `src/core/config/runtime_server.c` validation, server-level — independent of the read cache). Metrics: gauge `brix_wt_stage_usage_ratio` + counter `brix_wt_stage_throttled_total{action="wait\|reject"}`. E2E `tests/test_cmd_cache_stage_throttle.py`. |

### Cache storage on a driver (exclusively-VFS)
The cache performs **all** of its disk byte-I/O through the SD storage driver seam
(`../fs/backend/`), never a raw libc call — the same seam the export uses. By default
each cache role binds the **POSIX driver** to a per-worker `O_PATH` rootfd; a named
backend (e.g. `pblock`) is resolved through the backend registry instead, so a node
can run one object/block backend for its primary export AND a different one for each
cache role. There are three roles, each independently pluggable:

- **Read cache** (`brix_cache_root`, optional `brix_cache_storage_backend`) — the
  XCache data tree.
- **Sidecar/state tree** (`brix_cache_state_root`, always POSIX) — the `.meta`/`.cinfo`
  records. A driver-backed cache keeps its bytes in the driver namespace (no POSIX file
  at `cache_root + key`), so its sidecars **cannot** live under `cache_root`; a distinct
  POSIX `brix_cache_state_root` is required and validated at config time.
- **Write-back staging cache** (`brix_wt_stage_root`, optional
  `brix_wt_stage_backend`) — see Write-through below.

| File | Responsibility |
|---|---|
| `cache_storage.c` | Per-worker per-role SD instances + the `cache_root → instance` lookup table for the conf-less VFS/serve hooks. `brix_cache_storage_init/_cleanup` (build/close the rootfds + instances, from `src/core/config/process.c`), the role resolvers (`brix_cache_storage`/`_state_storage`/`_wt_stage`), the by-root resolvers (`brix_cache_storage_by_root`/`_state_by_root`/`_state_root_by_root`) — the last **lazily self-registers a POSIX co-located instance** for a cache root the stream-only init loop never visited (an HTTP `brix_webdav_cache_root`), `brix_cache_ready()` (driver-aware three-state readiness: a driver `stat` of the export-relative key for a backend-backed cache, else `brix_cache_file_ready()`), `brix_cache_key_under_root`, and `brix_cache_sidecar_path` (map `cache_path → state_root + key`). |
| `cache_key.c` | Pure, libc-only `brix_cache_key_from()` (export-relative, leading-slash cache key) — split out so the standalone unit test (`tests/c/test_cache_storage.c`) links without nginx symbols. |
| `cache_storage.h` | Public interface for the above. |

Both the root:// serve path (`src/protocols/root/read/open_resolved_file.c`, the `from_cache` branch)
and the WebDAV/S3 serve hook (`open.c`) open a driver-backed cache entry **through the
cache instance** (adopting the returned `sd_obj` into the handle), keyed on the
export-relative suffix under `cache_root`; a POSIX cache keeps the proven raw-fd path.
E2E: `tests/test_cmd_cache_pblock_posix.py` (pblock primary + POSIX read & write-staging),
`tests/test_cmd_cache_pblock_pblock.py` (every plane pblock + a separate POSIX state root).

### Shared / config / build
| File | Responsibility |
|---|---|
| `cache_internal.h` | Internal types (`brix_cache_origin_conn_t`, `brix_cache_fill_t`, `brix_wt_flush_t`), fill constants, and all cross-file prototypes. Pulls in `src/core/ngx_brix_module.h`. |
| `cache_http.h` | Minimal public header for HTTP handlers — exposes only `brix_cache_file_ready()` without dragging in stream types. |
| `open.h` | VFS-facing prototypes: `brix_cache_open`, `brix_cache_record_access`, `brix_cache_path_for_resolved`. |
| `directives.c` | nginx config parsers: `brix_cache_origin_family`, `_eviction_threshold` (ppm), `_max_file_size` (k/m/g), `_include_regex`, `brix_write_through`, `brix_wt_mode`, `brix_wt_origin`, `brix_wt_{allow,deny}_prefix`, and (parity) `brix_cache_{allow,deny}_prefix` + `brix_cache_state_root` + `brix_cache_dirty_max_age`. The write-back staging directives (`brix_wt_stage_root`, `brix_wt_stage_backend`, `brix_wt_stage_block_size`) are parsed in `src/protocols/root/stream/directives_cache.h` and prepared in `src/core/config/runtime_server.c`; the legacy `brix_cache_storage_backend`/`_block_size` pair is retired (§14) in favour of the tier grammar's `brix_cache_store`. The prefix push is shared by the write-through and read-cache lists. **Deliberate asymmetry:** there is no read "mode" knob — read fills are inherently async (thread-pool) and whole-vs-slice is already the tier grammar’s `brix_cache_slice_size`, so an `brix_cache_mode` directive would be a no-op; the write side keeps `brix_wt_mode sync|async`. |
| `noop.c` | Stub bodies for every public symbol — compiled only when the full cache is excluded from the build; returns `kXR_Unsupported` / `DECISION_DENY` / `NGX_DECLINED`. |

### Other files

| File | Responsibility |
|---|---|
| `directives_wt.c` | parse and validate the write-through nginx config directives (called during startup when reading the configuration file). |
| `reap_watermark.h` | A background per-worker timer that purges the read cache oldest-first when filesystem occupancy crosses the HIGH watermark, down to the LOW watermark (hysteresis), independent of cache fills. |

## Key types & data structures

- **`brix_cache_fill_t`** (`cache_internal.h`) — per-fill task ctx, heap-allocated
  via `ngx_thread_task_alloc` so a worker thread can own it. Carries the client
  connection/ctx, echoed `streamid`, `kXR_open` options/mode, the four path
  variants (`clean_path`, `cache_path`, `part_path`, `lock_path`), `file_size`
  (from `kXR_retstat`), and the error triple
  (`result`/`xrd_error`/`sys_errno`/`err_msg`) written by the worker and read by
  the done callback.
- **`brix_cache_origin_conn_t`** — the origin socket: `fd`, borrowed `ssl_ctx`,
  per-connection `ssl`. Stack-allocated per fetch; always torn down via
  `brix_cache_origin_close()` on every path.
- **`brix_wt_flush_t`** — write-through task: conf/log/metrics, `local_path` +
  derived `origin_path`, `mode_bits`, `bytes_flushed`, and the same error triple.
  Lives on the stack for sync flushes, or is `memcpy`'d into a thread task for async.
- **`brix_wt_decision_cfg_t` / `brix_wt_decision_t`** (`writethrough_decision.h`)
  — the policy engine: a `fn` pointer (default `brix_wt_default_decide`),
  allow/deny prefix arrays, size limit + include regex. The three outcomes are
  `DENY`, `ALLOW_SYNC`, `ALLOW_ASYNC`.
- **Legacy slice files** — the retired Phase-26 slice cache stored
  `<cache_path>.__xrds_<k>k_<idx>` window files + a `.__xrds.meta` sidecar; the
  reaper (`cache_reap.c`) and CSI scrub (`src/fs/backend/csi_scrub.c`) still
  recognise the `.__xrds` pattern so stale artifacts are skipped/cleaned.
- **`brix_cache_meta_t`** (`meta.h`) — the `.meta` sidecar contents: origin
  `mtime`, `size`, and a length-prefixed `etag` (≤55 bytes).
- **`brix_cache_evict_list_t` / `_candidate_t` / `_fs_usage_t`**
  (`evict_internal.h`) — the eviction working set: growable candidate array with a
  parallel `evicted[]` flag array, a `root_dev` same-device guard, a `protect_path`
  (the file being filled), and `occupancy_ppm` computed from `statvfs`.

## Control & data flow

**Read miss (whole file):** `src/protocols/root/read/open_cache.c` resolves+ACL-checks the path,
finds no cache copy, and calls `brix_cache_open_or_fill()`. That allocates a fill
task, binds `brix_cache_fill_thread`/`_done` via `brix_task_bind`, posts to
`conf->common.thread_pool`, and parks the client in `XRD_ST_AIO`. The worker mkdirs,
runs eviction (`evict_policy.c`), takes the per-file lock (`lock.c`), and calls
`brix_cache_fetch_origin()` which drives `origin_connection.c` → `origin_protocol.c`
→ `io.c`/`origin_response.c`. On completion the event loop runs
`brix_cache_fill_done`, which either redirects to origin (admission decline),
sends a `kXR_*` error, or calls `brix_open_resolved_file()` on the cached copy and
`brix_aio_resume()`s the connection.

**Read hit (VFS layer):** `src/fs/vfs/vfs_open.c` calls `brix_cache_open()`; it maps the
resolved export path to the cache path, validates the `.meta` sidecar against the
on-disk stat, and adopts the fd into the VFS (`brix_vfs_adopt_fd`). Hits then read
through the normal `../read/` + `../aio/` path.

**Read miss (slice/partial):** the composed `sd_cache` tier driver
(`src/fs/backend/cache/sd_cache_fill.c`) fetches only the touched
`brix_cache_slice_size` windows through the cstore adapter; missing windows park
the client (`kXR_wait`) while the fill proceeds.

**Write-through:** at open, `src/fs/vfs/vfs_write.c` consults
`brix_cache_should_writethrough()`; the handle records `wt_enabled`/dirty state via
the `writethrough_metrics.h` inlines. At `kXR_sync` (`src/protocols/root/write/sync.c`) or close
(`src/protocols/root/read/close.c`), `brix_wt_flush_on_close` submits a FLUSH
through the one async-staging engine (`brix_stage_submit`,
`src/fs/xfer/stage_engine.c`) — inline for `brix_wt_mode sync`, journalled +
scheduled for async — then marks the handle clean.

Calls out to: `../read/` (open/serve), `../write/` & `../fs/` (write-through, VFS
adopt), `../aio/` (resume/thread-task binding), `src/net/manager/registry.h`
(`brix_srv_register`/`_unregister_path` in manager mode), `../metrics/`
(counters), `../dashboard/` (flush events), `../protocol/` (wire structs/constants),
`../config/` (directives), and `src/core/compat/safe_size.h` (overflow-checked alloc).

## Invariants, security & gotchas

- **Cache tree is NOT `RESOLVE_BENEATH`-confined like the export root.** `open.c`
  (lines 177-191) documents this deliberately: `cache_path` lives under
  `cache_root_canon`, a *different* directory from the per-worker export rootfd, so
  `openat2(RESOLVE_BENEATH, export_rootfd, ...)` would wrongly refuse it. Confinement
  instead comes from (a) the server-controlled path mapping in
  `brix_cache_path_for_resolved()` (the client path is validated against
  `root_canon` and only a vetted suffix is appended — no raw client path), and
  (b) `O_NOFOLLOW` on every cache-file open. A dedicated cache rootfd + `openat2`
  is noted as future work, not yet done.
- **TOCTOU hardening on writes.** `.part` files are created with
  `O_CREAT|O_TRUNC|O_WRONLY|O_NOFOLLOW|O_CLOEXEC` in a single call (no prior
  `unlink`), so a symlink swapped in between calls is rejected (`fetch.c`,
  `meta.c`). Cache reads add `O_NOCTTY`.
- **Atomicity.** A file becomes visible only via `rename(.part → cache_path)` after
  `fsync`; readers never see a partial file. `brix_cache_file_ready()` is the sole
  hit predicate and rejects non-regular files (dir → `EISDIR`).
- **Concurrent-fill safety.** `lock.c` uses an `O_EXCL` sentinel, not `fcntl`, so it
  works across worker processes and UID drops. The wait loop polls at
  `BRIX_CACHE_LOCK_POLL_USEC` and gives up at `cache_lock_timeout`
  (`kXR_FileLocked`). The eviction lock is a separate directory-level sentinel with
  **stale-lock reclaim** (older than `cache_lock_timeout` → removed). Gotcha:
  locks are plain files — a `SIGKILL`'d worker can orphan a lock until the timeout
  reaps it.
- **Admission is a policy decision, not an error.** Oversized files that don't match
  `cache_include_regex` return `NGX_DECLINED` (value `1`), and the done callback
  **redirects** the client to the origin instead of failing — only if no origin is
  configured does it return `kXR_Unsupported`.
- **Event-loop discipline.** All blocking origin/TLS I/O and filesystem walks run in
  thread-pool workers (`*_thread`); only `*_done` callbacks touch the connection.
  `connect()` is non-blocking with a `poll()` timeout because `SO_SNDTIMEO` does not
  reliably bound `connect(2)` on Linux (`origin_connection.c`).
- **Origin must be a direct data server.** `kXR_redirect` from the origin open is
  treated as an error (`kXR_Unsupported`) — the cache does not chase manager
  redirects (`origin_protocol.c`). Anonymous login (`xrd`/`kXR_ver005`) is used;
  `kXR_authmore` → `kXR_AuthFailed`. If the origin advertises `kXR_gotoTLS` but
  `cache_origin_tls` is off → `kXR_TLSRequired`.
- **Wire correctness.** Origin requests use distinct `streamid[1]` slots per op
  (open=2, read=3, write=3, truncate=4, sync=5), big-endian offsets via `htobe64`,
  and the read loop honors `kXR_oksofar` until `kXR_ok`. Response bodies are bounded
  by `max_body` and NUL-terminated so `strtoull` on the `kXR_retstat` stat string is
  safe. Origin error codes are preserved verbatim, not collapsed to `ServerError`.
- **Eviction subtleties.** Occupancy uses `statvfs` (counts reserved blocks via
  `f_blocks`); the threshold is checked twice (before and after the lock) to avoid
  contention. Scans stay on `root_dev` (won't cross a mount), skip `.part`/`.lock`/
  `.meta`/sentinel files, never evict `protect_path`, and unlink the matching
  `.meta` alongside each file. Candidate growth is overflow-checked and capped at
  `BRIX_EVICT_MAX_CANDIDATES` (Phase 27). In manager mode, evicted paths are
  un-registered from the SHM registry so the cluster stops advertising them.
- **Write-through fail-closed.** `brix_wt_default_decide` returns `DENY` on NULL
  config/path; deny prefixes beat allow prefixes; an allow list set makes it a
  whitelist. The decision is made **once at open**, cached on the handle, never
  re-evaluated per write (`writethrough_decision.h`). A short read during flush
  ("file changed during flush") aborts rather than mirroring truncated data.
- **Stale `NGX_THREADS` comment.** `evict_internal.h` claims `cache_internal.h`
  wraps everything in `#if (NGX_THREADS)` — that guard is **not** present in the
  current source; the real build always compiles these files and uses `noop.c` only
  when the cache is dropped from `config`.

## Entry points / extending

- **New cache config directive:** add the field to `ngx_stream_brix_srv_conf_t`
  (`src/core/types/config.h`), write a parser in `directives.c`, register the
  `ngx_command_t`, and merge it in the server-conf merge. No `./configure` needed
  unless you add a new `.c` file.
- **New origin opcode (e.g. another write-through op):** add a
  `brix_cache_origin_<op>()` to `origin_protocol.c` following the existing pattern
  (build the `Client*Request`, pick an unused `streamid[1]`, `htobe64` offsets, read
  via `brix_cache_read_response`, branch on `kXR_error`/`kXR_ok`), declare it in
  `cache_internal.h`, and call it from `fetch.c` / the stage-engine flush path.
- **New cache metric:** add the counter (see `../metrics/`), then bump it with
  `brix_cache_metric_add(ctx, <member>, n)` (eviction) or the
  `writethrough_metrics.h` inlines (write-through). Keep labels low-cardinality.
- **Custom write-through policy:** provide a `brix_wt_decision_fn` and set
  `cfg->fn`/`cfg->user_data`; the engine is already pluggable.
- **Adding a `.c` file here:** register it in the repo-root `config`
  (`NGX_ADDON_SRCS`) and add headers to the dep list, then re-run `./configure`.

## See also

- `../../protocols/root/read/README.md` — open/read handlers that drive the read-through cache
  (`src/protocols/root/read/open_cache.c`, `src/protocols/root/read/close.c`).
- `../../protocols/root/write/README.md` — write/sync handlers that trigger write-through flush.
- `../vfs/README.md` — VFS layer; `src/fs/vfs/vfs_open.c`/`src/fs/vfs/vfs_write.c` call the cache hit and
  write-through-decision helpers.
- `../../core/aio/README.md` — thread-pool offload and event-loop resume used by every fill.
- `../path/README.md` — path resolution/confinement applied before the cache is
  consulted.
- `../../net/manager/README.md` — SHM server registry updated on fill/evict in manager mode.
- `../../observability/metrics/README.md`, `../../observability/dashboard/README.md` — counters and flush events.
- `../README.md` — master subsystem index.
