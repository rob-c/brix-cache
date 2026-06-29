# `src/cache/` — XCache-style read-through cache and write-through origin mirroring

## Overview

This subsystem turns a data server into a **caching gateway** in front of a remote
XRootD origin. It implements two complementary halves:

- **Read-through cache (XCache):** when a client opens a file for reading and the
  byte range (or whole file) is not yet local, a thread-pool worker connects to the
  configured origin (`xrootd_cache_origin`), speaks the XRootD wire protocol as a
  client, downloads the data into the local cache tree, and then serves it from
  disk. Subsequent opens hit the local copy with no origin round-trip. Two fill
  granularities exist: **whole-file** (`fetch.c`, the historical path) and
  fixed-size **slices** (`slice.c`/`slice_fill.c`, Phase 26 — `read://` random
  reads fetch only the touched 128 KiB-ish windows).
- **Write-through mirroring:** when write-through is enabled, files written locally
  are mirrored back to an origin (`xrootd_wt_origin` or the cache origin) at
  `kXR_sync`/`kXR_close` time, either synchronously or on a thread-pool worker.
  Policy (allow/deny prefixes, size limits) is decided **once at open time** and
  cached on the file handle.

Both halves share one **unified persistence-state engine**: the per-file `.cinfo`
record (v3) carries the read side's block-present bitmap AND file-level write-back
state (dirty extent, `dirty_since`, `flush_gen`, `last_flush`, `bytes_flushed`).
The read fill marks blocks present; a write-through flush marks the file dirty
before mirroring and clean on success; **eviction never reclaims a dirty file**;
and a per-worker **stale-dirty reaper** removes write-back staging dirty longer
than `xrootd_cache_dirty_max_age` (default 7 days) so an abandoned flush cannot
leak disk indefinitely. A single shared **admission filter** (`cache_admit.c`)
gives read-caching and write-through the same prefix/size/regex policy shape.

It exists so that nginx-xrootd can act as a regional cache/proxy node in a grid
storage federation without re-downloading hot data, and so that an edge node can
absorb writes and propagate them upstream asynchronously. It sits **below** the
protocol handlers: the stream `kXR_open` read path (`../read/open_cache.c`) and the
slice read path (`../read/slice_read.c`) call in, the VFS open path
(`../fs/vfs_open.c`) calls `xrootd_cache_open()` for hits, and the write path
(`../write/sync.c`, `../read/close.c`) calls the write-through flush entry points.
The HTTP plane (WebDAV/S3) shares only the lightweight readiness/slice helpers via
`cache_http.h`.

Everything that touches the origin runs in an **nginx thread-pool worker**, not on
the event loop: the origin protocol (`io.c`, `origin_*.c`) uses blocking
socket/TLS I/O with `poll()` timeouts. Completion callbacks
(`xrootd_cache_fill_done`, `xrootd_wt_flush_done`) run back on the single-threaded
event loop to resume the client and emit metrics. The cache namespace is a
**separate directory tree** (`cache_root`) from the export root, with its own
confinement model (see Invariants). `noop.c` is a stub implementation used only
when the full cache is excluded from the build; the live build (see repo-root
`config`) compiles the real sources.

## Files

### Read-through entry points & lifecycle
| File | Responsibility |
|---|---|
| `open_or_fill.c` | Public stream entry `xrootd_cache_open_or_fill()`: cache-hit → open directly; miss → allocate `xrootd_cache_fill_t`, post whole-file fill task, put client in `XRD_ST_AIO`. |
| `thread.c` | Whole-file fill worker `xrootd_cache_fill_thread` (ensure parent → evict → lock → fetch → evict → unlock) and the event-loop completion `xrootd_cache_fill_done` (redirect on admission decline / send error / open cached file / re-register in manager mode). |
| `fetch.c` | `xrootd_cache_fetch_origin()`: whole-file download into `.part`, admission filter (size + include-regex), `fsync`, atomic `rename` to the cache path, write `.meta` sidecar. |
| `open.c` | VFS-layer cache hit: `xrootd_cache_open()` (open the cached fd if meta validates), `xrootd_cache_path_for_resolved()` (map export-root path → cache-root path), `xrootd_cache_record_access()` (bump atime for LRU). |

### Slice cache (Phase 26)
| File | Responsibility |
|---|---|
| `slice.c` / `slice.h` | Pure path/range arithmetic: `xrootd_slice_enumerate()` (which slices cover `[start,end)`), `xrootd_slice_path()`, file-level meta validate/write (`xrootd_slice_meta_*`), and `xrootd_slice_evict_all()` (glob+unlink). No I/O — shared identically by HTTP and stream planes, unit-testable. |
| `slice_fill.c` | `xrootd_cache_slice_fetch_origin()` + `xrootd_cache_slice_fill_thread`: fetch one clamped slice window from origin into a per-slice file; evict siblings + rewrite `.__xrds.meta` on origin-size mismatch; then **record the filled block** in the `.cinfo` bitmap (best-effort). Fire-and-forget (client gets `kXR_wait` and retries). |
| `cinfo.c` / `cinfo.h` | The unified per-file state record `<cachefile>.cinfo` (**v3**): the read-side block-present **bitmap** PLUS file-level write-back state. `mark_dirty`/`mark_clean`/`dirty_extent` (flock RMW that preserves the present bitmap) drive the dirty flag + extent + `dirty_since`/`flush_gen`/`last_flush`/`bytes_flushed`; a legacy **v2** sidecar is read as present-only/clean (no cache cold-start on upgrade). Originally Phase-58 §9 — XrdPfc cinfo's state vector in this module's versioned format. Fixed header (origin validity + access stats + optional origin digest) followed by `ceil(size/block_size)` bits, one per slice granule, set as windows are fetched. `xrootd_cache_cinfo_record_block()` is the record-keeping entry point: an `flock(2)`-serialised read-modify-write so concurrent slice fills never lose each other's bits, with a validity reset when the origin file's size/mtime changes. Plus `load`/`store` (header verbatim + appended bitmap; a short/garbage sidecar loads as `NGX_DECLINED` → "nothing recorded", so a torn write is always safe), pure bit ops (`mark_block`/`block_present`/`present_count`/`refresh_flags` → COMPLETE/PARTIAL), and `from_meta` migration. Records cache contents durably; does not (yet) change how reads are served. Unit-tested standalone (`tests/c/test_cinfo.c`). |

### Origin protocol client (thread-pool, blocking)
| File | Responsibility |
|---|---|
| `origin_connection.c` | DNS resolve + non-blocking `connect()` with `poll()` timeout, `SO_RCVTIMEO`/`SO_SNDTIMEO`, optional TLS handshake (CA verify + SNI). `xrootd_cache_origin_close()` is the symmetric teardown. |
| `origin_protocol.c` | XRootD client framing: `_bootstrap` (handshake + `kXR_protocol` + anonymous `kXR_login`), `_open` (read open with `kXR_retstat` to learn size), `_open_write` (update+delete+mkpath), `_read_chunk`, `_write_chunk`, `_truncate`, `_sync`, `_close_file`, `_query_checksum` (`kXR_Qcksum`). **root:// origin auth matrix:** *anonymous* fills run in-process through the read-only `sd_xroot` SD driver (`../fs/backend/xroot/`, `fetch.c::xrootd_cache_fetch_origin_xroot` — driver→driver into the staged sink, `kXR_read` ranges via a memory sink); *GSI X.509-proxy and/or bearer-token* origins are filled by the native-client delegation (`xrootd_cache_fetch_origin_exec`, which sets `X509_USER_PROXY`/`X509_CERT_DIR` for GSI and `BEARER_TOKEN_FILE` from `xrootd_cache_origin_token_file` for token). The dispatch in `xrootd_cache_fetch_origin` routes proxy-or-token root:// origins to the exec path, else to the in-process driver. A fully in-process root:// token/GSI client is a follow-on (the client-side auth lives in `libxrdc`). E2E: `tests/run_cache_xroot_origin.sh` (anonymous). |
| `origin_response.c` | `xrootd_cache_read_response()` (read `ServerResponseHdr` + bounded body, NUL-terminate) and `xrootd_cache_set_origin_error()` (preserve the origin's exact `kXR_*` code + message). |
| `io.c` | Blocking `send`/`recv-exact`/`fd-write-all` loops handling SSL `WANT_READ/WANT_WRITE`, `EINTR`, and EOF→`EPIPE`/`ECONNRESET`. |

### Integrity (checksum-on-fill)
| File | Responsibility |
|---|---|
| `verify.h` / `verify.c` | Transport-agnostic checksum-on-fill: `xrootd_cache_verify_part()` recomputes a completed `.part`'s content checksum (shared `xrootd_checksum_hex_name_fd` kernel) and compares it to the digest the origin advertised, BEFORE the atomic rename — so a corrupted/truncated transfer never becomes a served entry. Policy `xrootd_cache_verify off\|best-effort\|require` (default **best-effort**, fail-closed): verify when a digest is available, commit-unverified when none is, never serve a proven-bad file. A verified digest is persisted into the `.meta` sidecar (`cks_alg`/`cks_hex`). The origin's digest comes from `kXR_Qcksum` for `root://` (`xrootd_cache_origin_query_checksum` in `origin_protocol.c`) and, in later phases, a `Digest` header for HTTP/Pelican origins. |
| `origin/transport.h` | Origin-transport seam (vtable `xrootd_cache_transport_t` + `xrootd_cache_origin_url_parse`) decoupling the fill engine from the origin wire protocol, so HTTP and Pelican origins reuse one fill loop and one verify path. The `xroot://` driver is the historical `origin_*.c`; HTTP/Pelican drivers land in `origin/`. |
| `origin/http_transport.{c,h}` | **HTTP(S)/WebDAV origin** (`http://`, `https://`, `davs://`). **Auth: bearer token AND GSI X.509-proxy** — the token is the configured cache credential (`xrootd_cache_origin_token_file`) and/or the forwarded client token (`xrootd_cache_origin_forward_token`); GSI is mutual-TLS with `xrootd_cache_origin_proxy` presented as the client cert+key (`CURLOPT_SSLCERT`/`SSLKEY`, a grid proxy is one PEM with cert+chain+key). Origin TLS is verified against `xrootd_cache_origin_cadir`/`xrootd_trusted_ca`. `xrootd_cache_http_download()` streams a ranged libcurl GET straight to the `.part` fd, follows redirects, and captures the RFC 3230 `Digest` response header (solicited with `Want-Digest`) into `t->origin_cks_*` so the same checksum-on-fill path verifies it. Bearer auth = the configured cache credential (`xrootd_cache_origin_token_file`) and/or the forwarded client token (`xrootd_cache_origin_forward_token`, from `ctx->bearer_token`). TLS uses `xrootd_cache_origin_cadir`/`xrootd_trusted_ca` for CA verification. `xrootd_cache_http_get_url()` is the URL-explicit core reused by the Pelican transport. Selected when `xrootd_cache_origin` uses an http/https/davs scheme; `fetch.c` dispatches on `cache_origin_scheme`. |
| `origin/s3_transport.{c,h}` | **S3 origin** (`s3://endpoint[:port]/bucket`): the server-side libcurl implementation of `xrootd_s3_transport_t` (`../../fs/backend/s3/sd_s3_transport.h`) — one synchronous request + response accessors — so the cache fronts an S3 origin by REUSING the whole shared `sd_s3` driver (SigV4 / HEAD / Range-GET), no protocol code duplicated. `fetch.c::xrootd_cache_fetch_origin_s3()` builds an `sd_remote` instance (`../fs/backend/remote/`) over this transport and copies driver→driver: open the origin object, `pread` sequential ranges into the staged-write sink, commit. The `Host` header is forced to `host:port` to match `sd_s3`'s SigV4 canonical host (`xrootd_format_host_port` always appends the port). Credentials: `xrootd_cache_origin_s3_{access_key,secret_key,region}` (region default `us-east-1`); the bucket is the first path segment of the `s3://` URL. `xrootd_cache_origin_tls on` selects https. E2E: `tests/run_cache_s3_origin.sh`. |
| `origin/pelican.{c,h}` | **Pelican/OSDF federation origin** (`pelican://<federation>`, consumer role): `xrootd_cache_pelican_download()` GETs `https://<fed>/.well-known/pelican-configuration`, parses `director_endpoint` (jansson), and fetches `<director_endpoint><logical-path>` via `xrootd_cache_http_get_url()` — libcurl follows the Director's 307 to the nearest cache/origin, with the same Digest capture + checksum-on-fill. The federation host needs no port (defaults to 443). |
| `origin/pelican_register.{c,h}` | **Pelican cache advertisement** (publisher role): when `xrootd_cache_advertise on`, a per-worker timer (armed in `init_process`) offloads to the cache thread pool a periodic (≥60s) `POST <director>/api/v1.0/director/registerCache` of an `OriginAdvertiseV2` JSON document, authenticated with a short-lived ES256 advertise JWT (scope `pelican.advertise`) minted by `../../token/jwt_sign.c`. Directives: `xrootd_cache_advertise[_key/_interval/_namespace]`, `xrootd_cache_data_url`, `xrootd_cache_web_url`, `xrootd_cache_sitename`, `xrootd_cache_issuer`. **Prerequisite:** the cache's public key must be registered with the federation **registry** out of band (the registry handshake is an operator step, not performed here). |
| `../../token/jwt_sign.{c,h}` | **ES256 JWT minting** (`xrootd_jwt_sign_es256` + `xrootd_jwt_load_ec_key`) — the codebase's only JWT-signing path (verification lives in `token/signature.c`). Used solely by the Pelican advertise token; the DER→P1363 conversion is the exact inverse of `xrootd_token_verify_es256`. |

### Cache filesystem bookkeeping
| File | Responsibility |
|---|---|
| `lock.c` | Per-file fill serialization: `xrootd_cache_try_lock` (`O_CREAT\|O_EXCL` sentinel) + `xrootd_cache_wait_or_lock` (poll loop: file-ready / claim lock / `kXR_FileLocked` timeout). |
| `paths.c` | `xrootd_cache_append_suffix`, `xrootd_cache_meta_path` (`.meta`), `xrootd_cache_ensure_parent` (recursive mkdir), `xrootd_cache_file_ready` (3-state stat: 1 ready / 0 miss / -1 error), and the state-engine path helpers `xrootd_cache_state_root` (explicit `xrootd_cache_state_root`, else `cache_root`, else NULL) + `xrootd_cache_state_path` (resolved export path → the `.cinfo`-bearing state-tree path). |
| `meta.c` / `meta.h` | `.meta` sidecar (origin mtime/size/etag) read/write/derive; used to detect a cached copy gone stale vs. the origin. |
| `errors.c` | `xrootd_cache_set_error` / `xrootd_cache_set_syserror`: record `result`/`xrd_error`/`sys_errno`/`err_msg` on the fill task for the done callback. |

### Eviction
| File | Responsibility |
|---|---|
| `evict_policy.c` | The eviction engine `xrootd_cache_purge_to_target(conf, ctx_or_NULL, c_or_NULL, protect, target_ppm, …)` — collect → qsort → **two-pass LRU** (large-file pass then oldest-first pass) to a target occupancy — decoupled from any fill task so BOTH the on-fill safety net (`xrootd_cache_evict_if_needed`, a thin caller targeting `cache_eviction_threshold`) and the proactive watermark reaper drive it. `ctx`/`c` are optional (the timer passes NULL). |
| `evict_candidates.c` | Helpers: `statvfs` occupancy (ppm), eviction sentinel lock (with stale-lock reclaim), recursive dir scan with skip-list + same-device guard, overflow-checked candidate growth (Phase 27 F9/W1), LRU comparator, free. **Skip-list excludes `*.part`/`*.lock`/`.meta`/`.cinfo`** — a `.cinfo` is cache STATE (dirty/present-bitmap), never a candidate; evicting one would orphan its data file's write-back-dirty protection. |
| `reap_watermark.c` | **Proactive watermark reaper** `xrootd_cache_watermark_purge()`: when cache_root occupancy crosses `cache_high_watermark`, take the cross-worker lock and `purge_to_target()` down to `cache_low_watermark` (hysteresis), oldest-first, dirty-skipping. Plus the self-rearming per-worker timer (`xrootd_cache_watermark_timer_handler`, armed in `process.c` at `cache_reap_interval`). Publishes the dedicated metrics (gauge `xrootd_cache_usage_ratio`; counters `xrootd_cache_watermark_{purges,evicted_files,evicted_bytes}_total`). A `statvfs` error is logged and skipped (fail-safe). E2E: `tests/run_cache_watermark.sh`. |
| `cache_fs_sampler.{c,h}` | TTL-cached `statvfs` sampler `xrootd_cache_fs_usage_sampled()` (pure freshness predicate `xrootd_cache_sample_fresh` in the header) so the reaper tick and the staging gate don't `statvfs` per call. Unit test `tests/c/run_fs_usage_tests.sh`. |
| `evict_internal.h` | Eviction structs (`evict_candidate_t`, `evict_list_t`, `fs_usage_t`), the `xrootd_cache_metric_add` macro, the sampler + `purge_to_target` prototypes. |

The watermark directives (`xrootd_cache_high_watermark`, `xrootd_cache_low_watermark` as `0.9`/`90%`, `xrootd_cache_reap_interval` in seconds) live in `directives.c` (shared parser `xrootd_conf_set_cache_watermark`) + `../stream/module.c`; `cache_eviction_threshold` remains the on-fill safety net and the default for HIGH. Validation (`0 < low < high < 1.0`): `../config/runtime_server.c`. Config test: `tests/run_cache_watermark_config.sh`.

### Unified state engine & parity
| File | Responsibility |
|---|---|
| `cache_admit.c` / `cache_admit.h` | The shared admission filter `xrootd_cache_admit()` (deny-prefix precedence → allow whitelist → size cap with include-regex bypass; `is_new` skips the size cap; fail-closed on NULL). Lifted out of the write-through decision so read-caching (`fetch.c`) and write-through (`writethrough_decision.c`) share one matcher. Unit-tested standalone (`tests/c/test_cache_admit.c`). |
| `cache_reap.c` / `cache_reap.h` | The stale-dirty reaper `xrootd_cache_reap_dirty()`: a recursive same-device scan of the state root that **unconditionally** removes any data file whose `.cinfo` has been DIRTY longer than `xrootd_cache_dirty_max_age` (data + `.cinfo`/`.meta` sidecars), with a `WARN` per file. Armed as a per-worker hourly timer in `src/config/process.c` (first tick 5 s), independent of occupancy. E2E: `tests/run_cache_reaper.sh`. |

### Write-through
| File | Responsibility |
|---|---|
| `writethrough_decision.c` | Default policy engine `xrootd_wt_default_decide()` (now delegates the size/prefix/regex match to the shared `xrootd_cache_admit()`; resolves the size via `stat` then returns `DENY`/`ALLOW_ASYNC`) and `xrootd_cache_should_writethrough()` (evaluated at open). Mirrors `XrdPfcDecision`. |
| `writethrough_flush.c` | …plus the unified-state hooks: `mark_dirty` at flush start, `mark_clean` on success (both sync and async-done) — the single write-back-state choke point. **Driver-backed primary (cache fronts a VFS backend):** when the export uses a non-POSIX storage driver (pblock/object/tape), `init_task` fsyncs the still-open write handle (committing the just-written size to the driver's catalog) and opens a fresh READ object through the driver; `copy_body` then mirrors the block-striped data via `obj->driver->pread` instead of a raw POSIX read. A GSI/proxy origin (external client) is unsupported for a driver-backed export (it cannot read the blocks) — flagged with `kXR_Unsupported`. E2E: `tests/run_pblock_writethrough.sh`. |
| `writethrough_flush.c` | The flush engine: `xrootd_wt_origin_path_from_local` (path remap), `xrootd_wt_run_flush` (connect → open-write → chunked `pread`+`write_chunk` → truncate+sync+close), and the sync/async/close entry points + thread/done callbacks. **Write-back staging cache:** when a staging role is configured (`xrootd_cache_wt_stage_root`/`_backend`), `run_flush` makes a durable copy of the just-written primary into the staging instance (`xrootd_wt_stage_copy`, `staged_open` → `pread`+`staged_write` → `staged_commit`) keyed on the logical path, then mirrors to the origin **from the staged copy** rather than the live primary — so a flush re-driven by `writethrough_replay` after a restart reads immutable bytes and survives an origin-down window. The **FRM journal** remains the write-back state engine (`xrootd_wt_journal_begin/finish`, kind `FRM_XFER_WT`); the staged copy is left for the reaper to reclaim once `flush_gen>0` and aged. With no staging role, the flush reads the primary directly (the Phase-1 fallback). |
| `writethrough_decision.h` | Decision enum (`DENY`/`ALLOW_SYNC`/`ALLOW_ASYNC`), callback signature, prefix/config structs, prototypes. |
| `writethrough.h` | One-line interface: `xrootd_cache_should_writethrough()` over a `xrootd_vfs_ctx_t`. |
| `writethrough_metrics.h` | Header-only inline metric helpers: dirty/clean marking on the handle, pending/success/error counters, byte totals. |
| `stage_admit.{c,h}` | **Two-tier write-back-staging backpressure.** `xrootd_wt_stage_admit(conf)` samples the staging filesystem (`cache_wt_stage_root`, via the TTL `cache_fs_sampler`) and returns ALLOW / WAIT / REJECT from the pure band `xrootd_wt_stage_decide(occ, low, high)` (in the header, unit-tested by `tests/c/run_stage_admit_tests.sh`). Enforced at the **root:// write-open** (`../read/open_resolved_file.c`, `is_write && wt_enable`, before any handle/temp allocation): soft band `[low,high)` → `kXR_wait` (the client retries; `XROOTD_WT_STAGE_WAIT_SECS`), hard cap `≥high` → `kXR_Overloaded`. **Reads are never throttled** (staging is filled only by root:// write-through — `xrootd_wt_flush_on_close` from `../read/close.c`; WebDAV/S3 PUT do not stage, so there is no PUT gate). **Fails open** (ALLOW) on a statvfs fault. Directives `xrootd_wt_stage_{high,low}_watermark` (shared parser, `../config/runtime_server.c` validation, server-level — independent of the read cache). Metrics: gauge `xrootd_wt_stage_usage_ratio` + counter `xrootd_wt_stage_throttled_total{action="wait\|reject"}`. E2E `tests/run_cache_stage_throttle.sh`. |

### Cache storage on a driver (exclusively-VFS)
The cache performs **all** of its disk byte-I/O through the SD storage driver seam
(`../fs/backend/`), never a raw libc call — the same seam the export uses. By default
each cache role binds the **POSIX driver** to a per-worker `O_PATH` rootfd; a named
backend (e.g. `pblock`) is resolved through the backend registry instead, so a node
can run one object/block backend for its primary export AND a different one for each
cache role. There are three roles, each independently pluggable:

- **Read cache** (`xrootd_cache_root`, optional `xrootd_cache_storage_backend`) — the
  XCache data tree.
- **Sidecar/state tree** (`xrootd_cache_state_root`, always POSIX) — the `.meta`/`.cinfo`
  records. A driver-backed cache keeps its bytes in the driver namespace (no POSIX file
  at `cache_root + key`), so its sidecars **cannot** live under `cache_root`; a distinct
  POSIX `xrootd_cache_state_root` is required and validated at config time.
- **Write-back staging cache** (`xrootd_cache_wt_stage_root`, optional
  `xrootd_cache_wt_stage_backend`) — see Write-through below.

| File | Responsibility |
|---|---|
| `cache_storage.c` | Per-worker per-role SD instances + the `cache_root → instance` lookup table for the conf-less VFS/serve hooks. `xrootd_cache_storage_init/_cleanup` (build/close the rootfds + instances, from `process.c`), the role resolvers (`xrootd_cache_storage`/`_state_storage`/`_wt_stage`), the by-root resolvers (`xrootd_cache_storage_by_root`/`_state_by_root`/`_state_root_by_root`) — the last **lazily self-registers a POSIX co-located instance** for a cache root the stream-only init loop never visited (an HTTP `xrootd_webdav_cache_root`), `xrootd_cache_ready()` (driver-aware three-state readiness: a driver `stat` of the export-relative key for a backend-backed cache, else `xrootd_cache_file_ready()`), `xrootd_cache_key_under_root`, and `xrootd_cache_sidecar_path` (map `cache_path → state_root + key`). |
| `cache_key.c` | Pure, libc-only `xrootd_cache_key_from()` (export-relative, leading-slash cache key) — split out so the standalone unit test (`tests/c/test_cache_storage.c`) links without nginx symbols. |
| `cache_storage.h` | Public interface for the above. |

Both the root:// serve path (`../read/open_resolved_file.c`, the `from_cache` branch)
and the WebDAV/S3 serve hook (`open.c`) open a driver-backed cache entry **through the
cache instance** (adopting the returned `sd_obj` into the handle), keyed on the
export-relative suffix under `cache_root`; a POSIX cache keeps the proven raw-fd path.
E2E: `tests/run_cache_pblock_posix.sh` (pblock primary + POSIX read & write-staging),
`tests/run_cache_pblock_pblock.sh` (every plane pblock + a separate POSIX state root).

### Shared / config / build
| File | Responsibility |
|---|---|
| `cache_internal.h` | Internal types (`xrootd_cache_origin_conn_t`, `xrootd_cache_fill_t`, `xrootd_wt_flush_t`), fill constants, and all cross-file prototypes. Pulls in `ngx_xrootd_module.h`. |
| `cache_http.h` | Minimal public header for HTTP handlers — exposes only `xrootd_cache_file_ready()` without dragging in stream types. |
| `open.h` | VFS-facing prototypes: `xrootd_cache_open`, `xrootd_cache_record_access`, `xrootd_cache_path_for_resolved`. |
| `directives.c` | nginx config parsers: `xrootd_cache_origin`, `_eviction_threshold` (ppm), `_max_file_size` (k/m/g), `_include_regex`, `xrootd_write_through`, `xrootd_wt_mode`, `xrootd_wt_origin`, `xrootd_wt_{allow,deny}_prefix`, and (parity) `xrootd_cache_{allow,deny}_prefix` + `xrootd_cache_state_root` + `xrootd_cache_dirty_max_age`. The cache-storage-on-a-driver directives (`xrootd_cache_storage_backend`, `xrootd_cache_storage_block_size`, `xrootd_cache_wt_stage_root`, `xrootd_cache_wt_stage_backend`, `xrootd_cache_wt_stage_block_size`) are parsed in `../stream/module.c` and prepared in `../config/runtime_server.c`. The prefix push is shared by the write-through and read-cache lists. **Deliberate asymmetry:** there is no read "mode" knob — read fills are inherently async (thread-pool) and whole-vs-slice is already `xrootd_cache_slice`, so an `xrootd_cache_mode` directive would be a no-op; the write side keeps `xrootd_wt_mode sync|async`. |
| `noop.c` | Stub bodies for every public symbol — compiled only when the full cache is excluded from the build; returns `kXR_Unsupported` / `DECISION_DENY` / `NGX_DECLINED`. |

## Key types & data structures

- **`xrootd_cache_fill_t`** (`cache_internal.h`) — per-fill task ctx, heap-allocated
  via `ngx_thread_task_alloc` so a worker thread can own it. Carries the client
  connection/ctx, echoed `streamid`, `kXR_open` options/mode, the four path
  variants (`clean_path`, `cache_path`, `part_path`, `lock_path`), `file_size`
  (from `kXR_retstat`), the Phase-26 slice fields (`slice_start`/`slice_len`/
  `file_cache_path` + read-resume params), and the error triple
  (`result`/`xrd_error`/`sys_errno`/`err_msg`) written by the worker and read by
  the done callback.
- **`xrootd_cache_origin_conn_t`** — the origin socket: `fd`, borrowed `ssl_ctx`,
  per-connection `ssl`. Stack-allocated per fetch; always torn down via
  `xrootd_cache_origin_close()` on every path.
- **`xrootd_wt_flush_t`** — write-through task: conf/log/metrics, `local_path` +
  derived `origin_path`, `mode_bits`, `bytes_flushed`, and the same error triple.
  Lives on the stack for sync flushes, or is `memcpy`'d into a thread task for async.
- **`xrootd_wt_decision_cfg_t` / `xrootd_wt_decision_t`** (`writethrough_decision.h`)
  — the policy engine: a `fn` pointer (default `xrootd_wt_default_decide`),
  allow/deny prefix arrays, size limit + include regex. The three outcomes are
  `DENY`, `ALLOW_SYNC`, `ALLOW_ASYNC`.
- **`xrootd_slice_t` + slice naming** (`slice.h`) — a slice covers
  `[file_start,file_end)` intersected with the request range; its cache file is
  `<cache_path>.__xrds_<SIZE/1024>k_<idx>`, with a shared `<cache_path>.__xrds.meta`
  sidecar. Slice size is encoded in the name so changing it auto-invalidates.
  `XROOTD_SLICE_MAX_PER_REQUEST` (16) caps a single request's span.
- **`xrootd_cache_meta_t`** (`meta.h`) — the `.meta` sidecar contents: origin
  `mtime`, `size`, and a length-prefixed `etag` (≤55 bytes).
- **`xrootd_cache_evict_list_t` / `_candidate_t` / `_fs_usage_t`**
  (`evict_internal.h`) — the eviction working set: growable candidate array with a
  parallel `evicted[]` flag array, a `root_dev` same-device guard, a `protect_path`
  (the file being filled), and `occupancy_ppm` computed from `statvfs`.

## Control & data flow

**Read miss (whole file):** `../read/open_cache.c` resolves+ACL-checks the path,
finds no cache copy, and calls `xrootd_cache_open_or_fill()`. That allocates a fill
task, binds `xrootd_cache_fill_thread`/`_done` via `xrootd_task_bind`, posts to
`conf->common.thread_pool`, and parks the client in `XRD_ST_AIO`. The worker mkdirs,
runs eviction (`evict_policy.c`), takes the per-file lock (`lock.c`), and calls
`xrootd_cache_fetch_origin()` which drives `origin_connection.c` → `origin_protocol.c`
→ `io.c`/`origin_response.c`. On completion the event loop runs
`xrootd_cache_fill_done`, which either redirects to origin (admission decline),
sends a `kXR_*` error, or calls `xrootd_open_resolved_file()` on the cached copy and
`xrootd_aio_resume()`s the connection.

**Read hit (VFS layer):** `../fs/vfs_open.c` calls `xrootd_cache_open()`; it maps the
resolved export path to the cache path, validates the `.meta` sidecar against the
on-disk stat, and adopts the fd into the VFS (`xrootd_vfs_adopt_fd`). Hits then read
through the normal `../read/` + `../aio/` path.

**Read miss (slice):** `../read/slice_read.c` calls `xrootd_slice_enumerate()`
(`slice.c`) to find covering slices; ready slices are served, missing ones get a
`xrootd_cache_slice_fill_thread` task and the client gets `kXR_wait` to retry.

**Write-through:** at open, `../fs/vfs_write.c` consults
`xrootd_cache_should_writethrough()`; the handle records `wt_enabled`/dirty state via
the `writethrough_metrics.h` inlines. At `kXR_sync` (`../write/sync.c`) or close
(`../read/close.c`), `xrootd_wt_flush_sync_handle`/`xrootd_wt_flush_on_close`
(`writethrough_flush.c`) run `xrootd_wt_run_flush` (reusing the origin protocol
client in write mode) either inline or on a worker, then mark the handle clean.

Calls out to: `../read/` (open/serve), `../write/` & `../fs/` (write-through, VFS
adopt), `../aio/` (resume/thread-task binding), `../manager/registry.h`
(`xrootd_srv_register`/`_unregister_path` in manager mode), `../metrics/`
(counters), `../dashboard/` (flush events), `../protocol/` (wire structs/constants),
`../config/` (directives), and `../shared/safe_size.h` (overflow-checked alloc).

## Invariants, security & gotchas

- **Cache tree is NOT `RESOLVE_BENEATH`-confined like the export root.** `open.c`
  (lines 177-191) documents this deliberately: `cache_path` lives under
  `cache_root_canon`, a *different* directory from the per-worker export rootfd, so
  `openat2(RESOLVE_BENEATH, export_rootfd, ...)` would wrongly refuse it. Confinement
  instead comes from (a) the server-controlled path mapping in
  `xrootd_cache_path_for_resolved()` (the client path is validated against
  `root_canon` and only a vetted suffix is appended — no raw client path), and
  (b) `O_NOFOLLOW` on every cache-file open. A dedicated cache rootfd + `openat2`
  is noted as future work, not yet done.
- **TOCTOU hardening on writes.** `.part` files are created with
  `O_CREAT|O_TRUNC|O_WRONLY|O_NOFOLLOW|O_CLOEXEC` in a single call (no prior
  `unlink`), so a symlink swapped in between calls is rejected (`fetch.c`,
  `slice_fill.c`, `meta.c`). Cache reads add `O_NOCTTY`.
- **Atomicity.** A file becomes visible only via `rename(.part → cache_path)` after
  `fsync`; readers never see a partial file. `xrootd_cache_file_ready()` is the sole
  hit predicate and rejects non-regular files (dir → `EISDIR`).
- **Concurrent-fill safety.** `lock.c` uses an `O_EXCL` sentinel, not `fcntl`, so it
  works across worker processes and UID drops. The wait loop polls at
  `XROOTD_CACHE_LOCK_POLL_USEC` and gives up at `cache_lock_timeout`
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
  `XROOTD_EVICT_MAX_CANDIDATES` (Phase 27). In manager mode, evicted paths are
  un-registered from the SHM registry so the cluster stops advertising them.
- **Write-through fail-closed.** `xrootd_wt_default_decide` returns `DENY` on NULL
  config/path; deny prefixes beat allow prefixes; an allow list set makes it a
  whitelist. The decision is made **once at open**, cached on the handle, never
  re-evaluated per write (`writethrough_decision.h`). A short read during flush
  ("file changed during flush") aborts rather than mirroring truncated data.
- **Stale `NGX_THREADS` comment.** `evict_internal.h` claims `cache_internal.h`
  wraps everything in `#if (NGX_THREADS)` — that guard is **not** present in the
  current source; the real build always compiles these files and uses `noop.c` only
  when the cache is dropped from `config`.

## Entry points / extending

- **New cache config directive:** add the field to `ngx_stream_xrootd_srv_conf_t`
  (`../types/config.h`), write a parser in `directives.c`, register the
  `ngx_command_t`, and merge it in the server-conf merge. No `./configure` needed
  unless you add a new `.c` file.
- **New origin opcode (e.g. another write-through op):** add a
  `xrootd_cache_origin_<op>()` to `origin_protocol.c` following the existing pattern
  (build the `Client*Request`, pick an unused `streamid[1]`, `htobe64` offsets, read
  via `xrootd_cache_read_response`, branch on `kXR_error`/`kXR_ok`), declare it in
  `cache_internal.h`, and call it from `fetch.c` / `writethrough_flush.c`.
- **New cache metric:** add the counter (see `../metrics/`), then bump it with
  `xrootd_cache_metric_add(ctx, <member>, n)` (eviction) or the
  `writethrough_metrics.h` inlines (write-through). Keep labels low-cardinality.
- **Custom write-through policy:** provide a `xrootd_wt_decision_fn` and set
  `cfg->fn`/`cfg->user_data`; the engine is already pluggable.
- **Adding a `.c` file here:** register it in the repo-root `config`
  (`NGX_ADDON_SRCS`) and add headers to the dep list, then re-run `./configure`.

## See also

- `../read/README.md` — open/read handlers that drive the read-through cache
  (`open_cache.c`, `slice_read.c`, `close.c`).
- `../write/README.md` — write/sync handlers that trigger write-through flush.
- `../fs/README.md` — VFS layer; `vfs_open.c`/`vfs_write.c` call the cache hit and
  write-through-decision helpers.
- `../aio/README.md` — thread-pool offload and event-loop resume used by every fill.
- `../path/README.md` — path resolution/confinement applied before the cache is
  consulted.
- `../manager/README.md` — SHM server registry updated on fill/evict in manager mode.
- `../metrics/README.md`, `../dashboard/README.md` — counters and flush events.
- `../README.md` — master subsystem index.
