# Phase 30: Hyper-Optimization — Throughput & Latency Across All Protocols

**Date:** 2026-06-12
**Author:** performance audit (whole-`src/` sweep)
**Status:** Historical audit / roadmap. Several entries were later implemented,
dropped, or corrected by Phase 32 and Phase 33; use those phase docs and current
source for final status before quoting an item as open.
**Scope:** Every protocol plane the module speaks — `root://`/`roots://` (stream),
`davs://`/`http://` (WebDAV), S3 REST, native TPC, cache, proxy/manager, and the
cross-cutting instrumentation (metrics, rate-limit, logging, TLS, SHM).
**Relationship to Phase 29:** Phase 29 (`../_archive/refactor/phase-29-read-throughput-bottlenecks.md`)
is the deep dive on the *single-stream `root://` read gap* (serial state machine,
no request pipelining, sendfile gated on `!c->ssl`). This phase is the **breadth**
companion: it catalogues every other measurable throughput/latency lever in the
tree and sequences them into an executable roadmap. Phase 29 remains the
authoritative plan for the read-pipelining pillar; this document references it
rather than restating it.

> **Non-negotiable:** none of the work below may weaken protocol correctness or
> the security invariants in `CLAUDE.md` (pgread/pgwrite per-page CRC, TLS buffer
> discipline, `resolve_path()` before every `open()`, `allow_write` gate before
> token scope, low-cardinality metric labels). Every item carries an
> invariant-preservation note. Optimizations that trade correctness for speed are
> out of scope.

---

## 0. How this audit was produced (and how to trust it)

Five independent read-only sweeps covered: (1) stream read/write + AIO, (2) HTTP
WebDAV + S3 data planes, (3) path/auth/token per-request overhead, (4)
cache/proxy/upstream/manager, (5) cross-cutting metrics/TLS/SHM/logging. Findings
were then **spot-verified against source** before landing here. Each finding below
carries a **confidence tag**:

- **`[VERIFIED]`** — I read the exact lines and confirmed the behavior.
- **`[AUDIT]`** — surfaced by a sweep, plausible from surrounding code, **but must
  be confirmed at implementation time** (and, where it claims a speedup, measured).

One sweep finding was **rejected on verification** and is documented in
Appendix A so nobody re-introduces it: the claim that the HTTP GET path buffers
whole files into memory over TLS and risks OOM is **false** — see A.1.

**Golden rule for this phase:** *measure before and after every item.* Several
"obvious" wins below are micro-optimizations whose real-world impact is unknown
until benchmarked on representative HEP workloads. The benchmark harness (§8) is a
prerequisite, not an afterthought.

---

## 1. Executive summary — the levers, ranked

| # | Lever | Plane | Effort | Expected gain | Confidence |
|---|---|---|---|---|---|
| **P0-1** | Remove duplicate bandwidth charge (`read.c:136-137`) | stream read | trivial | Correctness + un-throttles rate-limited reads 2× | **VERIFIED** |
| **P0-2** | PCLMULQDQ-folded CRC32c (replace serial `_mm_crc32_u64`) | pgread/pgwrite/TPC/cksum | small | Potential CRC throughput lift | **Superseded:** Phase 32 verified current CRC32C is hardware-accelerated and not the active bottleneck; profile before revisiting. |
| **P0-3** | Build flags: `-O3 -march=x86-64-v2 -flto` via `--with-cc-opt` | whole module | trivial | 3–10% across the board | **Superseded:** Phase 33 set `XROOTD_OPTIMIZE` defaults to `-O3 -march=x86-64-v2 -fno-plt`; LTO remains optional/experimental. |
| **P0-4** | Cumulative latency histogram → single-bucket increment | every request | small | Removes up to 8 atomics/request | **VERIFIED** |
| **P0-5** | `F_SETPIPE_SZ` 1 MiB on splice pipes | proxy relay | trivial | ~16× fewer `splice(2)` syscalls on large bodies | **VERIFIED** |
| **P1-1** | Request pipelining + TLS data-plane fix (Phase 29) | stream read | large | Close the 0.49–0.59× single-stream gap | see Phase 29 |
| **P1-2** | Redirect cache + server registry: hash index, drop global spinlock scan | manager | medium | O(n)→O(1) under the cluster hot lock | **VERIFIED** (redir), **AUDIT** (registry) |
| **P1-3** | Cache-line-pad / shard the hot metric counters | every request | medium | Kills RFO storms on high-core boxes | **VERIFIED** (no padding today) |
| **P1-4** | Per-request resolved-path + auth-result reuse (single canonicalize) | every request | medium | Cuts 10–30 `stat`/`realpath` syscalls on deep paths | **AUDIT** |
| **P1-5** | Reuse AIO task structs for `pgread`/`readv` (as `read.c` already does) | stream read | small | Removes a per-request pool alloc on hot ops | **VERIFIED** (read.c reuses; others don't) |
| **P1-6** | Precompute rule lengths; hash VO membership; parse JWT payload once | auth/token | medium | Removes O(N·M) string scans + 5× JSON re-parse/token | **AUDIT** |
| **P2-1** | Cache fill: `sync_file_range` instead of blocking `fsync`; `copy_file_range` origin→cache | cache | medium | Unblocks thread-pool saturation on fills | **AUDIT** |
| **P2-2** | Pre-size sendfile/memory chunk arrays in `aio/buffers.c` | stream large xfer | medium | Fewer pool allocs on TB-scale transfers | **AUDIT** |
| **P2-3** | Lock-free / sharded rate-limit + dashboard slot alloc | every request | medium | Removes SHM spinlock contention under load | **AUDIT** |
| **P2-4** | PROPFIND / S3 LIST: stat-after-filter, `statx` batching, PROPNAME skips stat | HTTP listing | medium | 2–10× fewer syscalls on big directories | **AUDIT** |
| **P3-x** | Connection-pool hashing, TLS resumption, buffered access log, EVP ctx reuse | various | medium | Tail-latency + CPU trims | **AUDIT** |

**The shape of the win:** P0 items are near-free correctness/throughput fixes that
should land first and immediately. P1 is the structural core (the read data plane,
the cluster lock, the metric false-sharing, the per-request resolve/auth cost). P2
and P3 are contention/syscall trims that matter most at high concurrency and
scale.

---

## 2. Pillar A — Stream (`root://`) data plane

The stream read path is the module's highest-bandwidth surface. Phase 29 owns the
pipelining + TLS analysis; the items here are the *complementary* fixes the breadth
sweep surfaced and I verified.

### A.1 `[VERIFIED]` Duplicate bandwidth charge on every cleartext read — **P0-1**

`src/read/read.c:136-137`:

```c
    xrootd_rl_charge_ctx(ctx, data_total);  /* Phase 25 bandwidth */
        xrootd_rl_charge_ctx(ctx, data_total);  /* Phase 25 bandwidth */
```

Two identical calls (note the inconsistent indentation — a classic copy-paste
artifact). The cleartext-sendfile fast path charges the Phase-25 bandwidth
leaky-bucket **twice per read**. On any deployment with `xrootd_rate_limit_bandwidth`
configured, every byte counts double, so clients are throttled to **half** their
configured budget on the fastest path. The non-TLS fallback path (later in the same
function) charges once, which is correct.

- **Fix:** delete one line. One-line diff.
- **Invariant note:** none affected; this *restores* intended rate-limit semantics.
- **Validation:** unit test asserting `rl_charge` is invoked exactly once per
  `kXR_read`; bandwidth-limit integration test sees full budget.

### A.2 `[VERIFIED]` Reuse AIO task structs for `pgread` and `readv` — **P1-5**

`src/read/read.c:211-222` already caches and reuses `ctx->read_aio_task` across
requests on a connection (reset `->next`/`->event.complete` on reuse). But:

- `src/read/pgread.c:158-161` allocates a fresh `ngx_thread_task_alloc(...)` every
  pgread.
- `src/read/readv.c:~331` allocates a fresh task every readv.

pgread is the modern xrdcp v5 streaming opcode — this is squarely on the hot path.

- **Fix:** add `ctx->pgread_aio_task` / `ctx->readv_aio_task`, mirror the read.c
  reuse pattern.
- **Invariant note:** pgread still emits `kXR_status(4007)` framing + per-page
  CRC; only the task allocation changes.
- **Validation:** pgread/readv correctness tests unchanged; confirm no
  per-request `ngx_thread_task_alloc` via a counter or `perf`/heap profile.

### A.3 `[AUDIT]` Zero-alloc fast path for pgread response chains — **P1-5 (adjacent)**

`src/read/pgread.c:210-250` builds the 2-link response (header + data) with ~5
fresh pool objects per request, whereas `read.c` reuses pre-allocated fast-path
chain/buf structs. Mirror the `xrootd_build_single_memory_chain` pattern with
`ctx->pgread_fast_*` structs.

- **Invariant note:** wire layout unchanged (`[CRC(4)][page]` per page).
- **Validation:** byte-identical pgread responses; allocation-count assertion.

### A.4 `[AUDIT]` Stack-allocate small `readv` working arrays

`src/read/readv.c:93` (`malloc(ranges_sz)`) and `:273` (segment-descriptor array)
allocate+free per readv. For the common case (≤ 64 segments) use a stack array and
fall back to heap only above a threshold. This removes malloc-lock traffic on
readv-heavy workloads.

- **Invariant note:** `XROOTD_READV_MAXSEGS`/overflow guards (Phase 27) must be
  preserved on both branches.

### A.5 `[AUDIT]` Writable-handle `fstat` per read

`src/read/read.c:112-122` re-`fstat`s on every read of a writable handle so a
concurrent write is visible. Correct, but one extra syscall per read for
write-then-read streaming. Consider caching `cached_size` and bumping it in
`write.c`/`pgwrite.c` on successful write, re-`fstat` only when a generation
counter says a foreign writer may have extended the file.

- **Risk:** correctness-sensitive — only worth it if profiling shows `fstat` is
  material. Default to leaving read-only path (already cached) alone.

### A.6 Large-transfer chunk-array pre-sizing — **P2-2**

`src/core/aio/buffers.c:277-334` (memory chains) and `:405-477` (sendfile chains)
allocate 4–5 pool objects **per 16 MiB chunk**. A 160 MiB read → 50 chunks → 250
allocations. Pre-allocate the chunk/`ngx_buf_t`/`ngx_file_t` arrays once per
response. `[AUDIT]` — pool allocs are cheap; measure before investing.

---

## 3. Pillar B — HTTP data plane (WebDAV + S3)

### B.1 `[VERIFIED-as-corrected]` TLS GET is **not** an OOM bug — it's an `aio threads` gap

See Appendix A.1 for why the "whole-file buffer over TLS" claim is false:
`src/core/compat/http_file_response.c:211-298` builds a single `in_file=1` buf and hands
it to `ngx_http_output_filter` — the **canonical** nginx pattern. Over TLS, nginx
reads the file in `output_buffers`-sized chunks; it never materializes the whole
file. The **real** lever is that those reads are **synchronous in the event loop**
unless `aio threads` is enabled, and they are small by default (`output_buffers
2 32k`).

- **Action (config + docs, not code):** ship a tuned reference config —
  `aio threads; directio 8m; output_buffers 4 256k; sendfile on; tcp_nopush on;`
  in the HTTP server blocks. Document that TLS throughput is gated by these.
- **Action (code, optional):** for the TLS GET path, offload the file read to the
  module thread pool the same way the stream path does, so large encrypted GETs
  don't stall the worker. `[AUDIT]`
- **Invariant note:** Invariant #2 (`b->memory=1` for TLS) is a **stream-protocol**
  rule for hand-built chains; the HTTP path correctly delegates to nginx's filter
  chain, which honors TLS vs sendfile itself. Do not "fix" the HTTP path to match
  the stream invariant.

### B.2 `[AUDIT]` PUT async path copies the whole body before dispatch

`src/protocols/webdav/put.c:246-272` allocates `ngx_palloc(r->pool, body_summary.bytes)` and
memcpys every body buf into it before posting the thread-pool write — defeating
nginx's streaming/temp-file spooling and doubling memory + copy cost on multi-GB
PUTs. Dispatch a descriptor holding the `xrootd_http_body_summary_t` + chain
pointer and have the worker `pwrite` directly from `r->request_body->bufs` (which
live until pool cleanup). Mirror for S3 `src/protocols/s3/put.c`.

- **Invariant note:** preserve the write-gate/auth ordering and any checksum
  computed during receive.
- **Validation:** large-PUT throughput + memory-high-water benchmark; integrity
  (ETag/checksum) unchanged.

### B.3 `[AUDIT]` Listing syscall amplification (PROPFIND / S3 LIST / COPY tree) — **P2-4**

Three walkers `stat()` every entry **before** applying the filter that would
discard it:

- `src/protocols/webdav/propfind.c` (Depth:1 ~`:853`, walk ~`:724`): one `stat` per entry;
  PROPNAME requests still `stat` despite needing only names.
- `src/protocols/s3/list_walk.c:~112`: `stat`s directories even when the delimiter prefix
  filter would skip them.
- `src/protocols/webdav/fs/copy_engine.c:~117`: sequential `lstat` per child + per-file
  `llistxattr`×2 on copy.

Fixes: (a) for PROPNAME, skip `stat` entirely — emit empty property elements;
(b) apply the name/prefix filter from `d_name` **before** `stat`; (c) batch with
`getdents64` + grouped `statx`. Expected 2–10× fewer syscalls on large
directories.

- **Invariant note:** confinement (`resolve_path`/beneath) must still gate every
  child path before it is opened/statted; filtering on `d_name` is allowed but the
  surviving entries still go through the canonical resolver.

### B.4 `[AUDIT]` S3 SigV4 canonical-request rebuild not cached

`src/protocols/s3/auth_sigv4_*`: the **signing key is cached** (verified the cache exists),
but the canonical query string + canonical headers are rebuilt per request
(`auth_sigv4_canonical.c` stack `qparam_t params[64]`, `enc[1024]`, `qsort`).
Add a single-range/simple-request fast path and consider caching canonical bytes
keyed by a request fingerprint on signing-key-cache hits.

- **Invariant note:** SigV4 ≠ WLCG token (Invariant #6) — keep the auth engines
  separate; do not let any caching bridge the two.

### B.5 `[AUDIT]` Single-range fast path for `Range`

`src/core/compat/range.c:39-77` always routes single-range `bytes=a-b` through the
general multi-range vector parser. Add an inline fast path for the dominant
single-range case.

---

## 4. Pillar C — Per-request overhead: path resolution, ACL, token

These run on **every** request, so wins compound across all protocols.

### C.1 `[AUDIT]` One canonicalization + reuse the result — **P1-4**

`src/fs/path/unified.c` calls `realpath()` (and the missing-parent/tail variants)
multiple times per resolve (`:468`, `:334`, `:384`), plus
`resolve_path_variants.c:16` re-derives the canonical root that the caller already
has. Each `realpath` is O(depth) `lstat`s; a write into a deep tree can cost
**10–30 syscalls**. Carry a per-request resolved-path struct (canonical path + its
`stat` + the relative/base components) so downstream `beneath`/open/stat reuse it
instead of re-scanning (`src/fs/path/beneath.c:83`, `resolve_confined_helpers.c`).

- **Invariant note:** Invariant #4 — *every* wire path still resolves before
  `open()`. The optimization is to resolve **once** and thread the result, not to
  skip resolution. For writes with `allow_missing_parents`, only `realpath` the
  deepest existing ancestor, then append the validated tail (avoids stat storms on
  non-existent intermediates) — but still confine the final path.

### C.2 `[AUDIT]` Precompute rule lengths; kill per-iteration `strlen` — **P1-6**

`src/auth/authz/find_rule.c:58-71,93-106,128-143` calls `strlen(rule[i].resolved)`
**inside** the match loop. Precompute `resolved_len` at config finalization
(`src/fs/path/helpers.c`) and store it on the rule struct. Pure config-time cost,
zero runtime.

### C.3 `[AUDIT]` Hash VO membership instead of comma-string scan — **P1-6**

`src/auth/authz/acl.c:88-101` linear-scans a comma-separated VO list with `strchr` per
ACL check. Build a small hash set on the identity at auth time
(`src/core/types/identity.c`) → O(1) membership.

### C.4 `[AUDIT]` Parse the JWT payload once — **P1-6**

`src/auth/token/json.c` + `src/auth/token/validate.c`: each claim extraction (`iss`, `sub`,
`aud`, `scope`, `groups`) re-runs `json_loadb()` over the whole payload — ~5
parses per token. Parse once into a `json_t` root, extract all claims, `decref`.
The header path already does this; apply the same to the payload.

- **Note:** full token *validation* results are already cached
  (`token_cache.c`, 5-min TTL) — verified. This item only removes redundant work
  on cache **misses**, which dominate first-contact and short-TTL scenarios.

### C.5 `[AUDIT]` Auth-gate cache key construction

`src/auth/authz/auth_gate.c:23-61` rebuilds a ~3.6 KB staging buffer and `strlen`s four
strings per request before SHA-256. Pass known lengths from the resolver (C.1) and
hash the four fields incrementally instead of concatenating into a temp buffer.

### C.6 `[AUDIT]` Streaming base64url decode

`src/auth/token/b64url.c:11-40` puts an 8 KiB scratch on the stack per token decode.
Feed OpenSSL `EVP_DecodeUpdate` incrementally with a small fixed buffer.

> **GSI / OCSP / JWKS:** verify (do not assume) that cert-chain verification,
> OCSP, and JWKS key fetches are cached and never block the request event loop. If
> any synchronous network fetch exists on the request path, that is a **latency
> cliff** and jumps to P1. The sweep did not find a blocking fetch, but this must
> be confirmed.

---

## 5. Pillar D — Cluster, cache, and proxy

### D.1 `[VERIFIED]` Redirect cache is an O(n) scan under a global spinlock — **P1-2**

`src/net/manager/redir_cache.c:148-163` (lookup) and `:183-208` (insert) hold
`xrootd_redir_mutex` across a **full linear scan** of all `capacity` (default 512)
entries, comparing `ngx_strcmp(e->path, path)` each slot. Every `kXR_open`/locate
that consults the redirect cache serializes on this one lock and walks ~200 KB of
entries (L3-missing). On a busy manager this is a top contention point.

- **Fix:** open-addressing hash table keyed by path hash (the SHM is already
  fixed-size — a hash over the same slot array is a small change); or a
  reader-writer lock since lookups dominate inserts. Skip expired entries in O(1).
- **Invariant note:** redirect correctness/TTL semantics unchanged; only the
  lookup structure changes.
- **Validation:** cluster redirect tests pass; micro-benchmark lookup latency vs
  entry count; contention visible in `perf lock`.

### D.2 `[AUDIT]` Server registry full-scan per locate/select — **P1-2**

`src/net/manager/registry.c` (`select_read`, `locate_all`, `register`,
`update_load`) scan the 128-slot registry under `xrootd_srv_mutex`, and
`srv_path_matches` (`:134-167`) re-parses colon-delimited path tokens per query.
Cache "best server per path" (TTL), and/or partition by path-hash bucket to shrink
lock scope. Pre-tokenize export paths at registration.

### D.3 `[AUDIT]` Cache fill blocks the thread pool on `fsync` — **P2-1**

`src/fs/cache/fetch.c:~113` does a full `fsync(outfd)` per completed fill on a pool
thread; with a 32-thread pool and 10–100 ms `fsync`, fill throughput caps low and
clients sit in `kXR_wait`. Use `sync_file_range(..., SYNC_FILE_RANGE_WRITE)` for
async writeback and reserve a durability barrier for the final
rename/commit. Consider `copy_file_range` for origin→cache when both ends are local
(zero-copy), and pipeline origin reads (send N before awaiting the first) on
high-RTT links.

- **Invariant note:** cache correctness — a slice must not be marked "ready" until
  its bytes are durably committed for the validity guarantees the cache makes;
  keep the commit barrier, only relax intermediate writeback.

### D.4 `[AUDIT]` Cache-hit metadata read per request

`src/fs/cache/meta.c:69-109` does open+read+close of the `.meta` sidecar on the cache
**hit** path (`open.c:155`). Cache parsed metadata per worker with a short TTL (or
a small SHM metadata cache) to make hits truly syscall-light.

### D.5 `[AUDIT]` Slice eviction uses `glob()`

`src/fs/cache/slice_fill.c:72-77` → `slice.c:~201` `glob()` to enumerate slices on
invalidation; pathological for files with 10⁵+ slices. Maintain a per-file slice
list in the metadata sidecar for O(1) eviction.

### D.6 `[VERIFIED]` Proxy splice pipes use the default 64 KiB — **P0-5**

`src/net/proxy/events_splice.c` creates pipes with `pipe2` and never calls
`fcntl(F_SETPIPE_SZ)` (verified: no `F_SETPIPE_SZ` anywhere). A 1 GiB relayed body
→ ~16 384 `splice` calls at 64 KiB each. Set the pipe to 1 MiB (Linux max default)
→ ~16× fewer syscalls.

- **Invariant note:** none; pure syscall-count reduction on the existing
  cleartext-splice fast path.

### D.7 `[AUDIT]` Proxy response body uses raw `ngx_alloc` per response

`src/net/proxy/events_read.c:~98` `ngx_alloc(resp_dlen + 1, ...)` per non-spliced
(TLS/pipelined) response, capped at 16 MiB. Use a per-worker buffer pool or
`ngx_palloc` to cut allocator churn; revisit the 16 MiB cap with chunked relay for
large TLS responses.

### D.8 `[AUDIT]` Upstream/proxy connection pool: O(n) scan + dead-keepalive

`src/net/proxy/pool.c:~228-262` linear-scans the 32-slot pool per acquire; the
keepalive timer (`:136-165`) re-arms but never validates the connection, so a
restarted upstream leaves zombie sockets that cost a failed read on first reuse.
Hash the pool by `(upstream_idx, auth, token_hash)`; either validate with a
real ping/drain on reuse or rely on `SO_KEEPALIVE` + `TCP_KEEPIDLE/INTVL/CNT`.

---

## 6. Pillar E — Cross-cutting instrumentation

### E.1 `[VERIFIED]` Cumulative latency histogram does up to 8 atomics/request — **P0-4**

`src/observability/metrics/unified.c:176-184`:

```c
for (i = 0; i < XROOTD_IO_LATENCY_BUCKETS - 1; i++) {
    if (latency_usec <= xrootd_latency_bounds[i]) {
        XROOTD_ATOMIC_INC(&shm->unified.io_latency_bucket[proto][op][i]);
    }
}
XROOTD_ATOMIC_INC(... [BUCKETS-1]);
XROOTD_ATOMIC_INC(&shm->unified.io_latency_count[proto][op]);
XROOTD_ATOMIC_ADD(&shm->unified.io_latency_sum_usec[proto][op], latency_usec);
```

This increments **every** bucket whose bound ≥ latency (a pre-cumulated histogram)
→ up to 8 atomic increments + count + sum per I/O. The standard pattern is to
increment **one** bucket (the one the sample falls in) and compute the cumulative
distribution **at scrape time** in the exporter (`src/observability/metrics/writer.c`). That
turns 8–10 atomics into 3 (one bucket + count + sum).

- **Invariant note:** Prometheus `_bucket` output stays cumulative (computed in the
  exporter); only the write-side representation changes. Scrape output is
  byte-compatible.
- **Validation:** golden-file test on `/metrics` histogram output unchanged;
  benchmark atomics/request.

### E.2 `[VERIFIED]` Hot metric counters are densely packed `ngx_atomic_t` arrays — **P1-3**

`src/observability/metrics/metrics.h` (op_ok/op_err per the file's own comment) and the WebDAV/S3
metric structs (`:193-235`) are contiguous `ngx_atomic_t` arrays with **no
cache-line padding**. Adjacent counters touched by different cores on different
requests share cache lines → RFO ping-pong (false sharing) on high-core machines.

- **Fix options (measure first):** (a) pad/segregate the hottest counters
  (`request_frames_total`, `bytes_*`, op_ok/op_err for read/write) onto their own
  cache lines; or (b) per-worker local counters flushed to SHM periodically (best
  scalability, more code). Start with (a) for the top ~6 counters.
- **Invariant note:** metric *values* and label cardinality unchanged (Invariant
  #8); only memory layout changes.
- **Validation:** `perf c2c` shows false-sharing before/after; counter totals
  identical under concurrent load.

### E.3 `[AUDIT]` Repeated null-checks and time reads on the metric/RL path

- `src/observability/metrics/metrics_macros.h:35-47`: `if (ctx && ctx->metrics)` re-evaluated at
  20+ call sites/request. Hoist a validated `metrics` pointer into the context once
  at request entry.
- `src/net/ratelimit/ratelimit.c:36,50,103,166,211`: `ngx_current_msec` re-read 5×/check
  — read once, pass down.
- `src/observability/metrics/tracking.c:154-158`: `gettimeofday()` syscall on new-user insert —
  use cached `ngx_time()`.
- `src/observability/metrics/tracking.c:55-66`: linear VO-slot string scan — hash like the user
  path already does.

### E.4 `[AUDIT]` Rate-limit + dashboard SHM spinlock contention — **P2-3**

`src/net/ratelimit/ratelimit.c:38-71` holds `shpool->mutex` across lookup + token-bucket
arithmetic; `src/core/shm/kv.c:247-282` holds the KV mutex across a linear-probe scan;
`src/observability/dashboard/transfer_table.c:82-135` holds `xrootd_dashboard_mutex` across an
O(512) free-slot scan + memzero + field copies on every open/close. Under a
single-key burst (bulk client / DDoS) all cores serialize. Move to per-identity
lock-free token buckets (CAS on a packed `{timestamp,tokens}` word), a free-list
for dashboard slots, and copy-out-then-compare-outside-lock for KV reads.

### E.5 `[AUDIT]` Access-log formatting + unbuffered writes

`src/observability/metrics/access_log.c:50-98` JSON-escapes path + subject (per-char scan) and
`ngx_log_error`s one line per request (one write/syslog datagram per request at
1000+ rps). Single-pass builder writing straight to a per-worker ring buffer,
flushed on a timer / size threshold. Sanitize once at parse time
(`src/core/compat/log.c:11-18`), not on every log call.

- **Invariant note:** keep `xrootd_sanitize_log_string` semantics (control-byte /
  quote escaping) — just do it once and reuse.

### E.6 `[AUDIT]` TLS: resumption + per-handshake allocs

`src/session/tls_config.c`: confirm session resumption / ticket policy is set
intentionally (`:84-89` sets versions but no explicit ticket policy);
`:54-60` `OPENSSL_malloc`s the OCSP staple copy per handshake (pre-allocate once).
Evaluate `SSL_sendfile` (OpenSSL 3.2+, in RHEL 9's openssl) for the cleartext-to-TLS
GET path. Per-request `EVP_MD_CTX_new/free` in `src/auth/token/signature.c` and
`X509_STORE_CTX` in `src/auth/crypto/gsi_verify.c` are inherent to the OpenSSL API but
are already shielded by the token/auth caches — leave unless profiling says
otherwise.

---

## 7. Pillar F — Build & compiler (free, global wins)

Phase 33 superseded the original build-flag finding: `XROOTD_OPTIMIZE` now
defaults to `-O3 -march=x86-64-v2 -fno-plt` with profile escapes. The original
proposal below is retained only for LTO / fleet-specific tuning experiments.

### F.1 `[SUPERSEDED]` Add an optimized cc-opt profile — **P0-3**

```
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads --add-module=$REPO \
  --with-cc-opt='-O3 -march=x86-64-v2 -mtune=native -flto=auto -fno-plt -pipe' \
  --with-ld-opt='-flto=auto'
```

- `-march=x86-64-v2` is the safe RHEL 9 baseline (SSE4.2/POPCNT guaranteed on all
  v2 hardware) — it lets the compiler emit SSE4.2 everywhere, not just in the
  `__attribute__((target("sse4.2")))` CRC functions. For homogeneous fleets,
  `x86-64-v3` (AVX2/BMI2) is a bigger win where the deployment CPUs allow it; gate
  behind a build profile.
- `-flto` cross-module inlines the hot helpers (path resolve, CRC, chain builders)
  that currently sit behind translation-unit boundaries.
- **Constraint honored:** no external RPMs — these are plain GCC flags shipped with
  RHEL 9's `gcc`.
- **Invariant note:** runtime CPU dispatch in `crc32c.c` still guards SSE4.2; but
  if the **whole** binary is built `-march=x86-64-v2`, the software CRC fallback
  becomes dead on supported hardware (keep it for portability builds).
- **Validation:** rebuild, full test suite green, A/B throughput on the §8 harness.

### F.2 `[PROFILE-FIRST]` Replace serial CRC32c with PCLMULQDQ-folded CRC — **P0-2**

Phase 32 verified the current CRC32C path is already hardware-accelerated and
not the active data-plane bottleneck. Keep the rationale below as an optional
future tuning idea, not as a current P0.

`src/core/compat/crc32c.c:140-170` (`hw_extend`) processes 8 bytes/iteration with a
**serial dependency** on `state` through `_mm_crc32_u64` (latency ~3 cycles,
throughput-bound to ~one 8-byte chunk per 3 cycles ≈ 2–3 GB/s). The
state-of-the-art is **3-way (or N-way) parallel folding with `PCLMULQDQ`** plus
multiple independent `crc32` accumulators, reaching 20–30 GB/s — the standard
"fast CRC32C" construction (Intel's slicing/folding paper; the same math zlib-ng
and ISA-L use). This directly gates pgread/pgwrite throughput, TPC copy+checksum,
and PROPFIND/fattr checksum responses.

- **Fix:** implement an N-way folded CRC32C in-tree (no external dependency — pure
  intrinsics behind `__attribute__((target("sse4.2,pclmul")))` with runtime
  `__builtin_cpu_supports("pclmul")` dispatch, mirroring the existing SSE4.2
  guard). Keep the serial path as the small-buffer / no-PCLMUL fallback. The
  single-pass `crc32c_copy` variant gets the same treatment for TPC.
- **Why in-tree, not a library:** ISA-L / zlib-ng are **not** in RHEL 9 base
  (constraint), and the folded CRC is ~150 lines of well-known intrinsics. No new
  dependency.
- **Invariant note:** Invariant #1 — per-page CRC32C values must be **bit-identical**
  to today's output. This is a performance-only change to a checksum that must
  match the wire. Gate behind an exhaustive equivalence test (random buffers, all
  page sizes, all alignments) vs the software reference before enabling.
- **Validation:** `crc_folded(buf) == crc_serial(buf) == crc_sw(buf)` for a large
  fuzz corpus; micro-benchmark GB/s; pgread/pgwrite interop tests with real xrdcp.

---

## 8. Benchmark & validation harness (prerequisite for the whole phase)

No item lands without a before/after number. Reuse and extend the existing
infrastructure (`tests/run_load_test.sh`, the port-deconfliction work noted in
memory, and Phase 29's baseline methodology).

**Workload matrix (per protocol):**

| Dimension | Values |
|---|---|
| Protocol | `root://` cleartext, `root://`+GSI+TLS, `davs://`, S3, native TPC, proxy/cache |
| Object size | 4 KiB (metadata-bound), 1 MiB, 1 GiB, 100 GiB (streaming) |
| Concurrency | 1, 16, 256, 1024 streams |
| Op mix | pure read, pure write, readv, pgread, PROPFIND/LIST (1–100 K entries), mixed |
| Box | low-core (4), high-core (≥ 32) — for false-sharing/lock items |

**Metrics captured:** MiB/s, p50/p99/p999 latency, syscalls/request (`strace -cf`
sample), allocations/request (heap profiler or `ltrace` sample), `perf stat`
(IPC, cache-misses), `perf lock`/`perf c2c` (contention/false-sharing),
CPU%/byte.

**Regression gates:** full `pytest tests/ -v` must stay green; the
3-tests-per-change rule (success + error + security-negative) applies to every
code item; `/metrics` golden output unchanged for E.1/E.2; CRC equivalence corpus
for F.2.

**Per-item template** (each item gets a one-pager): hypothesis → exact change →
predicted gain → measured gain → invariants re-verified → keep/revert.

---

## 9. Phased roadmap

**P0 — land immediately (days, near-zero risk):**
- A.1 duplicate RL charge (1-line)
- F.1 cc-opt `-O3 -march=v2 -flto`
- F.2 PCLMULQDQ CRC (behind equivalence gate)
- E.1 single-bucket histogram
- D.6 `F_SETPIPE_SZ` 1 MiB
- A.2 reuse pgread/readv AIO tasks

**P1 — structural core (the real throughput/latency):**
- P29 read pipelining + TLS data plane (Phase 29 plan)
- D.1 redirect-cache hash index (+ D.2 registry)
- E.2 metric counter cache-line padding/sharding
- C.1–C.5 resolve-once + rule-len + VO-hash + parse-payload-once + auth-key
- B.2 PUT streaming (no whole-body copy)

**P2 — contention & syscall trims (matter at scale):**
- D.3 cache-fill `sync_file_range`/`copy_file_range`
- E.4 lock-free rate-limit + dashboard free-list + KV read-outside-lock
- B.3 listing stat-after-filter / `statx` batching
- A.6 chunk-array pre-sizing; D.4/D.5 cache metadata/eviction; D.7/D.8 proxy buffers/pool

**P3 — tail-latency & polish:**
- B.4/B.5 SigV4 + single-range fast paths
- E.5 buffered access log; E.6 TLS resumption / `SSL_sendfile` / per-handshake allocs
- C.6 streaming base64url

Each phase ends with a harness run and a short results addendum to this doc.

---

## 10. Risk register & invariant-preservation checklist

| Risk | Items | Mitigation |
|---|---|---|
| CRC output drift breaks pgread/pgwrite interop | F.2 | Bit-exact equivalence fuzz vs SW reference before enable; real-xrdcp interop test |
| Histogram refactor changes `/metrics` output | E.1 | Golden-file scrape test; cumulative computed in exporter |
| Resolve-once weakens confinement | C.1, B.3 | Every final path still goes through `resolve_path`/beneath before `open`; resolve **once**, never **skip** |
| Lock-free RL/dashboard introduces races | E.4, D.1 | CAS-only updates, single-writer where possible; ASAN/TSAN run; keep spinlock fallback behind a flag |
| `-march=v3`/`native` on heterogeneous fleet | F.1 | Default to `x86-64-v2`; gate v3/native behind explicit build profile |
| Cache writeback relaxation risks durability | D.3 | Keep the commit/rename barrier; only relax intermediate `fsync` |
| PUT streaming changes auth/checksum ordering | B.2 | Preserve write-gate-before-scope and receive-time checksum; integrity tests |

**Invariants re-checked for every item** (from `CLAUDE.md`): (1) pgread/pgwrite
CRC framing, (2) TLS `b->memory` vs cleartext sendfile discipline on the **stream**
plane, (3) `allow_write` before token scope, (4) `resolve_path()` before `open()`,
(6) SigV4 ≠ WLCG, (8) low-cardinality metric labels.

---

## Appendix A — Rejected / corrected findings (do not re-introduce)

### A.1 "HTTP GET buffers whole files into memory over TLS → OOM" — **FALSE**

A sweep flagged `src/core/compat/http_file_response.c:253` (`b->in_file = 1` set
unconditionally) as forcing whole-file memory buffering over TLS. **Verified
false.** The function builds a single file-backed `ngx_buf_t` and calls
`ngx_http_send_header` + `ngx_http_output_filter` (`:280-298`) — the canonical
nginx file-serving pattern. Over a TLS connection, nginx's output/SSL filter chain
reads the file in `output_buffers`-sized chunks and encrypts incrementally; it does
**not** allocate the whole file. There is no OOM risk and no Invariant-#2 violation
(that invariant governs hand-built **stream** chains, not nginx's HTTP filter
chain). The genuine, much smaller issue is that those chunked reads are
**synchronous** unless `aio threads` is enabled and small by default — addressed by
B.1 as configuration + an optional thread-pool offload, **not** by changing the buf
type. Do not "fix" the HTTP path to use `b->memory=1`; that would *disable*
sendfile on the cleartext path and make throughput worse.

### A.2 Items deferred as "measure first, likely low-impact"

`copy_file_range` for repeated same-span reads (A-pillar), `POSIX_FADV_WILLNEED`
prefetch effectiveness (`src/read/prefetch.c`), `safe_size.h` overflow-check branch
cost — all plausible but probably noise; only pursue if the harness shows them on a
flame graph. The Phase-27 memory-safety guards (`safe_size.h`, readv overflow
checks) must **not** be removed for speed.
