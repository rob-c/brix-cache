# Phase 32: Data-Plane Performance Parity — beat vanilla XRootD / XrdHttp

**Date:** 2026-06-13
**Author:** performance deep-dive
**Status:** IN PROGRESS — WS1 (kTLS), WS2 (multi-chunk pipelining), WS4 (inline
warm-cache `preadv2(RWF_NOWAIT)` reads), WS5 (config bundle + tuning docs) DONE &
verified. WS3 **foundation** landed+verified (concurrent-AIO read-buffer/task pool)
+ architecture fully documented; the WS3 recv-state-machine flip is **deferred to a
benchmark-backed session** (throughput-unvalidatable here + flaky harness). WS5
access-log batching + WebDAV per-request cuts: tracked follow-ups (documented).

> **WS4 (2026-06-13):** `src/protocols/root/read/read.c` memory single-shot path probes the page
> cache with `preadv2(RWF_NOWAIT)` before posting AIO; a full hit completes inline
> (reusing the sync-fallback completion), skipping the thread round-trip on
> cache-hot reads. Regular-files-only, thread-pool-only; short/EAGAIN → AIO.
> Verified: integrity matrix 48 pass (TLS memory reads), readv+phase31 15 pass,
> byte-exact, no crashes. **WS5:** config bundle already in `nginx.perf.conf`
> (sendfile/tcp_nopush/output_buffers/thread_pool=64/ssl_buffer_size) + WS1 added
> it to the shared template; documented the full tuning bundle + the `directio`
> caveat (it defeats the WS4 warm path) in `performance-benchmarks.md`.

> **Implementation log (2026-06-13)**
> - **WS1 kTLS — DONE, verified.** Config-only (no module code): `sendfile on;
>   tcp_nopush on; output_buffers 2 256k;` in `http{}` + `ssl_conf_command Options
>   KTLS; ssl_buffer_size 64k;` in the davs:// blocks of
>   `tests/configs/nginx_shared.conf` and `tests/nginx.perf.conf`. Proven on-host:
>   config parses, kTLS available (OpenSSL 3.0.18, `tls` module, `/proc/net/tls_stat`),
>   **`TlsTxSw` +5 over 5 TLS GETs** (one kTLS socket/connection) and **`strace`
>   shows `sendfile`** on the TLS GET (SSL_sendfile, zero-copy from page cache).
>   This host has **software** kTLS only (`TlsTxDevice`=0 — no NIC offload), so the
>   win is userspace-copy elimination, not AES offload. 855 webdav/s3 tests pass.
>   Documented in `docs/05-operations/performance-benchmarks.md`. (`vfs_read.c`
>   `is_tls` gate confirmed dead code — left as-is.)
> - **WS2 multi-chunk pipelining — DONE, verified.** `XROOTD_SLOT_HDR_MAX` tunable;
>   `xrootd_resp_slot_t.hdr_bytes` widened 8→32 B (`src/core/types/context.h`); the
>   multi-chunk sendfile builder (`src/core/aio/buffers.c`) now writes per-chunk headers
>   into `slot->hdr_bytes` (not shared `read_hdr_scratch`) and sets
>   `resp_pipelinable=1`. **Full reconfigure+rebuild** (struct layout changed — the
>   mixed-ABI gotcha). Validated: 200 MiB multi-chunk root:// read **byte-exact**
>   (md5 == on-disk), read→readv self-consistent, 89 read/readv/integrity/phase31
>   tests pass, no worker crash.
> - **Recurring env quirk:** writing a brand-new file to the anon root:// port can
>   return `kXR_NotAuthorized` (3010); validate reads against pre-seeded
>   `large200.bin` instead. Standalone TLS shell tests need
>   `X509_USER_PROXY`/`X509_CERT_DIR` set (conftest sets them).
**Scope:** the three bulk data planes — `davs://`/WebDAV+TLS, S3, and `root://` —
`src/protocols/root/read`, `src/core/aio`, `src/protocols/root/connection`, `src/fs`, `src/shared`, `src/protocols/webdav`,
`src/protocols/s3`, plus nginx runtime config.
**Builds on:** Phase 29 (read bottlenecks), Phase 30 (hyper-opt), Phase 31
(memory-budget streaming: windowing + budget + pipelining ring scaffold). This
plan layers performance **on top of** that new functionality without regressing
its memory guarantees.

---

## Measured baseline (the targets)

| Plane | Today | Goal |
|---|---|---|
| `https://` WebDAV+TLS read | native **XrdHttp ~13% ahead** | match, then beat |
| `s3://` GET (cleartext) | **~5 Gbps** (already strong) | hold; lift the ceiling |
| `root://` read | **was ~2× vanilla XRootD**, regressed by new functionality | restore ≥2× |

**Why the asymmetry:** S3 GET is typically **cleartext** → nginx `sendfile(2)`
zero-copy. WebDAV is **TLS** → historically no sendfile → userspace
read+encrypt+write per chunk. `root://` regressed because the new
windowing/budget/trim work and a **depth-1 send pipeline** added per-transfer
overhead the old fast path didn't have.

---

## Verified architecture findings (confirmed in code, 2026-06-13)

1. **Build flags are already optimal.** `/tmp/nginx-1.28.3/objs/Makefile` CFLAGS
   already include `-O3 -march=x86-64-v2 -fno-plt`. The Phase-30 "no -O3" note is
   **stale** — no win here. (Optional experiment only: `-flto`.)
2. **CRC32C is already hardware-accelerated** (`src/core/compat/crc32c.c` uses
   `_mm_crc32_u64`, SSE4.2). Not a bottleneck. No action.
3. **nginx 1.28.3 supports `SSL_sendfile` (kTLS)** — 7 references in
   `src/event/ngx_event_openssl.c`. kTLS is achievable on this build.
4. **WebDAV/S3 GET serve the body as a file-backed buf** (`webdav/get.c:184`
   `dup(fd)` → `xrootd_http_send_file_range`; `shared/file_serve.c:71-80`;
   `compat/http_file_response.c` sets `b->in_file=1`). So on TLS the response is
   *already* a file buf — nginx will use `SSL_sendfile` **iff kTLS is enabled**,
   else it falls back to read()+`SSL_write`. **kTLS is the lever, not a rewrite.**
5. **`src/fs/vfs_read.c:199` forces a userspace memory chain whenever
   `fh->is_tls`** (`ngx_pnalloc(length)`+`pread`). This VFS read API is a second
   serve path; on any TLS path that uses it, it both defeats `SSL_sendfile` and
   adds a full copy+alloc. Must be gated to `want_pgcrc` only.
6. **`root://` send pipeline is effectively depth-1 for the cases that matter.**
   `resp_pipelinable` is set to **1 only in the single-chunk cleartext sendfile
   builder** (`src/core/aio/buffers.c:332`); it is **0** for multi-chunk (>16 MiB,
   `buffers.c:526`), for TLS/windowed reads, and reset each request
   (`recv.c:381,442`). The `out_ring[XROOTD_PIPELINE_MAX=4]` exists
   (`context.h:142`) but only small cleartext reads ever fill it. Large and TLS
   reads stall the recv loop until the response fully drains (`recv.c:406/465`
   gate on `resp_pipelinable`).
7. **Every memory read posts to the thread pool** (`read.c` → `xrootd_aio_post_task`);
   no inline fast path for small/cache-hot reads — each pays a thread round-trip.
8. **Access log writes per read** when configured (`read.c:178/248/363`, gated on
   `rconf->access_log_fd != NGX_INVALID_FILE`) — a synchronous `write(2)` per read.

---

# Section 1 — HTTPS / WebDAV+TLS: erase the 13% and pass XrdHttp

XrdHttp also runs TLS, so the 13% is **per-transfer CPU/syscall overhead**, not
the encryption itself. The decisive lever is moving the encrypt to the kernel
(kTLS) so we zero-copy like the cleartext S3 path does.

### 1A. Enable kTLS / `SSL_sendfile` for HTTP GET — **headline win**

**What:** Make the file-backed GET response use `SSL_sendfile` (kernel TLS)
instead of userspace read+`SSL_write`.

**How (config + verification, minimal code):**
- nginx side (test + production configs, `/tmp/xrd-test/conf` and docs):
  ```nginx
  sendfile on;
  ssl_conf_command Options KTLS;     # OpenSSL 3.0+; enables tx kTLS offload
  ```
  Requires: Linux ≥ 4.13 with the `tls` ULP (`modprobe tls`), OpenSSL ≥ 3.0
  built with kTLS, and an offloadable cipher (AES-128/256-GCM). nginx
  automatically falls back to read+`SSL_write` when kTLS is unavailable, so this
  is safe to ship on.
- code side — **remove the TLS memory-forcing** so a file buf actually reaches
  nginx's output filter:
  - `src/fs/vfs_read.c:199` — change
    `if (fh->is_tls || (fh->ctx && fh->ctx->want_pgcrc))` →
    `if (fh->ctx && fh->ctx->want_pgcrc)`. Only the CRC path (`want_pgcrc`, which
    must see plaintext bytes) needs a memory chain; plain TLS GET must use
    `xrootd_vfs_make_file_chain` (already correct: `in_file=1`, `file_pos`,
    `file_last` at `vfs_read.c:135-137`). **First confirm** whether the live
    WebDAV/S3 GET body actually flows through `xrootd_vfs_read` or only through
    `xrootd_http_send_file_range`; fix whichever serves the bytes. (get.c uses
    `xrootd_vfs_open` for the fd but sends via `send_file_range` — so the file
    buf path is already used; the vfs_read gate is the belt-and-suspenders fix.)

**Why it beats XrdHttp:** XrdHttp encrypts in userspace via OpenSSL. With kTLS we
hand the file + offset to the kernel and the NIC/CPU encrypts inline — no
userspace copy, far fewer syscalls. This is the same structural advantage that
makes cleartext S3 hit 5 Gbps, now applied to TLS.

**Risk:** kTLS cipher constraints; renegotiation/0-RTT edge cases — nginx handles
fallback. Validate the cipher negotiated is AES-GCM.

**Expected impact:** large TLS GET CPU drops ~40–60%; flips the 13% deficit to a
lead. **Validation:** `ss -ti` shows `tls` offload; `strace -c` shows
`sendfile`/`SSL_sendfile` not `write`; `perf stat` CPU-per-GiB; throughput vs
XrdHttp on the same 1 GiB TLS GET.

### 1B. Larger TLS records — `ssl_buffer_size`

**What:** Default `ssl_buffer_size` is 16k → many small TLS records/`SSL_write`
calls on the non-kTLS fallback and small first-byte batching.
**How:** set `ssl_buffer_size 64k;` (up to 128k) in the WebDAV/S3 HTTPS server
blocks (config, no code).
**Impact:** ~10–20% fewer TLS-record/syscall overheads on the fallback path;
negligible cost with kTLS. Trade-off: marginally higher TTFB — 64k is the sweet
spot for bulk reads.

### 1C. Per-transfer overhead reduction (the "more per-transfer overhead than
XrdHttp" the report cites)

Each of these shaves fixed per-request cost; together they matter on small/medium
GETs and keepalive range streams:

- **fd `dup(2)` per request/range** (`webdav/get.c:184`, `shared/file_serve.c:71`,
  `vfs_read.c:96`): on a keepalive connection re-GETting the same path (range
  streaming), cache the dup'd send-fd in the request/connection ctx and reuse it
  across ranges; invalidate on path change. Saves one `dup` + cleanup per range.
- **Path resolution per GET** (`webdav/path.c` `resolve_path` → openat2/realpath):
  cache the resolved canonical path keyed by `r->uri` on the connection for
  repeat/range GETs of the same object.
- **Auth re-verification** (`webdav/auth_cert.c`, `auth_token.c`): the GSI cert
  cache exists; add a per-connection `auth_verified` short-circuit and a
  per-TLS-session bearer-token (JWT exp/claims) cache so each keepalive request
  isn't re-walking verification.
- **CORS on every request** (`webdav/cors.c`, `access.c:81`): early-return when
  there is no `Origin` header and no configured CORS origins; precompute the
  `Allow` header string once at config time.
**Impact:** ~5–15% latency on small/medium and range-heavy workloads; precisely
the "fixed overhead" gap vs XrdHttp.

---

# Section 2 — root://: restore ≥2× over vanilla XRootD

The cleartext sendfile data plane is excellent; the regression is **serialization
and per-read fixed cost** added around it. Restore throughput by deepening the
pipeline and removing per-read overhead — without breaking Phase 31 memory bounds.

### 2A. Pipeline **all** read responses, not just small cleartext — **headline**

**What:** Today only single-chunk cleartext sendfile reads set
`resp_pipelinable=1`; multi-chunk (>16 MiB) and TLS/windowed reads run depth-1,
so the recv loop blocks until each large response fully drains — the dominant
`root://` regression for the large sequential reads HEP clients issue.

**How:**
1. **Multi-chunk sendfile:** set `resp_pipelinable=1` in the multi-chunk builder
   (`src/core/aio/buffers.c:526`). Each in-flight response already owns a slot
   (`out_ring[out_tail]`, `xrootd_resp_slot_t`); ensure the multi-chunk **header
   block** is stored per-slot (not in the shared `read_hdr_scratch`) so two
   multi-chunk responses can be queued without aliasing — extend
   `xrootd_resp_slot_t` with a small per-slot header area or a slot-owned
   `hdr_scratch`. Then the `recv.c:406/465` gate admits the next read while the
   prior multi-chunk response drains.
2. **Windowed/TLS reads:** allow the *next* kXR_read request to be admitted into
   a free ring slot while the current windowed read drains its last chunk — i.e.
   don't hard-block on `rd_win_active`; gate on `out_count < PIPELINE_MAX` and
   slot availability instead. (Careful: one windowed read owns `read_scratch`;
   pipelining a second concurrent windowed read needs a second window buffer.
   Simplest first step: pipeline cleartext multi-chunk now; treat concurrent
   windowed reads as a later increment.)
**Why 2×:** keeps the socket TX queue full across back-to-back large reads instead
of stalling a full RTT + drain per read — exactly what the native client
exploits. **Validation:** `tcp_info` send-queue never empties between reads;
single-connection 1 GiB read MiB/s vs vanilla; `XROOTD_PIPELINE_MAX` sweep.

### 2B. Inline fast path for small / cache-hot memory reads

**What:** every memory read posts to the thread pool (`read.c` →
`xrootd_aio_post_task`); a thread round-trip (~hundreds of µs) dominates a small
or page-cache-hot read whose `pread` is sub-µs.
**How:** before posting, if `rlen <= XROOTD_READ_INLINE_MAX` (new tunable, e.g.
256 KiB) **or** the range is known page-cache-resident (`preadv2(RWF_NOWAIT)`
probe → if it returns the data, no thread needed), do the `pread` inline on the
event thread and build the chunk directly; only fall back to the pool on
`EAGAIN`/large reads. (`preadv2 RWF_NOWAIT` is the clean primitive: cache hit →
instant inline; miss → post to pool, no blocking.)
**Impact:** removes the thread round-trip from the common warm-cache read — large
single-stream win since HEP reads are often re-reads of hot ROOT files.
**Validation:** `perf` shows fewer context switches; warm-cache read latency.

### 2C. TLS window sizing (Phase 31 interaction)

**What:** the Phase 31 TLS read window is 2 MiB; for a 200 MiB TLS read that's
~100 fill→drain round-trips, each an AIO + send cycle — more overhead than the
old whole-buffer path.
**How:** make `XROOTD_READ_WINDOW` a per-server directive
(`xrootd_read_window`, default keep 2 MiB for the memory guarantee) and let
throughput-oriented deployments raise it (e.g. 8–16 MiB), charged against the W4
budget so the safety bound holds. With kTLS (1A) the TLS read can also become a
file-backed `SSL_sendfile` and skip windowing entirely for cleartext-equivalent
speed — investigate routing TLS `root://`-over-stream reads similarly (harder:
stream module, not http).
**Impact:** fewer round-trips per large TLS read; tunable memory/throughput.

### 2D. Reduce per-read fixed cost

- **Access log batching** (`read.c:178/248/363`): replace the per-read
  synchronous `write(2)` with a per-worker buffered/coalesced access-log writer
  (flush on size/timer), or sample. The single biggest fixed per-read cost when
  logging is on.
- **Scratch trim hysteresis** (`src/core/aio/buffers.c` `xrootd_trim_one`,
  threshold `2×window`): a session doing back-to-back >4 MiB reads frees+reallocs
  `read_scratch` every request. Raise the trim threshold or keep the buffer warm
  while a stream is active (only trim after N idle requests). Minor but free.
- **Dashboard/metrics per read** (`read.c:166-176`): already conditional; batch
  the dashboard slot update to once per N bytes rather than per read.

---

# Section 3 — Cross-cutting & config (apply to all planes)

These are mostly nginx-config/tunable changes — document them in the deployment
guide and ship sane defaults in the test/sample configs:

| Lever | Where | Setting | Impact |
|---|---|---|---|
| `sendfile on` + `tcp_nopush on` | http/stream config | enables zero-copy + coalesces header+first chunk | 5–10% (S3/cleartext) |
| `output_buffers` | http config | `2 256k` (from 1 32k) | fewer pread/sendfile syscalls on large GET |
| `directio` | cache server blocks | `directio 4m` | bypass page-cache pollution on huge files; protects warm cache (pairs with 2B) |
| `ssl_buffer_size` | TLS blocks | `64k` | §1B |
| `thread_pool` | stream/http | `threads = ncpu*0.75 max_queue=131072` (from `threads=4`) | removes pool queueing under concurrency for pgread/pgwrite/cache fills |
| kTLS | TLS blocks | `ssl_conf_command Options KTLS` | §1A |
| build | root `config` | already `-O3 -march=x86-64-v2`; optionally trial `-flto` | marginal |

No action: CRC32C (already SSE4.2), build `-O3` (already set), metric atomics
(<1% measured).

---

## WS3 implementation architecture — concurrent-AIO read pipeline (2026-06-13)

Detailed design after tracing the send ring (`src/protocols/root/connection/write_helpers.c`
`xrootd_queue_response_*` + `xrootd_flush_pending`) and the recv gates
(`src/protocols/root/connection/recv.c`).

**Key constraint found:** the connection has a single state enum; recv returns
immediately on both `XRD_ST_AIO` and `XRD_ST_SENDING` (recv.c:153,170). Every
memory/TLS `kXR_read` posts to the thread pool → `XRD_ST_AIO` → recv stalls →
**depth-1**. Per-slot buffers alone do not fix this; the AIO-in-flight state must
be decoupled from the recv-blocking state.

**Key simplifying insight:** XRootD is streamid-multiplexed, so **out-of-order and
interleaved response frames are protocol-legal** — the client demuxes by streamid,
and each windowed read's `kXR_oksofar…kXR_ok` sequence stays in order because the
FIFO ring sends each committed frame atomically (one slot fully drains before the
next). Therefore the existing FIFO send ring (`out_ring`/`out_head`/`out_tail`/
`out_count`, `flush_pending` head-first drain) is kept **unchanged**; only a
concurrent-AIO front-end is added. Responses commit to the ring in AIO-**completion**
order (not dispatch order) — legal.

**Design (front-end only; ring untouched):**
1. **Per-connection pool of read buffers + tasks** (size `XROOTD_PIPELINE_MAX`),
   raw-`ngx_alloc`'d, with a free-list. A read in flight owns one pool buffer +
   one `ngx_thread_task_t`; the buffer's lifetime extends until the response it
   backs drains from its ring slot (then returned to the free-list). Replaces the
   singleton `read_scratch`/`read_aio_task` for the *read* path. (`write_scratch`/
   `payload_buf` stay per-connection — writes don't pipeline.)
2. **recv (`read.c` dispatch + `recv.c`):** a `kXR_read` reserves a pool entry,
   posts its AIO, and **does not set `XRD_ST_AIO`** — recv keeps reading the next
   request while `(in_flight_reads + out_count) < XROOTD_PIPELINE_MAX`. At the cap
   it suspends (backpressure) and resumes when a pool entry frees. A new
   per-connection `in_flight_reads` counter + an `XRD_ST_READING` non-blocking
   posture (or: leave state REQ_HEADER and gate purely on capacity) tracks this.
   Non-read opcodes keep the existing `recv_deferred` barrier (serialize behind a
   fully-drained ring) — unchanged.
3. **AIO done (`aio/reads.c`):** recover the pool entry from the task; build the
   chunk(s) from its buffer; `xrootd_queue_response_chain(…, owned_base=poolbuf)`
   commits to the ring (completion order). Decrement `in_flight_reads`; if recv
   was backpressured, resume it. Windowed read: emit one window, and on that
   slot's drain (send.c) pump the next window into the **same** pool buffer (a
   windowed read holds its pool entry for its whole life).
4. **Buffer release:** `xrootd_release_read_buffer` returns a pool buffer to the
   free-list (instead of the current no-op for the singleton scratch).
5. **Disconnect (`disconnect.c`):** the `destroyed` guard already discards stale
   AIO completions; additionally free all pool buffers. In-flight tasks complete
   but their done callbacks no-op via `xrootd_aio_restore_stream` (destroyed).
6. **Phase-31 budget (`budget.h`):** `xrootd_budget_sync` sums all in-use pool
   buffers (+ `write_scratch` + `payload_buf`); admit per-read `want=window`.
   Per-connection worst case becomes `PIPELINE_MAX × window` (≈ 4×2 MiB = 8 MiB) —
   bump `XROOTD_CONN_XFER_HEAP_MAX` and re-baseline the Phase-31 200 MiB-TLS
   resident-bound test to `≤ PIPELINE_MAX × window`.

**Risk + validation:** this rewrites the hottest, most safety-critical path (where
this session already fixed a remotely-triggerable worker crash). Correctness is
validatable here via the integrity suite (`test_integrity_matrix.py` does
byte-exact TLS reads across topologies), `test_concurrent.py` (concurrent TLS
reads), the read→readv crash repro, and the Phase-31 memory tests. **Throughput is
NOT validatable on the current host** (single-connection TLS benchmarks hang) — it
needs a clean benchmark host with `perf`/`ss -ti`. Implement incrementally
(single-shot memory reads first, then windowed), full-rebuild + full regression
after each step, and revert if the suite goes red.

## Sequencing (highest ROI first)

1. **§1A kTLS** (config + the `vfs_read.c:199` gate) — biggest HTTPS win, low code risk.
2. **§2A pipeline all reads** (multi-chunk first) — biggest `root://` win.
3. **§3 config bundle** (sendfile/tcp_nopush/output_buffers/ssl_buffer_size/thread pool/directio) — cheap, broad.
4. **§2B inline `preadv2(RWF_NOWAIT)` fast path** — single-stream warm-cache win.
5. **§1C per-transfer overhead** (fd reuse, path/auth cache, CORS early-out).
6. **§2C window directive**, **§2D access-log batching + trim hysteresis** — polish.

Each code step: build clean (`-Werror`), 3 tests (success + error + security/neg)
per CLAUDE.md, no regression in the Phase 31 memory bounds (re-run
`tests/test_phase31_memory.py`, the read→readv repro, and the 200 MiB-TLS
resident-bound check), and byte-exact integrity (`tests/test_integrity_matrix.py`,
`tests/test_readv.py`, `tests/test_concurrent.py`).

## Measurement methodology (prove each win)

- **Per-plane single-connection throughput** vs vanilla: `xrdcp`/`davix`/`aws s3`
  of a 1 GiB file to `/dev/null`, warm cache, n=1; report MiB/s ratio.
- **CPU efficiency:** `perf stat -e task-clock,cycles,context-switches` → cycles
  per GiB transferred (the real "overhead" metric vs XrdHttp).
- **Syscall profile:** `strace -f -c` → confirm `sendfile`/`SSL_sendfile`
  dominate and `write`/`pread` counts drop.
- **kTLS confirmation:** `ss -ti` / `/proc/net/tls_stat`.
- **Pipelining:** instrument `out_count` high-water; confirm TX send-queue stays
  non-empty between back-to-back reads.
- **Regression guards:** Phase 31 memory tests + full integrity/concurrency suite
  green; `xrootd_xfer_heap_high_water_bytes` still bounded.

## Expected outcome

| Plane | Mechanism | Target |
|---|---|---|
| `https://` WebDAV+TLS | kTLS zero-copy (§1A) + records (§1B) + fixed-cost cuts (§1C) | from −13% to **> XrdHttp** |
| `s3://` | already sendfile; config bundle (§3) + thread pool | hold 5 Gbps, lift ceiling |
| `root://` | full pipelining (§2A) + inline warm reads (§2B) + less per-read cost (§2D) | **restore ≥2× vanilla** |
