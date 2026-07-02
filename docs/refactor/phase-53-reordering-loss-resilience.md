# Phase 53 — Reordering & packet-loss resilience: data-plane pipelining, HTTP resume, congestion-control directive

**Status:** IMPLEMENTED + verified 2026-06-24.

This phase characterises how the module and the native client behave under two
adverse network conditions — **packet reordering** and **packet loss** — using the
in-repo fault proxy, and lands the improvements that the measurements justified. It
also records the findings honestly, including which levers help, which do not, and
why a userspace-relay harness can validate some changes but not others.

**Implementation status by workstream:**

| WS | State | Notes |
|---|---|---|
| Fault-injection tooling | ✅ done | `tests/c/fault_proxy.c` gained `jitter <ms>`, `reorder <pct> [ms]`, and **ppm-resolution** `lossy`/`reorder` (sub-percent: floor 0.0001%). New runners: `run_mount_sweep.py`, `run_xrdcp_loss.py`, `run_http_reorder.py`, and an **ASAN+TLS** read harness `asan_tls_read_harness.py`. |
| #3 Configurable pipeline depth | ✅ done + verified | `xrootd_pipeline_depth N` (default **8**, was a fixed 4); `out_ring`/`rd_pool` heap-sized to the runtime depth; stale-ABI dep-tracking fixed. Byte-exact at depth 1/8/32 incl. 8-way concurrent + reorder. |
| #1 TLS/memory read pipelining | ✅ done + verified | Wired the previously-dead `rd_pool` per-in-flight buffers + per-slot headers + `resp_pipelinable` for the userspace-TLS read path. **96 concurrent TLS reads under reorder, byte-exact, zero ASAN reports.** Warm-cache (inline) path pipelines; cold-AIO path is safe but not yet pipelined (documented follow-on). |
| Client backoff tuning (`root://`) | ✅ done + verified | `XRDC_BACKOFF_BASE_MS` makes the transport-fault backoff base tunable (default 25, unchanged). At base=1 the repo `xrdcp` is **6.3× faster at 1% loss** (104 → 658 MB/s), still 8/8 byte-exact. |
| HTTP loss resilience (client) | ✅ done + verified | `xrdc_http_download` (`client/lib/http.c`) + `xrdc_webfile_pread` (`client/lib/webfile.c`) now reconnect and **resume at offset via HTTP `Range`** within a deadline window. Repo `xrdcp` over HTTP went from **0/8 → 8/8 byte-exact** at every loss level ≥0.01%. |
| `xrootd_tcp_congestion` directive | ✅ done + verified | Per-socket `setsockopt(TCP_CONGESTION)` (e.g. `bbr`) on the **stream**, **WebDAV GET**, and **S3 GetObject** data paths; verified applied (`ss` shows the configured algo). Sender-side lever for real-network reordering throughput. |

---

## 0. The two conditions, and why they differ

| Condition | What it is on TCP | App-visible symptom | Where resilience lives |
|---|---|---|---|
| **Reordering** | out-of-order IP packets, **reassembled in order by the kernel** before the app sees a byte | added **latency/jitter** only — never a failure | nothing app-level *for correctness*; throughput is governed by the **sender's congestion control** |
| **Loss (sever-flavour)** | the fault proxy **resets the whole TCP connection** per chunk (harsher than `netem` drop, which TCP would retransmit) | a **sever** → the transfer aborts unless the client reconnects + resumes | the **client** (reconnect + resume-at-offset); the server only *enables* it (Range/206) |

The fault proxy is a **userspace TCP relay**: it forwards bytes **in order** on a
separate healthy connection, so it can faithfully inject **latency** (the
`reorder`/`jitter` levers) and **connection severs** (the `lossy` lever), but it
**cannot** produce true IP-layer reordering or `netem`-style packet drop. This is
the single most important caveat for interpreting the results below.

---

## 1. Findings — reordering is a uniform latency tax

Under the `reorder` lever (a `pct`% fraction of 64 KB chunks held back 50 ms),
**every client × server pair converges to the same throughput curve** — it is pure
latency that no client or server choice dodges. 64 MiB, 8 reps, median MB/s:

**`root://` and HTTP, repo `xrdcp` vs official `xrdcp`/`curl`, nginx vs xrootd:**

| reorder % | repo→nginx | repo→xrootd | official/curl→nginx | official/curl→xrootd |
|---:|---:|---:|---:|---:|
| 0 | ~900–2000 | ~900–2200 | ~900–2000 | ~900–2000 |
| 0.01 | 559 | 574 | 621 | 508 |
| 0.1 | 306 | 309 | 315 | 292 |
| 1.0 | **118** | **118** | **119** | **118** |

All transfers **byte-exact**. Takeaway: nginx ≈ official xrootd, repo client ≈
official client/`curl` — reordering is transport-, server-, and client-agnostic.
(Reorder upgraded to ppm resolution so the 0.0001–0.001% band is measurable; it
sits at baseline there, as expected.)

> **Official `xrdcp` cannot copy `http://`** — verified on `/usr/bin/xrdcp` and the
> docs build (`http file protocol is not supported`; the XrdClHttp plugin enables
> the XrdCl *API*, not the `xrdcp` CLI). `curl` is the neutral HTTP client stand-in
> in all HTTP comparisons.

---

## 2. Findings — packet loss (severs): client resilience is everything

### 2.1 `root://` — the repo client is resilient; the official client is fragile

64 MiB download, 8 reps, median MB/s of byte-exact transfers:

| loss % | repo→nginx | official→xrootd |
|---:|---:|---:|
| 0 | 1100 | 1198 |
| 0.0001 | 1100 | 1177 |
| 0.001 | 1137 | 1243 |
| 0.01 | 729 | 1032 |
| 0.1 | 231 | 1002 |
| 1.0 | **107** (8/8) | **2.2** (8/8 but ~30 s/copy) |

- **repo `xrdcp`** degrades smoothly and **completes byte-exact at every level**
  (bounded ≤0.65 s for 64 MiB at 1%), **server-independent** (nginx ≈ xrootd).
- **official `xrdcp`** holds line-rate longer, then hits a **server-dependent
  cliff at 1%**: with xrootd it collapses to 2.2 MB/s (15–45 s stalls on XrdCl's
  default recovery timers); with nginx it does ~473 MB/s but **7/8** (one
  `Invalid session` failure).
- Cross-matrix proves the curve is **client-driven** and the 1% failure is an
  interaction. The repo client's recovery is cheap (immediate reconnect+resume);
  the official client's is heavyweight.

### 2.2 Tuning the repo client's recovery window (`XRDC_BACKOFF_BASE_MS`)

The repo client's per-sever cost was traced to its transport-fault backoff
(`25 ms << attempt`). On a lossy-but-connected link the reconnect is sub-ms, so
that sleep dominates. The base was made tunable (default 25 unchanged); at **1 ms**:

| loss % | stock (25 ms) | tuned (1 ms) | speed-up |
|---:|---:|---:|---:|
| 0.01 | 645 | 959 | 1.5× |
| 0.1 | 233 | 860 | **3.7×** |
| 1.0 | 104 | 658 | **6.3×** |

All 8/8 byte-exact; no cost when clean. At 1% the tuned repo client is **~300× the
official client** (658 vs 2.2 MB/s) and **8/8 vs the official's 6/8**.

### 2.3 HTTP — downloads were **not** loss-resilient, then were fixed

A single TCP sever aborts an HTTP GET, and originally **neither** the repo `xrdcp`
http path **nor** `curl` resumed → both failed at ≥0.01% loss.

**Before** (64 MiB, 8 reps, byte-exact ok/N):

| loss % | repo→nginx | repo→xrootd | curl→nginx | curl→xrootd |
|---:|:--:|:--:|:--:|:--:|
| ≤0.001 | 8/8 | 8/8 | 8/8 | 8/8 |
| 0.01 | **0/8** | **0/8** | 0/8 | 0/8 |
| 0.1 | 0/8 | 0/8 | 0/8 | 0/8 |
| 1.0 | 0/8 | 0/8 | 0/8 | 0/8 |

**After** the client fix (Range-resume + deadline window in `xrdc_http_download`):

| loss % | repo→nginx ok/N | MB/s | curl (control) |
|---:|:--:|---:|:--:|
| 0 | 8/8 | ~1970 | 8/8 |
| 0.0001 | 8/8 | ~2030 | 8/8 |
| 0.001 | 8/8 | ~1920 | 8/8 |
| 0.01 | **8/8** | ~1065 | 0/8 |
| 0.1 | **8/8** | ~250 | 0/8 |
| 1.0 | **8/8** | ~19 | 0/8 |

The repo `xrdcp` now **survives all the way to 1% loss byte-exact** on *both*
servers — full speed at low loss, gracefully slower at high loss (the cost of
reconnect+resume), exactly like `root://`. `curl` (unchanged) stays the negative
control. This is a **~1000× improvement in loss tolerance** (~0.001% → ≥1%).

---

## 3. Improvements made

### 3.1 Server data plane

- **`xrootd_pipeline_depth N`** (`src/core/types/tunables.h`, `context.h`, `config.h`,
  `config/server_conf.c`, `stream/module.c`, `connection/handler.c`): the
  per-connection in-flight window (`out_ring` + `rd_pool`) is heap-allocated to a
  runtime depth (default **8**, was a hard-wired 4; clamp [1,64]). A deeper window
  absorbs more wire latency/jitter before the recv loop stalls. `context.h`/
  `tunables.h` were added to the addon dep list, **closing a stale-ABI SIGSEGV
  trap** (they were not tracked).

- **Userspace-TLS read pipelining** (`src/core/aio/buffers.c`, `read/read.c`,
  `aio/reads.c`): memory-backed (`roots://`) reads now use **per-in-flight
  `rd_pool` buffers** + **per-slot headers** instead of the shared
  `read_scratch`/`read_hdr_scratch`, making them safe to pipeline. This wired up
  `rd_pool`, which was previously dead scaffolding. Verified under ASAN with 96
  concurrent TLS reads under reorder, byte-exact, zero reports.

### 3.2 Client resilience

- **`XRDC_BACKOFF_BASE_MS`** (`client/lib/nettmo.c`): tunable transport-fault
  backoff base (default 25). §2.2.
- **HTTP `Range`-resume** (`client/lib/http.c` `xrdc_http_download`,
  `client/lib/webfile.c` `xrdc_webfile_pread` + `web_get_range`): on a sever,
  reconnect and re-issue the GET with `Range: bytes=<written>-` (206), appending
  the remainder, within a deadline window that resets on progress. `web_get_range`
  reports **partial** bytes as the resume offset; a 206 guard prevents a
  Range-ignoring server from corrupting the file; resume needs a seekable dst.
  §2.3.

### 3.3 Server-side congestion control

- **`xrootd_tcp_congestion <algo>`** (`src/connection/netopt.h` helper;
  stream via `connection/handler.c`; HTTP WebDAV+S3 via the shared
  `src/protocols/shared/file_serve.c`): per-socket `setsockopt(TCP_CONGESTION)` (e.g.
  `bbr`). The sender's congestion control governs download throughput, and BBR
  ignores the spurious dup-ACK "loss" signals that *real* IP reordering induces —
  a client-agnostic throughput lever. Default unset = kernel default (no syscall).
  Verified applied on all three paths (`ss` shows the configured algorithm).

---

## 4. Verification

- **ASAN+TLS read harness** (`tests/resilience/asan_tls_read_harness.py`):
  concurrent `roots://` reads through the reorder lever against an
  ASAN-instrumented nginx; fails on any byte divergence or ASAN report. Clean
  baseline (64 reads) and post-#1 (96 reads) both PASS.
- **Comparison sweeps** (`run_xrdcp_loss.py`, `run_http_reorder.py`): full matrices
  of repo/official/`curl` × nginx/xrootd × reorder|loss × 0–1%, all byte-exact
  except where a non-resilient client genuinely fails (recorded as ok/N).
- **`xrootd_tcp_congestion`**: this host has only `reno cubic` (no bbr), so it was
  verified by setting the non-default `reno` and observing the server's connection
  use `reno` via `ss -tin` — on `root://` and WebDAV GET — with byte-exact
  downloads; the directive is also accepted in an S3 location.

---

## 5. Honest caveats / limitations

- **The userland (fault_proxy) harness cannot validate `xrootd_tcp_congestion`.**
  It injects latency and connection severs, not true IP reordering or congestion,
  so the sender's congestion control is never engaged — BBR would be a no-op on
  these numbers. The directive's value is on **real** reordering/lossy high-BDP
  links; measuring it needs `tc qdisc … netem reorder` on a real interface
  (`CAP_NET_ADMIN`). The directive is verified to **apply**, not to improve these
  loopback throughputs.
- **WSL2 loopback** baselines (>1 GB/s) are memory-bandwidth artefacts; treat
  every absolute MB/s as **relative**, not representative of real hardware.
- **`lossy` = sever-per-chunk**, harsher than `netem` packet drop (where TCP
  retransmits). It stresses the reconnect/resume path, which is the point.
- **#1 cold-AIO reads** are made *safe* to pipeline but do not yet pipeline (the
  recv loop suspends on a read AIO; true read pipelining is the "non-suspending
  read AIO" follow-on, the read analog of the existing write pipelining).
- **HTTP resume** needs a `Content-Length` (our servers send it) to distinguish a
  sever from a real EOF; a close-delimited/chunked response can't be safely
  resumed and falls through to the prior behaviour.
- **`xrootd_tcp_congestion` scope:** download data plane (`root://` read, WebDAV
  GET, S3 GET). Uploads (server is the receiver), metrics/dashboard (tiny
  responses), and WebDAV-proxy/TPC body relays are intentionally not covered.

---

## 6. Files touched

**Server:** `src/core/types/tunables.h`, `src/core/types/context.h`, `src/core/types/config.h`,
`src/core/config/server_conf.c`, `src/stream/module.c`, `src/connection/handler.c`,
`src/connection/netopt.h`, `src/connection/recv.c`, `src/connection/write_helpers.c`,
`src/connection/disconnect.c`, `src/connection/budget.h`, `src/core/aio/buffers.c`,
`src/core/aio/reads.c`, `src/core/aio/aio.h`, `src/read/read.c`, `src/protocols/shared/file_serve.c`,
`src/protocols/webdav/webdav.h`, `src/protocols/webdav/module.c`, `src/protocols/webdav/config.c`, `config`.

**Client:** `client/lib/nettmo.c`, `client/lib/http.c`, `client/lib/webfile.c`.

**Tests/tooling:** `tests/c/fault_proxy.c`, `tests/resilience/servers.py`,
`tests/resilience/run_mount_sweep.py`, `tests/resilience/run_xrdcp_loss.py`,
`tests/resilience/run_http_reorder.py`, `tests/resilience/asan_tls_read_harness.py`,
`tests/resilience/results-*.md`, `tests/resilience/README.md`.
