# Phase 29: Single-Stream Read-Throughput Bottlenecks (nginx-xrootd vs native xrootd)

**Date:** 2026-06-12
**Author:** performance audit
**Status:** PLAN — not yet begun
**Scope:** `root://` large-file read path (`src/read`, `src/core/aio`, `src/connection/recv.c`)
**Premise:** nginx-xrootd *should* match or beat native xrootd for a single-stream
large-file read (nginx's sendfile data plane is excellent).

---

## ⚠ CORRECTION (2026-06-12, after implementing R3 fair-benchmark)

**The "nginx is ~0.5× slower" premise below was a measurement artifact.** Once the
benchmark compares **like-for-like** (the R3 `--data-tls off` knob: cleartext on
**both** servers, via the warm XRootD Python client on the de-conflicted ports),
nginx **matches or beats** native xrootd at n=1, 1 GiB `root://` read:

| Fair run (cleartext both sides) | nginx-xrootd | native xrootd |
|---|---|---|
| run 1 | **1550 MiB/s** | 1252 MiB/s |
| run 2 | **1889 MiB/s** | 1890 MiB/s |

So **B1 (no pipelining) is NOT the binding constraint for single-stream cleartext** —
nginx's sendfile path already saturates loopback at parity with xrootd. The
original 905-vs-1525 / 333-vs-681 figures compared **nginx-TLS (encrypting, memory
path) vs xrootd-cleartext (sendfile)** — i.e. **B4 (benchmark unfairness)** was the
real cause, not B1. The earlier "8 MiB/s" was orphaned-`reuseport`-worker
contamination (now fixed by R7).

**Consequence for the remediation plan:** the high-risk pipelining refactor
(R1 / Phases 1–3) is **not justified for n=1 single-stream** — that goal is already
met. The genuinely-remaining work is **B2/R2 (the TLS path can't sendfile → kTLS)**
and **B6/R6 (n=8 concurrency failures)**. The analysis below is retained for
accuracy and for the multi-stream/TLS cases, but read it with this correction in
mind.

---

---

## Measured baseline (n=1, 1 GiB read over `root://`, localhost)

Two independent methods agree on the **gap** (nginx slower), which rules out a
one-off artifact:

| Method | nginx-xrootd | native xrootd | nginx / xrootd |
|---|---|---|---|
| `load_test.py` (XRootD Python client, GSI, warm) | **905 MiB/s** | **1525 MiB/s** | **0.59×** |
| `xrdcp` CLI, cleartext-anon vs xrootd-GSI-cleartext | **333 MiB/s** | **681 MiB/s** | **0.49×** |
| `xrdcp` CLI, nginx GSI **+TLS** | 174 MiB/s | — | — |
| `xrdcp` CLI, nginx GSI `--tlsnodata` | 176 MiB/s | — | — |

**Two findings fall straight out of the data:**

1. **Even nginx's *cleartext sendfile* path is ~half of xrootd** (333 vs 681).
   So this is **not** purely a TLS penalty — there is a genuine data-plane gap.
2. **The nginx GSI path is the worst case** (174–176) because it runs TLS, and
   `--tlsnodata` does **not** help — confirming the slowdown is the *connection*
   being SSL (which disables sendfile), not per-frame data encryption.

> Absolute numbers differ by method (Python client warm-cache vs `xrdcp` CLI to
> `/dev/null` on a loaded box with a slightly older stable binary). Treat the
> **ratios** as the signal, not the absolute MiB/s. The earlier "8 MiB/s" figure
> was a separate artifact (orphaned `reuseport` workers with mismatched certs)
> already resolved by the Phase-port-deconfliction work.

---

## How the read path actually works (the relevant architecture)

A `kXR_read` is served by `src/read/read.c`:

- **Cleartext + regular file** (`read.c:93` — `is_regular && !c->ssl`):
  `xrootd_build_sendfile_chain()` → an `ngx_buf_t` with `in_file=1` → nginx's
  output filter issues **`sendfile(2)`** (zero-copy). 16 MiB frame split, up to a
  64 MiB request (`XROOTD_READ_REQUEST_MAX`).
- **Otherwise (TLS, or non-regular)** (`read.c:170`+): allocate a per-session
  scratch buffer → if a thread pool is configured, **post a task to the thread
  pool** (`read.c:195–233`) that does a blocking `pread(2)` on a worker thread →
  on completion, build a chain pointing into the scratch buffer and send. For TLS
  the bytes are then **encrypted in userspace** (no sendfile).
- **Prefetch** (`src/read/prefetch.c`) is **`POSIX_FADV_WILLNEED` hints only** — it
  warms the page cache, it does **not** pipeline responses.

The connection driver `src/connection/recv.c` is a **strictly serial state
machine**: `HANDSHAKE → REQ_HEADER → REQ_PAYLOAD → dispatch`, then it *resets for
the next request*. Its own docstring: *"Suspend states (SENDING/AIO/UPSTREAM/TLS)
return immediately without reading."*

That last sentence is the core bottleneck.

---

## Bottleneck analysis (ranked)

### B1 — No request pipelining: disk and network are never overlapped *(primary, cleartext)*

`recv.c` reads **one** `kXR_read`, serves it to completion (`SENDING`/`AIO`
suspend state), and only then reads the next. While the current chunk's response
is being `sendfile`'d to the socket — or while its `pread` runs on the AIO thread
— **the server reads nothing and prepares nothing**. So for a sequential 1 GiB
download split into N chunks, the timeline is:

```
[recv req1][pread/sendfile resp1][idle: wait req2][recv req2][resp2]...
```

The link sits idle between chunks, and chunk N+1's disk read never overlaps chunk
N's network send. Native xrootd keeps multiple reads outstanding and pre-stages
the next block, so its link stays saturated. **This is why even cleartext
sendfile nginx (333) trails xrootd (681)** — the path is *latency-bound*, not
bandwidth-bound, at n=1. `xrdcp` issues a read-ahead window of requests, but
nginx serializes them, so the client's pipelining is wasted.

**Evidence:** `recv.c` state machine (one request per dispatch; SENDING/AIO
suspend reads); `prefetch.c` is fadvise-only (no response pipelining).

### B2 — sendfile disabled under TLS + no kTLS *(primary, GSI/TLS)*

`read.c:93` gates sendfile on `!c->ssl`. The perf GSI server sets `xrootd_tls on`,
and XRootD-5 `xrdcp` **prefers TLS when offered** (`kXR_wantTLS` after login,
`src/session/tls_config.c:9`), so the connection becomes SSL → sendfile is
skipped → the **memory + thread-pool `pread` + userspace-encrypt** path runs. The
nginx build has **no kTLS** (`nginx -V` shows plain OpenSSL, no
`--with-openssl-opt=enable-ktls`), so TLS *cannot* use sendfile at all.
`--tlsnodata` doesn't help because the gate is the whole-connection `c->ssl`, not
per-frame encryption. Result: the GSI-TLS path (174) is the slowest of all.

### B3 — Per-request thread-pool hop on the memory path *(secondary)*

On the non-sendfile path every chunk posts a task to the thread pool
(`read.c:195–233`) for a blocking `pread`, then wakes the event loop on
completion (`src/core/aio/reads.c`). At n=1 single-stream this adds a **context switch
+ event notification per chunk** that the synchronous native-xrootd loop avoids —
pure latency with no concurrency to amortize it. (For the cleartext sendfile path
this hop is correctly skipped.)

### B4 — Benchmark fairness: nginx-TLS vs xrootd-cleartext *(measurement)*

The default `root-gsi` suite compares **nginx with `xrootd_tls on`** (encrypting)
against **native xrootd with no `xrd.tls`** (cleartext). That is apples-to-oranges
— nginx is doing strictly more work. A fair comparison must align the TLS posture
on both sides (both cleartext, or both TLS).

### B5 — Socket / syscall tuning headroom *(minor)*

`sendfile on; tcp_nopush on; tcp_nodelay on` are set (good), but there is no
`SO_SNDBUF`/`sendfile_max_chunk` tuning, and each request issues a fresh sendfile
chain. Larger socket buffers and bigger contiguous sendfile spans reduce syscall
count on the fast path.

### B6 — Concurrency instability (related, separate) 

At n=8 the GSI path returned `ok=5/8` (3 failures) with a collapsed aggregate —
a concurrency-scaling defect (likely fd / thread-pool-queue / TLS-handshake
contention) distinct from the n=1 throughput gap, but worth fixing in the same
campaign because it gates any multi-stream comparison.

---

## Remediation plan

### R1 — Pipeline the read path (highest impact) 
Decouple "read the next request" from "finish sending the current response."

- Let `recv.c` continue reading the next `kXR_read` header while a response is in
  `SENDING`/`AIO` (bounded by a small per-connection in-flight window, e.g. 2–4),
  instead of hard-suspending.
- Pre-issue the **next chunk's `pread`** (AIO) while the **current chunk is being
  sent**, so disk and network overlap. A double-buffered scratch (ping-pong) lets
  chunk N+1 land while chunk N drains to the socket.
- For the sendfile path, queue the next chunk's sendfile buf as soon as the
  current one is handed to the output filter, keeping the socket write queue full.

This targets B1 directly and should close most of the cleartext gap (sequential
1 GiB read becomes bandwidth-bound, not latency-bound).

### R2 — sendfile-over-TLS via kTLS 
Rebuild nginx with kernel-TLS so encrypted streams keep zero-copy:
`--with-openssl-opt='enable-ktls'` (OpenSSL ≥ 3.0 + kernel `tls` module) and
`ssl_conf_command Options KTLS;`. Then relax `read.c:93` to use sendfile when
kTLS is active (kernel encrypts in the sendfile path). Addresses B2 — lets the
GSI-TLS path reclaim zero-copy. (If kTLS is unavailable, at minimum ensure
AES-NI + larger encrypt buffers and skip the thread-pool hop for TLS reads where
the data is already cached.)

### R3 — Fair, explicit benchmark posture 
In `tests/run_load_test.sh` / `load_test.py`, make the TLS posture symmetric:
add a `--data-tls {on,off}` knob that configures **both** servers the same way
(nginx `xrootd_tls` + xrootd `xrd.tls all`), and default the headline comparison
to **cleartext-vs-cleartext** so the data-plane number is apples-to-apples.
Document that GSI-TLS-vs-cleartext is not a like-for-like comparison.

### R4 — Socket & sendfile tuning 
Add `SO_SNDBUF` sizing, evaluate `sendfile_max_chunk`, and prefer one large
sendfile span per request over many small frames where the wire protocol allows
(respect the 16 MiB frame split only as a framing boundary, not an I/O boundary —
issue a single `sendfile` covering multiple frames' data regions).

### R5 — Memory-path modernization (optional) 
Where the memory path is unavoidable (TLS without kTLS), replace the
per-request thread-pool `pread` with batched / `io_uring`-style submission so
multiple chunks are read with one submission and no per-chunk wakeup.

### R6 — Fix concurrency failures (B6) 
Profile the n=8 `ok=5/8` failures (fd table limits per `XROOTD_MAX_FILES`,
thread-pool `max_queue`, GSI/TLS handshake CPU under parallel connects) and
remove the failure mode before re-measuring multi-stream throughput.

### R7 — Test-infra: fix `reuseport` worker orphaning 
`tests/run_load_test.sh` `stop_nginx` uses `nginx -s quit`, which under
`reuseport` + `worker_processes auto` leaves worker processes holding the listen
sockets across runs (observed repeatedly: stale workers on the perf ports). Make
teardown reap the master's **process group** (as the CMS-mesh harness now does),
so successive runs start from a clean socket set — stale workers were themselves a
source of measurement noise.

---

## Sequencing & expected effect

1. **R3 + R7** (cheap, test-only) — get a *fair, reproducible* baseline first.
2. **R1** (pipelining) — the big structural win for single-stream cleartext;
   expect nginx to reach or exceed xrootd once disk/network overlap.
3. **R2** (kTLS) — reclaim zero-copy for the GSI-TLS path.
4. **R4/R5/R6** — tuning, memory-path, and concurrency hardening.

Effort: R3/R7 ~½ day each; R1 ~3–5 days (touches `recv.c` state machine +
`read.c` + `aio/` buffering — the riskiest change, needs the full read/readv/pgread
test matrix); R2 ~1–2 days (build + gate relaxation); R4 ~1 day; R5 ~3 days; R6
~1–2 days.

---

## Verification

```bash
# Fair, reproducible n=1 baseline (after R3/R7): cleartext both sides
tests/run_load_test.sh both --suite root --data-tls off --concurrency 1
#   target: nginx MiB/s >= xrootd MiB/s

# Controlled cross-check (per path)
xrdcp -f -np root://localhost:<nginx-cleartext>//load_1g.bin /dev/null   # sendfile
xrdcp -f -np root://localhost:<xrootd>//load_1g.bin /dev/null            # baseline

# After R1 (pipelining): single-stream cleartext should be bandwidth-bound
#   — verify with `iostat`/`sar`: link saturated, no idle gaps between chunks.

# After R2 (kTLS): GSI-TLS path should approach the cleartext sendfile number.

# Regression: full read suite must stay green (read/readv/pgread + integrity)
PYTHONPATH=tests pytest tests/ -k "read or readv or pgread or interop_io" -v
```

Each change ships with success + error + (where relevant) integrity tests per the
repo rule; R1 especially must preserve byte-exact output and `kXR_oksofar`/`kXR_ok`
framing under the pipelined path.

---

## Risk Assessment

- **R1 is the highest-risk change** — it alters the `recv.c` request lifecycle and
  response buffering. Bugs here cause data corruption, framing desync, or
  use-after-free of the scratch buffer. Bound the in-flight window small (2–4),
  keep ping-pong buffers strictly owned, and gate behind the full read matrix +
  an ASAN run (Phase 27 W6).
- **R2 kTLS** depends on kernel + OpenSSL build support; keep it optional and
  fall back to the memory path when unavailable.
- **R4** larger buffers raise per-connection memory — bound by config.
- Keep all changes behind measurement: do not merge a "fast path" that fails the
  integrity/pgread tests.

## Appendix — key code references

- `src/connection/recv.c` — serial state machine; SENDING/AIO suspend reads (B1).
- `src/read/read.c:93` — sendfile gated on `!c->ssl` (B2); `:150` sendfile chain;
  `:170`–`:233` memory + thread-pool `pread` path (B3).
- `src/core/aio/reads.c` — thread-pool `pread` worker + completion wakeup (B3).
- `src/read/prefetch.c` — `POSIX_FADV_WILLNEED` hints only (not pipelining; B1).
- `src/core/aio/buffers.c` — sendfile/memory chain builders; 16 MiB frame split.
- `src/core/types/tunables.h` — `XROOTD_READ_MAX` 4 MiB, `_CHUNK_MAX` 16 MiB,
  `_REQUEST_MAX` 64 MiB (B4/B5).
- `src/session/tls_config.c` — `kXR_wantTLS` opt-in upgrade (B2).
- `tests/nginx.perf.conf` — `xrootd_tls on` on the GSI server (B2/B4);
  `sendfile/tcp_nopush/tcp_nodelay on` (B5).

---

## Implementation results (Phases 1–4, 2026-06-13)

- **Phase 1 — output-queue slot FIFO** (`xrootd_resp_slot_t out_ring[]`): DONE.
  Behaviour-identical foundation. NB: the prior "readv corruption" that blocked this
  was a **stale-object mixed-ABI build** (header layout change + incremental make),
  not a code bug — always full-recompile (`touch src/*.c`) after a struct/header edit.
- **Phase 2 — cleartext sendfile pipelining**: DONE + validated. recv keeps reading
  and queueing follow-on single-chunk sendfile `kXR_read`s into the ring (depth ≤4)
  while earlier ones drain head-first; drain barrier defers non-read opcodes. Gotcha:
  `kXR_read` carries a read-ahead list (`dlen>0`) so it dispatches via the *payload*
  recv site — both sites need the pipelining branch. Engagement confirmed (depth
  1→2→3) byte-exact; only activates under real send backpressure (not fast loopback).
- **Phase 4 — kTLS**: mechanism DONE (`xrootd_ktls_send_active()` + relaxed sendfile
  gate + `xrootd_ktls` directive), but **kTLS is a 2.4–5.5× THROUGHPUT REGRESSION on
  AES-NI CPUs with software kTLS** (measured GSI+TLS: kTLS-off n=1=309 / n=4=970 MB/s
  vs kTLS-on n=1=128 / n=4=175 MB/s). Userspace OpenSSL+AES-NI beats software kTLS, so
  the directive defaults **off**; it is an opt-in only for hosts with hardware
  TLS-offload NICs. This also undercuts the original B2 premise — userspace TLS is
  already fast (309 MB/s single-stream) here.

**Net:** nginx-xrootd matches/beats native xrootd single-stream cleartext (premise
overturned); Phase-2 pipelining is in place for when links are saturated; kTLS is
available but off (regression without HW offload). Remaining: Phase 3 (pgread/readv +
memory-path pipelining) and Phase 5 (socket tuning + concurrency hardening).
