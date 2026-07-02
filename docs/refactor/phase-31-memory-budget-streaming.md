# Phase 31: Memory-Budget Streaming — 1 GB RAM at 100× In-Flight

**Date:** 2026-06-12
**Author:** memory audit
**Status:** MOSTLY COMPLETE — raw-alloc scratch fix + W1 trim (re-enabled) + W3 +
W2.1 windowed read + W2.2 PUT + W4 budget all landed & verified; W2.3 readv is
budget-bounded (full resident windowing is a follow-up)
**Scope:** all bulk data paths — `src/protocols/root/read`, `src/protocols/root/write`, `src/core/aio`, `src/protocols/webdav`,
`src/protocols/s3`, `src/fs/cache`, `src/protocols/root/session`, `src/core/types/context.h`, `src/core/types/tunables.h`
**Companion:** Phase 29 (read throughput) and Phase 30 (whole-src hyper-opt). 29/30
make a single stream *fast*; 31 makes N concurrent streams *cheap*. They share the
data plane and must land consistently — do not regress the sendfile path.

---

## Implementation status (2026-06-13)

| Workstream | Status | Notes |
|---|---|---|
| **Raw-alloc scratch fix** | **DONE, verified** | Root cause of the trim corruption: `read_scratch`/`write_scratch`/`read_hdr_scratch` were nginx-**pool**-backed (`ngx_palloc`/`ngx_pfree`), so the trim's free+realloc churned the pool large-allocation list under stale pointers → use-after-free. Switched to **raw `ngx_alloc`/`ngx_free`** (`src/core/aio/buffers.c`), freed explicitly on disconnect (`src/protocols/root/connection/disconnect.c`), exactly like `payload_buf`. Fixed both the trim corruption AND the pre-existing TLS "Bad address" EFAULT. `read→readv` repro survives 10/10; TLS large-read test flipped xfail→xpass; 1072-test regression clean. |
| **W1.1 scratch trim** | **DONE, RE-ENABLED** | Now safe on the raw-alloc foundation; re-enabled in `src/protocols/root/connection/recv.c` (REQ_HEADER boundary). Idle warmed connections shrink back to `XROOTD_READ_WINDOW`. |
| **W1.2 per-conn ceiling** | Subsumed | W2.1 keeps `read_scratch` ≤ window; W4 budget enforces the aggregate. No separate reject path. |
| **W3 SHM handle table** | **DONE** | `512×8` = 4096 slots ≈ 17 MB (was 68 MB). `src/protocols/root/session/registry.h`. |
| **W2.2 PUT streaming** | **DONE, verified** | `webdav/put.c` + `s3/put.c` stream the body via `xrootd_http_body_write_to_fd` — no full-body copy. |
| **W2.1 windowed read** | **DONE, verified** | Memory-backed `kXR_read` (TLS / non-regular) > `XROOTD_READ_WINDOW` is served as a fill→drain→fill loop of `kXR_oksofar` chunks ending in `kXR_ok`, holding ~one window in `read_scratch`. New `rd_win_*` ctx state, `xrootd_build_window_chain()`, `xrootd_read_window_pump()`/`_emit()` in `src/core/aio/reads.c`, continuation hook in `src/protocols/root/connection/send.c`. **Validated: a 200 MiB TLS read is byte-exact and `xrootd_xfer_heap_high_water_bytes` peaks at ~2 MiB** (vs up to 64 MiB before) — 32× per-stream reduction. |
| **W2.3 readv** | **PARTIAL** | `kXR_readv` now respects the budget (`xrootd_budget_admit`/`_sync` in `src/protocols/root/read/readv.c`) so a burst of large readv cannot blow the cap — **safe/bounded**. Full *resident* windowing (256 MiB upfront → window via incremental segment-batch streaming) is a tracked **follow-up**: readv's interleaved `[seghdr][data]` layout needs an incremental builder, higher risk for lower frequency. |
| **W4 SHM budget + backpressure** | **DONE, verified** | `xrootd_memory_budget` directive (off_t, default 768m); SHM atomics in `ngx_xrootd_srv_metrics_t`; idempotent charge/release in `src/protocols/root/connection/budget.h`; admission defers over-budget reads with `kXR_wait`; `/metrics` gauges. |

**Net effect:** memory is now bounded and enforced end-to-end — idle connections
trim to the window, an active large TLS read holds ~2 MiB (windowing), readv and
single reads are budget-admitted with `kXR_wait` backpressure, and the SHM floor
dropped ~50 MB. The two pre-existing crashes/bugs (trim corruption, TLS EFAULT)
are fixed by the raw-alloc foundation.

**Remaining follow-up:** full readv *resident* windowing; `kXR_pgread` windowing
(kXR_status/CRC framing — currently budget-bounded). Both are safe today via the
budget; they would further improve per-stream density.

---

## Goal (stated as a hard invariant)

> The worker-process **resident heap** devoted to data movement stays under a
> configured budget (target **1 GB**) while the module sustains **≥ 100 GB of
> concurrently in-flight transfer** (the bytes "in the pipe" between disk and the
> remote socket across all connections).

The ratio is only achievable one way: **in-flight bytes must live in the kernel
(page cache, socket send/recv buffers, disk) and on the wire — not in module
heap.** Module heap should hold only what is needed to *align/coalesce* requests
into sensible syscalls, plus small fixed per-connection bookkeeping. Every place
the current code parks transfer bytes in `malloc`/pool memory for the duration of
a request (or worse, a session) is a place that breaks the 100:1 ratio.

This is a budget-and-streaming refactor, not a rewrite. The cleartext `root://`
path is already close (sendfile = zero module-heap data). The work is: (1) bound
and reclaim the buffers that persist, (2) bring the TLS and PUT paths down to the
same streaming model, (3) add a worker-wide memory budget with backpressure so
the invariant is *enforced*, not hoped for.

---

## Where the memory actually goes today (audited)

Constants verified in `src/core/types/tunables.h`; per-connection layout in
`src/core/types/context.h`.

### A. Per-connection scratch buffers — persist at high-water for session life

`xrootd_ctx_t` (`src/core/types/context.h:43-126`) owns three `malloc`/`realloc`
buffers that **grow once to the largest request seen and are never trimmed until
disconnect**:

| Field | Cap (tunables.h) | Filled by |
|---|---|---|
| `read_scratch` | `XROOTD_READ_REQUEST_MAX` = **64 MiB** | TLS `kXR_read`/`kXR_pgread`/`kXR_readv` |
| `write_scratch` | `XROOTD_MAX_WRITE_PAYLOAD` = **16 MiB** | `kXR_pgwrite` decode |
| `payload_buf` | `XROOTD_MAX_WRITE_PAYLOAD` = **16 MiB** | `kXR_write` recv accumulation |

Comment at `context.h:111-121` is explicit: these are "malloc/realloc single
buffer per session lifetime [to] avoid pool growth." That is correct for *pool
fragmentation* but is exactly wrong for the **memory budget**: a `davs://` client
that issues one 64 MiB read holds **96 MiB of resident heap until it
disconnects**, even while idle. This is the dominant scaling term.

> **Worst-case math, current design:** 16 concurrent TLS sessions each having
> touched a 64 MiB read = **1.0 GB in `read_scratch` alone** — and that is with
> *zero* bytes actually moving at that instant. The budget is blown by 16 idle-
> but-warmed connections. A real WLCG gateway serves hundreds.

### B. TLS read path — no sendfile, copies through `read_scratch`

`src/protocols/root/read/read.c:181-295`: cleartext uses `xrootd_build_sendfile_chain()`
(file-backed buffers, kernel sendfile, **zero module-heap data**). TLS cannot
sendfile, so it `pread`s the *entire* request (up to 64 MiB, chunked on the wire
at `XROOTD_READ_CHUNK_MAX` = 16 MiB) into `read_scratch` and hands it to the SSL
layer. For HEP this is the **common** path — `davs://` is TLS by default. So the
worst-case buffer above is also the *normal* buffer.

### C. PUT paths — collect whole body into one contiguous buffer

- `src/protocols/webdav/put.c` (AIO path) and `src/protocols/s3/put.c:112` collect the request body
  into a single contiguous allocation before dispatching the async `pwrite`.
  `s3_put_aio_t` embeds `PATH_MAX` twice (~8.5 KB) *plus* the body pointer.
- nginx has **already** buffered the body — in `r->request_body->bufs`, possibly
  spilled to a spool file. Collecting it again doubles resident memory for the
  in-memory case and defeats the spool for the large case.

### D. `kXR_readv` — up to 256 MiB allocated upfront

`src/protocols/root/read/readv.c`: response buffer sized to the sum of all segment payloads,
allocated before the first `preadv`. A single large `readv` is a 256 MiB resident
spike per request.

### E. Shared memory (fixed, cross-worker) — ~70 MB baseline, one big item

From `src/protocols/root/session/registry.c:178-191`:

- **Handle table** = `XROOTD_SESSION_HANDLE_SLOTS` = `1024 × 16` slots, each
  carrying a `PATH_MAX` path ⇒ **~68 MB**. This is the single largest fixed
  allocation in the module and is paid even at idle.
- Session registry ~1.2 MB (1024 slots), server registry ~180 KB, dashboard
  tables ~0.85 MB, TPC keys ~35 KB. All fixed, all small next to the handle
  table.

SHM is shared across workers (not per-worker heap), but it still counts against
the 1 GB box budget and is trivially shrinkable.

### F. Connection pool cap — a guardrail, not a budget

`XROOTD_MAX_CONN_POOL_BYTES` = 64 MiB per connection (`tunables.h:93`,
`context.h:73`). This caps *one* connection's pool growth and closes it with
`kXR_NoMemory` on breach. It does **not** bound the sum across connections, and
it does not cover the `malloc`'d scratch buffers (A) at all — those are outside
the pool accounting. There is **no worker-wide ceiling today.**

---

## Strategy

Four workstreams, roughly in dependency order. W1 and W2 are the load-bearing
ones for the invariant; W3–W4 are reinforcement and enforcement.

### W1 — Bound and reclaim per-connection transfer buffers

The fix is to stop letting a single large request permanently inflate a session,
and to stop holding transfer bytes longer than the syscall that consumes them.

1. **Introduce a streaming window cap, separate from the request cap.**
   Add `XROOTD_READ_WINDOW` (proposed default **2 MiB**) — the maximum bytes the
   module buffers *in heap at once* for one in-flight read, independent of the
   logical request size. A 64 MiB TLS read becomes 32 × 2 MiB fill→encrypt→drain
   cycles over the same 2 MiB buffer, using the existing `kXR_oksofar`/chunk
   framing (`src/core/aio/buffers.c` already builds multi-chunk chains; we cap the
   *resident* slice, not the wire chunk). Cleartext is unaffected — it stays on
   sendfile with no heap data.

2. **Trim scratch buffers back to the window after each request.**
   In `xrootd_get_pool_scratch()` (`src/core/aio/buffers.c:23-49`) and the
   request-completion path, `realloc` the scratch buffers back down to
   `XROOTD_READ_WINDOW` once a request finishes, instead of leaving them at
   high-water. Keeps the steady-state per-connection heap at ~`window` not
   ~`request_max`. (Keep a small hysteresis so a readv-heavy session doesn't
   thrash realloc — trim only when current > 2× window.)

3. **Per-connection transfer-heap ceiling.** Track the sum of
   `read_scratch_size + write_scratch_size + payload_buf_size` and cap it
   (proposed `XROOTD_CONN_XFER_HEAP_MAX`, default **4 MiB**). This makes the
   per-connection contribution to the budget *bounded and predictable*:
   `N_connections × 4 MiB`. At the 1 GB budget that is ~250 fully-active
   streams, with idle streams costing only the fixed `xrootd_ctx_t` (~17 KB).

**Outcome:** worst case goes from `concurrency × 96 MiB` to
`concurrency × ≤4 MiB`. The 16-idle-warmed-connections = 1 GB pathology
disappears.

### W2 — Stream the TLS read and the PUT paths (no full-object buffering)

1. **TLS read = bounded fill/drain loop** (depends on W1's window). Replace
   "pread whole request into `read_scratch`" with: `pread` ≤ window → submit to
   SSL `send_chain` → on drain, refill next window. This is the same
   suspend/resume the slice-cache fill already uses (`src/fs/cache/`). The wire
   framing is unchanged (chunks are still `XROOTD_READ_CHUNK_MAX`); only the
   resident slice shrinks. This also *helps Phase 29's TLS number* — smaller
   working set, better L2/L3 residency, earlier first-byte.

2. **PUT = write directly from nginx's own body chain.** Stop collecting into a
   contiguous buffer in `webdav/put.c` and `s3/put.c`. Walk
   `r->request_body->bufs`:
   - memory bufs → `pwrite`/`pwritev` directly from `buf->pos`;
   - file (spooled) bufs → `copy_file_range`/`sendfile`-to-fd from the spool fd,
     or chunked `pread→pwrite` bounded by the window.
   The shared helper `webdav_copy_fds()` (HELPERS) already does the fd→fd case
   for TPC; extend/reuse it. Drop the duplicate `PATH_MAX` embeds in
   `s3_put_aio_t`; pass a pointer to the already-resolved canonical path.

3. **`readv`: cap resident response, stream segments.** Replace the upfront
   256 MiB allocation with a bounded assembly buffer (window-sized) that fills,
   drains to the socket, and refills per coalesced `preadv` batch. Keep the
   `MAXSEGS`/overflow guards added in Phase 27.

**Outcome:** every bulk path obeys the same rule — *bytes in the pipe, not in the
heap*. The only heap is the alignment window.

### W3 — Shrink fixed shared memory

1. **Make the handle table dimension configurable and right-size the default.**
   `XROOTD_SESSION_HANDLE_SLOTS` is currently hard-wired `1024 × 16`. Most
   gateways never approach 16k concurrently-published handles. Expose it (or
   derive it from a new `xrootd_session_slots` × a smaller per-session factor)
   and drop the default to e.g. `512 × 8` ⇒ ~17 MB. Saves ~50 MB of fixed
   footprint. Store a path *offset into a slab* or a hash, not an inline
   `PATH_MAX`, if we want it smaller still (stretch).

2. Leave session/server/dashboard/TPC zones as-is (already small); just document
   their sizes in the config reference so an operator sizing for 1 GB can see the
   fixed floor.

### W4 — Worker-wide memory budget with backpressure (the enforcement)

A per-connection cap (W1.3) bounds each stream but not the *sum*. Add a
worker-level accountant so the invariant holds under any concurrency.

1. **`xrootd_memory_budget <size>` directive** (default e.g. **768m**, leaving
   headroom under 1 GB for SHM + nginx core + TLS contexts). A per-worker atomic
   counter tracks bytes currently checked out for transfer buffers (the W1.3
   pool, the W2 windows).

2. **Admission / backpressure when the budget is hot.** Before allocating a new
   transfer window, try to reserve from the budget. On failure:
   - `root://` stream: send `kXR_wait` (the protocol's native backpressure — the
     rate-limiter in `src/net/ratelimit/` already does this) and retry on drain;
   - HTTP/WebDAV/S3: `503` with `Retry-After`, or defer the read in the event
     loop.
   This converts an OOM-kill risk into graceful slowdown — exactly the behavior
   a storage gateway wants when 100 GB tries to flow through 1 GB.

3. **Expose budget gauges** on `/metrics` and the dashboard:
   `xfer_heap_bytes_in_use`, `xfer_heap_high_water`, `budget_waits_total`. These
   are the numbers that *prove* the invariant in production (see Verification).
   Labels stay low-cardinality (INVARIANT 8).

---

## Non-goals / explicitly out of scope

- **Page-cache accounting.** Bytes in the kernel page cache are reclaimable and
  are *not* part of the module heap budget — that is the whole point. We do not
  try to limit page cache (that is what `directio` is for; see below).
- **`directio` for huge files (optional follow-up).** For files far larger than
  RAM, page-cache pressure can evict everything else. A `directio` threshold
  (bypass page cache above N) is a reasonable *throughput/fairness* tuning but is
  orthogonal to the heap budget — track separately, do not bundle here.
- **Wire-protocol correctness.** pgread/pgwrite CRC32c framing, TLS
  `b->memory=1` invariant, `kXR_attn` framing — untouched (INVARIANTS 1–4).
- **Cleartext sendfile path rework.** It already meets the invariant. Phase 29
  owns making it *fast*; do not disturb it here.

---

## Sequencing & risk

| Step | Depends on | Risk | Why |
|---|---|---|---|
| W1.1 window constant + W1.2 trim | — | Low | Local to `aio/buffers.c` + completion; cleartext untouched |
| W1.3 per-conn ceiling | W1.1 | Low | Accounting only |
| W2.1 TLS fill/drain | W1.1 | **Med** | Touches the suspend/resume read state machine; needs the readv/pgread chunk tests |
| W2.2 PUT streaming | — | **Med** | Mixed memory/spool chains; correctness-sensitive (atomic rename, O_EXCL) |
| W2.3 readv streaming | W1.1 | Med | Keep Phase-27 overflow guards |
| W3 SHM shrink | — | Low | Config default change; verify no handle-exhaustion under load |
| W4 budget + backpressure | W1.3 | Med | New directive + atomic + integrate with existing `kXR_wait`/ratelimit |

W1 and W3 can land first and independently — they already move the needle and
are low risk. W2 is the correctness-sensitive heart. W4 makes the guarantee
enforceable and should land last so the gauges measure the post-W1/W2 world.

Per CLAUDE.md: every code step ships **3 tests** (success + error + security/neg)
and registers any new `.c`/`.h` in `src/core/config/config.h`. New constants go in
`src/core/types/tunables.h`; the new directive follows the RECIPES "New config
directive" pattern (field in `config.h`, `ngx_command_t`, merge in
`merge_*_conf`).

---

## Verification — prove the invariant, don't assume it

Baseline first (must stay green throughout — CLAUDE.md BUILD & TEST):

```bash
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

**The defining test — memory under sustained concurrent load:**

```bash
# Drive ≥100 concurrent large TLS reads/writes (davs:// + root://+TLS) totalling
# ≥100 GB in-flight, while sampling worker RSS once per second.
# PASS = peak summed worker RSS stays under the configured budget (1 GB) AND
#        aggregate throughput does not collapse (backpressure, not stall).
tests/run_load_test.sh --streams 128 --size 1g --tls --watch-rss
# expect: max RSS < 1024 MiB; budget_waits_total may be >0 (healthy backpressure)
```

Per-workstream checks:

- **W1:** open a TLS session, do one 64 MiB read, go idle 30 s → assert
  per-connection resident heap returns to ~window (not ~64 MiB). Unit test on
  the trim path in `aio/buffers.c`.
- **W2.1:** TLS vs cleartext byte-for-byte identical output for a 1 GiB read;
  resident high-water during the TLS read ≤ window × small constant.
- **W2.2:** PUT a 1 GiB object (both small-enough-to-be-in-memory and
  large-enough-to-spool) → correct bytes on disk, atomic rename intact, peak
  heap ≤ window. Security-neg: oversized/short body, path-escape attempt.
- **W3:** saturate handle table at the new smaller default → graceful
  `kXR_NoMemory`/`kXR_overQuota`, not corruption; confirm SHM size dropped
  (`ipcs`/startup log).
- **W4:** drive past the budget → observe `kXR_wait`/`503 Retry-After` and
  `budget_waits_total` incrementing; throughput degrades smoothly and recovers.

Cross-check Phase 29: the single-stream cleartext and TLS read numbers must not
regress — re-run its `load_test.py` / `xrdcp` matrix after W2.1.

---

## Expected outcome

| | Before | After (target) |
|---|---|---|
| Per warmed-then-idle TLS conn | up to **96 MiB** resident | ≤ **4 MiB** (`XROOTD_CONN_XFER_HEAP_MAX`) |
| Worst-case at 1 GB budget | ~16 connections | **~250** active + hundreds idle |
| In-flight : module-heap ratio | ~1–4 : 1 (TLS) | **≥ 100 : 1** |
| Fixed SHM floor | ~70 MB | ~17 MB |
| Behavior at memory ceiling | OOM-kill risk | graceful `kXR_wait` / `503` backpressure |
| Enforcement | none (hope) | worker budget + live gauges |

The 100:1 ratio is reached by making the kernel hold the in-flight bytes
(sendfile, socket buffers, page cache) and reducing the module's own job to
*aligning* requests into window-sized syscalls — with a worker budget that turns
the guarantee from aspiration into an enforced, measurable invariant.
