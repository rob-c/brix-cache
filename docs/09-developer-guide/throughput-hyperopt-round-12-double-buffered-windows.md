# Throughput hyper-optimization — round 12: double-buffered windowed reads

Date: 2026-09-02 · Status: implemented, tested, benched (single-stream 1.36×; 8-client gap −9% → ahead) · landed in 5f5822004 (+ post-round fixes below, working tree)

## Symptom

Round 11's train removed the per-request pool handoffs and took the 8-client
aggregate from parity to +21%, but the train **self-serializes**: read (+
pgread encode/CRC), send, and drain of every window run strictly in sequence,
so each worker's throughput is capped by one event-loop core doing all three.
On a clean host stock's best 8-client mean (5,316 MiB/s) still beat brix
(4,830, −9%) — the residual gap is exactly the serialized read+CRC+copy on the
critical path.

## Design — overlap window N's send with window N+1's read

While window N drains from `rd.read_scratch`, window N+1 is read (and, for
pgread, encoded + CRCed) by a counted thread-pool task into a second buffer
`rd.win_scratch_b`; after every successful emit the two buffers swap roles
(field-triple swap of `ptr/size/hot` — queued frames and the in-flight task
hold raw pointers, which never move).

- **Prefetch posts BEFORE emit** (`brix_read_window_emit_step`): the post
  flips `ctx->state` to `XRD_ST_AIO` and the emit overwrites state after, so
  the pre-emit ordering keeps the state machine consistent.
- **Safety invariant**: a window is emitted only after the previous frame
  fully drained (`send.c` re-enters the pump only when `brix_flush_pending`
  reports empty), so the read-ahead always targets a buffer no queued frame
  references.
- **Completion routing is by task identity**: `task == rd.read_aio_task`
  gates the windowed family (that task is used ONLY by windowed posts);
  within it `rd.win_prefetch` distinguishes read-ahead from current-window.
  A pipelined single-shot completion (per-slot task) falls through to the
  classic deliver path even mid-train.
- **Rendezvous**: the read-ahead completion stashes its result in
  `rd.win_pf_{nread,osz,errno}` (`win_ready`); the frame's drain and the
  completion meet in the pump — whichever arrives last emits.
- **Graceful degradation**: any obstacle (no pool, driver-backed handle,
  budget refusal, OOM, queue full, EOF-ending window) silently degrades that
  step to the round-11 serial train.
- The prefetch condition `nread > 0 && nread < win_remaining` means an
  EOF-short window still prefetches; the read-ahead reads 0 at EOF and the
  stashed `nread=0` emits the zero-byte Final frame — identical to serial
  semantics.

## Design — trains start quiescent (fixes a round-11 latent bug)

`brix_read_aio_deliver`/write dones end with `state = XRD_ST_REQ_HEADER` +
`brix_aio_resume` — a straggler single-shot read OR write completion landing
mid-train would clobber the train's recv suspension (latent in round 11;
only mixed-size pipelined workloads hit it). Fix in `brix_recv_should_defer`:
a would-be-windowed read (`rlen` from `cur_body[12..16]` `> BRIX_READ_WINDOW`)
is deferred through the existing Phase-29 drain-barrier park/re-dispatch
machinery while `out.wr_inflight > 0 || rd.aio_inflight > 0`. Deliberately
over-approximates (the memory path clamps to file size; sendfile never
windows) — the cost is one extra defer, never a wrong dispatch. Small reads
and all writes keep their pipelining unchanged.

## Hazards closed

- **Counted posts**: every windowed post is now `t->counted = 1` +
  `rd.aio_inflight++` — a read-ahead runs on a worker WHILE a frame drains,
  so a send-error teardown must defer until the worker leaves the buffer
  (`brix_defer_teardown_if_writing` → `brix_read_aio_orphaned` runs the held
  teardown on the last counted op). The pre-round-12 `counted=0` relied on
  recv being suspended AND nothing sending during `XRD_ST_AIO`.
- **Emit error with read-ahead in flight**: `brix_read_window_park_or_resume`
  parks in `XRD_ST_AIO` (truthful — a counted task is in flight); resuming
  immediately would let a new train reuse the busy task struct or free
  scratch under the worker. The discard path in
  `brix_read_window_prefetch_done` (`win_prefetch && !win_active`) clears the
  flag and — only when parked — restores `REQ_HEADER` + resumes.
- **Sync-send escape**: the pump's `win_prefetch` branch sets `XRD_ST_AIO`
  before returning, so a synchronously-drained emit can't leave recv live
  under an in-flight task.
- **Budget**: `win_scratch_b_size` joins `brix_budget_ctx_footprint`;
  `brix_budget_admit` is consulted only when the back buffer must GROW;
  refusal skips the prefetch (no `kXR_wait`).
- **Idle memory (round-9 guard)**: `brix_trim_scratch` frees a COLD
  `win_scratch_b` outright (never re-seats it at window size) — only
  streaming trains pay for a second window. Disconnect frees it
  (`brix_release_disconnect_owned_buffers`); the release-buffer no-op guard
  recognizes it as a kept slot (post-swap frames reference it).
- Warm-probe hits also prefetch: with overlap, the pool round-trip for the
  NEXT window is desirable again even when the current window was warm.

## Files

- `src/core/aio/reads_window.c` (NEW — split from reads.c, size cap): the
  train's forward drive — `brix_read_window_emit` / `_emit_dispatch` /
  `read_window_sizes(_at)` / `read_window_post_aio` (offset-parameterized,
  counted) / `brix_read_window_prefetch` / `_swap_buffers` / `_emit_step` /
  `_park_or_resume` / `_final_sample` / `_pump_ready` /
  `read_window_inline_step` / `brix_read_window_pump`.
- `src/core/aio/reads.c` — thread fn + completions; `brix_read_aio_done`
  routes on task identity → `prefetch_done` / `window_done` / stale-resume;
  `brix_read_window_prefetch_done` (stash/discard rendezvous).
- `src/core/aio/aio.h` — seam decls (`_emit_step`, `_park_or_resume`).
- `src/core/types/ctx_structs.h` — `rd.win_scratch_b{,_size,_hot}`,
  `win_prefetch:1`, `win_ready:1`, `win_pf_{nread,osz,errno}` (ABI: clean
  addon rebuild).
- `src/protocols/root/connection/recv_process.c` — the quiescence gate
  (`brix_recv_read_is_windowed` + amended `brix_recv_should_defer`).
- `src/protocols/root/connection/recv_payload_buf.c` (NEW — size-cap split):
  `brix_ensure_payload_buffer` / `brix_grow_payload_buffer` folded onto one
  `preserve`-flagged core (they were near-clones); decls in `recv_frame.h`.
- `src/protocols/root/connection/budget.h` — footprint term.
- `src/core/aio/buffers_scratch.c` — release no-op guard + cold-free trim.
- `src/protocols/root/connection/disconnect.c` — disconnect free.
- `src/protocols/root/read/read_buffered.c`, `pgread_window.c` — defensive
  `win_prefetch/win_ready` clears at both train arm sites.
- `config` — the two new compilation units.

## Results

A/B on the settled host (load ~2 during the interleaved runs; 20 cores, 8 GiB
file, xrdcp 5.9.6 → /dev/null, both servers on the same page-cached file).

Single-stream (`thrcheck.py`, 5 reps interleaved, medians):

| server | MB/s | server CPU |
|---|---|---|
| brix (round 12) | **2,817** (best 3,173) | ~331 µs/MB |
| stock xrootd | 2,070 (best 2,270) | ~470 µs/MB |

**1.36×** — up from round 11: the read+CRC+copy left the critical path, and
CPU per byte fell with it.

8-client aggregate (`abmulti2.py`, 6 reps, per-rep interleaved with
alternating order — the original all-A-then-all-B harness is biased under
decaying host load and two such runs were discarded):

| server | best | mean | median |
|---|---|---|---|
| brix (round 12) | **5,503** | **4,913** | **5,300** |
| stock xrootd | 5,322 | 4,823 | 4,776 |

The round-11 8-client deficit (4,830 vs 5,316, −9%) is closed: brix now edges
ahead on every summary statistic. 4-client (older biased harness, brix-first
under higher load): brix 4,650 mean / 5,466 best vs stock 4,428 / 4,884.
At 8×8 the host is CPU-saturated, so the overlap mostly converts to lower
tail latency rather than aggregate; the aggregate win is variance-level, the
single-stream and CPU/byte wins are not. Bench error log: zero
error/alert/crit lines across all runs.

## Proof

- `tests/test_read_window_overlap.py` (NEW, 3 tests) — mixed burst [small
  pgread, small read, 3 MiB read train, 3 MiB pgread train, small pgread] in
  ONE write: trains defer behind stragglers, all five byte-exact
  (success); bad-handle windowed pgread mid-burst fails alone, neighbours
  intact (error); kXR_close behind a straggler + train retires the handle
  only after both (security-neg).
- Round-11 full family re-run against the round-12 binary: **50 passed, 1
  skipped** (partial_stream + wire_conformance + pipelining + client_retry +
  primary_stream + phase31_memory + lazy_file_table_preopen); plain-read
  conformance `test_conf_io_read.py` 46 passed.
- `xrdcp` byte-exact: 25 MiB pgrw+plain, 32 MiB pgrw, odd-size, and 8 GiB
  pgrw + plain trains (≈4,000 prefetch/swap cycles each).
- All CI guards green (config_coverage, complexity, duplication, file_size,
  vfs_seam, vfs_mutation_gate, python_quality, import_direction, namespace).

## Post-round fixes (2026-09-02 evening, found by the full fast tier)

Three defects surfaced when the whole `-m "not slow"` tier ran against the
round-12 binary; all three are fixed in the working tree on top of 5f5822004.

1. **pgread short-window framing = silent truncation** (`pgread_window.c`,
   `reads_window.c`). The emit treated ANY `got < win_remaining` as "more
   windows follow" and kept the train going — but a short read is EOF, and
   pgread framing permits a partial page only in the FINAL frame. The short
   window went out as `kXR_PartialResult`, the follow-up read returned 0, and
   the zero-byte Final under-filled the request: the client saw a corrupt
   tail page / short file. Rule now pinned in both files: **a short window is
   EOF and MUST end the train in the same emit** (`kXR_FinalResult` on the
   short frame); only a byte-exact full window with bytes still owed
   continues. The prefetch side got the mirror guard — a read-ahead behind a
   train-ending short window would outlive the train and race the swapped
   scratch buffer, so `brix_read_window_prefetch` now skips when
   `nread < want`. Proof: `test_pgread_primary_stream.py` +
   `test_vfs_read_only_static.py` (EOF-straddling windowed pgreads).

2. **Budget admission starvation** (`budget.h`). The idle-pool escape was
   `others == 0` — but every logged-in connection pins a few framing bytes
   (`payload_buf`), so `others` is almost never exactly 0, and a
   `want > budget` transfer fell into a permanent `kXR_wait` retry loop the
   moment any second session existed. The threshold is now `others <=
   budget/2`: real transfer scratch (≥ one streaming window) sits far above
   half-budget, idle framing residue far below, and an admitted over-budget
   transfer then holds enough charge to defer the next — which is the
   backpressure the cap exists for. Proof: `test_fsoverload_stall.py`.

3. **`config` dep-list gap** (build governance). `budget.h` was never in
   `ngx_brix_stream_deps`, so editing it rebuilt NOTHING — the fix above
   silently didn't take until a manual `touch` of an includer. The general
   trap: a new header that misses the deps list produces stale-binary
   debugging sessions, and no guard catches it (`check_config_coverage.py`
   audits `.c` source entries only, not `NGX_ADDON_DEPS`). When adding a
   header under `src/`, add it to the deps block in `config` in the same
   change; symptom of the gap is an edit that "doesn't do anything" until
   re-`./configure` or a clean build.

Trap for the next reader: the two payload-buffer helpers tripped
`check_duplication` the moment they moved to their own file — the clone was
pre-existing but invisible inside a big unit. Bench-harness trap: the
scratchpad `benchport_plugin.py` hardcoded 23190; it now honors
`BRIX_PGSTREAM_PORT` / `BRIX_BENCH_METRICS_PORT` so the family can run
against a functional server on a non-ladder port (28790/28792) while a peer
session owns the ladder.
