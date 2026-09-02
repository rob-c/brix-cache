# Throughput hyper-optimization — round 11: windowed primary-path pgread + warm inline windows

Date: 2026-09-02 · Status: implemented, tested, benched · UNCOMMITTED

## Symptom

After round 10 the single-stream scoreboard read 1.42–1.48× over stock, but
the **8-client aggregate was dead even** with stock XRootD. `xrdcp` v5.9.6
streams an 8 GiB file as 1,024 pipelined 8 MiB `kXR_pgread` requests; each was
answered as ONE monolithic frame, which meant per request:

- an 8 MiB+CRC scratch encode before the first byte hit the socket, and
- a full thread-pool round-trip (post → worker read+encode → completion
  wakeup) whose handoffs (~4,100 wakeups per 8 GiB stream per client) contend
  across 8 workers × 8 clients.

## Design — the pgread train

A pgread larger than one streaming window (`BRIX_READ_WINDOW`, 2 MiB) on the
primary channel now streams through the shared Phase-31 windowed-read pump
(`rd.win_pgread:1`) as a **kXR_status frame train**: every window is one frame
(`kXR_PartialResult` … `kXR_FinalResult`), window cuts land on the absolute
4 KiB page grid, each window is encoded into the hot `rd.read_scratch` as
`[32-byte ServerStatusResponse_pgRead][gapped [CRC32c(4)][page]]…`. The train
is **self-serializing**: recv stays suspended (`XRD_ST_AIO`) for the whole
train and `send.c` re-enters the pump on drain, so pipelined over-window
requests queue in the socket and are answered train-after-train. ≤ 2 MiB
requests keep the classic pipelined single-frame path untouched.

Wire-shape consequences (all protocol-legal, proven against stock `xrdcp`
byte-exactly): a > 2 MiB pgread no longer answers as one frame; a capped huge
rlen (INT32_MAX → `BRIX_READ_REQUEST_MAX`) streams as a train; a
short-at-EOF window emits its Partial frame off-grid followed by a zero-byte
Final frame. Every frame of a train echoes the ORIGINAL request streamid
(`rd.win_streamid` snapshot — `cur_streamid` is overwritten by the next
inbound header).

## Design — warm inline window probe

Because the train self-serializes, the thread pool buys **no read/send overlap
between windows** — it only adds handoff latency. `brix_pgread_window_try_warm`
therefore probes each window inline on the event loop with
`preadv2(RWF_NOWAIT)` (same discipline as the round-6 `brix_pgread_try_warm`):
pool configured + `is_regular` + effective obj `driver->preadv2 != NULL`; a
hit is exactly `io_errno == 0 && nread == want` and must charge
`brix_metric_backend_bytes` itself (the warm path bypasses
`vfs_io_execute`). A short/EOF window is a MISS — the pool path owns EOF
framing. A resident window thus skips the pool round-trip entirely, bounded to
one window (2 MiB) of inline work per pump entry.

## Files

- `src/protocols/root/read/pgread_window.c` (NEW, 274 lines) —
  `brix_pgread_window_want` / `_scratch` / `_emit` / `_try_warm` /
  `brix_pgread_serve_windowed`. Emit contract: `nread < 0` → error frame with
  the original streamid + `NGX_ERROR`; success advances
  `win_offset`/`win_remaining`, Final iff `(win_remaining == 0 || got == 0)`.
- `src/core/aio/reads.c` — pump hook (warm probe before pool post) +
  extracted `read_window_sizes` (pgread grid-cut vs plain window sizes) and
  `read_window_post_aio` (the full thread-pool post block; task-union hazard:
  `t->pg` must be cleared in `read_post_aio`, `rd.win_pgread` in
  `read_serve_windowed`).
- `src/core/aio/aio.h` — declarations (`BRIX_PGREAD_WARM_INLINE_MAX` =
  `BRIX_READ_WINDOW`).
- `src/core/types/ctx_structs.h` — `rd.win_pgread:1` beside the existing
  `win_idx/win_fd/win_offset/win_remaining/win_streamid` window state.

## Results (8 GiB warm-cache xrdcp A/B, 8 workers + reuseport)

Clean host, single stream: **brix 2,483.9 MB/s vs stock 1,752.8 (1.42×)**,
server CPU/byte 388–432 vs 550–647 µs/MB. Under a loaded host (load ~9.3,
concurrent agent sessions; both servers see the same load so the A/B holds):

| metric | brix | stock | ratio |
|---|---|---|---|
| single stream (median of 5) | 1,784.6 MB/s | 1,232.2 MB/s | **1.45×** |
| server CPU/byte | 500–565 µs/MB | 687–847 µs/MB | −29% |
| 4-client aggregate (mean/best of 3) | 3,867 / 4,619 MiB/s | 3,648 / 3,888 MiB/s | +6% / +19% |
| 8-client aggregate (mean/best of 3) | **4,223 / 4,409 MiB/s** | 3,491 / 3,816 MiB/s | **+21% / +16%** |

The 8-client case — the round's target — moved from parity to +21% mean; the
deleted pool handoffs are exactly the contention that showed up only at high
client counts. Single-stream ratio held (1.42→1.45×) — the train framing costs
nothing on the wire.

## Proof

- `tests/test_pgread_primary_stream.py` (NEW, 5 tests) — primary-channel
  train shape (≥2 frames, Partial…Final, grid cuts, contiguous offsets,
  byte-exact reassembly), sub-window single-Final regression guard, EOF
  early-Final (off-grid short window + zero-byte Final tolerated), bogus
  fhandle error + no desync + next train works, negative rlen →
  `kXR_ArgInvalid` + no desync (unsigned-wrap ~4 GiB allocation guard).
- `tests/test_pgread_partial_stream.py`, `test_pgread_wire_conformance.py`
  (`test_huge_rlen_capped` drains the train), `test_pgread_pipelining.py`
  (per-sid train reassembly in `_drain_many`; close-barrier behind a
  2-window train) — all made train-aware.
- Full family green against the bench server: `test_pgread_partial_stream +
  wire_conformance + pipelining + client_retry + primary_stream +
  phase31_memory + lazy_file_table_preopen` = **50 passed, 1 skipped**.
- 8 GiB and odd-size (`odd.bin`) `xrdcp` transfers byte-exact through mixed
  warm/pool window trains; client verifies every page CRC32c.
- Zero error/alert/crit lines in the bench server log across all runs on the
  final binary.
- All CI guards green (config_coverage, complexity, duplication, file_size,
  vfs_seam, vfs_mutation_gate, python_quality).

Residual: `clear_page_erms` ~9.7% of worker CPU remains; a double-buffered
window (encode window N+1 while N drains) is the natural round-12 candidate.
Bench topology and harness live with
`throughput-hyperopt-round-10-hot-trim.md` / `throughput-hyperopt-rounds-5-6.md`.
