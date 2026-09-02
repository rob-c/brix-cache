# Throughput hyper-optimization — round 10: hot-deferred scratch trim

Date: 2026-09-02 · Status: implemented, tested, benched · UNCOMMITTED

## Symptom

Round-5/6 re-measurement (8 workers + reuseport, 8 GiB warm-cache `xrdcp`
pgread stream) showed brix ahead on wall time but spending **2.1× more server
CPU per byte** than stock XRootD: 851–981 µs/MB vs 398–441 µs/MB. `perf` on the
workers during the stream:

| symbol | % |
|---|---|
| `_copy_to_iter` | 21.0 |
| `_copy_from_iter` | 11.0 |
| `do_user_addr_fault` | 9.9 |
| `brix_crc32c_hw3_extend` | 9.8 |
| `rt_spin_lock` (RT kernel) | 8.8 |
| `clear_page_erms` | 5.8 |
| `__rmqueue_pcplist` | 5.8 |
| `unmap_page_range` + page-alloc entries | ~4 |

The fault/zeroing/page-allocator block (~25% of worker CPU) has no business in
a steady-state read stream — the buffers should be warm.

## Root cause — per-request trim × glibc equal-size mmap churn

`brix_trim_scratch()` runs at the top of every request (recv_frame.c, gated on
full quiescence) and freed any idle `rd.pool` slot larger than
`BRIX_SCRATCH_TRIM_THRESHOLD` (4 MiB) down to size 0. `xrdcp` v5.9.6 streams an
8 GiB file as 1,024 back-to-back 8 MiB `kXR_pgread` requests, and pgread can
never use sendfile (per-page CRC32c framing), so every request grew a pool slot
to 8 MiB and the next request's trim freed it.

The glibc detail that turns this into a 25% CPU tax: an 8 MiB chunk is above
the mmap threshold, so it is mmap'd; freeing it munmaps it; and because the
**dynamic mmap threshold adapts to the size of freed chunks**, an equal-size
free/malloc cycle re-arms the threshold at the same size forever — the
allocation never migrates to the reusable heap. Every request therefore paid
munmap + mmap + 2,048 first-touch page faults + kernel page zeroing for the
same 8 MiB it had just released.

## Fix — one-cycle hot deferral

A slot used since the previous trim pass is *hot* and skipped for one cycle
(clearing the mark); a slot idle for a full cycle is trimmed exactly as before.
A streaming transfer now reuses ONE warm buffer for the whole stream; an idle
connection still returns to window-scale heap, one request later than the eager
trim did. The `in_use` safety gate is untouched, so nothing is freed earlier
than before — the change is strictly a deferral.

Implementation (5 files):

- `src/core/types/context.h` — `brix_read_slot_t` gains `unsigned hot:1`.
- `src/core/types/ctx_structs.h` — four `*_hot:1` bits in `rd` (read/hdr/
  write/cmp scratch; hdr+cmp carry the mark only for macro uniformity).
- `src/core/aio/aio.h` — `BRIX_GET_SCRATCH` becomes a comma expression that
  sets `slot_field##_hot = 1` before calling `brix_get_pool_scratch` (the
  token paste lands on the last member of the dotted argument).
- `src/core/aio/buffers_scratch.c` — `brix_acquire_read_buffer` marks
  `pool[i].hot`; `brix_trim_scratch` hot-gates both `brix_trim_one` calls and
  the pool-slot loop, clearing marks as it passes.
- `src/core/types/tunables.h` — threshold comment documents the deferral.

Struct bitfield additions = ABI change → clean rebuild of the module objects
(delete `objs/addon` contents but **keep the directory skeleton** — the
generated Makefile does not `mkdir -p`; recreate with
`grep -oE "objs/addon[a-zA-Z0-9_/.-]*\.o" objs/Makefile | xargs -n1 dirname |
sort -u | xargs mkdir -p` if you clean too hard).

## Results (same A/B harness, 8 GiB warm pgread, medians of 5)

| metric | before | after |
|---|---|---|
| brix server CPU/byte | 851–981 µs/MB | **527–634 µs/MB** (−35%) |
| stock server CPU/byte | 398–441 µs/MB (earlier window) | 497–613 µs/MB (same window as after) |
| brix throughput | ~2,380–2,440 MB/s (1.09×) | **2,699 MB/s median, 3,196 peak (1.48×)** |
| stock throughput | ~2,120–2,270 MB/s | 1,819 MB/s median |
| idle per-session RSS (N=256) | 26.6 KB (round 9) | **18.0 KB** (no trim regression) |

brix CPU/byte is now at parity with stock in the same measurement window while
delivering 1.48× the wall throughput (the client is the next bottleneck: xrdcp
runs at ~190% CPU against brix vs ~110% against stock). The remaining brix CPU
is copies (~32%) + CRC32c (~10%) — attacking those means changing the
single-preadv/single-writev copy discipline, out of scope this round.

This also explains most of the round-5/6 scoreboard discrepancy: the banked
−23% CPU/byte predates the per-request pool-slot trim behaviour that pgread
pipelining exposed; the churn regression ate the round-5/6 margin, and this
round returns it with interest.

## Proof

- `tests/test_phase31_memory.py` — existing 6 cases green PLUS a new trio:
  - `test_hot_streaming_readv_reuses_warm_scratch` — 8 back-to-back large
    readvs byte-exact (the skipped-trim path can never serve stale bytes).
  - `test_deferred_trim_fires_then_regrows_byte_exact` — large readv → two
    small requests (first clears hot, second's trim actually fires) → large
    readv regrows, ×3 cycles, byte-exact (the deferred-trim new-code path).
  - `test_interleaved_large_read_write_no_cross_slot_bleed` — interleaved
    large writes and readvs on one connection (multiple slots hot at once),
    plus full read-back of the written file.
- `tests/test_lazy_file_table_preopen.py` — 13/13 (round-9 structs share the
  ctx; proves no ABI fallout).
- 32 MiB `xrdcp` write→read round-trip `cmp`-exact; pgread integrity is
  additionally client-verified per page (CRC32c) across every bench run.
- All six CI guards green (file_size, complexity, config_coverage,
  duplication, vfs_seam, vfs_mutation_gate).

Bench topology, harness scripts (`thrcheck.py`, `idlemem.py`) and the round-9
context live in `idle-session-memory-hyperopt-round-9.md` and
`throughput-hyperopt-rounds-5-6.md`.
