# Round 9 — the order-of-magnitude hunt: idle-session memory (lazy file table)

Rounds 5–8 banked wins on all four scored axes (throughput, latency,
metadata-ops, sign-in). Round 9 hunted for regimes where a full order of
magnitude is feasible — and found one where brix was on the WRONG side of
it: **per-idle-session memory**. A brix session that had authenticated but
opened nothing held ~167 KB of touched RSS; stock xrootd held ~9 KB. Not a
scored axis, but an 8× deficit is a scaling ceiling (sessions per GB of
worker RSS) and a cheap remote memory-pressure lever, so it was fixed
before any further benchmark banking.

## Measurement

`idlemem.py`: open N=256 authenticated-but-idle sessions against each
server, delta the worker-set RSS, divide. Same host, same run:

| build | per-idle-session |
|-------|------------------|
| brix, before | ~167 KB |
| brix, after (lazy table) | **25.2–26.6 KB** |
| stock xrootd 5.9.6 | 9.2–10.4 KB |

6.3–6.6× improvement; the deficit vs stock falls from ~18× (touched) to
~2.6×.

## Root cause: the embedded 16-slot handle table

`brix_ctx_t` embedded `brix_file_t files[BRIX_MAX_FILES]` directly —
`sizeof(brix_ctx_t)` was **183,216 bytes**, ~170 KB of which was the
handle table, and the ctx is `pcalloc`'d per connection, so every page was
touched (zeroed) whether or not the session ever opened a file. A
metadata-only session (stat/dirlist storms, the redirector pattern) and an
idle authenticated session both paid the full table.

## Fix: lazy allocation, fixed address, NULL-guarded everywhere

`brix_ctx_t.files` is now a `brix_file_t *`, NULL until the first
`kXR_open` (or bound-secondary handle ensure) calls
`brix_files_ensure()` (`src/protocols/root/connection/fd_table.c`), which
`pcalloc`s the one fixed 16-slot block. `sizeof(brix_ctx_t)` fell to
**12,472 bytes**. Two design constraints:

1. **The table is never reallocated or grown.** In-flight AIO tasks hold
   `brix_file_t *` across worker threads; a growable table would dangle
   them. Lazy-but-fixed keeps every existing pointer-stability assumption.
2. **NULL means "no handle is open", and every indexing path must fail
   cleanly.** An unguarded `ctx->files[idx]` deref on a fresh session is a
   remotely triggerable worker segfault (one crafted frame carrying a
   handle before any open). Audited and guarded: the fd_table
   validators/teardown/disconnect-report, fattr dispatch, qcksum-by-handle,
   writev, query dispatch, readv prefetch, and eight sites in the TPC
   engine (`src/tpc/engine/done.c`).

Collateral: the guard work pushed `fd_table.c` over the 600-line cap — the
bound-secondary machinery moved verbatim to `fd_table_bound.c` (new unit in
`./config`); the prefetch guard pushed `brix_prefetch_readv_segments` over
CCN 15 — per-segment decode extracted as `prefetch_decode_segment`.

## Proof

`tests/test_lazy_file_table_preopen.py` (13 raw-wire tests, permanent):
open/write/read/close round-trip (table allocates on first open);
post-close I/O is `kXR_FileNotOpen`; and the security-negative sweep — all
11 handle-bearing ops (read, write, sync, truncate, close, pgread,
pgwrite, readv, writev, fattr, qcksum-by-handle) sent on a fresh session
with the table still NULL each get a clean error (the plain-validated ops
exactly `kXR_FileNotOpen` = 3004) with the worker provably alive after
(same-connection ping where the protocol allows it, fresh-session ping
always). Note: writev with an invalid descriptor answers and then drops
the link BY DESIGN (framing is unresynchronisable — see `writev.c`), so
crash detection uses fresh-session liveness, not same-connection survival.
Plus the standing smokes: `xrdcp` read and 8 MB write round-trip.

## Quiet-window regression bank (split binary, load1 < 1 at start)

Re-run of the standing comparative benchmarks against the lazy-table build,
confirming the memory win cost nothing anywhere else:

- **stat ladder** (`ladder.py`, persistent `xrdfs` shells, N=1..256): brix
  1.20× at N=1, 0.98–1.24× across the concurrent rungs — parity to modest
  win, all 1.4 M ops verified, zero bad processes. Above N=8 both servers
  sit on the same client-process floor (spawn alone is 27–31 s at N=256).
- **GSI sign-in storm** (`gsistorm.py`, N=8/32/64 × 3 reps): brix
  **1.45–1.58×** stock sessions/s at every rung, zero failures, p50 and
  p95 both well ahead (e.g. N=64: p50 688 ms vs 1,053 ms) — the round-8
  server-leg win intact.
- **server CPU per stat op** (`cpuop.py`, 20 k ops): brix 132.5 µs vs
  stock 127.0 µs — parity within noise; the lazy table's ensure check adds
  no measurable CPU.
- **xrdcp throughput** (8 GB read, 2 GB write, interleaved reps): read —
  brix 2,380–2,438 MB/s vs stock 2,119–2,272 MB/s warm (~1.1×, the
  rounds-5/6 win intact; the first sample was a cold page cache). Write —
  both servers are disk-writeback-bound on this host (526–1,230 MB/s
  across reps, brix aggregate slightly ahead); no cliff. This matters
  because the fd_table split and the prefetch decode extraction touched
  the read path — behavior-preserving, now perf-verified.
- **connection churn** (`churn.py`, raw-wire connect+handshake+login+close,
  no client-process spawn): brix 1.30× at N=1 (2,848 vs 2,191 sess/s),
  1.03–1.09× at N=8..64, zero failures. This was the last untested
  order-of-magnitude candidate; there is no 10× here — both servers
  converge on the same TCP-accept + login floor (~1,000 sess/s), and at
  concurrency the GIL-bound Python client is likely the binding
  constraint anyway. Verdict: churn is not a differentiating regime;
  idle-session memory (this round) was the one true 10×-class gap, and it
  was on brix's side of the ledger until now.

## What remains of the ~26 KB, and the deferred phase-2 lever

Roughly 12.5 KB is the (pcalloc-touched) ctx itself and ~13 KB the nginx
pool/connection floor. Largest ctx members: `bearer_token` 4,096 B, token
2,088, login 1,808, krb5 1,560, rate-limit 1,304. Making `bearer_token`
lazy was evaluated and **deferred**: ~37 deref sites across 12 files in
four protocols plus proxy and TPC would each need a NULL discipline — the
crash-surface risk outweighs 4 KB. The remaining gap to stock is dominated
by per-scheme auth state brix keeps inline that xrootd allocates on
demand; further shrinking is possible but past the knee of the
risk/reward curve.
