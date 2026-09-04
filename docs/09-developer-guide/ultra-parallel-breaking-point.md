# Ultra-parallel breaking-point storms — FTS-shaped overload vs official XRootD

**Status:** delivered 2026-09-02 (working tree). Tests:
`tests/test_ultra_parallel_breaking_point.py` (single-shape FTS ladder) and
`tests/test_ultra_parallel_mixed_storm.py` (16k-wide mixed metadata+transfer
storms), both slow tier, `xdist_group("lc-ultra-parallel")`, ladder port
30952, shared machinery in `tests/_test_ultra_parallel_helpers.py`. Template:
`tests/configs/nginx_lc_ultra_parallel.conf` (2 workers × 16384 connections,
`worker_rlimit_nofile 65536`, listen `backlog=16384` — sized so the widest
rung measures the server, not the config).

## Why this test exists

Production FTS traffic is indistinguishable from a DoS attack: thousands of
independent transfer jobs, each a **fresh TCP connect + handshake + kXR_login
+ kXR_stat + kXR_open + kXR_read (full file) + kXR_close + disconnect**,
submitted concurrently by a scheduler whose client-side backoff is poor. A
server that handles this badly turns the load into hangs, mid-frame drops of
established sessions, or worker crashes — and FTS then retries, amplifying the
storm.

## The graceful-degradation contract

The test does not assert the server *survives unlimited load* — it asserts the
server *degrades cleanly* when it can't keep up:

1. **Well-formed answers only.** Every request on an established session is
   answered with a complete frame — served, or shed via `kXR_wait` (the
   protocol backoff signal FTS/xrdcp honor).
2. **Admission-time shedding only.** Failures may happen at connect/handshake
   time (refused / reset before login-OK), never as a mid-session drop of a
   logged-in stream.
3. **No starvation.** A session established before the storm keeps completing
   timely, byte-exact reads while a top-rung storm rages (the partial-DoS /
   fairness property).
4. **Immediate recovery.** The first transfer after the storm is byte-exact.

Outcome classification is the contract: `served` (byte-verified) /
`throttled` (`kXR_wait` — clean) / `refused` (pre-login failure — clean) /
`errored` (**dirty** — established session broken, bad bytes, hang). The
*breaking rung* is the first ladder rung whose dirty count exceeds
`max(3, dispatched/100)`.

## The four tests

- **Ladder (success):** rungs of N×3 FTS jobs (default N = 16..256), all
  released on a barrier. No rung may go dirty; base rung ≥ 99 % served;
  post-storm recovery transfer byte-exact.
- **Concurrency cap (backpressure):** `brix_concurrency_limit … limit=16`
  under a 96-way storm must shed the excess via `kXR_wait` — never dirtily —
  while still serving some jobs. Proves the shed lever emits the protocol
  backoff signal, i.e. BriX actively tells FTS to back off instead of
  falling over.
- **Fairness (security-negative):** victim opens `/victim.bin` *before* the
  storm, then reads it in 256 KiB chunks under a top-rung storm — every chunk
  byte-exact and under the op deadline.
- **Comparison:** the identical ladder against an official `xrootd` daemon
  (skips when the RPM binary is absent) on the same payloads;
  BriX must not break at a rung the official server survives.

Tunables: `ULTRA_RUNGS` (comma list), `ULTRA_JOBS_PER_THREAD` (default 3),
`ULTRA_OP_TIMEOUT` (seconds). Run:

```
cd tests && PYTHONPATH=. python3 -m pytest test_ultra_parallel_breaking_point.py -v -s
ULTRA_RUNGS="512,1024,2048" … ::test_breaking_point_no_earlier_than_official_xrootd -v -s
```

## Results (2026-09-02, WSL2, 20 cores, tree at 5f5822004 + working tree)

Default ladder — BriX, zero dirty failures at every rung:

```
   n  served throttl refused errored  jobs/s   p50ms   p99ms
  16      48       0       0       0   177.6    78.4   157.7
 256     768       0       0       0   269.1   262.6   453.3
```

Concurrency cap (limit=16, n=96): 94 served / **194 throttled via kXR_wait** /
0 refused / 0 dirty — the backoff signal works.

Big-rung comparison (1 MiB payload, N×3 jobs per rung, sequential ladders):

| n (simultaneous) | BriX dirty | BriX p50/p99 ms | official dirty | official p50/p99 ms |
|---:|---:|---:|---:|---:|
| 512  | 0 | 254 / 424 | 0 | 254 / 437 |
| 1024 | 0 | 277 / 473 | 0 | 247 / 452 |
| 2048 | 0 | 267 / 459 | 0 | 256 / 424 |
| 4096 | 0 | 288 / 496 | 0 | 247 / 415 |
| 8192 | 0 | 285 / 510 | 0 | 281 / 490 |

**Breaking rung: neither server, up to 8192-way simultaneous storms.** BriX
and official XRootD both satisfy the contract to the top of the ladder;
latency at parity throughout.

## The 16k-wide MIXED storm suite (test_ultra_parallel_mixed_storm.py)

Real FTS overload is wider and mixed: a wall of cheap r/o metadata probes
(stat polling) arrives in the same instant as the transfer wave. Every rung
releases n clients through one barrier — **1 in 4 runs a full FTS transfer
(64 KiB, byte-verified), the rest run r/o metadata loops (login + 6 stats)**
— laddered 1024 → 4096 → 16384 concurrent clients. The contract adds one
clause: neither client class may be starved to zero while the other is
served.

Client-side engineering that makes 16k-wide rungs honest: 512 KiB thread
stacks; the fd soft limit raised per rung (a low hard limit clamps the ladder
instead of failing it); client source addresses spread over 127.0.0.2-9 so
the 4-tuple space and TIME_WAIT budget never become the bottleneck; a
client-side thread-spawn failure counts as *unspawned*, never as a server
dirty failure.

Four tests mirror the single-shape suite: the ladder (success), a
`brix_concurrency_limit limit=8` shed test (error/backpressure — single
source, 3 jobs/client, **heavy 1 MiB transfers**: light 64 KiB single-shot
jobs drain in milliseconds and never hold enough in-flight concurrency to
engage a cap, and source spreading would dilute a key=ip cap 8×), fairness
(security-negative), and the official-xrootd comparison. Tunables:
`ULTRA_MIX_RUNGS`, `ULTRA_MIX_JOBS`, `ULTRA_MIX_META_OPS`,
`ULTRA_MIX_PRESSURE`.

### Mixed results (2026-09-02, same host)

Comparison ladder, sequential, identical payloads — **zero throttled /
refused / dirty everywhere; both classes served at every rung**:

| n (simultaneous) | class mix (meta/xfer) | BriX p50/p99 ms | official p50/p99 ms |
|---:|---:|---:|---:|
| 1024  | 768 / 256    | 74 / 162  | 76 / 152 |
| 4096  | 3072 / 1024  | 98 / 194  | 86 / 163 |
| 16384 | 12288 / 4096 | 102 / 215 | 94 / 186 |

**Mixed breaking rung: neither server, up to 16384-way simultaneous mixed
storms.** BriX served every one of 16384 barrier-released clients with a
p99 of ~215 ms; latency parity with official XRootD throughout.

Capped mixed storm (limit=8, n=256, heavy transfers): ~620–630 served /
**~140 throttled via kXR_wait** / 0 refused / 0 dirty across repeated runs —
the shed lever engages under mixed load exactly as under pure transfer load.

## Honest caveats

- The single-process Python client is GIL-bound at ~220–300 jobs/s sustained,
  so the ladder is a **simultaneous-connection/admission storm** (all N
  sockets connect and log in at barrier release — the FTS-DoS shape), not a
  sustained max-rate bench. Finding an absolute rate-based breaking point
  needs a multi-process or C driver; the scratchpad bench rig's harnesses are
  the place for that.
- Zero refusals at the top rungs are real but partly architectural: short job
  lifetimes mean the listen backlog absorbs the surge and connections are
  accepted as earlier ones close (the config is sized at 2×16384 connections
  precisely so the widest rung measures the server, not the config). A
  long-lived-connection storm would exercise the refusal path instead.
- Ladders run sequentially against warm servers on the same host; compare
  breaking rungs and shapes, not absolute jobs/s between tables.
- The mixed fairness test caps its pressure at 256 threads: past that the
  GIL-bound client starves its own victim thread (a 256 KiB victim read
  measured 26.5 s under 1024 client-side pressure threads — pure client
  scheduling, not server starvation). Width belongs to the ladder tests;
  the fairness test measures fairness.
