# Session-registry hyper-optimization — round 13: the live-prefix mark

Date: 2026-09-02 · Status: implemented, unit-tested (46 assertions), benched
(table-size scaling removed: CPU/job spread 6.1× → flat) · working tree,
UNCOMMITTED

## Symptom

The FTS-shaped storm A/B (`tools/diag/storm_ab_bench.py`) showed BriX's
admission cost rising with a knob that should not have mattered: the
*configured* size of the SHM session registry. Holding the storm width at 512
and varying only `brix_session_slots` — so the live session population never
changed and only the table's declared capacity did — produced:

| `brix_session_slots` | jobs/s | server CPU ms/job |
|---|---|---|
| 256 | 1843.9 | 0.840 |
| 1024 (default) | 1437.9 | 0.996 |
| 8192 | 1350.1 | 1.777 |
| 32768 | 820.2 | 5.117 |

CPU per job scaled roughly linearly with the configured capacity. That is the
signature of an O(capacity) cost paid per connection, not an O(population) one.

## Root cause

`brix_session_register` and `brix_session_unregister` each walked the table to
`tbl->capacity` under the single cross-worker `brix_session_mutex` — two full
walks per FTS-shaped connection (one at login, one at disconnect), independent
of how many slots were actually occupied. `brix_session_lookup` and
`brix_session_find_locked` (the three pathid-bitmap operations) walked the same
way.

The walk is not cheap per slot: `brix_session_entry_t` is ~1.1 KB (two 512-byte
identity strings), so a 1024-slot pass streams over a megabyte of shared memory,
and `brix_session_scan` additionally does an `ngx_strcmp` per occupied slot for
the W5 per-source quota key. All of it inside one mutex shared by every worker.

## Fix — a `high_water` live-prefix mark

`brix_session_table_t` gains one mutex-guarded field:

```c
ngx_uint_t high_water;   /* 1 + highest slot index currently in_use */
```

Every scan bounds itself by `high_water` instead of `capacity`. This is the
same mark, with the same mechanics, that the sibling `brix_shared_handle_table_t`
already carries in `handles.c` — whose in-repo comment records that the
full-table walk there "was 25% of worker CPU on the open-heavy metadata
benchmark."

Four touch points:

- **`brix_session_scan`** and **`brix_session_find_locked`**: loop bound
  `capacity` → `high_water`.
- **`brix_session_scan`'s free-slot fallback**: when the live prefix contains no
  hole, the free slot is the frontier itself (`high_water`), guarded by
  `high_water < capacity`.
- **`brix_session_fill_slot`**: raises the mark (`slot >= high_water` →
  `high_water = slot + 1`).
- **`brix_session_shrink`** (new): walks the mark back down over a freed
  trailing run, so it tracks the peak *live* population rather than the
  boot-time peak. Without it one transient burst would tax every later scan for
  the process's lifetime — exactly the cost the mark exists to remove.

`brix_session_lookup` and `brix_session_unregister` in `registry.c` open-code
their own passes; both were bounded the same way.

### Why `shrink` is called from exactly one place

Only `brix_session_unregister` calls it. The other two slot clears — the F4
global-LRU reap (`brix_session_reap_lru`) and the W5 self-eviction
(`brix_session_src_cap_evict`) — hand their freed index straight back to
`brix_session_fill_slot`, so the slot is occupied again before any scan can
observe it; retiring the frontier there would be undone on the next line.

## The invariant, and why it is a security property

> **Every `in_use` slot has index `< high_water`.**

If that is ever violated, a bounded scan silently under-counts, and two
defences built on the scan degrade quietly rather than loudly:

- **W5 per-source soft quota** (`BRIX_SESSION_PER_SOURCE_SOFT_CAP` = 64):
  `src_count` is accumulated *during* the scan. An occupied slot beyond the mark
  would not be counted, so an identity could exceed its quota — the cap would
  stop biting before 64.
- **F4 global-LRU reap-on-full** (`BRIX_SESSION_REAP_MIN_AGE_MS` = 60000): the
  LRU minimum is also folded during the scan. A missed slot could never be
  chosen as the victim, so a slot-exhaustion attacker's oldest session would
  become unreapable.

Both failure modes are silent, which is why the unit battery asserts the
invariant directly rather than only asserting outcomes.

## Tests — `tests/c/test_session_registry_high_water.c`

Registered as the `session_registry_high_water` object unit in
`tests/cmdscripts/c_object_units.py`, which links the one real
`registry_slots.o` against spies for its five cross-TU symbols
(`brix_rl_key_sub_hash`, `brix_rl_key_dn_hash`, `brix_session_handle_unpublish_all`,
`ngx_worker`, and `ngx_brix_shm_zone` — the last a NULL zone pointer rather than
a spy function, because `brix_metrics_shared()` is a `static ngx_inline` that
already returns NULL when the zone is unset). 46 assertions, four batteries:

1. **success — prefix tracking**: the mark rises with each fill and falls back
   to 0 when the table drains.
2. **boundary — holes and full**: a hole inside the prefix is reused before the
   frontier; a full table leaves `high_water == capacity`; `shrink` over a
   freed top run retires only the trailing free slots, never a live one below a
   hole.
3. **security-negative — quota sees every slot**: a registrant at the soft cap
   is still detected as over-quota when its slots sit at the top of the prefix,
   i.e. the bounded scan counts what the unbounded one counted.
4. **security-negative — invariant under churn**: 4000 register/unregister steps
   over a 64-slot table with 90 distinct sessids, asserting
   `prefix_covers_every_live_slot()` after *every* step, then asserting a fully
   drained table returns `high_water == 0`.

## Result

Re-running the same capacity sweep after the fix:

| `brix_session_slots` | before j/s | before CPU | after j/s | after CPU |
|---|---|---|---|---|
| 256 | 1843.9 | 0.840 | 1769.8 | 0.840 |
| 1024 | 1437.9 | 0.996 | 1394.2 | 1.094 |
| 8192 | 1350.1 | 1.777 | 1702.1 | 0.898 |
| 32768 | 820.2 | 5.117 | 1461.4 | 1.074 |

The 6.1× CPU/job spread across the range collapses to flat (0.840–1.094, within
run-to-run noise). At 32768 slots the change is 1.78× throughput and 4.8× CPU
efficiency. At the default 1024 slots with a width-512 storm the table is not
oversized relative to the population, so the change is correctly a no-op there —
the win is that capacity is now free to configure for the peak without taxing
the common case.

Against the official daemon on the same sweep (width 512): 3.22× / 3.46× /
4.11× / 3.60× throughput at 256 / 1024 / 8192 / 32768 slots — BriX ahead
everywhere, and now essentially independent of the knob.

## What this does NOT fix

The registry scan is now O(live population), not O(capacity) — but it is still
O(n) under a single cross-worker mutex, and once the storm width exceeds the
configured capacity the table saturates, `high_water` pins to `capacity`, and
the full-length scan returns.

That residual is real but **small**, and the measurement discipline needed to
establish that is worth recording, because a first pass got it wrong.

### A retracted claim, and why

An initial sequential sweep at width 2048 (`brix_session_slots` 1024 vs 8192 vs
16, each a separate invocation minutes apart) appeared to show a dramatic
pathology at the default 1024 slots — ~400 jobs/s against ~700–730 for both the
much larger and the much smaller table, with a p99 of 4.6–5.0 s against ~2.6 s.
The reading was that a table "big enough for the scan to cost and small enough
to saturate" was the worst case.

That did not survive an interleaved retest. Cycling the three configs
round-robin *within* each repeat (so load drift lands on all three equally)
gave, over four repeats:

| `brix_session_slots` | jobs/s (median) | CPU ms/job (median) |
|---|---|---|
| 1024 | 874.0 | 0.844 |
| 8192 | 1009.9 | 0.748 |
| 16 | 777.6 | 0.778 |

The within-config sample spread was larger than the between-config difference
(the 1024 samples alone ran 525 → 961 jobs/s), and the host's load average
swung from 22 to 74 across the run under other sessions' builds. The CPU/job
spread — the load-independent metric — is only ~12%. **The "pathology" was load
noise; the claim is withdrawn.**

The lesson is the one already recorded in `host_load_excuse_debunked`: on this
host, wall-clock rates are only comparable when the configurations being
compared are interleaved. `storm_ab_bench.py` already does this for BriX vs
stock (`_run_rounds` alternates the two subjects *within* each round, with both
daemons up simultaneously), which is why the BriX-vs-official ratios below are
trustworthy while the BriX-vs-BriX sweep above was not.

### A second retraction: there was no metadata deficit — the client was the bottleneck

Paired measurement at width 2048 first appeared to show a real split:

| shape | BriX j/s | official j/s | ratio |
|---|---|---|---|
| every job a 1 MiB transfer | 949.9 | 732.7 | 1.30× BriX |
| metadata only | 652.1 | 853.1 | 0.76× official |

Two facts sat awkwardly against that "deficit": BriX was using ~1.6× *less* CPU
per job in the shape it supposedly lost, and a `perf` profile of the workers
during the storm showed them only ~26% busy, with the whole session-registry
family at 3.5% of samples and the profile dominated by kernel socket wakeups
(`try_to_wake_up`/`pollwake`). A server that is losing on throughput while
sitting 74% idle and spending less CPU per unit of work is not the constraint.

The constraint was the **measuring harness**. `_round` shards the storm over
`--client-procs` CPython processes, and a process running 2048/8 = 256 client
threads is deep into GIL thrash. Holding the offered work identical (same width,
same shape, same round-robin against both daemons) and varying only the client's
own process count:

| `--client-procs` | BriX j/s | official j/s | ratio | BriX p99 | official p99 |
|---|---|---|---|---|---|
| 8 | 640.4 | 748.1 | 0.86× official | 2956 ms | 2416 ms |
| 32 | 2485.9 – 2893.7 | 823 – 949 | **2.9 – 3.5× BriX** | 451 – 515 ms | 1985 – 2284 ms |
| 64 | 2864.6 – 3168.5 | 840 – 890 | **3.4 – 3.6× BriX** | 279 – 343 ms | 2147 – 2152 ms |

The diagnostic is the *asymmetry of the response*, not either column alone.
Widening the client 8→32 moved the official daemon by +27% and BriX by +333%.
A subject whose number moves when only the client changes was never being
measured; a subject whose number does not move is at its own ceiling. Stock sits
flat at ~820–950 jobs/s under every client width — that is the official daemon's
ceiling. BriX plateaus at ~2870–3170 across both 32 and 64 procs, which is the
point at which the plateau becomes BriX's own.

So on metadata at width 2048 BriX is **~3.4× ahead**, not 0.76× behind, with a
p99 roughly **6× lower** (≈300 ms against ≈2.1 s) and ~1.3–1.5× less CPU per
job. The 1.30× transfer figure in the first table is understated for the same
reason and needs re-reading at ≥32 client procs.

**Method rule, generalised:** before any BriX-vs-official ratio is quoted, the
harness must be shown not to be the limit — vary the client's own capacity and
confirm the subject's number *doesn't* move. Interleaving the two subjects
(§ above) removes load drift but is blind to this failure, because a client
ceiling throttles both subjects into the same funnel and makes the faster server
look merely equal. Both checks are required.

Round 14 therefore does **not** start from a metadata concurrency defect; there
is no evidence one exists. It starts from re-baselining every earlier round's
ratios through a harness proven to be out of the way — and the first thing that
re-baselining turned up is below.

### What the unmasked harness exposed: a large-read CPU regression

> **RETRACTED IN PART, 2026-09-03 — read this before acting on the section
> below.** The CPU half of this finding does not reproduce and its diagnosis was
> wrong. See "Retraction" at the end of this document. The section is kept
> unedited as the record of what was believed at the time.

Re-reading the transfer shape at 32 client procs did not confirm the 1.30×
lead — it inverted it, and the split is by **transfer size**, not by width.
Width 2048, `--transfer-every 1`, three repeats each:

| size | BriX j/s | official j/s | ratio | BriX CPU | official CPU |
|---|---|---|---|---|---|
| 64 KiB | 1589 – 3654 | 750 – 926 | **2.1 – 3.9× BriX** | 0.99 – 1.50 | 0.79 – 1.27 |
| 1 MiB | 253 – 288 | 459 – 488 | **0.53 – 0.59× official** | 2.21 – 2.31 | 1.67 – 1.89 |

The load-independent metric is the one to trust here, and it is strikingly
stable: across *every* 1 MiB measurement taken — widths 128, 512 and 2048, nine
samples spanning host loads from 26 to 148 — BriX's CPU-efficiency ratio against
the official daemon sits between **0.72 and 0.93**, i.e. BriX spends 8–27% *more*
CPU per 1 MiB job. The same harness at 64 KiB and on metadata puts BriX ~3×
ahead. The regression is therefore in the large-read path specifically, and it
is **not** a width-scaling effect — it is already present at width 128
(efficiency 0.93), where wall-clock is still at parity (0.95×).

Width then compounds it rather than causing it: the flat per-job CPU surplus
only converts into lost throughput once the box saturates, which is why the
wall-clock ratio decays from ~0.95× at width 128 and 512 to ~0.55× at 2048.

This is the correct target for round 14, and it deserves priority over any
further micro-optimization: it is a *scaling* regression in exactly the sense
the work was told to avoid introducing. The suspects are the rounds that tuned
the large-read path — round 10's hot-deferred scratch trim, round 11's windowed
pgread train, round 12's double-buffered windows — all of which were benched at
low width through the client-limited harness this document has just discredited,
and all of which add per-session buffering that 2048 concurrent sessions pay for.
Note that 1 MiB sits *below* round 11's >2 MiB train threshold, so round 12's
double-buffering is the more likely of the three. **Profile the 1 MiB path first
and let the profile name the culprit** — no code change is justified until a
quiet host (load < 10) is available to profile on, since a 20-core box at load
105 attributes other sessions' contention to whatever is being measured.

---

## Retraction — the "large-read CPU regression" (2026-09-03)

Re-measured on the current tree, on the **same shape** the claim was made from
(width 2048, 1 MiB, `--transfer-every 1`, `--client-procs 32`), 11 rounds,
interleaved against stock xrootd, at two registry sizings:

| registry slots | BriX j/s | official j/s | throughput ratio | BriX CPU ms/job | official CPU ms/job | CPU efficiency |
|---|---|---|---|---|---|---|
| 1024 (default) | 461.6 | 560.5 | 0.824× | 1.289 | 1.621 | **1.258× BriX cheaper** |
| 8192 | 418.0 | 513.1 | 0.815× | 1.309 | 1.689 | **1.291× BriX cheaper** |

**The CPU claim is refuted.** The section above states that BriX's CPU-efficiency
ratio "sits between 0.72 and 0.93 — i.e. BriX spends 8–27% *more* CPU per 1 MiB
job", and calls that the load-independent metric to trust. It now measures
**1.26–1.29×, i.e. BriX spends ~23% *less* CPU per 1 MiB job**, reproducibly and
in the opposite direction. There is no large-read CPU regression.

**The wall-clock deficit is real but much smaller than reported**: 0.815–0.824×,
not 0.53–0.59×. Registry sizing is not the cause — the two rows above bracket the
F4 reap being permanently armed (width 2048 into 1024 slots) and never armed
(8192 slots), and the ratio does not move.

**The diagnosis was therefore wrong, and so was the recommended next step.** BriX
uses ~23% *less* CPU per job while delivering ~18% *less* throughput. That
combination cannot be a cost regression in the large-read path; it is a
serialization limit — BriX is failing to convert a real CPU advantage into
throughput at width. Auditing rounds 10/11/12's large-read buffering, which this
document proposed as the priority for round 14, would have been aimed at
something that is not there.

The actual limiter was in the family that rounds 14 and 15 went on to attack:
per-disconnect O(live-population) scans under one cross-worker mutex, whose cost
rises with concurrency. Round 15 alone moved this workload's p99 spread from
1345 ms to 421 ms and its CPU efficiency from 1.571× to 1.778×
(`session-teardown-hyperopt-rounds-14-15.md`). Note also that the deficit is
specific to the 100%-transfer shape: on the mixed metadata+transfer shape the FTS
storm actually presents (`--transfer-every 4`), the same tree measures BriX
**1.742× ahead** with CPU efficiency 1.778×.

**Method note.** What survives from the section above is its own warning, applied
to itself: a ratio quoted from a small number of rounds on one host is not a
finding. The 0.53–0.59× figure came from three repeats; the 11-round replication
puts the same quantity at 0.82×, outside that range. Round-to-round spread on
this host is large enough that fewer than ~11 rounds cannot resolve effects of
this size — see the method rules in the rounds 14–15 document.
