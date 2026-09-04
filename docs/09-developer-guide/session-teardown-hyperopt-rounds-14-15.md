# Session-teardown hyper-optimization — rounds 14 and 15 (publish-time slot hints)

*2026-09-03. Follows round 13 (`session-registry-hyperopt-round-13-live-prefix.md`),
which introduced the `high_water` live prefix these rounds build on.*

## The target: a teardown family whose cost grows with concurrency

Profiling the ultra-parallel storm shape (width 2048, 1 MiB transfers, 32 client
processes) named a family that together accounted for ~9.4% of BriX worker CPU,
every member of it an O(N) scan serializing on one cross-worker mutex:

| symbol | self |
|---|---|
| `ngx_shmtx_lock` | 3.58% |
| `brix_session_unregister` | 1.79% |
| `brix_session_scan` | 1.56% |
| `brix_session_handle_unpublish_all` | 1.25% |
| `brix_transfer_slot_free_all_for_session` | 1.25% |

The shape of the defect matters more than the percentage. Each of these scans a
shared table bounded by the *live* population, under a global lock, once per
disconnect — so the cost of tearing a session down is highest exactly when every
session is tearing down at once. That is the "does a less than excellent job of
backing off" behaviour an FTS storm provokes: the server's per-unit overhead
rises with load instead of flattening.

Rounds 14 and 15 apply the same fix to the two largest members: **record the slot
at publish time, clear that slot at teardown, and keep the scan only as the
`hint < 0` fallback.**

## Why a slot hint is sound

Both tables clear entries **in place and never relocate** them. That is what
makes a publish-time slot index authoritative rather than advisory: an entry is
either still at the recorded index or it is gone, and a 16-byte sessid re-check
under the lock distinguishes the two. Neither round widens a lock, changes an SHM
ABI, or adds a global.

The hint is also **stricter than the scan it replaces**, which is the security
argument and not merely a performance one. If the F4 global-LRU reap or the W5
per-source self-eviction recycled a session's slot and the same sessid was later
re-registered by a *different* connection, the old scan would find that live
re-registration by sessid and destroy it — one connection's teardown evicting
another's session, a confused deputy. The hint refuses to touch a slot it does
not own, so that path closes. `tests/c/test_session_unregister_hint.c` pins
exactly this divergence.

Revocation stays unconditional: a hint that matches nothing still runs
`brix_session_handle_unpublish_all()`, so no bound secondary can outlive its
primary's teardown even when the registry entry is already gone.

## Round 14 — the shared handle table

`brix_session_handle_publish()` records `file->shared_handle_slot_hint`;
`brix_session_handle_unpublish_hinted()` clears at that index.
`brix_session_handle_unpublish()` becomes a `hint = -1` delegate.

A teardown-ordering detail found while doing it: `brix_session_unregister()`
(disconnect.c:322) runs *before* `brix_close_all_files()` (disconnect.c:405), so
`unpublish_all` has already cleared everything by the time the per-file
`unpublish` calls run — every one of them was a **guaranteed-failing full scan of
4096 × 4.2 KB slots under the global mutex**. Round 14 removes that work outright.

**Measured: ~2%, inside noise.** Paired A/B (a baseline binary with the hint
forced to `-1` against the round-14 binary, each interleaved against stock
xrootd): baseline 1.367 ms/job, round 14 1.338 ms/job. The profile explains it —
round 14 removed the *smaller* half. The per-file `unpublish` no longer appears
in the profile at all; the larger `unpublish_all` half remains.

Round 14 is kept because it deletes provably-dead work and closes the same
confused-deputy hole round 15 does, not because it moved a number.

## Round 15 — the session registry

`brix_session_register()` now returns the slot it occupies (its own on a
re-register, the newly filled one otherwise, `-1` on rejection). The connection
keeps it in `ctx->login.session_slot_hint`, and the disconnect calls
`brix_session_unregister_hinted()`.

Touched: `ctx_structs.h`, `connection/handler.c` (the sentinel must be set
explicitly — a `pcalloc` zero would read as "registered in slot 0"),
`registry_slots_internal.h` + `registry_slots.c` (the scan reports `match_slot`),
`registry.c`, `registry.h`, `connection/disconnect.c`, and the eight register
call sites in `auth/{krb5,host,gsi,unix,sss,pwd}` and `session/login.c`.

### Result

Paired binaries, identical compiler flags, one edit apart, each run interleaved
against stock xrootd; **11 rounds each**, width 2048, 1 MiB, 32 client processes,
8192 session slots. Ratios are computed **per round against stock**, which
cancels host drift:

| metric (median of 11, vs stock) | baseline | round 15 | change | p |
|---|---|---|---|---|
| CPU efficiency (load-independent) | 1.571× | **1.778×** | +13.2% | 0.0014 |
| throughput ratio | 1.334× | **1.726×** | +29.4% | 0.0050 |
| BriX p99 | 1339 ms | **1117 ms** | −16.6% | 0.0014 |
| **p99 spread across rounds** | **1345 ms** | **421 ms** | **−69%** | — |

(Permutation test on round medians, 200k resamples. Stock was a stable control
across the two runs: 838.0 vs 860.7 jobs/s.)

The last row is the real headline and the one that answers the original
complaint. Round 15 did not merely make teardown faster — it made the tail
*bounded*. The lock hold that grew with the live population was the tail
generator; removing it collapsed the p99 spread by more than a factor of three,
and round 15's **worst** round (1254 ms) is better than the baseline's **median**
(1339 ms).

Profile confirmation, which is load-independent and unambiguous:
`brix_session_unregister_hinted` **leaves the profile entirely** (2.56% self →
below the 0.2% cutoff) and `ngx_shmtx_lock` falls 1.14% → 0.45%, a 60% drop in
contention on the global session mutex. `brix_session_scan`'s share *rises*
(1.52% → 2.34%) — that is the untouched **register-side** free-slot scan, whose
share grows only because the denominator shrank. It is the next target.

## Method rule established by these rounds

Round 13 established that an interleaved A/B removes host-load drift but is blind
to a client ceiling, so a subject's number must be shown not to move as
`--client-procs` varies. Rounds 14 and 15 add a second rule:

> **An interleaved A/B against stock is not a substitute for a paired A/B of your
> own change.** Build two binaries — change on, change off — from the same tree
> with the same flags, run both, and compare per-round ratios. Otherwise a delta
> cannot be attributed to the edit.

And a third, learned from round 15 nearly being discarded:

> **Measure on the shape that pays the cost.** The first round-15 A/B used a
> metadata-only workload and returned 1.3% — indistinguishable from round 14's
> nothing. The same change on the transfer shape, which actually churns sessions
> at width, returned +29% throughput at p=0.005. A null result on the wrong shape
> is not a null result.

Five rounds is also not enough to resolve a ~15% effect against this host's
round-to-round spread; eleven is. The 5-round pair had overlapping ranges and
would have been reported as "directionally positive, not resolvable".

## Build-environment note

`/tmp/nginx-1.28.3` is shared with concurrent sessions and was reconfigured for a
gcov coverage build mid-measurement, which changed `CFLAGS` and broke the tree
under `-Werror`. Both A/B binaries were therefore built in a **private tree**
(`scratchpad/ngx-ab`) so the two differ by exactly one edit and nothing else. Any
future paired measurement should do the same rather than race the shared tree.

## Next

1. **`brix_session_scan`, register side** (now 2.34%) — the free-slot scan. A
   free-slot cursor is the obvious analogue, but unlike the teardown hints it is
   not self-validating: a stale cursor must never hand out an occupied slot, so
   it needs the same in-lock re-check plus a fallback scan when the cursor lands
   on a live entry.
2. **`brix_transfer_slot_free_all_for_session`** (1.23%) — same shape, same fix.
3. **`brix_session_handle_unpublish_all`** (1.67%) — cannot use a single slot
   hint (a session owns many handles). Needs either a per-session handle list or
   a compact parallel key array so the sweep is cache-efficient; the latter is an
   SHM ABI change and requires a clean rebuild across the fleet.

## Tests

- `tests/c/test_handle_unpublish_hint.c` — round 14, registered in
  `tests/cmdscripts/c_object_units.py` as `handle_unpublish_hint`.
- `tests/c/test_session_unregister_hint.c` — round 15, registered as
  `session_unregister_hint`; 32 assertions. It links the **real** `registry.o`
  and `registry_slots.o` rather than modelling them locally (as the older
  `session_registry_high_water` unit does), so `brix_session_unregister_hinted()`
  itself is under test. Success / error / security-negative batteries as above.

Both pass; the full `tests/test_c_object_units.py` sweep is 23 passed, 1 skipped,
with the single red (`vfs_service_domain`) being a concurrent session's in-flight
`vfs_policy_domain.c` edit, unrelated to these rounds.
