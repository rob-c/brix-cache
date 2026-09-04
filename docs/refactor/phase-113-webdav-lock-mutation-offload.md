# Phase 113 — Mutation-safe WebDAV LOCK metadata offload

**Status:** CLOSED / TRIGGER NOT OBSERVED (Phase-111 decision, 2026-09-03)
**Depends on:** Phase 109 and the Phase-107/108 VFS mutation model
**Trigger:** measurable LOCK-driven event-loop stalls on a remote backend or
cold credential exchange

## Problem

Phase 109 moved remote/EXCHANGE PROPFIND and SEARCH walks to the nginx thread
pool but correctly excluded LOCK. LOCK's descendant conflict walk is not
read-only: it can remove expired lock-null resources and then update the lock
table. Moving only the blocking read would split one decision across the event
loop and a worker, creating a time-of-check/time-of-use window and risking a
worker-thread mutation of nginx-owned state.

No repository workload or operator report demonstrates a LOCK-driven event-loop
stall. The current walk is entry-bounded and its backend calls are time-bounded;
keeping expired lock-null cleanup and lock-table mutation on the event-loop side
preserves ordering without a new generation/restart protocol. Consequently no
offload code is warranted in the current product. If the trigger is measured,
reopen this design as a new phase and satisfy every boundary below together.

## Conditional design boundary

- Separate the descendant scan into an immutable, worker-safe observation
  result. It may contain paths, lock generations and expiry verdicts, but no
  nginx pool pointers or borrowed mutable entries.
- Return to the event loop before changing the lock table or removing an
  expired lock-null resource.
- Revalidate every generation/precondition immediately before mutation. A
  changed entry restarts or refuses; it never applies a stale worker verdict.
- Route resource removal through the typed VFS mutation policy and lock gate
  in their established order. A read-only export still returns `EROFS` before an
  authorization or lock conflict.
- Carry identity and backend credentials by the same immutable snapshot
  discipline Phase 109 uses for PROPFIND/SEARCH.
- Bound scan entries, result memory and restart count; exhaustion produces a
  stable HTTP error and leaves state unchanged.
- Preserve LOCK atomicity from the caller's perspective: no success response
  before both storage cleanup and lock-table mutation have completed.

## Verification

- success: remote LOCK with an expired descendant completes without blocking a
  second request on the event loop;
- error: backend timeout/cancel leaves both lock table and lock-null resource in
  a consistent, retryable state;
- security negative: a changed generation, read-only export or lost identity
  refuses before mutation;
- race: concurrent refresh/unlock between worker scan and completion is detected
  and cannot delete the newer state;
- teardown: client disconnect and worker cancellation cannot use request-pool
  memory after free;
- regression: Phase-109 PROPFIND/SEARCH offload tests and cross-protocol lock
  tests remain green.

## Boundary closure (as built)

No offload ships, so there is nothing to test in the conditional design. What is
pinned instead is the *supported* boundary the deferral rests on — the facts that
keep the bounded inline LOCK path safe and keep the deferral from silently
becoming the TOCTOU bug it declined. `tests/test_phase113_lock_offload_boundary.py`
(8 cases):

- **LOCK is not offloaded** — no `webdav_lock_offload` symbol exists anywhere in
  the module (the two adopted front doors, `webdav_propfind_offload` /
  `webdav_search_offload`, are asserted present so the absence is meaningful),
  and no LOCK-path file (`lock.c`, `lock_check.c`, `lock_discovery.c`) dispatches
  through any offload seam. The complementary structural guard — that the seam is
  absent *while the walk still reaps inline* — is `test_metadata_offload_guard.py`.
- **read-only export refuses before it mutates** — `webdav_lock_expired_cleanup`
  consults the typed VFS mutation policy first and returns on anything but
  `ALLOWED`, before the lock-xattr delete or the lock-null reap (phase-105
  Appendix H.2; the "returns EROFS before an authorization or lock conflict"
  boundary bullet).
- **the lock-null reap cannot be redirected** — it unlinks only a lock-null
  record's reserved name, only after a no-follow probe confirms a regular
  zero-length file, and only through `brix_vfs_unlink` (never a bare syscall).
- **the descendant conflict walk is entry-bounded because it is cycle-safe** —
  it opens confined-quiet and recurses only on a kind established from `d_type`
  or a no-follow probe, never a follow-stat, so it cannot descend through a
  symlink and cycle. That is the "current walk is entry-bounded and time-bounded"
  premise the deferral names.

The `walk_offload.h` header comment that had listed LOCK among the "planned W2
adopters" was corrected here: LOCK is a deliberate non-adopter, and reopening its
offload must satisfy this whole boundary together, not merely move the blocking
read.

## Non-goals

Do not rewrite the synchronous backend transport and do not move lock-table
ownership to worker threads. If the trigger is not observed in real deployments,
the bounded inline LOCK path remains an accepted limitation rather than an
automatic implementation commitment.
