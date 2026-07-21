# Negative-Path Backoff (negcache)

E-4 DoS resilience: a per-principal sliding-window counter of *missing-path*
lookups (kXR_stat / kXR_locate that resolve to kXR_NotFound). When one
principal's miss rate crosses the configured threshold inside the window the
slot arms, and every further miss inside a backoff interval is answered with a
kXR_wait instead of the NotFound. Because the stock XRootD client answers
kXR_wait by sleeping and re-sending the *same* request, each lookup still
completes (on its retry, one interval later) while a path-enumeration /
stat-harvest loop is throttled to roughly one path per backoff interval.
Legitimate clients rarely miss, never arm, and are untouched.

File split (same ngx-free-core convention as wverify / opaque / seccomp):

- `negcache_core.h` / `negcache_core.c` — the pure, nginx-free arithmetic:
  one direct-mapped slot per principal (hash % nslots, victim replacement on
  collision), fresh-window/arming/interval-pacing logic in
  `brix_negcache_core_note()`. Linked directly by `tests/c/test_negcache.c`.
- `negcache.h` / `negcache.c` — the ngx side: the `brix_negcache_backoff`
  directive setter, the cross-worker SHM zone (8192 slots, allocated via
  `brix_shm_table_alloc` per INVARIANT 10), and `brix_negcache_note_miss()`,
  which derives the principal hash and calls the core under the zone mutex.

The principal is chosen most-specific first: authenticated token subject, else
GSI subject DN, else client IP (so an unauthenticated harvester is always
bucketed). Each class is FNV-1a hashed under a distinct dimension tag so the
three classes occupy disjoint hash sub-spaces.

Gotchas: this is a throttle, never a correctness oracle — a hash collision
merely resets the loser's counter, weakening the throttle slightly but never
mis-throttling a bystander. Everything fails open: an unattached SHM zone,
NULL slot array, or misconfigured params returns 0 and the NotFound goes
through. `key == 0` is the empty-slot sentinel (hash 0 is remapped to 1). The
caller must serialise concurrent calls on the slot array — the SHM wrapper
holds the zone mutex around the core call.
