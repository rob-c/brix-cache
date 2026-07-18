/* ---- File: src/core/negcache/negcache_core.h — negative-path backoff core ----
 *
 * The nginx-free heart of the E-4 DoS-resilience "negative cache": a per-
 * principal sliding-window counter of *missing-path* lookups (kXR_stat /
 * kXR_locate that resolve to kXR_NotFound). When one principal's miss rate
 * crosses a threshold inside the window the slot ARMS, and note() then paces the
 * principal to at most one served miss per backoff interval — every excess miss
 * gets a kXR_wait. Because the stock XRootD client answers kXR_wait by sleeping
 * and re-sending the *same* request, this guarantees each lookup still completes
 * (on its retry, one interval later) while a path-enumeration / stat-harvest
 * loop is throttled to ~one path per backoff interval. Legitimate clients — who
 * rarely miss and so never arm — are untouched.
 *
 * No ngx_* dependency, so tests/c/test_negcache.c links this file directly and
 * drives the trip / decay / per-principal-isolation behaviour under plain C.
 * The ngx wrapper (negcache.c) owns the SHM slot array + mutex and derives the
 * principal hash; this file is pure arithmetic over a caller-owned slot array.
 */
#ifndef BRIX_NEGCACHE_CORE_H
#define BRIX_NEGCACHE_CORE_H

#include <stdint.h>

/*
 * One direct-mapped slot: a principal's recent miss count within a window.
 * key == 0 marks an empty slot (a principal whose hash is 0 is remapped to 1 by
 * the core), so the SHM table needs no separate in-use flag. A hash collision
 * between two principals reuses the slot by victim-replacement — this is a
 * throttle, never a correctness oracle, so a collision merely resets the loser's
 * counter (weakening the throttle slightly, never mis-throttling a bystander).
 */
typedef struct {
    uint32_t key;         /* principal hash (0 = empty)                       */
    uint32_t misses;      /* misses accumulated in the current window         */
    uint64_t window_ms;   /* start of the current window (ms, monotonic)      */
    uint64_t served_ms;   /* last armed miss let through (0 = none this window)*/
} brix_negcache_slot_t;

/* Per-call tunables (carried from the server's brix_negcache_backoff rule). */
typedef struct {
    unsigned threshold;   /* misses within a window that ARM the throttle(>=1)*/
    unsigned window_ms;   /* sliding-window length in ms (>= 1)               */
    unsigned backoff_s;   /* kXR_wait seconds + min gap between served misses */
} brix_negcache_params_t;

/*
 * Record one missing-path lookup for `key_hash` at `now_ms` and return the
 * kXR_wait seconds to impose (0 = let the NotFound through). Once the slot is
 * armed (>= threshold misses in the window), the first miss of each backoff
 * interval is served (returns 0) and every earlier miss in that interval is
 * throttled (returns backoff_s) — so a flood is paced without ever wedging a
 * request. Fail-open: returns 0 on a NULL/empty slot array or a misconfigured
 * params block. The caller must serialise concurrent calls on the same slot
 * array (the SHM wrapper holds the zone mutex around this call).
 */
unsigned brix_negcache_core_note(brix_negcache_slot_t *slots, unsigned nslots,
    uint32_t key_hash, uint64_t now_ms, const brix_negcache_params_t *p);

#endif /* BRIX_NEGCACHE_CORE_H */
