/* ---- File: src/core/negcache/negcache_core.c — negative-path backoff core ----
 *
 * Pure sliding-window + interval-pacing arithmetic; see negcache_core.h for the
 * contract and the E-4 rationale. One direct-mapped slot per principal
 * (hash % nslots) with victim replacement on collision. Each call opens a fresh
 * window when the slot is empty, owned by a different principal, or the previous
 * window has fully elapsed — then charges one miss. Below the threshold every
 * miss is served. At/above it the slot is armed: the first miss of each backoff
 * interval is served and each earlier miss in that interval is throttled, so the
 * stock client's wait-and-retry always lands a served miss one interval later.
 */

#include "core/negcache/negcache_core.h"

#include <stddef.h>

unsigned
brix_negcache_core_note(brix_negcache_slot_t *slots, unsigned nslots,
    uint32_t key_hash, uint64_t now_ms, const brix_negcache_params_t *p)
{
    brix_negcache_slot_t *s;
    unsigned              idx;
    uint64_t              backoff_ms;

    if (slots == NULL || nslots == 0 || p == NULL
        || p->threshold == 0 || p->window_ms == 0)
    {
        return 0;                 /* misconfigured → fail open (allow) */
    }

    if (key_hash == 0) {
        key_hash = 1;             /* 0 is the empty-slot sentinel */
    }

    idx = key_hash % nslots;
    s = &slots[idx];

    /*
     * Start a fresh window when: the slot is empty / owned by another principal
     * (claim by victim replacement), the clock ran backwards (monotonic-source
     * wrap or reload), or the prior window has fully elapsed. Each case zeroes
     * the count and the pacing anchor and re-anchors the window at now_ms.
     */
    if (s->key != key_hash
        || now_ms < s->window_ms
        || now_ms - s->window_ms >= (uint64_t) p->window_ms)
    {
        s->key = key_hash;
        s->window_ms = now_ms;
        s->misses = 0;
        s->served_ms = 0;
    }

    if (s->misses < UINT32_MAX) {
        s->misses++;
    }

    if (s->misses < p->threshold) {
        return 0;                 /* not yet armed → serve */
    }

    /*
     * Armed. Serve the first miss of each backoff interval (and recover from a
     * backwards clock), throttle the rest. served_ms == 0 means "none served in
     * this window yet", so the arming miss itself is always let through.
     */
    backoff_ms = (uint64_t) p->backoff_s * 1000u;
    if (s->served_ms == 0
        || now_ms < s->served_ms
        || now_ms - s->served_ms >= backoff_ms)
    {
        s->served_ms = now_ms;
        return 0;
    }

    return p->backoff_s;
}
