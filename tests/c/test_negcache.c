/*
 * test_negcache.c — standalone unit test for the E-4 negative-path backoff core
 * (src/core/negcache/negcache_core.c). Drives the SHIPPED sliding-window +
 * interval-pacing logic directly over a caller-owned slot array (no ngx, no SHM):
 *
 *   success  — a per-principal miss burst arms the slot, after which rapid
 *              further misses are throttled to one served miss per backoff
 *              interval (the stat-harvest loop is paced), and each throttled
 *              request is served once its interval elapses (never wedged);
 *   decay    — once the window elapses the counter resets and misses are served
 *              again (the throttle is transient, not a permanent ban);
 *   security — a second principal in a different slot is unaffected while the
 *              first is flooded (per-principal isolation — one abuser cannot
 *              starve everyone), and a misconfigured/empty table fails OPEN.
 *
 * ngx-free: links libc only, mirroring the core it exercises.
 */
#include "core/negcache/negcache_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define NSLOTS  16u

/* Arms on the 5th miss within a 10 s window; 7 s pacing interval once armed. */
static const brix_negcache_params_t P = {
    .threshold = 5,
    .window_ms = 10000,
    .backoff_s = 7,
};

/* Two principals whose hashes land in DIFFERENT slots of a 16-slot table:
 * 0x10 % 16 == 0, 0x21 % 16 == 1. */
#define KEY_A  0x00000010u
#define KEY_B  0x00000021u


/* success: the arming burst is served, then rapid misses in the same interval
 * are throttled, and a request retried a full interval later is served again —
 * so the harvester is paced without any lookup ever hanging. */
static void
test_burst_paces_then_releases(void)
{
    brix_negcache_slot_t slots[NSLOTS];
    unsigned             i, w;

    memset(slots, 0, sizeof(slots));

    /* Misses 1..5 (up to and including the arming miss) are all served. */
    for (i = 1; i <= 5; i++) {
        w = brix_negcache_core_note(slots, NSLOTS, KEY_A, 100, &P);
        assert(w == 0);
    }

    /* Further rapid misses in the same interval are throttled. */
    w = brix_negcache_core_note(slots, NSLOTS, KEY_A, 200, &P);
    assert(w == P.backoff_s);
    w = brix_negcache_core_note(slots, NSLOTS, KEY_A, 300, &P);
    assert(w == P.backoff_s);

    /* The client sleeps backoff_s and retries: one interval later the miss is
     * served again (the request completes), then the next rapid miss re-throttles. */
    w = brix_negcache_core_note(slots, NSLOTS, KEY_A, 100 + 7000, &P);
    assert(w == 0);
    w = brix_negcache_core_note(slots, NSLOTS, KEY_A, 100 + 7000, &P);
    assert(w == P.backoff_s);
    printf("ok burst_paces_then_releases\n");
}


/* decay: after the window fully elapses the slot resets and misses are served
 * again from scratch — the throttle is transient. */
static void
test_window_decay_resets(void)
{
    brix_negcache_slot_t slots[NSLOTS];
    unsigned             i, w;

    memset(slots, 0, sizeof(slots));

    for (i = 0; i < 6; i++) {           /* arm + throttle */
        (void) brix_negcache_core_note(slots, NSLOTS, KEY_A, 100, &P);
    }
    assert(brix_negcache_core_note(slots, NSLOTS, KEY_A, 200, &P) == P.backoff_s);

    /* now_ms advances past window_start + window_ms → fresh window, count 1,
     * served immediately. */
    w = brix_negcache_core_note(slots, NSLOTS, KEY_A, 100 + 10000, &P);
    assert(w == 0);
    printf("ok window_decay_resets\n");
}


/* security: flooding principal A must not throttle principal B (distinct slot),
 * and a misconfigured / empty table must fail OPEN (never throttle). */
static void
test_principal_isolation_and_failopen(void)
{
    brix_negcache_slot_t slots[NSLOTS];
    unsigned             i, w;
    brix_negcache_params_t bad = P;

    memset(slots, 0, sizeof(slots));

    for (i = 0; i < 50; i++) {          /* hammer A well past the threshold */
        (void) brix_negcache_core_note(slots, NSLOTS, KEY_A, 100, &P);
    }
    assert(brix_negcache_core_note(slots, NSLOTS, KEY_A, 100, &P) == P.backoff_s);

    /* B is a different principal in a different slot → served, not throttled */
    w = brix_negcache_core_note(slots, NSLOTS, KEY_B, 100, &P);
    assert(w == 0);

    /* fail-open guards: NULL table, zero slots, zero threshold, zero window */
    assert(brix_negcache_core_note(NULL, NSLOTS, KEY_A, 100, &P) == 0);
    assert(brix_negcache_core_note(slots, 0, KEY_A, 100, &P) == 0);
    bad.threshold = 0;
    assert(brix_negcache_core_note(slots, NSLOTS, KEY_A, 100, &bad) == 0);
    bad = P;
    bad.window_ms = 0;
    assert(brix_negcache_core_note(slots, NSLOTS, KEY_A, 100, &bad) == 0);
    printf("ok principal_isolation_and_failopen\n");
}


/* a principal hashing to 0 is remapped to a real slot (not silently dropped):
 * it arms and throttles like any other. */
static void
test_zero_key_is_bucketed(void)
{
    brix_negcache_slot_t slots[NSLOTS];
    unsigned             i;

    memset(slots, 0, sizeof(slots));

    for (i = 0; i < 5; i++) {           /* arming misses all served */
        assert(brix_negcache_core_note(slots, NSLOTS, 0, 100, &P) == 0);
    }
    /* a rapid post-arm miss is throttled → proves key 0 lands in a live slot */
    assert(brix_negcache_core_note(slots, NSLOTS, 0, 200, &P) == P.backoff_s);
    printf("ok zero_key_is_bucketed\n");
}


int
main(void)
{
    test_burst_paces_then_releases();
    test_window_decay_resets();
    test_principal_isolation_and_failopen();
    test_zero_key_is_bucketed();
    printf("PASS test_negcache\n");
    return 0;
}
