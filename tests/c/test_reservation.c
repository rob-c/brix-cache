/*
 * test_reservation.c — hermetic unit for the XrdBwm-style bandwidth reservation
 * engine (src/net/ratelimit/reservation.c), wired in phase-92 to the root:// read
 * open path (brix_throttle_bandwidth_zone / _budget → open reserves file size,
 * brix_free_fhandle releases the exact bytes).
 *
 * The engine is pure C over libc (snprintf/strcmp) — no ngx runtime — so this
 * links reservation.o directly with no stubs. Three cases:
 *   (1) success + byte-precise release: a grant frees EXACTLY its bytes on done()
 *       so a sibling transfer can reuse the freed budget while others are still
 *       outstanding (the fix for the old aggregate-collapse first cut).
 *   (2) error / over-budget: an oversized or budget-full schedule() is refused
 *       (returns 0, mirroring the kXR_Overloaded open refusal), and the budget
 *       recovers after a done().
 *   (3) security-neg: the aggregate ceiling cannot be over-committed by many
 *       grants, and a bogus over-release cannot inflate/corrupt the budget
 *       (clamped, no underflow); NULL / unconfigured zones stay safe.
 */

#include <assert.h>
#include <stdio.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include "net/ratelimit/reservation.h"

/* Convenience accessors over the opaque zone via the public status snapshot. */
static uint64_t
in_use_of(brix_resv_zone_t *z)
{
    uint64_t queued = 0, in_use = 0;
    int granted = 0;
    brix_resv_status(z, &queued, &in_use, &granted);
    return in_use;
}

static int
granted_of(brix_resv_zone_t *z)
{
    uint64_t queued = 0, in_use = 0;
    int granted = 0;
    brix_resv_status(z, &queued, &in_use, &granted);
    return granted;
}

/* (1) success: grant within budget, byte-precise release frees exactly its bytes. */
static void
test_success_byte_precise_release(void)
{
    brix_resv_zone_t *z = brix_resv_zone_create(NULL, "bwm-ok", 1000);
    uint64_t h1, h2, h3;

    assert(z != NULL);
    /* create is idempotent: same name resolves to the same zone. */
    assert(brix_resv_zone_get("bwm-ok") == z);

    h1 = brix_resv_schedule(z, 400);
    h2 = brix_resv_schedule(z, 400);
    assert(h1 != 0 && h2 != 0);          /* 800 <= 1000 -> both granted        */
    assert(in_use_of(z) == 800);
    assert(granted_of(z) == 2);

    /* Over the ceiling while both are outstanding -> refused. */
    assert(brix_resv_schedule(z, 300) == 0);
    assert(in_use_of(z) == 800);         /* refusal must not consume budget     */

    /* Release h1's 400 exactly. The KEY byte-precise property: in_use drops to
     * 400 immediately (not held at 800 until the last grant drains), so a fresh
     * 400-byte transfer fits again while h2 is still outstanding. The old
     * aggregate-collapse code left in_use at 800 here and refused this. */
    brix_resv_done(z, 400);
    assert(in_use_of(z) == 400);
    assert(granted_of(z) == 1);

    h3 = brix_resv_schedule(z, 400);
    assert(h3 != 0);                     /* 400 + 400 <= 1000 -> reuse freed     */
    assert(in_use_of(z) == 800);
    assert(granted_of(z) == 2);

    /* Drain fully; the last release zeroes the aggregate. */
    brix_resv_done(z, 400);
    brix_resv_done(z, 400);
    assert(in_use_of(z) == 0);
    assert(granted_of(z) == 0);

    printf("PASS: success + byte-precise release\n");
}

/* (2) error: oversized / full schedule refused (0); budget recovers after done. */
static void
test_over_budget_refuse_and_recover(void)
{
    brix_resv_zone_t *z = brix_resv_zone_create(NULL, "bwm-err", 500);

    assert(z != NULL);

    /* A single request larger than the whole budget is refused outright. */
    assert(brix_resv_schedule(z, 600) == 0);
    assert(in_use_of(z) == 0);

    /* Exact fit grants; the zone is now full. */
    assert(brix_resv_schedule(z, 500) != 0);
    assert(in_use_of(z) == 500);
    assert(brix_resv_schedule(z, 1) == 0);   /* full -> refused                 */

    /* Releasing recovers the budget for a subsequent transfer. */
    brix_resv_done(z, 500);
    assert(in_use_of(z) == 0);
    assert(brix_resv_schedule(z, 500) != 0);
    brix_resv_done(z, 500);

    printf("PASS: over-budget refuse + recover\n");
}

/* (3) security-neg: aggregate ceiling cannot be over-committed; a bogus
 * over-release cannot inflate or corrupt the budget; NULL/unconfigured safe. */
static void
test_security_no_overcommit_no_inflation(void)
{
    brix_resv_zone_t *z = brix_resv_zone_create(NULL, "bwm-sec", 1000);
    int i;

    assert(z != NULL);

    /* Flood: ten 100-byte grants exactly fill 1000; the eleventh is refused.
     * An attacker opening many large files cannot exceed the aggregate. */
    for (i = 0; i < 10; i++) {
        assert(brix_resv_schedule(z, 100) != 0);
    }
    assert(in_use_of(z) == 1000);
    assert(brix_resv_schedule(z, 100) == 0);      /* ceiling holds             */

    /* Bogus over-release: a caller (or corruption) returning far more than one
     * grant reserved must be clamped, NOT wrap in_use below zero (which would
     * make the budget look infinite and defeat the limit). */
    brix_resv_done(z, (uint64_t) -1);             /* clamp to outstanding      */
    assert(in_use_of(z) <= 1000);                 /* never underflows/wraps    */

    /* Drain the rest with correctly-sized releases; aggregate returns to 0. */
    for (i = 0; i < 9; i++) {
        brix_resv_done(z, 100);
    }
    assert(in_use_of(z) == 0);
    assert(granted_of(z) == 0);

    /* Budget is intact (not inflated by the over-release): full budget grants,
     * one byte past it is still refused. */
    assert(brix_resv_schedule(z, 1000) != 0);
    assert(brix_resv_schedule(z, 1) == 0);
    brix_resv_done(z, 1000);

    /* Unconfigured zone (budget 0): always grants, done is a harmless no-op. */
    {
        brix_resv_zone_t *zu = brix_resv_zone_create(NULL, "bwm-unconf", 0);
        assert(zu != NULL);
        assert(brix_resv_schedule(zu, 1u << 30) != 0);   /* unconfigured grants */
        brix_resv_done(zu, 1u << 30);                     /* no-op, no crash     */
        assert(in_use_of(zu) == 0);
    }

    /* NULL zone: defensive — grant, no-op release, zeroed status. */
    assert(brix_resv_schedule(NULL, 123) != 0);
    brix_resv_done(NULL, 123);
    assert(in_use_of(NULL) == 0 && granted_of(NULL) == 0);

    printf("PASS: security-neg (no over-commit, no inflation)\n");
}

int
main(void)
{
    test_success_byte_precise_release();
    test_over_budget_refuse_and_recover();
    test_security_no_overcommit_no_inflation();
    printf("ALL PASS: reservation\n");
    return 0;
}
