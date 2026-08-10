/*
 * test_offload_registry.c — unit tests for the per-worker (sessid,pathid)->conn
 * offload map (src/protocols/root/session/offload_registry.c), audit §1.1 slice 1.
 *
 * Links the real offload_registry.o, which is pure C (only memcpy/memcmp) — no
 * nginx, no stubs. The connection is an opaque void*, so plain fake pointers
 * stand in for real ngx_connection_t here.
 *
 * Build/run via cmdscripts/c_object_units.py (SPECS["offload_registry"]),
 * surfaced by tests/test_offload_registry.py.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "offload_registry.h"

static int g_pass, g_fail;
#define CHECK(cond, msg) do {                                               \
        if (cond) { g_pass++; }                                             \
        else { g_fail++; fprintf(stderr, "FAIL: %s (%s:%d)\n",              \
                                  msg, __FILE__, __LINE__); }               \
    } while (0)

/* distinct non-NULL fake connection pointers */
#define CONN(n) ((void *) (uintptr_t) (n))

static void
mksess(unsigned char out[BRIX_SESSION_ID_LEN], unsigned a, unsigned b)
{
    memset(out, 0, BRIX_SESSION_ID_LEN);
    out[0] = (unsigned char) a;
    out[1] = (unsigned char) b;
}

int
main(void)
{
    unsigned char sA[BRIX_SESSION_ID_LEN], sB[BRIX_SESSION_ID_LEN];
    size_t        i;

    mksess(sA, 0xAA, 0x01);
    mksess(sB, 0xBB, 0x02);

    CHECK(brix_offload_count() == 0, "fresh table is empty");

    /* ---- register + lookup ---- */
    CHECK(brix_offload_register(sA, 1, CONN(101)) == 1, "register A/1");
    CHECK(brix_offload_register(sA, 2, CONN(102)) == 1, "register A/2");
    CHECK(brix_offload_register(sB, 1, CONN(201)) == 1, "register B/1 (same pathid, diff sess)");
    CHECK(brix_offload_count() == 3, "three live entries");

    CHECK(brix_offload_lookup(sA, 1) == CONN(101), "lookup A/1");
    CHECK(brix_offload_lookup(sA, 2) == CONN(102), "lookup A/2");
    CHECK(brix_offload_lookup(sB, 1) == CONN(201), "lookup B/1 (keyed by sessid too)");

    /* ---- misses ---- */
    CHECK(brix_offload_lookup(sA, 3) == NULL, "miss: unbound pathid");
    CHECK(brix_offload_lookup(sB, 2) == NULL, "miss: unbound pathid on other sess");
    CHECK(brix_offload_lookup(sA, 0) == NULL, "pathid 0 is the primary, never offloaded");

    /* ---- re-register replaces in place, no leak of a slot ---- */
    CHECK(brix_offload_register(sA, 1, CONN(999)) == 1, "re-register A/1");
    CHECK(brix_offload_lookup(sA, 1) == CONN(999), "A/1 now points at the new conn");
    CHECK(brix_offload_count() == 3, "re-register did not grow the table");

    /* ---- unregister by connection pointer ---- */
    brix_offload_unregister(CONN(999));
    CHECK(brix_offload_lookup(sA, 1) == NULL, "A/1 gone after unregister");
    CHECK(brix_offload_count() == 2, "count dropped by one");
    brix_offload_unregister(CONN(102));
    brix_offload_unregister(CONN(201));
    CHECK(brix_offload_count() == 0, "all unregistered");
    CHECK(brix_offload_lookup(sA, 2) == NULL && brix_offload_lookup(sB, 1) == NULL,
          "lookups miss after full teardown");

    /* ---- edge/guard: NULL args are refused, never crash ---- */
    CHECK(brix_offload_register(NULL, 1, CONN(1)) == 0, "NULL sessid refused");
    CHECK(brix_offload_register(sA, 1, NULL) == 0, "NULL conn refused");
    CHECK(brix_offload_lookup(NULL, 1) == NULL, "NULL sessid lookup is a miss");
    brix_offload_unregister(NULL);   /* no-op, must not crash */
    CHECK(brix_offload_count() == 0, "guards did not mutate the table");

    /* ---- capacity: the table is bounded; overflow is refused, not corrupt ---- */
    for (i = 0; i < BRIX_OFFLOAD_MAX; i++) {
        unsigned char s[BRIX_SESSION_ID_LEN];
        mksess(s, (unsigned) (i >> 8), (unsigned) (i & 0xff));
        CHECK(brix_offload_register(s, 1, CONN(i + 1)) == 1, "fill to capacity");
    }
    CHECK(brix_offload_count() == BRIX_OFFLOAD_MAX, "table is full");
    {
        unsigned char over[BRIX_SESSION_ID_LEN];
        mksess(over, 0xFE, 0xFE);
        CHECK(brix_offload_register(over, 9, CONN(0xDEAD)) == 0,
              "register past capacity is refused (0), not silently dropped");
        CHECK(brix_offload_lookup(over, 9) == NULL, "the refused entry is not present");
    }
    /* a full table still serves its live entries correctly */
    {
        unsigned char s0[BRIX_SESSION_ID_LEN];
        mksess(s0, 0, 0);
        CHECK(brix_offload_lookup(s0, 1) == CONN(1), "capacity fill entries look up");
    }

    printf("test_offload_registry: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
