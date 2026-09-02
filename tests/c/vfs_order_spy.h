/*
 * vfs_order_spy.h — phase-107 W0: the §3.4 ordering assertion, reusable.
 *
 * WHAT: A tiny event recorder plus relative-order asserts for the canonical
 *       VFS mutation sequence:
 *
 *         policy -> lock -> leaf -> capability -> credential -> backend
 *                -> invalidation
 *
 * WHY:  Phase-105 found four real defects by asserting exactly this order
 *       with per-site spy counters.  Phase-107's new verbs (recall, evict,
 *       delete_many, exchange, spill entry) get the assertion from their
 *       first commit rather than as a later audit — each new C unit's stubs
 *       call ord_hit() at the stage they represent, and the test body calls
 *       ord_assert_before() for every adjacent pair that applies.
 *
 * HOW:  Header-only statics, included by exactly one TU per unit binary (the
 *       test's own .c), same as the counter-spy idiom in
 *       test_vfs_read_only_spy.c.  Not linked into the server.
 *
 * Usage:
 *       ord_reset();
 *       ...exercise the mutator with stubs that call ord_hit(ORD_*)...
 *       ord_assert_before(ORD_POLICY, ORD_LEAF,  "unlink: gate before leaf");
 *       ord_assert_absent(ORD_BACKEND, "read-only: no backend reached");
 */

#ifndef VFS_ORDER_SPY_H
#define VFS_ORDER_SPY_H

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    ORD_POLICY = 1,     /* the phase-105 mutation-policy kernel            */
    ORD_LOCK,           /* brix_vfs_require_unlocked (C7)                  */
    ORD_LEAF,           /* leaf/namespace resolution                       */
    ORD_CAP,            /* capability probe (brix_sd_caps)                 */
    ORD_CRED,           /* credential selection/copy                       */
    ORD_BACKEND,        /* the driver slot itself                          */
    ORD_INVALIDATE,     /* cache invalidation after the mutation           */
    ORD_STAGE_MAX
} ord_stage_t;

#define ORD_SEQ_MAX 128

static int ord_seq[ORD_SEQ_MAX];
static int ord_n;

static const char *const ord_names[ORD_STAGE_MAX] = {
    "?", "policy", "lock", "leaf", "capability", "credential", "backend",
    "invalidation",
};

static void
ord_reset(void)
{
    memset(ord_seq, 0, sizeof(ord_seq));
    ord_n = 0;
}

static void
ord_hit(ord_stage_t stage)
{
    assert(ord_n < ORD_SEQ_MAX);
    ord_seq[ord_n++] = (int) stage;
}

/* First occurrence of `stage`, or -1 when it never fired. */
static int
ord_index(ord_stage_t stage)
{
    int i;

    for (i = 0; i < ord_n; i++) {
        if (ord_seq[i] == (int) stage) {
            return i;
        }
    }
    return -1;
}

/* Both fired, and the first `a` strictly precedes the first `b`. */
static void
ord_assert_before(ord_stage_t a, ord_stage_t b, const char *what)
{
    int ia = ord_index(a);
    int ib = ord_index(b);

    if (ia < 0 || ib < 0 || ia >= ib) {
        fprintf(stderr,
                "ORDERING FAIL (%s): %s@%d must precede %s@%d\n",
                what, ord_names[a], ia, ord_names[b], ib);
        assert(0);
    }
}

/* `stage` never fired — the refused-mutation shape. */
static void
ord_assert_absent(ord_stage_t stage, const char *what)
{
    int i = ord_index(stage);

    if (i >= 0) {
        fprintf(stderr, "ORDERING FAIL (%s): %s fired at %d on a path that "
                "must not reach it\n", what, ord_names[stage], i);
        assert(0);
    }
}

/* `stage` fired exactly `want` times — the one-gate-per-batch rule (C4). */
static void
ord_assert_count(ord_stage_t stage, int want, const char *what)
{
    int i, got = 0;

    for (i = 0; i < ord_n; i++) {
        if (ord_seq[i] == (int) stage) {
            got++;
        }
    }
    if (got != want) {
        fprintf(stderr, "ORDERING FAIL (%s): %s fired %d times, want %d\n",
                what, ord_names[stage], got, want);
        assert(0);
    }
}

#endif /* VFS_ORDER_SPY_H */
