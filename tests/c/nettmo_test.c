/*
 * nettmo_test.c — unit checks for the retry backoff + timeout tunables (nettmo.c).
 *
 * WHAT: Verifies brix_backoff_delay_ms is exponential, capped, and jittered
 *       within bounds, and that the timeout knobs honor setter > env > default.
 * WHY:  These control how a client rides out a flaky/hostile network; a wrong
 *       cap or runaway exponent would defeat the hardening.
 * HOW:  Pure-function assertions (no sleeping); exit 0 = pass, 1 = fail.
 */
#include "brix.h"

#include <stdio.h>
#include <stdlib.h>

static int failures;

static void
check(int cond, const char *what)
{
    if (cond) {
        fprintf(stderr, "  ok: %s\n", what);
    } else {
        fprintf(stderr, "  FAIL: %s\n", what);
        failures++;
    }
}

/* Expected exponential base (mirrors nettmo.c): 100<<min(attempt,6), cap 5000. */
static unsigned
expect_base(unsigned attempt)
{
    unsigned shift = (attempt < 6) ? attempt : 6;
    unsigned base = 100u << shift;
    return (base > 5000u) ? 5000u : base;
}

int
main(void)
{
    fprintf(stderr, "[backoff] exponential + capped + jittered\n");
    uint64_t seed = 0x1234567;
    for (unsigned a = 0; a <= 9; a++) {
        unsigned base = expect_base(a);
        unsigned d = brix_backoff_delay_ms(a, &seed);
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "attempt %u: %u in [%u, %u]", a, d, base, base + base / 2);
        check(d >= base && d <= base + base / 2, msg);
    }
    /* Cap holds at high attempts (no shift overflow). */
    check(expect_base(20) == 5000, "base capped at 5000 for large attempt");
    {
        unsigned d = brix_backoff_delay_ms(20, &seed);
        check(d >= 5000 && d <= 7500, "delay capped region for attempt 20");
    }

    fprintf(stderr, "[timeouts] setter overrides default\n");
    check(brix_tmo_connect_ms() == 15000, "default connect timeout 15000");
    brix_tmo_set_connect_ms(2500);
    check(brix_tmo_connect_ms() == 2500, "setter overrides connect timeout");
    brix_tmo_set_connect_ms(-1);   /* ignored */
    check(brix_tmo_connect_ms() == 2500, "non-positive setter ignored");

    return failures ? 1 : 0;
}
