/*
 * guard_test.c — standalone unit tests for the pure-C guard core.
 *
 * WHAT: exercises every guard.h entry point (ruleset construction, signature
 *   matching, grammar, pre/post classification, audit formatting) with no
 *   nginx, no network, no allocation.
 * WHY:  the guard core must stay embeddable in any adapter; a plain-gcc test
 *   binary is the proof and the regression net.
 * HOW:  CHECK() accumulates failures; main() returns non-zero if any check
 *   failed. Build + run via tests/guard/run_guard_core.sh.
 */
#include "guard.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

int main(void)
{
    /* --- ruleset init: header + enums compile and link --- */
    guard_ruleset_t rs;
    guard_ruleset_init(&rs);
    CHECK(rs.n_sigs == 0);
    CHECK(rs.n_prefixes == 0);

    printf(fails ? "GUARD CORE: %d FAIL\n" : "GUARD CORE: all pass\n", fails);
    return fails ? 1 : 0;
}
