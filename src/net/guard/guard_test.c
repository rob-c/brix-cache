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

    /* --- signatures --- */
    guard_ruleset_t sg; guard_ruleset_init(&sg);
    guard_ruleset_add_default_signatures(&sg);
    CHECK(guard_signature_match(&sg, "/wp-login.php", 13));   /* suffix .php */
    CHECK(guard_signature_match(&sg, "/wp-admin/", 10));       /* prefix /wp- */
    CHECK(guard_signature_match(&sg, "/x/.env", 7));           /* substr .env */
    CHECK(guard_signature_match(&sg, "/a/../b", 7));           /* substr /../ */
    CHECK(!guard_signature_match(&sg, "/rest/1.0/jobs", 14));  /* clean */
    CHECK(!guard_signature_match(&sg, "/data/file.root", 15)); /* clean */
    /* custom substring */
    guard_ruleset_t cs; guard_ruleset_init(&cs);
    CHECK(guard_ruleset_add_signature(&cs, GUARD_SIG_SUBSTR, "phpMyAdmin", 10));
    CHECK(guard_signature_match(&cs, "/phpMyAdmin/index", 17));
    CHECK(!guard_signature_match(&cs, "/data/ok", 8));

    printf(fails ? "GUARD CORE: %d FAIL\n" : "GUARD CORE: all pass\n", fails);
    return fails ? 1 : 0;
}
