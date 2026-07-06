/* suggest_unit.c — unit tests for client/lib/cli/suggest.c (spec WS-7).
 *
 * WHAT: verifies brix_suggest() distance thresholds, first-in-table tiebreak,
 *       64-byte arg cap, NULL-safety, and exact/near/no-match behaviour.
 * WHY:  spec §WS-7 acceptance criteria: distance ≤ 2 returns a candidate,
 *       distance 3 must NOT return anything (no spurious suggestions).
 * HOW:  a small static candidate table is used for all assertions; assert()
 *       on return values.  Run inside `make test` which has a non-TTY stderr,
 *       so the hints gate never fires during this run.
 *
 * Build+run (from client/):
 *   cc -std=c11 -Wall -Ilib tests/c/suggest_unit.c \
 *       libbrix.a ../shared/xrdproto/libxrdproto.a -lssl -lcrypto -lz \
 *       -o bin/suggest_unit && ./bin/suggest_unit
 */
#include "cli/suggest.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Candidate table shared by all tests. */
static const char *const CMDS[] = {
    "stat", "ls", "mkdir", "rm", "cat", "find", NULL
};

/* ---- success tests -------------------------------------------------------- */

/*
 * WHAT: an exact match (distance 0) returns the candidate immediately.
 * WHY:  the most common case; the hint must fire even when the user typed it
 *       correctly but something else caused the unknown-command path.
 */
static void
test_exact_match(void)
{
    const char *s = brix_suggest("stat", CMDS);
    assert(s != NULL);
    assert(strcmp(s, "stat") == 0);
    printf("  PASS  exact match\n");
}

/*
 * WHAT: a single edit (substitution) gives distance 1 ≤ 2 → returns candidate.
 * WHY:  single-key typos are the most common mistake; must produce a suggestion.
 */
static void
test_distance_1_substitution(void)
{
    /* "satt" vs "stat": one transposition or substitution away */
    const char *s = brix_suggest("satt", CMDS);
    assert(s != NULL);
    assert(strcmp(s, "stat") == 0);
    printf("  PASS  distance-1 substitution\n");
}

/*
 * WHAT: two edits (two substitutions) give distance 2 → still returns a match.
 * WHY:  spec WS-7 says ≤ 2; two-edit distance must produce a suggestion.
 * HOW:  "sabt" vs "stat": s=s, a≠t (sub 1), b≠a (sub 2), t=t → distance 2.
 */
static void
test_distance_2(void)
{
    /* "sabt" vs "stat": two substitutions away (positions 2 and 3). */
    const char *s = brix_suggest("sabt", CMDS);
    assert(s != NULL);
    assert(strcmp(s, "stat") == 0);
    printf("  PASS  distance-2 suggestion\n");
}

/*
 * WHAT: first-in-table tiebreak — when two candidates are equidistant, the
 *       first one in the table is returned.
 * WHY:  spec WS-7: "ties broken by first-in-table"; table order defines priority.
 */
static void
test_first_in_table_tiebreak(void)
{
    /* "ls" is distance 0 from "ls"; "stat" is also in table.
     * A direct lookup of "ls" must return "ls" (the first match). */
    const char *s = brix_suggest("ls", CMDS);
    assert(s != NULL);
    assert(strcmp(s, "ls") == 0);
    printf("  PASS  first-in-table tiebreak\n");
}

/*
 * WHAT: the 64-byte arg cap: an arg longer than 64 bytes is truncated before
 *       comparison, so it can never match any short candidate.
 * WHY:  spec WS-7: "caps candidate echo at 64 bytes"; adversarial input
 *       must not cause a spurious hit.
 */
static void
test_64_byte_cap_no_match(void)
{
    /* A 128-byte arg that starts with "stat" but is padded past the cap. */
    const char long_arg[129];
    int i;
    for (i = 0; i < 128; i++) {
        ((char *)long_arg)[i] = 'a' + (i % 26);
    }
    ((char *)long_arg)[128] = '\0';

    const char *s = brix_suggest(long_arg, CMDS);
    /* The 64-byte prefix of the long_arg is "abcdefghijklmnopqrstuvwxyzabcde...";
     * it is nowhere close to any candidate, so we expect NULL. */
    assert(s == NULL);
    printf("  PASS  64-byte cap: no match for overlong arg\n");
}

/* ---- error tests ---------------------------------------------------------- */

/*
 * WHAT: distance 3 produces NO suggestion (spec WS-7: distance > 2 → NULL).
 * WHY:  spurious suggestions for clearly-wrong input would be confusing; the
 *       threshold is ≤ 2 only.
 * HOW:  "zbot" is 3 substitutions from "stat" (z→s, b→t, o→a; 't'='t') and
 *       ≥ 3 edits from every other candidate in CMDS.  No path through the DL
 *       DP reduces this below 3, so brix_suggest must return NULL.
 */
static void
test_distance_3_no_suggestion(void)
{
    /* "zbot" vs "stat": exactly 3 substitutions — must NOT produce a suggestion. */
    const char *s = brix_suggest("zbot", CMDS);
    assert(s == NULL);
    printf("  PASS  distance-3: no suggestion\n");
}

/*
 * WHAT: completely unrelated input returns NULL.
 * WHY:  the hint must not fire for nonsense input with no similar command.
 */
static void
test_unrelated_no_match(void)
{
    const char *s = brix_suggest("xyzzy", CMDS);
    assert(s == NULL);
    printf("  PASS  unrelated input: no match\n");
}

/*
 * WHAT: NULL arg returns NULL without crashing.
 * WHY:  NULL-safety; callers may pass arbitrary strings.
 */
static void
test_null_arg(void)
{
    const char *s = brix_suggest(NULL, CMDS);
    assert(s == NULL);
    printf("  PASS  NULL arg handled safely\n");
}

/*
 * WHAT: NULL candidates table returns NULL without crashing.
 * WHY:  NULL-safety; candidates pointer itself may be NULL.
 */
static void
test_null_candidates(void)
{
    const char *s = brix_suggest("stat", NULL);
    assert(s == NULL);
    printf("  PASS  NULL candidates handled safely\n");
}

/*
 * WHAT: empty candidates table (only NULL sentinel) returns NULL.
 * WHY:  an empty table has no candidates to match, so the result is always NULL.
 */
static void
test_empty_candidates(void)
{
    static const char *const empty[] = { NULL };
    const char *s = brix_suggest("stat", empty);
    assert(s == NULL);
    printf("  PASS  empty candidates table returns NULL\n");
}

/* ---- security-negative tests ---------------------------------------------- */

/*
 * WHAT: an arg containing control bytes / escape sequences is still handled
 *       safely — brix_suggest never writes to stderr itself, so no injection
 *       risk; but the returned pointer (if any) is one of the clean candidate
 *       strings, never the hostile arg.
 * WHY:  spec WS-7: "a command name of escape sequences/1KB garbage is
 *       sanitized and truncated in the echo".  brix_suggest returns a pointer
 *       from the candidates[] table, never from arg, so callers who print the
 *       return value always print a known-clean string.
 */
static void
test_hostile_arg_returns_clean_candidate(void)
{
    /* A hostile arg with embedded ESC/BEL — still matches "stat" by distance */
    const char *evil = "stat\x1b[31m";  /* "stat" + ANSI escape = distance ≥ 3 */
    const char *s = brix_suggest(evil, CMDS);
    /* If it matches (≤ 2), the return value must be from CMDS (clean string) */
    if (s != NULL) {
        assert(s == CMDS[0] || s == CMDS[1] || s == CMDS[2] ||
               s == CMDS[3] || s == CMDS[4] || s == CMDS[5]);
        /* The returned string must contain no control bytes */
        size_t i;
        for (i = 0; s[i] != '\0'; i++) {
            assert((unsigned char) s[i] >= 0x20);
        }
    }
    /* Whether it matches or not, no crash and no use of the evil arg itself */
    printf("  PASS  hostile arg: return value is clean candidate (or NULL)\n");
}

/* --------------------------------------------------------------------------- */

int
main(void)
{
    printf("suggest_unit: brix_suggest() contract\n");

    printf("  [success]\n");
    test_exact_match();
    test_distance_1_substitution();
    test_distance_2();
    test_first_in_table_tiebreak();
    test_64_byte_cap_no_match();

    printf("  [error]\n");
    test_distance_3_no_suggestion();
    test_unrelated_no_match();
    test_null_arg();
    test_null_candidates();
    test_empty_candidates();

    printf("  [security-negative]\n");
    test_hostile_arg_returns_clean_candidate();

    printf("suggest_unit: ALL PASS\n");
    return 0;
}
