/*
 * egress_guard_unittest.c — standalone unit test for the TPC source-egress
 * allowlist's pure predicate (brix_tpc_host_pattern_match).
 *
 *   cc -std=c11 -Wall -Wextra -Werror -I../../.. -DXRDPROTO_NO_NGX \
 *      egress_guard_unittest.c -o /tmp/ut && /tmp/ut
 *   (run from src/tpc/common/)
 *
 * Exit 0 = all checks pass. Pure C — the ngx wrappers (allowlist iteration and
 * refusal-text rendering) are excluded by XRDPROTO_NO_NGX and covered online by
 * test_tpc_source_egress_guard.py against a live gateway.
 */
#include <stdio.h>

#include "egress_guard.c"

static int g_fail;
#define CHECK(cond) do {                                                   \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
                   g_fail++; }                                             \
} while (0)


/* SUCCESS: an exact hostname matches, case-insensitively. */
static void
test_exact(void)
{
    CHECK(brix_tpc_host_pattern_match("se.example.org", "se.example.org"));
    CHECK(brix_tpc_host_pattern_match("SE.Example.ORG", "se.example.org"));
    CHECK(brix_tpc_host_pattern_match("se.example.org", "SE.EXAMPLE.ORG"));
}


/* SUCCESS: a leading-'.' pattern matches any strict sub-domain. */
static void
test_suffix(void)
{
    CHECK(brix_tpc_host_pattern_match(".example.org", "se.example.org"));
    CHECK(brix_tpc_host_pattern_match(".example.org", "a.b.example.org"));
    CHECK(brix_tpc_host_pattern_match(".EXAMPLE.org", "se.example.ORG"));
}


/* ERROR / boundary: near-misses must NOT match. */
static void
test_negatives(void)
{
    /* different host */
    CHECK(!brix_tpc_host_pattern_match("se.example.org", "evil.example.com"));
    /* exact pattern is not a suffix rule: a sub-domain must not match it */
    CHECK(!brix_tpc_host_pattern_match("example.org", "se.example.org"));
    /* suffix must be a STRICT suffix: the bare domain (== suffix minus dot) and
     * an equal-length string do not match a '.'-led rule */
    CHECK(!brix_tpc_host_pattern_match(".example.org", "example.org"));
    CHECK(!brix_tpc_host_pattern_match(".example.org", ".example.org"));
    /* a suffix rule must align on the dot, not mid-label */
    CHECK(!brix_tpc_host_pattern_match(".example.org", "notexample.org"));
    /* prefix, not suffix */
    CHECK(!brix_tpc_host_pattern_match("se.example.org", "se.example.org.evil.com"));
}


/* ERROR: degenerate inputs never match (empty / NULL pattern or host). */
static void
test_degenerate(void)
{
    CHECK(!brix_tpc_host_pattern_match("", "se.example.org"));
    CHECK(!brix_tpc_host_pattern_match(NULL, "se.example.org"));
    CHECK(!brix_tpc_host_pattern_match("se.example.org", NULL));
    CHECK(!brix_tpc_host_pattern_match(".example.org", ""));
    /* a lone '.' is a zero-length suffix: nothing is strictly longer-and-ends */
    CHECK(!brix_tpc_host_pattern_match(".", "example.org"));
}


int
main(void)
{
    test_exact();
    test_suffix();
    test_negatives();
    test_degenerate();

    if (g_fail == 0) {
        printf("all checks passed\n");
        return 0;
    }
    printf("%d check(s) FAILED\n", g_fail);
    return 1;
}
