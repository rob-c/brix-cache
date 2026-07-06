/* WLCG token scope conformance — Layer-1 unit (ngx-free).
 *
 * WHAT: Standalone unit tests for brix_token_scope_path_matches() boundary semantics.
 * WHY:  Ensures the path-prefix guard prevents "/data" matching "/database" and
 *       correctly covers "/data/f" and any path under the root scope.
 * HOW:  Links scopes.c only; no nginx headers. Three initial skeleton checks (SCP-01..03).
 */
#include <stdio.h>
#include <string.h>
#include "auth/token/scopes.h"

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                            \
    g_checks++;                                                           \
    if (cond) { printf("  ok   %s\n", name); }                           \
    else { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

static void test_path_boundary(void)
{
    /* SCP-01: "/data" scope must NOT authorize "/database". */
    CHECK(brix_token_scope_path_matches("/data", "/database") == 0,
          "SCP-01 boundary /data != /database");
    CHECK(brix_token_scope_path_matches("/data", "/data/f") == 1,
          "SCP-02 /data covers /data/f");
    CHECK(brix_token_scope_path_matches("/", "/anything") == 1,
          "SCP-03 root scope covers all");
}

int main(void)
{
    test_path_boundary();
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
