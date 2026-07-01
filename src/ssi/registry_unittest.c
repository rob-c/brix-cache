/*
 * registry_unittest.c — standalone unit test for the SSI session registry.
 *
 *   gcc -Wall -Wextra -Werror -DSSI_UT_STANDALONE -I src -o /tmp/ssi_reg_ut \
 *       src/ssi/registry_unittest.c src/ssi/registry.c && /tmp/ssi_reg_ut
 */
#include "registry.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static void test_add_find_remove(void)
{
    xrootd_ssi_session_t s;
    memset(&s, 0, sizeof(s));
    s.generation = 5;

    xrootd_ssi_registry_add(1234, &s);
    CHECK(xrootd_ssi_registry_find(1234, 5) == &s);
    CHECK(xrootd_ssi_registry_find(1234, 6) == NULL);   /* generation moved */
    CHECK(xrootd_ssi_registry_find(9999, 5) == NULL);   /* unknown conn */

    xrootd_ssi_registry_remove(1234);
    CHECK(xrootd_ssi_registry_find(1234, 5) == NULL);
}

static void test_recycled_conn_id_refreshes_generation(void)
{
    xrootd_ssi_session_t a, b;
    memset(&a, 0, sizeof(a)); a.generation = 10;
    memset(&b, 0, sizeof(b)); b.generation = 11;

    xrootd_ssi_registry_add(4242, &a);
    /* same conn_id reused by a new session before remove → entry refreshes */
    xrootd_ssi_registry_add(4242, &b);
    CHECK(xrootd_ssi_registry_find(4242, 11) == &b);
    CHECK(xrootd_ssi_registry_find(4242, 10) == NULL);   /* stale gen rejected */
    xrootd_ssi_registry_remove(4242);
}

int main(void)
{
    test_add_find_remove();
    test_recycled_conn_id_refreshes_generation();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
