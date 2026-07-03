/*
 * session_unittest.c — standalone unit test for the SSI session RRTable.
 *
 *   gcc -Wall -Wextra -Werror -DSSI_UT_STANDALONE -I src \
 *       -o /tmp/ssi_session_ut \
 *       src/ssi/session_unittest.c src/ssi/session.c && /tmp/ssi_session_ut
 */
#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static void test_create_and_lookup(void)
{
    brix_ssi_provider_t prov = { "echo", (brix_ssi_process_fn) 0x1 };
    brix_ssi_session_t *s = brix_ssi_session_create(NULL, "echo", 4, &prov);
    CHECK(s != NULL);
    CHECK(strcmp(s->service, "echo") == 0);
    CHECK(s->provider.process == (brix_ssi_process_fn) 0x1);

    brix_ssi_req_t *a = brix_ssi_session_req(s, 7, 1);
    CHECK(a != NULL && a->req_id == 7 && a->in_use);
    /* same reqId returns the same slot */
    CHECK(brix_ssi_session_req(s, 7, 0) == a);
    /* a different reqId is a distinct slot (multiplex) */
    brix_ssi_req_t *b = brix_ssi_session_req(s, 9, 1);
    CHECK(b != NULL && b != a && b->req_id == 9);

    free(s);
}

static void test_lookup_absent(void)
{
    brix_ssi_provider_t prov = { "echo", (brix_ssi_process_fn) 0x1 };
    brix_ssi_session_t *s = brix_ssi_session_create(NULL, "echo", 4, &prov);
    CHECK(brix_ssi_session_req(s, 42, 0) == NULL);   /* not created */
    free(s);
}

static void test_table_full(void)
{
    brix_ssi_provider_t prov = { "echo", (brix_ssi_process_fn) 0x1 };
    brix_ssi_session_t *s = brix_ssi_session_create(NULL, "echo", 4, &prov);
    for (uint32_t i = 0; i < BRIX_SSI_MAX_INFLIGHT; i++) {
        CHECK(brix_ssi_session_req(s, 100 + i, 1) != NULL);
    }
    CHECK(brix_ssi_session_req(s, 999, 1) == NULL);  /* full → NULL */
    brix_ssi_session_drop(s, 100);                   /* free one slot */
    CHECK(brix_ssi_session_req(s, 999, 1) != NULL);  /* now fits */
    free(s);
}

static void test_generation_increments(void)
{
    brix_ssi_provider_t prov = { "echo", (brix_ssi_process_fn) 0x1 };
    brix_ssi_session_t *a = brix_ssi_session_create(NULL, "echo", 4, &prov);
    brix_ssi_session_t *b = brix_ssi_session_create(NULL, "echo", 4, &prov);
    CHECK(a->generation != 0);
    CHECK(b->generation == a->generation + 1);
    free(a); free(b);
}

int main(void)
{
    test_create_and_lookup();
    test_lookup_absent();
    test_table_full();
    test_generation_increments();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
