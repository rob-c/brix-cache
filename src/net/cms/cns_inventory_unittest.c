/*
 * cns_inventory_unittest.c — standalone unit test for the CNS inventory table.
 *
 *   gcc -Wall -Wextra -Werror -I src/net/cms -o /tmp/cns_inv_ut \
 *       src/net/cms/cns_inventory_unittest.c src/net/cms/cns_inventory.c \
 *   && /tmp/cns_inv_ut
 *
 * Exit 0 = all checks pass. Pure C (no nginx, no filesystem, no SHM) — it drives
 * the POD table exactly as cns.c does under its lock, so the slot/upsert/delete
 * semantics that a multi-worker SHM inventory relies on are proven deterministic.
 */

#include "cns_inventory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static brix_cns_inv_t *
mk(uint32_t cap)
{
    brix_cns_inv_t *inv = calloc(1, brix_cns_inv_bytes(cap));
    brix_cns_inv_init(inv, cap);
    return inv;
}

/* An ADD becomes a statable regular file; count tracks it. */
static void
test_add_then_stat(void)
{
    brix_cns_inv_t *inv = mk(16);
    uint64_t sz = 0, mt = 0;
    int      dir = -1;

    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "/atlas/f1", 4096, 111, 7) == 0);
    CHECK(brix_cns_inv_count(inv) == 1);
    CHECK(brix_cns_inv_stat(inv, "/atlas/f1", &sz, &mt, &dir) == 0);
    CHECK(sz == 4096 && mt == 111 && dir == 0);
    CHECK(brix_cns_inv_stat(inv, "/atlas/missing", &sz, &mt, &dir) == 1);   /* miss */
    free(inv);
}

/* MKDIR statable as a directory; DEL/RMDIR clear and free the slot. */
static void
test_mkdir_and_delete(void)
{
    brix_cns_inv_t *inv = mk(16);
    int      dir = 0;

    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_MKDIR, "/atlas/d", 0, 5, 1) == 0);
    CHECK(brix_cns_inv_stat(inv, "/atlas/d", NULL, NULL, &dir) == 0 && dir == 1);

    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_RMDIR, "/atlas/d", 0, 0, 0) == 0);
    CHECK(brix_cns_inv_stat(inv, "/atlas/d", NULL, NULL, NULL) == 1);
    CHECK(brix_cns_inv_count(inv) == 0);

    /* deleting an absent path is a no-op, not an error */
    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_DEL, "/nope", 0, 0, 0) == 0);
    CHECK(brix_cns_inv_count(inv) == 0);
    free(inv);
}

/* Re-ADD of the same path upserts in place: count stays, metadata updates. */
static void
test_upsert_in_place(void)
{
    brix_cns_inv_t *inv = mk(16);
    uint64_t sz = 0;

    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "/p", 10, 1, 1) == 0);
    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "/p", 20, 2, 2) == 0);
    CHECK(brix_cns_inv_count(inv) == 1);
    CHECK(brix_cns_inv_stat(inv, "/p", &sz, NULL, NULL) == 0 && sz == 20);
    free(inv);
}

/* A freed slot is reused, so a delete-then-add churn never exhausts capacity. */
static void
test_slot_reuse_after_delete(void)
{
    brix_cns_inv_t *inv = mk(2);
    int i;

    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "/a", 1, 1, 1) == 0);
    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "/b", 1, 1, 1) == 0);
    for (i = 0; i < 100; i++) {
        CHECK(brix_cns_inv_apply(inv, BRIX_CNS_DEL, "/b", 0, 0, 0) == 0);
        CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "/b", 1, 1, 1) == 0);
    }
    CHECK(brix_cns_inv_count(inv) == 2);
    free(inv);
}

/* A full table rejects a new path (-1) but still upserts an existing one. */
static void
test_full_table(void)
{
    brix_cns_inv_t *inv = mk(2);

    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "/a", 1, 1, 1) == 0);
    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "/b", 1, 1, 1) == 0);
    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "/c", 1, 1, 1) == -1);   /* full */
    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "/a", 9, 9, 9) == 0);    /* upsert ok */
    CHECK(brix_cns_inv_count(inv) == 2);
    free(inv);
}

/* Bad inputs are rejected without touching the table. */
static void
test_bad_inputs(void)
{
    brix_cns_inv_t *inv = mk(16);
    char big[BRIX_CNS_PATH_MAX + 8];

    memset(big, 'x', sizeof(big));
    big[sizeof(big) - 1] = '\0';

    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, "", 1, 1, 1) == -1);       /* empty */
    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, NULL, 1, 1, 1) == -1);     /* NULL  */
    CHECK(brix_cns_inv_apply(inv, BRIX_CNS_ADD, big, 1, 1, 1) == -1);      /* long  */
    CHECK(brix_cns_inv_apply(inv, 99, "/p", 1, 1, 1) == -1);               /* op    */
    CHECK(brix_cns_inv_stat(NULL, "/p", NULL, NULL, NULL) == -1);
    CHECK(brix_cns_inv_count(inv) == 0);
    free(inv);
}

int
main(void)
{
    test_add_then_stat();
    test_mkdir_and_delete();
    test_upsert_in_place();
    test_slot_reuse_after_delete();
    test_full_table();
    test_bad_inputs();

    if (g_fail) {
        printf("cns_inventory_unittest: %d checks FAILED\n", g_fail);
        return 1;
    }
    printf("cns_inventory_unittest: all checks passed\n");
    return 0;
}
