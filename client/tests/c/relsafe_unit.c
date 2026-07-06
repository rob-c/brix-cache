/* relsafe_unit.c — brix_rel_is_unsafe: the guard that keeps server-supplied or
 * manifest-supplied relative paths inside the destination root. */
#include <assert.h>
#include <stdio.h>
#include "brix.h"
#include "brix_ops.h"

/* Test rmtree root guard: ensures rmtree refuses export root, all-slash, empty, NULL */
static void test_rmtree_root_guard(void)
{
    brix_status st;

    /* Refuse export root */
    brix_status_clear(&st);
    assert(brix_rmtree(NULL, "/", 0, NULL, NULL, &st) == -1);
    brix_status_clear(&st);

    /* Refuse all-slash */
    brix_status_clear(&st);
    assert(brix_rmtree(NULL, "//", 0, NULL, NULL, &st) == -1);
    assert(st.msg[0] != '\0');  /* st set */
    brix_status_clear(&st);

    /* Refuse empty string */
    assert(brix_rmtree(NULL, "", 0, NULL, NULL, &st) == -1);
    brix_status_clear(&st);

    /* Refuse NULL path */
    assert(brix_rmtree(NULL, NULL, 0, NULL, NULL, &st) == -1);
}

int main(void)
{
    /* success: benign paths pass */
    assert(brix_rel_is_unsafe("a/b/c.txt") == 0);
    assert(brix_rel_is_unsafe("a..b/c..d") == 0);     /* dots inside names OK */
    assert(brix_rel_is_unsafe("...") == 0);
    /* error/edge: empty is safe to join (degenerate but not escaping) */
    assert(brix_rel_is_unsafe("") == 0);
    /* security-negative: every escape shape is caught */
    assert(brix_rel_is_unsafe(NULL) == 1);             /* fail-closed: NULL → unsafe */
    assert(brix_rel_is_unsafe("/etc/passwd") == 1);
    assert(brix_rel_is_unsafe("..") == 1);
    assert(brix_rel_is_unsafe("../x") == 1);
    assert(brix_rel_is_unsafe("x/../y") == 1);
    assert(brix_rel_is_unsafe("x/..") == 1);
    printf("relsafe_unit: ALL PASS\n");

    test_rmtree_root_guard();
    printf("test_rmtree_root_guard: ALL PASS\n");

    return 0;
}
