/* relsafe_unit.c — brix_rel_is_unsafe: the guard that keeps server-supplied or
 * manifest-supplied relative paths inside the destination root. */
#include <assert.h>
#include <stdio.h>
#include "brix.h"
#include "brix_ops.h"

int main(void)
{
    /* success: benign paths pass */
    assert(brix_rel_is_unsafe("a/b/c.txt") == 0);
    assert(brix_rel_is_unsafe("a..b/c..d") == 0);     /* dots inside names OK */
    assert(brix_rel_is_unsafe("...") == 0);
    /* error/edge: empty is safe to join (degenerate but not escaping) */
    assert(brix_rel_is_unsafe("") == 0);
    assert(brix_rel_is_unsafe(NULL) == 0);
    /* security-negative: every escape shape is caught */
    assert(brix_rel_is_unsafe("/etc/passwd") == 1);
    assert(brix_rel_is_unsafe("..") == 1);
    assert(brix_rel_is_unsafe("../x") == 1);
    assert(brix_rel_is_unsafe("x/../y") == 1);
    assert(brix_rel_is_unsafe("x/..") == 1);
    printf("relsafe_unit: ALL PASS\n");
    return 0;
}
