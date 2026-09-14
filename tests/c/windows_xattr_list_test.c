/* Portable checks for the list oracle used by the native Windows xattr suites. */
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "platform/windows/xattr_test_helpers.h"

static void
test_success(void)
{
    const char list[] = "user.attr1\0user.attr2\0user.attr3\0";
    ptrdiff_t size = (ptrdiff_t) sizeof(list) - 1;

    assert(brix_test_xattr_list_contains(list, size, "user.attr1"));
    assert(brix_test_xattr_list_contains(list, size, "user.attr2"));
    assert(brix_test_xattr_list_contains(list, size, "user.attr3"));
    assert(!brix_test_xattr_list_contains(list, size, "user.missing"));
}

static void
test_error(void)
{
    const char list[] = "user.attr1\0";

    assert(!brix_test_xattr_list_contains(list, -1, "user.attr1"));
    assert(!brix_test_xattr_list_contains(list, 0, "user.attr1"));
    assert(!brix_test_xattr_list_contains(NULL, sizeof(list), "user.attr1"));
    assert(!brix_test_xattr_list_contains(list, sizeof(list), NULL));
}

static void
test_malformed(void)
{
    const char unterminated[] = {'u', 's', 'e', 'r', '.', 'a'};
    const char prefix[] = "user.attr10\0";
    const char list[] = "user.attr1\0user.attr2\0";
    ptrdiff_t first_entry_size = sizeof("user.attr1");

    assert(!brix_test_xattr_list_contains(unterminated, sizeof(unterminated), "user.a"));
    assert(!brix_test_xattr_list_contains(prefix, sizeof(prefix), "user.attr1"));
    assert(!brix_test_xattr_list_contains(list, first_entry_size - 1, "user.attr1"));
    assert(!brix_test_xattr_list_contains(list, first_entry_size, "user.attr2"));
}

int
main(int argc, char **argv)
{
    assert(argc == 2);
    if (strcmp(argv[1], "success") == 0) {
        test_success();
        return 0;
    }
    if (strcmp(argv[1], "error") == 0) {
        test_error();
        return 0;
    }
    assert(strcmp(argv[1], "malformed") == 0);
    test_malformed();
    return 0;
}
