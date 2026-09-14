/* Bounded NUL-separated attribute-list assertions for Windows unit tests.
 * Requires only standard C headers; it does not load Windows or nginx APIs.
 */
#pragma once

#include <stddef.h>
#include <string.h>

static inline int
brix_test_xattr_list_contains(const char *list, ptrdiff_t size, const char *name)
{
    const char *cursor = list;
    size_t remaining;
    size_t expected_size;

    if (list == NULL || name == NULL || size <= 0) {
        return 0;
    }
    remaining = (size_t) size;
    expected_size = strlen(name);
    while (remaining > 0) {
        const char *end = memchr(cursor, '\0', remaining);
        size_t entry_size;

        if (end == NULL) {
            return 0;
        }
        entry_size = (size_t) (end - cursor);
        if (entry_size == expected_size && memcmp(cursor, name, entry_size) == 0) {
            return 1;
        }
        cursor = end + 1;
        remaining -= entry_size + 1;
    }
    return 0;
}
