/* Link the actual confinement splitter through its shared header declaration. */
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include "fs/path/path_internal.h"

typedef int (*split_parent_fn)(const char *, char *, size_t, char *, size_t);
typedef int (*open_root_fn)(ngx_log_t *, const char *);
typedef int (*open_parent_fn)(int, const char *);
typedef int (*open_canonical_parent_fn)(ngx_log_t *, const char *, const char *,
    char *, size_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&brix_split_relative_parent),
    split_parent_fn), "splitter returns an int status, never a pointer");
_Static_assert(__builtin_types_compatible_p(__typeof__(&brix_open_root_fd),
    open_root_fn), "root opener signature changed");
_Static_assert(__builtin_types_compatible_p(__typeof__(&brix_open_confined_parent_fallback),
    open_parent_fn), "fallback parent opener signature changed");
_Static_assert(__builtin_types_compatible_p(__typeof__(&brix_open_confined_parent_canon),
    open_canonical_parent_fn), "canonical parent opener signature changed");

typedef struct {
    unsigned char before;
    char value[8];
    unsigned char after;
} guarded_buffer_t;

static void
test_success(void)
{
    char parent[32], base[16];

    assert(brix_split_relative_parent("file", parent, sizeof(parent),
                                     base, sizeof(base)) == 1);
    assert(strcmp(parent, ".") == 0);
    assert(strcmp(base, "file") == 0);
    assert(brix_split_relative_parent("one/two/file", parent, sizeof(parent),
                                     base, sizeof(base)) == 1);
    assert(strcmp(parent, "one/two") == 0);
    assert(strcmp(base, "file") == 0);
}

static void
test_invalid(void)
{
    const char *invalid[] = {NULL, "", "."};
    char parent[8], base[8];
    char unchanged[8];

    memset(unchanged, 0x5a, sizeof(unchanged));
    for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
        memcpy(parent, unchanged, sizeof(parent));
        memcpy(base, unchanged, sizeof(base));
        errno = 0;
        assert(brix_split_relative_parent(invalid[index], parent, sizeof(parent),
                                         base, sizeof(base)) == 0);
        assert(errno == EINVAL);
        assert(memcmp(parent, unchanged, sizeof(parent)) == 0);
        assert(memcmp(base, unchanged, sizeof(base)) == 0);
    }
}

static void
assert_buffer_bounds(const guarded_buffer_t *buffer, size_t capacity)
{
    assert(buffer->before == 0xa5);
    assert(buffer->after == 0xa5);
    for (size_t index = capacity; index < sizeof(buffer->value); index++) {
        assert((unsigned char) buffer->value[index] == 0xa5);
    }
}

static void
test_bounds(void)
{
    const struct {
        const char *path;
        size_t parent_capacity;
        size_t base_capacity;
    } cases[] = {
        {"file", 0, 8}, {"file", 1, 8}, {"file", 8, 0}, {"file", 8, 4},
        {"dir/file", 3, 8}, {"dir/file", 8, 4}, {"dir/", 8, 8}, {"/file", 8, 8},
    };
    guarded_buffer_t parent, base;

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        memset(&parent, 0xa5, sizeof(parent));
        memset(&base, 0xa5, sizeof(base));
        errno = 0;
        assert(brix_split_relative_parent(cases[index].path, parent.value,
            cases[index].parent_capacity, base.value, cases[index].base_capacity) == 0);
        assert(errno == ENAMETOOLONG);
        assert_buffer_bounds(&parent, cases[index].parent_capacity);
        assert_buffer_bounds(&base, cases[index].base_capacity);
    }

    memset(&parent, 0xa5, sizeof(parent));
    memset(&base, 0xa5, sizeof(base));
    assert(brix_split_relative_parent("dir/file", parent.value, 4, base.value, 5) == 1);
    assert(strcmp(parent.value, "dir") == 0);
    assert(strcmp(base.value, "file") == 0);
    assert_buffer_bounds(&parent, 4);
    assert_buffer_bounds(&base, 5);
}

int
main(int argc, char **argv)
{
    assert(argc == 2);
    if (strcmp(argv[1], "success") == 0) {
        test_success();
        return 0;
    }
    if (strcmp(argv[1], "invalid") == 0) {
        test_invalid();
        return 0;
    }
    assert(strcmp(argv[1], "bounds") == 0);
    test_bounds();
    return 0;
}
