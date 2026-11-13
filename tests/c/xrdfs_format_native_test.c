/* Observable CLI formatting and parsing use the configured xrdfs object. */
#include "apps/fs/xrdfs_internal.h"
#include <assert.h>
#include <limits.h>

static void report(const char *operation, const char *path, int extended)
{
    brix_statinfo info = {.id = 123, .size = 9007199254740991LL, .mtime = 0,
        .ctime = 1, .atime = 2, .flags = kXR_isDir | kXR_readable,
        .mode = 04755, .have_ext = extended};
    snprintf(info.owner, sizeof(info.owner), "owner\"\n");
    snprintf(info.group, sizeof(info.group), "group\\name");
    if (!strcmp(operation, "json")) { json_statinfo(path, &info); }
    else { print_statinfo(path, &info); }
}

int main(int argc, char **argv)
{
    assert(argc == 4); const char *op = argv[1], *value = argv[2];
    int option = atoi(argv[3]);
    if (!strcmp(op, "json") || !strcmp(op, "text")) { report(op, value, option); }
    else if (!strcmp(op, "chmod")) { printf("%d\n", parse_chmod_mode(value)); }
    else if (!strcmp(op, "touch")) {
        struct timespec stamp = {.tv_sec = 77, .tv_nsec = 88};
        int rc = touch_parse_time(value, &stamp);
        if (rc) { assert(stamp.tv_sec == 77 && stamp.tv_nsec == 88); puts("invalid"); }
        else { assert(stamp.tv_nsec == 0); printf("%lld\n", (long long) stamp.tv_sec); }
    } else if (!strcmp(op, "time")) { print_stat_time("Time: ", strtol(value, NULL, 10)); }
    else if (!strcmp(op, "space")) {
        int64_t total, avail, used, largest;
        int rc = df_parse_space(value, &total, &avail, &used, &largest);
        printf("%d %lld %lld %lld %lld\n", rc, (long long) total,
            (long long) avail, (long long) used, (long long) largest);
    } else if (!strcmp(op, "flags")) {
        char output[258]; memset(output, 0xa5, sizeof(output));
        assert(option > 0 && option <= 256); flags_to_str(atoi(value), output + 1, option);
        assert((unsigned char) output[0] == 0xa5 && (unsigned char) output[option + 1] == 0xa5);
        assert(memchr(output + 1, 0, option)); puts(output + 1);
    } else if (!strcmp(op, "integer")) {
        unsigned long long number = 77;
        int rc = parse_u64_strict(!strcmp(value, "<null>") ? NULL : value, &number);
        if (rc) { assert(number == 77); puts("invalid"); }
        else { printf("%llu\n", number); }
    } else { assert(!strcmp(op, "dot")); printf("%d\n", is_dot(value)); }
    return 0;
}
