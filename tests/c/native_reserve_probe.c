/* Independent native preallocation oracle plus the real production PAL.
 * The parent supplies an owned regular-file descriptor, never a pathname.
 * Allocation is bounded to 8 MiB; no extend-and-truncate fallback is used.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "platform/platform_api.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if BRIX_PLATFORM_LINUX
#include <linux/falloc.h>
#endif

/* WHAT: Parse one bounded nonnegative argument, rejecting partial numbers.
 * WHY: A probe must never allocate an accidentally huge sparse fixture.
 * HOW: Check the conversion, full input and explicit caller-owned limit. */
static long
bounded_argument(const char *text, long limit)
{
    char *end;
    long value;

    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0 || value > limit) {
        return -1;
    }
    return value;
}

/* WHAT: Ask the host directly, independently of BriX's implementation.
 * WHY: A PAL that always returns ENOTSUP cannot hide a supported capability.
 * HOW: Linux KEEP_SIZE / Darwin F_PREALLOCATE; FreeBSD's POSIX primitive is
 * also exercised, but its documented EOF extension is NOT KEEP_SIZE. */
static int
native_reserve(int descriptor, off_t size, const char **semantics)
{
#if BRIX_PLATFORM_LINUX
    (void) semantics;
    return fallocate(descriptor, FALLOC_FL_KEEP_SIZE, 0, size);
#elif BRIX_PLATFORM_DARWIN
    fstore_t allocation;

    (void) semantics;
    memset(&allocation, 0, sizeof(allocation));
    allocation.fst_flags = F_ALLOCATEALL;
    allocation.fst_posmode = F_PEOFPOSMODE;
    allocation.fst_length = size;
    return fcntl(descriptor, F_PREALLOCATE, &allocation);
#elif BRIX_PLATFORM_FREEBSD
    int error;

    *semantics = "changes-eof";
    error = posix_fallocate(descriptor, 0, size);
    if (error != 0) {
        errno = error;
        return -1;
    }
    return 0;
#else
#error "Native reserve probe needs an explicit host implementation"
#endif
}

/* WHAT: Report the native or production result, never manufacture success.
 * WHY: Python verifies bytes/inodes/size independently around this process.
 * HOW: Only inherited descriptors and bounded sizes; EINTR alone is retried. */
int
main(int argc, char **argv)
{
    const char *semantics = "keep-size";
    long descriptor, size;
    int result, error, native;

    if (argc != 4) { return 2; }
    native = strcmp(argv[1], "native") == 0;
    if (!native && strcmp(argv[1], "pal") != 0) { return 2; }
    descriptor = bounded_argument(argv[2], INT_MAX);
    size = bounded_argument(argv[3], 8L * 1024 * 1024);
    if (descriptor < 0 || size <= 0) { return 2; }
    do {
        errno = 0;
        result = native ? native_reserve((int) descriptor, (off_t) size, &semantics)
                        : brix_plat_reserve((int) descriptor, (off_t) size);
    } while (result < 0 && errno == EINTR);
    error = result == 0 ? 0 : errno;
    printf("{\"result\":%d,\"errno\":%d,\"semantics\":\"%s\"}\n",
           result, error, semantics);
    return 0;
}
