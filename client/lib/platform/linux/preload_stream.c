/*
 * client/lib/platform/linux/preload_stream.c - a FILE* over a shim descriptor
 *
 * WHAT: brixposix_stream_open for glibc: fopencookie hands back a REAL FILE*
 *       whose backing store is the shim's shadow fd, so glibc keeps doing the
 *       buffering, fgets, fscanf, ungetc and feof.
 * WHY:  The cookie's read/write/seek/close are the shim's OWN interposed
 *       wrappers, not libc's: a FILE* opened here reads remote bytes without
 *       this file knowing anything about the wire.
 * HOW:  cookie_io_functions_t adapters; off64_t is glibc's seek type.
 */

#include "platform/preload.h"

#if BRIX_PLATFORM_LINUX

#include "brixposix_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static ssize_t
cookie_read(void *cookie, char *buf, size_t size)
{
    return BRIXPOSIX_WRAP(read)((int) (intptr_t) cookie, buf, size);
}

static ssize_t
cookie_write(void *cookie, const char *buf, size_t size)
{
    return BRIXPOSIX_WRAP(write)((int) (intptr_t) cookie, buf, size);
}

static int
cookie_seek(void *cookie, off64_t *offset, int whence)
{
    off_t pos = BRIXPOSIX_WRAP(lseek)((int) (intptr_t) cookie, (off_t) *offset,
                                      whence);

    if (pos < 0) {
        return -1;
    }
    *offset = (off64_t) pos;
    return 0;
}

static int
cookie_close(void *cookie)
{
    return BRIXPOSIX_WRAP(close)((int) (intptr_t) cookie);
}

static const cookie_io_functions_t g_cookie_fns = {
    .read = cookie_read, .write = cookie_write,
    .seek = cookie_seek, .close = cookie_close,
};

BRIXPOSIX_HIDDEN FILE *
brixposix_stream_open(int fd, const char *mode)
{
    FILE *fp = fopencookie((void *) (intptr_t) fd, mode, g_cookie_fns);

    if (fp == NULL) {
        int saved = errno;
        BRIXPOSIX_WRAP(close)(fd);
        errno = saved;
    }
    return fp;
}

#endif /* BRIX_PLATFORM_LINUX */
