/*
 * client/lib/platform/darwin/preload_stream.c - a FILE* over a shim descriptor
 *
 * WHAT: brixposix_stream_open for Darwin's libc: funopen hands back a REAL
 *       FILE* whose backing store is the shim's shadow fd, so libc keeps doing
 *       the buffering, fgets, fscanf, ungetc and feof.
 * WHY:  Same contract as the glibc fopencookie body; BSD stdio spells the
 *       callbacks with int lengths and an fpos_t seek, and selects read or
 *       write by which callback is present rather than by a mode string.
 * HOW:  The callbacks are the shim's own wrappers (brixposix_*), never the
 *       libc functions they interpose.
 */

#include "platform/preload.h"

#if BRIX_PLATFORM_DARWIN

#include "brixposix_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static int
cookie_read(void *cookie, char *buf, int size)
{
    ssize_t n = BRIXPOSIX_WRAP(read)((int) (intptr_t) cookie, buf, (size_t) size);

    return (n < 0) ? -1 : (int) n;
}

static int
cookie_write(void *cookie, const char *buf, int size)
{
    ssize_t n = BRIXPOSIX_WRAP(write)((int) (intptr_t) cookie, buf, (size_t) size);

    return (n < 0) ? -1 : (int) n;
}

static fpos_t
cookie_seek(void *cookie, fpos_t offset, int whence)
{
    return (fpos_t) BRIXPOSIX_WRAP(lseek)((int) (intptr_t) cookie, (off_t) offset,
                                          whence);
}

static int
cookie_close(void *cookie)
{
    return BRIXPOSIX_WRAP(close)((int) (intptr_t) cookie);
}

BRIXPOSIX_HIDDEN FILE *
brixposix_stream_open(int fd, const char *mode)
{
    int   writing = (mode != NULL && mode[0] == 'w');
    FILE *fp = funopen((void *) (intptr_t) fd,
                       writing ? NULL : cookie_read,
                       writing ? cookie_write : NULL,
                       cookie_seek, cookie_close);

    if (fp == NULL) {
        int saved = errno;
        BRIXPOSIX_WRAP(close)(fd);
        errno = saved;
    }
    return fp;
}

#endif /* BRIX_PLATFORM_DARWIN */
