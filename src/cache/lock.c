#include "cache_internal.h"

#if (NGX_THREADS)

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static int
xrootd_cache_try_lock(xrootd_cache_fill_t *t)
{
    int  fd, n;
    char body[64];

    fd = open(t->lock_path, O_CREAT | O_EXCL | O_WRONLY | O_NOCTTY | O_CLOEXEC, 0600);
    if (fd < 0) {
        return (errno == EEXIST) ? 0 : -1;
    }

    n = snprintf(body, sizeof(body), "pid=%ld\n", (long) getpid());
    if (n > 0) {
        ssize_t wr;

        wr = write(fd, body, (size_t) n);
        if (wr < 0) {
            int err;

            err = errno;
            close(fd);
            unlink(t->lock_path);
            errno = err;
            return -1;
        }
    }
    close(fd);

    return 1;
}

int
xrootd_cache_wait_or_lock(xrootd_cache_fill_t *t, int *owned)
{
    time_t start;

    *owned = 0;
    start = time(NULL);

    for (;;) {
        int ready;

        ready = xrootd_cache_file_ready(t->cache_path);
        if (ready == 1) {
            return 0;
        }
        if (ready < 0) {
            xrootd_cache_set_syserror(t, kXR_IOError,
                                      "cache path is not usable");
            return -1;
        }

        ready = xrootd_cache_try_lock(t);
        if (ready == 1) {
            *owned = 1;
            return 0;
        }
        if (ready < 0) {
            xrootd_cache_set_syserror(t, kXR_IOError,
                                      "cache lock create failed");
            return -1;
        }

        if (time(NULL) - start >= t->conf->cache_lock_timeout) {
            xrootd_cache_set_error(t, kXR_FileLocked, 0,
                                   "timed out waiting for cache fill lock");
            return -1;
        }

        usleep(XROOTD_CACHE_LOCK_POLL_USEC);
    }
}

#endif /* NGX_THREADS */
