#include "cache_internal.h"

#if (NGX_THREADS)

#include <errno.h>
#include <stdio.h>
#include <string.h>

void
xrootd_cache_set_error(xrootd_cache_fill_t *t, int xrd_error,
    int sys_errno, const char *msg)
{
    t->result = NGX_ERROR;
    t->xrd_error = xrd_error;
    t->sys_errno = sys_errno;

    if (msg == NULL || msg[0] == '\0') {
        msg = "cache fill failed";
    }

    snprintf(t->err_msg, sizeof(t->err_msg), "%s", msg);
}

void
xrootd_cache_set_syserror(xrootd_cache_fill_t *t, int xrd_error,
    const char *prefix)
{
    char msg[256];
    int  err;

    err = errno;
    snprintf(msg, sizeof(msg), "%s: %s", prefix, strerror(err));
    xrootd_cache_set_error(t, xrd_error, err, msg);
}

#endif /* NGX_THREADS */
