#include "cache_internal.h"


#include <errno.h>
#include <stdio.h>
#include <string.h>

/* ---- xrootd_cache_set_error — record cache fill failure state ----
 *
 * WHAT: Populates the cache_fill task with error result flags and message. Sets t->result to NGX_ERROR, records both xrd_error (kXR opcode) and sys_errno for dual-layer reporting. Falls back to "cache fill failed" if msg is NULL or empty. Stores into t->err_msg buffer (sizeof=256). */

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

/* ---- xrootd_cache_set_syserror — record failure with current errno ----
 *
 * WHAT: Convenience wrapper that captures the current errno value and formats it into a combined error message (prefix + strerror). Calls xrootd_cache_set_error() with both kXR opcode and captured sys_errno. Preserves errno across snprintf call via local variable. */

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

