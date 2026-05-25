/*
 * tmp_path.c — uniform temporary-file path construction for all subsystems.
 *
 * All three subsystems that write data atomically (WebDAV COPY, WebDAV TPC
 * pull, S3 PUT) previously used ad-hoc suffix formats.  Centralising the
 * format means:
 *
 *   - operators can clean orphaned temp files with a single glob:
 *       find /export -name "*.xrd-tmp.*" -mtime +1 -delete
 *   - the uniqueness strategy (pid + ngx_random()) is consistent everywhere
 *   - a future "scan for stale tmps" monitor only needs one pattern
 */

#include "tmp_path.h"

#include <stdio.h>
#include <unistd.h>

/*
 * WHAT: Construct a unique temporary file path based on a base (final) path.
 *
 * WHY: Atomic writes need a temp file that won't collide with existing files or concurrent
 *      writers. The format <base>.xrd-tmp.<pid>.<random> guarantees uniqueness across processes
 *      and retries, while the .xrd-tmp. prefix lets operators glob-clean orphaned temps.
 *
 * HOW: snprintf combines base_path + ".xrd-tmp." + getpid() + ngx_random(). Returns NGX_OK
 *      on success, NGX_ERROR if truncation occurs (n >= out_sz or n < 0). Caller uses this
 *      path with O_EXCL open to guarantee no collision.
 *
 * Parameters:
 *   base_path — the final destination path (used as prefix for temp name)
 *   out — output buffer to receive the constructed tmp path
 *   out_sz — size of out buffer
 */
ngx_int_t
xrootd_make_tmp_path(const char *base_path, char *out, size_t out_sz)
{
    int n;

    n = snprintf(out, out_sz, "%s.xrd-tmp.%ld.%u",
                 base_path, (long) getpid(), (unsigned) ngx_random());
    if (n < 0 || (size_t) n >= out_sz) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
