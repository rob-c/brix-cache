/*
 * slice_fill.c — Phase 26 Step B: fetch a single cache slice from the origin.
 *
 * This reuses the existing origin-protocol primitives (origin_protocol.c) and
 * the xrootd_cache_fill_t task struct.  A slice fill differs from the whole-file
 * fetch (fetch.c) only in that:
 *   - the byte window is constrained to [slice_start, slice_start+slice_len),
 *     clamped to the origin file size (the last slice may be short);
 *   - cache_path/part_path/lock_path point at the per-slice files;
 *   - the file-level .__xrds.meta sidecar (keyed on file_cache_path) is checked
 *     for an origin size change and, on mismatch, every sibling slice is evicted
 *     before this slice is written.
 *
 * The worker is fire-and-forget from the stream plane's point of view: the
 * kXR_read handler schedules it and answers the client with kXR_wait; the client
 * retries and finds the slice ready (or waits again).  No suspend/resume of the
 * client connection is needed, so the done callback only frees nothing and
 * returns.
 */

#include "cache_internal.h"
#include "slice.h"
#include "meta.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>


/* ngx_min for off_t without signedness surprises. */
static off_t
slice_min_off(off_t a, off_t b)
{
    return (a < b) ? a : b;
}


/*
 * xrootd_cache_slice_fetch_origin — fetch one slice window from the origin into
 * t->part_path and atomically rename it to t->cache_path (the slice file).
 *
 * Returns 0 on success, -1 on error (t->result/err_msg set), 1 on admission
 * decline (never happens for slices — admission is a whole-file policy).
 */
int
xrootd_cache_slice_fetch_origin(xrootd_cache_fill_t *t)
{
    xrootd_cache_origin_conn_t oc;
    u_char                     fhandle[XRD_FHANDLE_LEN];
    int                        outfd;
    off_t                      window, pos;
    ngx_log_t                 *log;

    outfd = -1;
    log = (t->c != NULL) ? t->c->log : NULL;

    if (xrootd_cache_origin_connect(t, &oc) != 0
        || xrootd_cache_origin_bootstrap(t, &oc) != 0
        || xrootd_cache_origin_open(t, &oc, fhandle) != 0)
    {
        xrootd_cache_origin_close(&oc);
        return -1;
    }

    /*
     * Consistency: if a prior fill recorded a different origin size for this
     * file, every sibling slice is now stale.  Evict them all and rewrite the
     * meta before this slice lands.  (etag is not available from the origin
     * open path, so validation is size-based — still catches repacks.)
     */
    if (xrootd_slice_meta_validate(t->file_cache_path, t->file_size, "", log)
        == NGX_DECLINED)
    {
        (void) xrootd_slice_evict_all(t->file_cache_path, log);
    }
    (void) xrootd_slice_meta_write(t->file_cache_path, t->file_size, "", 0, log);

    /* Clamp the slice window to the real file size (last slice may be short). */
    if (t->slice_start >= t->file_size) {
        window = 0;
    } else {
        window = slice_min_off(t->slice_len, t->file_size - t->slice_start);
    }

    outfd = open(t->part_path,
                 O_CREAT | O_TRUNC | O_WRONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW,
                 0644);
    if (outfd < 0) {
        xrootd_cache_origin_close_file(&oc, fhandle);
        xrootd_cache_origin_close(&oc);
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache slice part open failed");
        return -1;
    }

    pos = 0;
    while (pos < window) {
        size_t got = 0;
        size_t want = (size_t) slice_min_off((off_t) XROOTD_CACHE_FETCH_CHUNK,
                                             window - pos);

        if (xrootd_cache_origin_read_chunk(t, &oc, fhandle, outfd,
                                           (uint64_t) (t->slice_start + pos),
                                           want, &got) != 0)
        {
            close(outfd);
            unlink(t->part_path);
            xrootd_cache_origin_close_file(&oc, fhandle);
            xrootd_cache_origin_close(&oc);
            return -1;
        }
        if (got == 0) {
            break;   /* unexpected EOF inside the window */
        }
        pos += (off_t) got;
    }

    if (fsync(outfd) != 0 || close(outfd) != 0) {
        unlink(t->part_path);
        xrootd_cache_origin_close_file(&oc, fhandle);
        xrootd_cache_origin_close(&oc);
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache slice part flush failed");
        return -1;
    }
    outfd = -1;

    xrootd_cache_origin_close_file(&oc, fhandle);
    xrootd_cache_origin_close(&oc);

    if (rename(t->part_path, t->cache_path) != 0) {
        unlink(t->part_path);
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache slice rename failed");
        return -1;
    }

    return 0;
}


/*
 * xrootd_cache_slice_fill_thread — thread-pool worker: lock the slice, skip if
 * another worker already filled it, otherwise fetch the window from origin.
 * Mirrors xrootd_cache_fill_thread but uses the slice fetch + the slice paths.
 */
void
xrootd_cache_slice_fill_thread(void *data, ngx_log_t *log)
{
    xrootd_cache_fill_t *t = data;
    int                  owned = 0;

    (void) log;

    t->result    = NGX_OK;
    t->xrd_error = 0;
    t->sys_errno = 0;
    t->err_msg[0] = '\0';

    if (xrootd_cache_ensure_parent(t->cache_path) != 0) {
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache slice parent mkdir failed");
        return;
    }

    if (xrootd_cache_wait_or_lock(t, &owned) != 0) {
        return;   /* lock wait failed (t->result set) */
    }
    if (!owned) {
        return;   /* another worker filled it while we waited — success */
    }

    if (xrootd_cache_file_ready(t->cache_path) == 1) {
        unlink(t->lock_path);
        return;
    }

    (void) xrootd_cache_slice_fetch_origin(t);

    unlink(t->lock_path);
}
