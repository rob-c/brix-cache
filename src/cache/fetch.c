#include "cache_internal.h"


#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ---- xrootd_cache_fetch_origin — origin file fetch and cache fill ----
 *
 * WHAT: Thread-pool worker function that fetches a complete file from the configured XRootD origin into a local `.part` file,
 *       then atomically renames it to the cache path. Handles admission filtering (size + regex) before caching begins. */

/* ---- Fetch protocol sequence ----
 *
 * HOW: Connect → bootstrap (handshake+login) → open source file → read loop → fsync local part → rename atomic.
 *      Each phase is isolated with error cleanup (origin close on failure). Returns 1 for policy rejection, -1 for errors, 0 for success. */

/* ---- Admission filter invariant ----
 *
 * WHY: Large files (> cache_max_file_size) are not cached unless basename matches include regex.
 *      Rejection returns NGX_DECLINED (not error) so done callback redirects client to origin directly instead of failing. */

int
xrootd_cache_fetch_origin(xrootd_cache_fill_t *t)
{
    xrootd_cache_origin_conn_t oc;
    u_char                    fhandle[XRD_FHANDLE_LEN];
    int                       outfd;
    uint64_t                  offset;

    outfd = -1;
    offset = 0;

    if (xrootd_cache_origin_connect(t, &oc) != 0) {
        xrootd_cache_origin_close(&oc);
        return -1;
    }

    if (xrootd_cache_origin_bootstrap(t, &oc) != 0) {
        xrootd_cache_origin_close(&oc);
        return -1;
    }

    if (xrootd_cache_origin_open(t, &oc, fhandle) != 0) {
        xrootd_cache_origin_close(&oc);
        return -1;
    }

    /*
     * Admission filter: skip caching when the file is larger than the
     * configured limit AND its basename doesn't match the include regex.
     * Returning 1 (not -1) tells the caller this is a policy decision, not
     * an error — the done callback will redirect the client to the origin.
     */
    if (t->conf->cache_max_file_size > 0
        && t->file_size > t->conf->cache_max_file_size)
    {
        const char *basename = strrchr(t->clean_path, '/');
        basename = (basename != NULL) ? basename + 1 : t->clean_path;

        if (!t->conf->cache_include_regex_set
            || regexec(&t->conf->cache_include_regex, basename,
                       0, NULL, 0) != 0)
        {
            xrootd_cache_origin_close_file(&oc, fhandle);
            xrootd_cache_origin_close(&oc);
            t->result = NGX_DECLINED;
            return 1;
        }
    }

    /*
     * Open the part file in a single atomic call — O_CREAT|O_TRUNC creates or
     * truncates, O_NOFOLLOW rejects any symlink placed at part_path between
     * calls (prevents TOCTOU / symlink-swap attacks).  The prior unlink() was
     * removed: it created a race window and is made redundant by O_TRUNC.
     */
    outfd = open(t->part_path,
                 O_CREAT | O_TRUNC | O_WRONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW,
                 0644);
    if (outfd < 0) {
        xrootd_cache_origin_close_file(&oc, fhandle);
        xrootd_cache_origin_close(&oc);
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache part file open failed");
        return -1;
    }

    for (;;) {
        size_t got;

        got = 0;
        if (xrootd_cache_origin_read_chunk(t, &oc, fhandle, outfd, offset,
                                           XROOTD_CACHE_FETCH_CHUNK,
                                           &got) != 0) {
            close(outfd);
            unlink(t->part_path);
            xrootd_cache_origin_close_file(&oc, fhandle);
            xrootd_cache_origin_close(&oc);
            return -1;
        }

        offset += (uint64_t) got;
        if (got < XROOTD_CACHE_FETCH_CHUNK) {
            break;
        }
    }

    if (fsync(outfd) != 0) {
        close(outfd);
        unlink(t->part_path);
        xrootd_cache_origin_close_file(&oc, fhandle);
        xrootd_cache_origin_close(&oc);
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache part file fsync failed");
        return -1;
    }

    if (close(outfd) != 0) {
        unlink(t->part_path);
        xrootd_cache_origin_close_file(&oc, fhandle);
        xrootd_cache_origin_close(&oc);
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache part file close failed");
        return -1;
    }
    outfd = -1;

    xrootd_cache_origin_close_file(&oc, fhandle);
    xrootd_cache_origin_close(&oc);

    if (rename(t->part_path, t->cache_path) != 0) {
        unlink(t->part_path);
        xrootd_cache_set_syserror(t, kXR_IOError,
                                  "cache part file rename failed");
        return -1;
    }

    return 0;
}

