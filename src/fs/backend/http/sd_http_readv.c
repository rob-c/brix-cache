/*
 * sd_http_readv.c — vectored-read coalescing for the HTTP-origin driver.
 *
 * WHAT: The `preadv` vtable slot: read one contiguous span with a single ranged
 *       GET and scatter it across the caller's iovecs, plus the loop
 *       (sd_http_pread_full) that covers a span larger than one GET.
 *
 * WHY:  kXR_readv requests and pgread batches describe ONE contiguous span split
 *       into many page-sized iovecs. Without this slot brix_sd_obj_preadv falls
 *       back to one driver->pread per iovec — one HTTP round trip per 4 KiB —
 *       which turns a single 4 MiB vector read into a thousand requests against
 *       the origin and times the client out. sd_remote already coalesces this
 *       way over S3; a WebDAV/HTTP origin speaks the same Range grammar, so it
 *       can too. It lives in its own TU rather than in sd_http_read.c because
 *       that file is at the size cap and coalescing is its own concern: the
 *       single-request read path knows nothing about iovecs.
 *
 * HOW:  Both functions are pure composition over sd_http_pread (sd_http_read.c)
 *       — no transport, credential, or endpoint knowledge lives here.
 */

#include "sd_http_internal.h"    /* sd_http_pread + the obj/inst layout */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* sd_http_pread_full — fill `len` bytes at `off`, looping over the per-request
 * SD_HTTP_PREAD_MAX cap.
 *
 * WHAT: Bytes read (short only at EOF), or -1 with errno set when the FIRST
 *       range GET failed.
 * WHY:  sd_http_pread returns at most SD_HTTP_PREAD_MAX per call and a 200-mode
 *       origin can return less still, so a caller that needs a whole span must
 *       loop; only preadv does, and only here.
 * HOW:  Repeat sd_http_pread until the span is covered. A 0 means EOF and ends
 *       the loop; a partial span already read is reported as a short read rather
 *       than discarded, matching pread(2). */
static ssize_t
sd_http_pread_full(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    size_t done = 0;

    while (done < len) {
        ssize_t n = sd_http_pread(obj, (char *) buf + done, len - done,
                                  off + (off_t) done);
        if (n < 0) {
            return (done > 0) ? (ssize_t) done : -1;
        }
        if (n == 0) {
            break;                                 /* EOF */
        }
        done += (size_t) n;
    }
    return (ssize_t) done;
}

/* sd_http_preadv — vectored read as ONE contiguous range GET, scattered.
 *
 * WHAT: Reads [off, off + sum(iov_len)) and scatters it across the iovecs.
 *       Total bytes read (short = EOF), or -1 with errno set.
 * WHY:  kXR_readv runs and pgread batches describe one contiguous span split
 *       into many page-sized iovecs. Without this slot brix_sd_obj_preadv falls
 *       back to one driver->pread per iovec — one HTTP round trip per 4 KiB —
 *       which turns a single 4 MiB vector read into a thousand requests and
 *       times the client out. sd_remote already coalesces this way over S3; a
 *       WebDAV origin speaks the same Range grammar, so it can too.
 * HOW:  A single iovec reads straight into the caller's buffer (no copy). A
 *       scattered call fills one malloc'd bounce buffer and memcpys out of it —
 *       the HTTP body is copied out of the response anyway, so the bounce costs
 *       one extra pass over bytes that have already crossed the socket. */
ssize_t
sd_http_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    size_t   total = 0, scattered;
    ssize_t  n;
    char    *bounce;
    int      i;

    for (i = 0; i < iovcnt; i++) {
        total += iov[i].iov_len;
    }
    if (total == 0) {
        return 0;
    }
    if (iovcnt == 1) {
        return sd_http_pread_full(obj, iov[0].iov_base, iov[0].iov_len, off);
    }

    bounce = malloc(total);
    if (bounce == NULL) {
        errno = ENOMEM;
        return -1;
    }
    n = sd_http_pread_full(obj, bounce, total, off);
    if (n < 0) {
        free(bounce);
        return -1;
    }

    scattered = 0;
    for (i = 0; i < iovcnt && scattered < (size_t) n; i++) {
        size_t take = iov[i].iov_len;

        if (take > (size_t) n - scattered) {
            take = (size_t) n - scattered;
        }
        memcpy(iov[i].iov_base, bounce + scattered, take);
        scattered += take;
    }
    free(bounce);
    return n;
}
