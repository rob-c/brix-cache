/*
 * iobuf.c — per-handle read-ahead / write-back engine (see iobuf.h).
 *
 * Lifted verbatim from the two FUSE drivers' identical xfs_read / xfs_write /
 * flush_wbuf logic; the only thing abstracted is the server I/O (the b->pread /
 * b->pwrite function pointers over b->be).
 */
#include "iobuf.h"

#include <stdlib.h>
#include <string.h>

void
brix_iobuf_init(brix_iobuf *b, void *be, brix_iobuf_pread_fn pr,
                brix_iobuf_pwrite_fn pw, int writable,
                size_t ra_size, size_t wb_size)
{
    memset(b, 0, sizeof(*b));
    b->be       = be;
    b->pread    = pr;
    b->pwrite   = pw;
    b->writable = writable;
    b->ra_size  = ra_size;
    b->wb_size  = wb_size;
}

int
brix_iobuf_flush(brix_iobuf *b, brix_status *st)
{
    if (b->wbuf == NULL || b->wbuf_len == 0) {
        return 0;
    }
    if (b->pwrite(b->be, (int64_t) b->wbuf_off, b->wbuf, b->wbuf_len, st) != 0) {
        return -1;
    }
    b->wbuf_len = 0;
    return 0;
}

/* ---- Report whether a byte range is already resident in the read-ahead buffer ----
 *
 * WHAT: Returns non-zero when [off, off+n) lies entirely within the currently
 * buffered window [rbuf_off, rbuf_off+rbuf_len); returns zero otherwise (buffer
 * empty, range starts before the window, or range extends past the window end).
 *
 * WHY: The refill decision reads clearest as "refill unless already cached". A
 * single named predicate keeps the caller from carrying an inverted compound
 * condition that is easy to get subtly wrong.
 *
 * HOW:
 *   1. A window with rbuf_len == 0 holds nothing, so the range is not cached.
 *   2. The range must start at or after the window start (off >= rbuf_off).
 *   3. The range end, measured from the window start, must fit within rbuf_len.
 */
static int
iobuf_range_cached(const brix_iobuf *b, off_t off, size_t n)
{
    return b->rbuf_len > 0 && off >= b->rbuf_off
           && (size_t) (off - b->rbuf_off) + n <= b->rbuf_len;
}

/* ---- Refill the read-ahead buffer at a new offset ----
 *
 * WHAT: Issues one backend pread into rbuf starting at off and records the new
 * window (rbuf_off/rbuf_len). Returns 0 on success, or -1 on backend error (with
 * st set by the backend).
 *
 * WHY: Isolates the fetch-and-record side effect so the serve path stays pure and
 * the read orchestrator stays a flat sequence.
 *
 * HOW:
 *   1. Prefetch the whole read-ahead window on sequential access (off == ra_next),
 *      otherwise fetch only the requested n bytes so random reads don't
 *      repeatedly over-fetch.
 *   2. pread into rbuf; propagate a negative result as -1.
 *   3. Record the window origin and the (possibly short, at EOF) fill length.
 */
static int
iobuf_refill(brix_iobuf *b, off_t off, size_t n, brix_status *st)
{
    ssize_t r;
    size_t  fill = (off == b->ra_next) ? b->ra_size : n;

    r = b->pread(b->be, (int64_t) off, b->rbuf, fill, st);
    if (r < 0) {
        return -1;
    }
    b->rbuf_off = off;
    b->rbuf_len = (size_t) r;
    return 0;
}

/* ---- Copy the requested bytes out of the read-ahead buffer ----
 *
 * WHAT: Copies up to n bytes for offset off out of rbuf into out and returns the
 * number of bytes copied (a short count only happens at EOF); returns 0 when off
 * falls outside the buffered window.
 *
 * WHY: Keeps the memcpy bounds arithmetic in one pure helper so the orchestrator
 * only has to advance the read-ahead cursor by the returned count.
 *
 * HOW:
 *   1. If off is outside [rbuf_off, rbuf_off+rbuf_len), nothing is available.
 *   2. Clamp the copy to whichever is smaller: the bytes left in the window or n.
 *   3. memcpy from the in-window position and return the copied count.
 */
static size_t
iobuf_serve(const brix_iobuf *b, off_t off, char *out, size_t n)
{
    size_t inbuf;
    size_t avail;

    if (!(off >= b->rbuf_off && (size_t) (off - b->rbuf_off) < b->rbuf_len)) {
        return 0;
    }
    inbuf = b->rbuf_len - (size_t) (off - b->rbuf_off);
    avail = (inbuf < n) ? inbuf : n;
    memcpy(out, b->rbuf + (off - b->rbuf_off), avail);
    return avail;
}

ssize_t
brix_iobuf_read(brix_iobuf *b, off_t off, char *out, size_t n, brix_status *st)
{
    size_t avail;

    /* Coherence: a read on a writable handle must see pending buffered writes. */
    if (b->wbuf_len > 0 && brix_iobuf_flush(b, st) != 0) {
        return -1;
    }

    /* Direct read for writable handles, when read-ahead is off, or for reads
     * larger than the buffer (no benefit from caching those). */
    if (b->writable || b->ra_size == 0 || n >= b->ra_size) {
        return b->pread(b->be, (int64_t) off, out, n, st);
    }

    if (b->rbuf == NULL) {
        b->rbuf = malloc(b->ra_size);
        if (b->rbuf == NULL) {           /* fall back to a direct read on OOM */
            return b->pread(b->be, (int64_t) off, out, n, st);
        }
    }

    /* Refill unless [off, off+n) is already buffered. */
    if (!iobuf_range_cached(b, off, n) && iobuf_refill(b, off, n, st) != 0) {
        return -1;
    }

    /* Serve from the buffer (a short count only happens at EOF). */
    avail = iobuf_serve(b, off, out, n);
    b->ra_next = off + (off_t) avail;
    return (ssize_t) avail;
}

int
brix_iobuf_write(brix_iobuf *b, off_t off, const char *in, size_t n,
                 brix_status *st)
{
    /* Write-back disabled, or a write at/above the buffer size: flush any pending
     * buffer and write straight through. */
    if (b->wb_size == 0 || n >= b->wb_size) {
        if (brix_iobuf_flush(b, st) != 0) {
            return -1;
        }
        return b->pwrite(b->be, (int64_t) off, in, n, st);
    }

    if (b->wbuf == NULL) {
        b->wbuf = malloc(b->wb_size);
        if (b->wbuf == NULL) {           /* fall back to a direct write on OOM */
            return b->pwrite(b->be, (int64_t) off, in, n, st);
        }
    }

    /* A non-contiguous write, or one that won't fit, flushes the current buffer
     * first; then this write starts (or extends) a fresh contiguous run. */
    if (b->wbuf_len > 0
        && (off != b->wbuf_off + (off_t) b->wbuf_len
            || b->wbuf_len + n > b->wb_size)) {
        if (brix_iobuf_flush(b, st) != 0) {
            return -1;
        }
    }
    if (b->wbuf_len == 0) {
        b->wbuf_off = off;
    }
    memcpy(b->wbuf + b->wbuf_len, in, n);
    b->wbuf_len += n;
    return 0;
}

void
brix_iobuf_dispose(brix_iobuf *b)
{
    free(b->rbuf);
    free(b->wbuf);
    b->rbuf = NULL;
    b->wbuf = NULL;
}
