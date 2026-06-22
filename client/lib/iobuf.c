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
xrdc_iobuf_init(xrdc_iobuf *b, void *be, xrdc_iobuf_pread_fn pr,
                xrdc_iobuf_pwrite_fn pw, int writable,
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
xrdc_iobuf_flush(xrdc_iobuf *b, xrdc_status *st)
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

ssize_t
xrdc_iobuf_read(xrdc_iobuf *b, off_t off, char *out, size_t n, xrdc_status *st)
{
    ssize_t r;
    size_t  avail;

    /* Coherence: a read on a writable handle must see pending buffered writes. */
    if (b->wbuf_len > 0 && xrdc_iobuf_flush(b, st) != 0) {
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

    /* Refill unless [off, off+n) is already buffered. Prefetch the whole window
     * only on sequential access so random reads don't repeatedly over-fetch. */
    if (!(b->rbuf_len > 0 && off >= b->rbuf_off
          && (size_t) (off - b->rbuf_off) + n <= b->rbuf_len)) {
        size_t fill = (off == b->ra_next) ? b->ra_size : n;

        r = b->pread(b->be, (int64_t) off, b->rbuf, fill, st);
        if (r < 0) {
            return -1;
        }
        b->rbuf_off = off;
        b->rbuf_len = (size_t) r;
    }

    /* Serve from the buffer (a short count only happens at EOF). */
    avail = 0;
    if (off >= b->rbuf_off && (size_t) (off - b->rbuf_off) < b->rbuf_len) {
        size_t inbuf = b->rbuf_len - (size_t) (off - b->rbuf_off);
        avail = (inbuf < n) ? inbuf : n;
        memcpy(out, b->rbuf + (off - b->rbuf_off), avail);
    }
    b->ra_next = off + (off_t) avail;
    return (ssize_t) avail;
}

int
xrdc_iobuf_write(xrdc_iobuf *b, off_t off, const char *in, size_t n,
                 xrdc_status *st)
{
    /* Write-back disabled, or a write at/above the buffer size: flush any pending
     * buffer and write straight through. */
    if (b->wb_size == 0 || n >= b->wb_size) {
        if (xrdc_iobuf_flush(b, st) != 0) {
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
        if (xrdc_iobuf_flush(b, st) != 0) {
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
xrdc_iobuf_dispose(xrdc_iobuf *b)
{
    free(b->rbuf);
    free(b->wbuf);
    b->rbuf = NULL;
    b->wbuf = NULL;
}
