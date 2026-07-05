/*
 * iobuf.h — per-handle read-ahead / write-back buffering engine for the FUSE
 * drivers, parameterised by a backend pread/pwrite pair.
 *
 * WHAT: an brix_iobuf coalesces sequential reads into one larger server read and
 *       small contiguous writes into one larger server write (flushed on
 *       flush/fsync/release), exactly the state machine both FUSE drivers used to
 *       open-code. The actual server I/O is supplied as two function pointers over
 *       an opaque backend handle, so one engine serves every backend:
 *         - legacy: brix_file_read/_write over a pinned brix_conn+brix_file;
 *         - async : afh_pread (mfile/webfile) + brix_mfile_pwrite.
 * WHY:  the read/write/flush logic was duplicated byte-for-byte across xrootdfs.c
 *       and xrootdfs_legacy.c (~220 LoC); this is the one copy.
 * HOW:  NOT thread-safe — the caller (the FUSE handler) holds its per-handle mutex
 *       across the call, matching the historical behaviour. Read-ahead applies only
 *       to read-only handles; write-back only to writable ones; either is disabled
 *       by passing size 0.
 */
#ifndef XRDC_IOBUF_H
#define XRDC_IOBUF_H

#include "brix.h"

#include <stddef.h>
#include <sys/types.h>   /* off_t, ssize_t */

/* Backend I/O: pread returns bytes (>=0) or <0 on error; pwrite returns 0 / -1.
 * Both set *st on failure. `be` is the opaque backend handle. */
typedef ssize_t (*brix_iobuf_pread_fn)(void *be, int64_t off, void *buf,
                                       size_t n, brix_status *st);
typedef int     (*brix_iobuf_pwrite_fn)(void *be, int64_t off, const void *buf,
                                        size_t n, brix_status *st);

typedef struct {
    void                 *be;        /* opaque backend handle                    */
    brix_iobuf_pread_fn   pread;
    brix_iobuf_pwrite_fn  pwrite;
    int                   writable;
    size_t                ra_size;   /* read-ahead window (0 disables)           */
    size_t                wb_size;   /* write-back window (0 disables)           */

    unsigned char        *rbuf;      /* read-ahead: holds [rbuf_off, +rbuf_len)  */
    off_t                 rbuf_off;
    size_t                rbuf_len;
    off_t                 ra_next;    /* next sequential offset (prefetch hint)   */

    unsigned char        *wbuf;      /* write-back: pending [wbuf_off, +wbuf_len) */
    off_t                 wbuf_off;
    size_t                wbuf_len;
} brix_iobuf;

/* Configure (zero-inits the buffers). */
void brix_iobuf_init(brix_iobuf *b, void *be, brix_iobuf_pread_fn pr,
                     brix_iobuf_pwrite_fn pw, int writable,
                     size_t ra_size, size_t wb_size);

/* Read `n` bytes at `off` into `out` (serving from / refilling the read-ahead
 * buffer; flushing pending writes first for coherence). Returns bytes (>=0) or
 * -1 with *st set. */
ssize_t brix_iobuf_read(brix_iobuf *b, off_t off, char *out, size_t n,
                        brix_status *st);

/* Write `n` bytes at `off` (coalescing into the write-back buffer). Returns 0 on
 * success (all `n` accepted) or -1 with *st set. */
int  brix_iobuf_write(brix_iobuf *b, off_t off, const char *in, size_t n,
                      brix_status *st);

/* Flush any pending buffered writes to the backend. 0 / -1 (st). */
int  brix_iobuf_flush(brix_iobuf *b, brix_status *st);

/* Free the read-ahead / write-back buffers (does NOT flush — call flush first). */
void brix_iobuf_dispose(brix_iobuf *b);

#endif /* XRDC_IOBUF_H */
