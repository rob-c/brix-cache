#ifndef XRDC_URING_H
#define XRDC_URING_H

/* ---- File: client/lib/uring.h — optional io_uring disk ring (Phase 44) ----
 *
 * WHAT: A thin liburing wrapper for the native client.  CB-W2 uses it to give
 *       the xrdcp transfer pump disk⇄network overlap: a deep queue of buffers
 *       lets the local disk write of chunk k proceed while the network read of
 *       chunk k+1 is in flight (download), and symmetrically for uploads — while
 *       still presenting the synchronous, in-order, one-chunk face the pump
 *       expects (Option A).  The socket event loop engine swap (CB-W4) layers on
 *       top later.
 *
 * WHY:  The pump (client/lib/copy.c) is strictly serial today — a download
 *       blocks the network read until the disk write completes.  Overlapping
 *       them is the single biggest local-disk streaming win, and it is fully
 *       isolated behind two adapters, so the pump's tested cancel/progress/
 *       short-read discipline is untouched.
 *
 * HOW:  Everything is gated by BRIX_HAVE_LIBURING.  When undefined the whole
 *       TU compiles to inert stubs (brix_uring_available() -> 0, create -> NULL),
 *       so the epoll/pread path is the only thing in the binary and there is no
 *       -luring dependency — identical to the always-compiled krb5 stub model. */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "brix.h"   /* brix_status */

/* Memoized runtime probe: 1 iff a ring can be created and the disk-ring opcodes
 * (READ/WRITE) are supported; 0 otherwise (and in any stub build). */
int brix_uring_available(void);

typedef struct brix_disk_ring brix_disk_ring;

/*
 * Create a disk ring bound to an already-open local fd.
 *   depth  = max ops in flight = number of internal buffers (clamped 2..256)
 *   bufsz  = per-op buffer size (match the pump chunk, e.g. XRDC_COPY_CHUNK)
 *   direct = reserved for an O_DIRECT tier (currently a no-op hint; buffered I/O)
 * Returns NULL (with *st set) on failure or when built without liburing.
 */
brix_disk_ring *brix_disk_ring_create(int fd, unsigned depth, size_t bufsz,
                                      int direct, brix_status *st);

/* Drain all in-flight ops and free the ring.  Safe on NULL. */
void brix_disk_ring_destroy(brix_disk_ring *r);

/*
 * Write-behind: copy n bytes (n <= bufsz) into a ring buffer and queue a pwrite
 * at off, returning before it completes so the caller can fetch the next chunk
 * while the disk drains.  Blocks only to reap the oldest completion when the
 * window is full.  Returns 0 on success, -1 (with *st) on a prior write's error.
 */
int brix_disk_ring_pwrite(brix_disk_ring *r, int64_t off, const uint8_t *buf,
                          size_t n, brix_status *st);

/* Drain every queued write to completion (call before close/rename).  Returns 0
 * or -1 (with *st) if any queued write failed. */
int brix_disk_ring_flush(brix_disk_ring *r, brix_status *st);

/*
 * Read-ahead: deliver up to cap bytes at off (sequential offsets expected — the
 * pump reads in order), keeping up to depth reads in flight ahead of the
 * delivery cursor.  Returns the byte count (>0), 0 at EOF, or -1 (with *st) on
 * error.  A non-sequential off transparently resets the window.
 */
ssize_t brix_disk_ring_pread(brix_disk_ring *r, int64_t off, uint8_t *out,
                             size_t cap, brix_status *st);

/* Return the per-op buffer size the ring was created with.  Safe on NULL (returns 0).
 * Callers that issue writes larger than bufsz must split them into bufsz-sized pieces
 * before calling brix_disk_ring_pwrite — that function asserts n <= bufsz. */
size_t brix_disk_ring_bufsz(const brix_disk_ring *r);

#endif /* XRDC_URING_H */
