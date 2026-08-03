/* uring_stub.c — inert io_uring disk-ring implementation.
 *
 * WHAT: The !BRIX_HAVE_LIBURING half of the disk-ring API: every entry point
 *       resolves, but probing reports unavailable and construction fails with
 *       XRDC_EUNSUPPORTED, so callers fall back to plain pread/pwrite.
 *
 * WHY:  Split out of uring.c, which crossed the 600-line cap
 *       (coding-standards §1). Keeping the two halves in separate TUs also
 *       makes "which one did this build link?" answerable from the object list.
 *
 * HOW:  The whole file compiles to nothing when liburing IS present, so both
 *       TUs stay unconditionally in LIB_SRCS and exactly one defines the
 *       symbols. Contract and doc comments live in uring.h. */

#include "uring.h"

#if !(BRIX_HAVE_LIBURING)

int
brix_uring_available(void)
{
    return 0;
}

brix_disk_ring *
brix_disk_ring_create(int fd, unsigned depth, size_t bufsz, int direct,
                      brix_status *st)
{
    (void) fd; (void) depth; (void) bufsz; (void) direct;
    brix_status_set(st, XRDC_EUNSUPPORTED, 0,
                    "io_uring not compiled in (rebuild with liburing)");
    return NULL;
}

void
brix_disk_ring_destroy(brix_disk_ring *r)
{
    (void) r;
}

int
brix_disk_ring_pwrite(brix_disk_ring *r, int64_t off, const uint8_t *buf,
                      size_t n, brix_status *st)
{
    (void) r; (void) off; (void) buf; (void) n; (void) st;
    return -1;
}

int
brix_disk_ring_flush(brix_disk_ring *r, brix_status *st)
{
    (void) r; (void) st;
    return -1;
}

ssize_t
brix_disk_ring_pread(brix_disk_ring *r, int64_t off, uint8_t *out, size_t cap,
                     brix_status *st)
{
    (void) r; (void) off; (void) out; (void) cap; (void) st;
    return -1;
}

size_t
brix_disk_ring_bufsz(const brix_disk_ring *r)
{
    (void) r;
    return 0;
}

#endif /* !BRIX_HAVE_LIBURING */
