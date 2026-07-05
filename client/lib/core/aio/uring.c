/* File: client/lib/uring.c — optional io_uring disk ring (Phase 44) *
 * WHAT: Runtime probe + a disk ring that overlaps local-disk I/O with the
 *       network side of an xrdcp transfer.  Write-behind (downloads) queues a
 *       pwrite and returns so the next network read overlaps the disk write;
 *       read-ahead (uploads) keeps several reads in flight ahead of the
 *       delivery cursor.  Both present the synchronous, in-order, one-chunk face
 *       the pump expects (Option A) — one memcpy survives, which is the price of
 *       not touching the pump contract.
 *
 * WHY:  See uring.h — disk⇄network overlap is the biggest local-disk streaming
 *       win and is fully isolated behind the copy.c adapters.
 *
 * HOW:  liburing IORING_OP_READ/WRITE over a small pool of buffers, one op per
 *       buffer (user_data = buffer/slot index).  Stubs out under
 *       !BRIX_HAVE_LIBURING.  Buffered I/O only for now; an O_DIRECT tier is a
 *       documented deferral (it needs the fd opened O_DIRECT by copy.c). */

#include "uring.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if (BRIX_HAVE_LIBURING)

#include <liburing.h>

enum { SLOT_FREE = 0, SLOT_INFLIGHT = 1, SLOT_DONE = 2 };

typedef struct {
    int       state;   /* SLOT_FREE / INFLIGHT / DONE                  */
    uint64_t  seq;     /* submit order (read-ahead delivers by seq)    */
    uint8_t  *buf;     /* points into the slab                         */
    int64_t   off;     /* file offset of this op                       */
    size_t    len;     /* bytes requested                              */
    int32_t   res;     /* cqe->res once SLOT_DONE (>=0 bytes / -errno) */
} ring_slot;

struct brix_disk_ring {
    struct io_uring  ring;
    int              fd;
    unsigned         depth;
    size_t           bufsz;
    int              direct;        /* reserved (O_DIRECT tier deferred) */
    ring_slot       *slots;
    uint8_t         *slab;
    unsigned         inflight;

    /* write-behind */
    int              werr;          /* sticky -errno of a failed write   */

    /* read-ahead */
    uint64_t         ra_next_seq;   /* seq for the next submitted read   */
    uint64_t         ra_deliver_seq;/* seq the pump consumes next        */
    int64_t          ra_submit_off; /* next file offset to submit        */
    int64_t          ra_deliver_off;/* file offset the pump expects next */
    int              ra_eof;        /* a short/zero read seen            */
    int              ra_active;     /* read-ahead path engaged           */
};


/* probe */
int
brix_uring_available(void)
{
    static int cached = -1;
    struct io_uring        ring;
    struct io_uring_probe *probe;
    int                    ok;

    if (cached != -1) {
        return cached;
    }
    if (io_uring_queue_init(8, &ring, 0) < 0) {
        cached = 0;
        return 0;
    }
    probe = io_uring_get_probe_ring(&ring);
    ok = (probe != NULL
          && io_uring_opcode_supported(probe, IORING_OP_READ)
          && io_uring_opcode_supported(probe, IORING_OP_WRITE));
    if (probe != NULL) {
        io_uring_free_probe(probe);
    }
    io_uring_queue_exit(&ring);
    cached = ok ? 1 : 0;
    return cached;
}


/* lifecycle (no goto: a single failure helper) */
static brix_disk_ring *
brix_disk_ring_fail(brix_disk_ring *r, int ring_inited)
{
    if (r != NULL) {
        if (ring_inited) {
            io_uring_queue_exit(&r->ring);
        }
        free(r->slab);
        free(r->slots);
        free(r);
    }
    return NULL;
}

brix_disk_ring *
brix_disk_ring_create(int fd, unsigned depth, size_t bufsz, int direct,
                      brix_status *st)
{
    brix_disk_ring *r;

    if (depth < 2)   { depth = 2;   }
    if (depth > 256) { depth = 256; }

    if (!brix_uring_available()) {
        brix_status_set(st, XRDC_EUNSUPPORTED, 0, "io_uring unavailable");
        return NULL;
    }

    r = calloc(1, sizeof(*r));
    if (r == NULL) {
        brix_status_set(st, XRDC_ESOCK, errno, "disk ring alloc");
        return NULL;
    }
    r->fd     = fd;
    r->depth  = depth;
    r->bufsz  = bufsz;
    r->direct = direct;

    r->slots = calloc(depth, sizeof(ring_slot));
    if (r->slots == NULL) {
        brix_status_set(st, XRDC_ESOCK, errno, "disk ring slots");
        return brix_disk_ring_fail(r, 0);
    }
    r->slab = malloc((size_t) depth * bufsz);
    if (r->slab == NULL) {
        brix_status_set(st, XRDC_ESOCK, errno, "disk ring buffers");
        return brix_disk_ring_fail(r, 0);
    }
    {
        unsigned i;
        for (i = 0; i < depth; i++) {
            r->slots[i].buf = r->slab + (size_t) i * bufsz;
        }
    }

    if (io_uring_queue_init(depth, &r->ring, 0) < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "io_uring_queue_init");
        return brix_disk_ring_fail(r, 0);
    }
    return r;
}


/* slot helpers */
static ring_slot *
brix_ring_free_slot(brix_disk_ring *r, unsigned *idx)
{
    unsigned i;

    for (i = 0; i < r->depth; i++) {
        if (r->slots[i].state == SLOT_FREE) {
            *idx = i;
            return &r->slots[i];
        }
    }
    return NULL;
}

/* Reap exactly one completion (blocking), marking its slot SLOT_DONE with res.
 * Returns the slot index, or -1 on a wait error. */
static int
brix_ring_reap_one(brix_disk_ring *r)
{
    struct io_uring_cqe *cqe;
    unsigned             idx;

    if (io_uring_wait_cqe(&r->ring, &cqe) < 0) {
        return -1;
    }
    idx = (unsigned) io_uring_cqe_get_data64(cqe);
    if (idx < r->depth) {
        r->slots[idx].state = SLOT_DONE;
        r->slots[idx].res   = cqe->res;
    }
    io_uring_cqe_seen(&r->ring, cqe);
    if (r->inflight > 0) {
        r->inflight--;
    }
    return (int) idx;
}


/* write-behind (downloads) */
int
brix_disk_ring_pwrite(brix_disk_ring *r, int64_t off, const uint8_t *buf,
                      size_t n, brix_status *st)
{
    ring_slot           *slot;
    struct io_uring_sqe *sqe;
    unsigned             idx;

    if (n > r->bufsz) {
        brix_status_set(st, XRDC_ESOCK, 0, "disk ring chunk too large");
        return -1;
    }

    /* Reap a completed write to free a buffer when the window is full. */
    while ((slot = brix_ring_free_slot(r, &idx)) == NULL) {
        int done = brix_ring_reap_one(r);
        if (done < 0) {
            brix_status_set(st, XRDC_ESOCK, 0, "io_uring wait");
            return -1;
        }
        if (r->slots[done].res < 0
            || (size_t) r->slots[done].res < r->slots[done].len)
        {
            r->werr = r->slots[done].res < 0 ? -r->slots[done].res : EIO;
        }
        r->slots[done].state = SLOT_FREE;
    }

    if (r->werr) {
        brix_status_set(st, XRDC_ESOCK, r->werr, "local write: %s",
                        strerror(r->werr));
        return -1;
    }

    memcpy(slot->buf, buf, n);
    slot->off = off;
    slot->len = n;

    sqe = io_uring_get_sqe(&r->ring);
    if (sqe == NULL) {            /* SQ momentarily full — drain, then retry once */
        if (brix_ring_reap_one(r) < 0) {
            brix_status_set(st, XRDC_ESOCK, 0, "io_uring wait");
            return -1;
        }
        sqe = io_uring_get_sqe(&r->ring);
        if (sqe == NULL) {
            brix_status_set(st, XRDC_ESOCK, 0, "io_uring_get_sqe");
            return -1;
        }
    }
    io_uring_prep_write(sqe, r->fd, slot->buf, (unsigned) n, (__u64) off);
    io_uring_sqe_set_data64(sqe, idx);
    slot->state = SLOT_INFLIGHT;
    if (io_uring_submit(&r->ring) < 0) {
        slot->state = SLOT_FREE;
        brix_status_set(st, XRDC_ESOCK, errno, "io_uring_submit");
        return -1;
    }
    r->inflight++;
    return 0;
}

int
brix_disk_ring_flush(brix_disk_ring *r, brix_status *st)
{
    while (r->inflight > 0) {
        int done = brix_ring_reap_one(r);
        if (done < 0) {
            brix_status_set(st, XRDC_ESOCK, 0, "io_uring wait");
            return -1;
        }
        if (r->slots[done].state == SLOT_DONE
            && (r->slots[done].res < 0
                || (size_t) r->slots[done].res < r->slots[done].len))
        {
            r->werr = r->slots[done].res < 0 ? -r->slots[done].res : EIO;
        }
        r->slots[done].state = SLOT_FREE;
    }
    if (r->werr) {
        brix_status_set(st, XRDC_ESOCK, r->werr, "local write: %s",
                        strerror(r->werr));
        return -1;
    }
    return 0;
}


/* read-ahead (uploads) */
/* Submit reads to fill the window ahead of the delivery cursor. */
static int
brix_ring_readahead_fill(brix_disk_ring *r)
{
    while (r->inflight < r->depth && !r->ra_eof) {
        ring_slot           *slot;
        struct io_uring_sqe *sqe;
        unsigned             idx;

        slot = brix_ring_free_slot(r, &idx);
        if (slot == NULL) {
            break;
        }
        sqe = io_uring_get_sqe(&r->ring);
        if (sqe == NULL) {
            break;
        }
        slot->off = r->ra_submit_off;
        slot->len = r->bufsz;
        slot->seq = r->ra_next_seq++;
        io_uring_prep_read(sqe, r->fd, slot->buf, (unsigned) r->bufsz,
                           (__u64) slot->off);
        io_uring_sqe_set_data64(sqe, idx);
        slot->state = SLOT_INFLIGHT;
        if (io_uring_submit(&r->ring) < 0) {
            slot->state = SLOT_FREE;
            r->ra_next_seq--;
            return -1;
        }
        r->inflight++;
        r->ra_submit_off += (int64_t) r->bufsz;
    }
    return 0;
}

/* Drain (discard) all in-flight reads — used on a non-sequential seek. */
static void
brix_ring_readahead_reset(brix_disk_ring *r, int64_t off)
{
    while (r->inflight > 0) {
        (void) brix_ring_reap_one(r);
    }
    {
        unsigned i;
        for (i = 0; i < r->depth; i++) {
            r->slots[i].state = SLOT_FREE;
        }
    }
    r->ra_next_seq    = 0;
    r->ra_deliver_seq = 0;
    r->ra_submit_off  = off;
    r->ra_deliver_off = off;
    r->ra_eof         = 0;
}

ssize_t
brix_disk_ring_pread(brix_disk_ring *r, int64_t off, uint8_t *out, size_t cap,
                     brix_status *st)
{
    ring_slot *slot = NULL;
    unsigned   i;
    size_t     n;

    if (!r->ra_active) {
        r->ra_active      = 1;
        r->ra_submit_off  = off;
        r->ra_deliver_off = off;
    } else if (off != r->ra_deliver_off) {
        brix_ring_readahead_reset(r, off);   /* non-sequential: rewind window */
    }

    if (brix_ring_readahead_fill(r) < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "io_uring_submit");
        return -1;
    }

    /* Find the slot holding the next sequence to deliver. */
    for (i = 0; i < r->depth; i++) {
        if (r->slots[i].state != SLOT_FREE
            && r->slots[i].seq == r->ra_deliver_seq)
        {
            slot = &r->slots[i];
            break;
        }
    }
    if (slot == NULL) {
        return 0;   /* nothing in flight (window drained at EOF) -> EOF */
    }

    /* Reap until the target slot is done. */
    while (slot->state != SLOT_DONE) {
        if (brix_ring_reap_one(r) < 0) {
            brix_status_set(st, XRDC_ESOCK, 0, "io_uring wait");
            return -1;
        }
    }

    if (slot->res < 0) {
        int e = -slot->res;
        slot->state = SLOT_FREE;
        brix_status_set(st, XRDC_ESOCK, e, "local read: %s", strerror(e));
        return -1;
    }

    n = (size_t) slot->res;
    if (n > cap) {
        n = cap;   /* defensive: never overrun the caller buffer */
    }
    if (n > 0) {
        memcpy(out, slot->buf, n);
    }
    if ((size_t) slot->res < r->bufsz) {
        r->ra_eof = 1;   /* short read => EOF reached for a regular file */
    }
    slot->state = SLOT_FREE;
    r->ra_deliver_seq++;
    r->ra_deliver_off += (int64_t) slot->res;
    return (ssize_t) n;
}


/* bufsz accessor */
size_t
brix_disk_ring_bufsz(const brix_disk_ring *r)
{
    return r ? r->bufsz : 0;
}

/* destroy */
void
brix_disk_ring_destroy(brix_disk_ring *r)
{
    if (r == NULL) {
        return;
    }
    while (r->inflight > 0) {     /* drain so no CQE lands on freed memory */
        if (brix_ring_reap_one(r) < 0) {
            break;
        }
    }
    io_uring_queue_exit(&r->ring);
    free(r->slab);
    free(r->slots);
    free(r);
}

#else  /* !BRIX_HAVE_LIBURING — inert stubs */

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

#endif /* BRIX_HAVE_LIBURING */
