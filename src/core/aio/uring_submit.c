#include "core/ngx_brix_module.h"
#include "aio.h"
#include "uring.h"
#include "core/compat/safe_size.h"   /* Phase 27 W1: overflow-checked size math */


/* File: src/aio/uring_submit.c — io_uring SQE submission (Phase 44)
 * WHAT: Maps a bound AIO thread task to an io_uring opcode and submits its SQE
 *       (SB-W3: READ/WRITE; SB-W4 extends this with READV and WRITEV+linked
 *       FSYNC).  The completion side (slot table + reaper + cqe->res -> OUT
 *       translation) lives in uring.c; this TU owns only submission.
 *
 * WHY:  Submission is the only place that differs from the thread-pool tier —
 *       the six *_aio_t structs, the *_aio_done callbacks, and every call site
 *       are reused verbatim.  Keeping submission in its own TU keeps the seam
 *       small and the reaper independent of opcode prep.
 *
 * HOW:  brix_uring_op_for() identifies the op by the task's bound worker-fn
 *       pointer.  brix_uring_submit() reserves a completion slot, builds the
 *       SQE from the task's IN fields, encodes (generation<<32|slot) into
 *       user_data, and submits; any failure releases the slot and returns
 *       *posted = 0 so the caller falls through to the thread pool.  Whole TU
 *       is compiled only when BRIX_HAVE_LIBURING is defined (the config
 *       script lists it in the stream module srcs only in that build). */

#if (BRIX_HAVE_LIBURING)

/* Max iovecs in a single readv/writev SQE.  Matches the thread-pool coalescer's
 * preadv cap (BRIX_READV_PREADV_MAXIOV) and stays well under UIO_MAXIOV. */
#define BRIX_URING_IOV_MAX  64

/*
 * brix_readv_is_single_group — true iff the whole readv is one contiguous
 * same-fd region of 1..IOV_MAX non-empty segments.  Only then can one
 * IORING_OP_READV scatter the contiguous file region into the per-segment
 * payload buffers; any gap, fd change, zero-length segment, or overflow routes
 * to the thread pool (which coalesces run-by-run).
 */
static ngx_int_t
brix_readv_is_single_group(brix_readv_aio_t *t)
{
    size_t i;

    if (t->segment_count == 0 || t->segment_count > BRIX_URING_IOV_MAX) {
        return 0;
    }
    for (i = 0; i < t->segment_count; i++) {
        if (t->segments[i].read_length == 0 || t->segments[i].offset < 0) {
            return 0;
        }
        if (t->segments[i].fd != t->segments[0].fd) {
            return 0;
        }
        if (i > 0
            && t->segments[i].offset != t->segments[i - 1].offset
               + (off_t) t->segments[i - 1].read_length)
        {
            return 0;
        }
    }
    return 1;
}

/*
 * brix_writev_is_single_contig_fd — true iff the whole writev is one
 * contiguous same-fd region of 1..IOV_MAX non-empty segments, so one
 * IORING_OP_WRITEV can gather the buffers into the contiguous file region.
 */
static ngx_int_t
brix_writev_is_single_contig_fd(brix_writev_aio_t *t)
{
    size_t i;

    if (t->n_segs == 0 || t->n_segs > BRIX_URING_IOV_MAX) {
        return 0;
    }
    for (i = 0; i < t->n_segs; i++) {
        if (t->segs[i].wlen == 0 || t->segs[i].offset < 0) {
            return 0;
        }
        if (t->segs[i].fd != t->segs[0].fd) {
            return 0;
        }
        if (i > 0
            && t->segs[i].offset != t->segs[i - 1].offset
               + (off_t) t->segs[i - 1].wlen)
        {
            return 0;
        }
    }
    return 1;
}

/*
 * brix_uring_op_for — see uring.h.  The worker-fn the task was bound to via
 * brix_task_bind() is the op identity.  readv/writev map to io_uring only for
 * a single contiguous group; multi-fd/multi-group fall to the pool, as do
 * pgread (per-page CRC interleave) and dirlist (opendir/readdir).
 */
brix_uring_op_e
brix_uring_op_for(ngx_thread_task_t *task)
{
    void (*fn)(void *, ngx_log_t *) = task->handler;

    if (fn == brix_read_aio_thread) {
        return XRD_URING_OP_READ;
    }
    if (fn == brix_write_aio_thread) {
        return XRD_URING_OP_WRITE;
    }
    if (fn == brix_readv_aio_thread) {
        return brix_readv_is_single_group(task->ctx)
               ? XRD_URING_OP_READV : XRD_URING_OP_NONE;
    }
    if (fn == brix_writev_write_aio_thread) {
        return brix_writev_is_single_contig_fd(task->ctx)
               ? XRD_URING_OP_WRITEV : XRD_URING_OP_NONE;
    }

    return XRD_URING_OP_NONE;
}

/*
 * brix_uring_nsqe — how many SQEs (and in-flight CQEs) the op consumes: 2 for
 * a WRITEV whose do_sync links a trailing FSYNC, 1 otherwise.
 */
static uint32_t
brix_uring_nsqe(brix_uring_op_e op, ngx_thread_task_t *task)
{
    if (op == XRD_URING_OP_WRITEV) {
        brix_writev_aio_t *t = task->ctx;
        return t->do_sync ? 2 : 1;
    }
    return 1;
}

/*
 * brix_uring_prep_primary — fill the primary SQE from the task's IN fields
 * and report the fd (for a possible trailing FSYNC).  readv/writev build their
 * iovec from the segment descriptors, allocated from the connection pool so it
 * stays valid until the CQE (io_uring reads the iovec asynchronously).  Returns
 * NGX_ERROR on an unmapped op or OOM (caller falls back).
 */
static ngx_int_t
brix_uring_prep_primary(struct io_uring_sqe *sqe, brix_uring_op_e op,
    ngx_thread_task_t *task, int *fd_out)
{
    switch (op) {

    case XRD_URING_OP_READ: {
        brix_read_aio_t *t = task->ctx;
        io_uring_prep_read(sqe, t->fd, t->databuf, (unsigned) t->rlen,
                           (__u64) t->offset);
        *fd_out = t->fd;
        return NGX_OK;
    }

    case XRD_URING_OP_WRITE: {
        brix_write_aio_t *t = task->ctx;
        io_uring_prep_write(sqe, t->fd, t->data, (unsigned) t->len,
                            (__u64) t->offset);
        *fd_out = t->fd;
        return NGX_OK;
    }

    case XRD_URING_OP_READV: {
        brix_readv_aio_t *t = task->ctx;
        struct iovec       *iov;
        size_t              i;

        iov = brix_palloc_array(t->c->pool, t->segment_count,
                                  sizeof(struct iovec));
        if (iov == NULL) {
            return NGX_ERROR;
        }
        for (i = 0; i < t->segment_count; i++) {
            iov[i].iov_base = t->segments[i].payload_ptr;
            iov[i].iov_len  = (size_t) t->segments[i].read_length;
        }
        io_uring_prep_readv(sqe, t->segments[0].fd, iov,
                            (unsigned) t->segment_count,
                            (__u64) t->segments[0].offset);
        *fd_out = t->segments[0].fd;
        return NGX_OK;
    }

    case XRD_URING_OP_WRITEV: {
        brix_writev_aio_t *t = task->ctx;
        struct iovec        *iov;
        size_t               i;

        iov = brix_palloc_array(t->c->pool, t->n_segs, sizeof(struct iovec));
        if (iov == NULL) {
            return NGX_ERROR;
        }
        for (i = 0; i < t->n_segs; i++) {
            iov[i].iov_base = (void *) t->segs[i].data;
            iov[i].iov_len  = (size_t) t->segs[i].wlen;
        }
        io_uring_prep_writev(sqe, t->segs[0].fd, iov, (unsigned) t->n_segs,
                             (__u64) t->segs[0].offset);
        *fd_out = t->segs[0].fd;
        return NGX_OK;
    }

    default:
        return NGX_ERROR;
    }
}

/*
 * brix_uring_submit — see uring.h.  Reserve a completion slot, build the
 * primary SQE (plus a linked FSYNC for a do_sync writev), stash the task
 * identity, encode the UAF-safe cookie, and submit.  For the 2-SQE chain the SQ
 * free space is checked up front so the second get_sqe can never fail mid-build
 * (no un-prep needed).  Every failure path releases the slot and leaves
 * *posted = 0 so the caller uses the next tier; no op is ever dropped.
 */
ngx_int_t
brix_uring_submit(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_task_t *task, brix_uring_op_e op, ngx_flag_t *posted)
{
    brix_uring_t      *u = brix_uring_worker();
    brix_uring_slot_t *slot;
    struct io_uring_sqe *sqe;
    uint32_t             idx;
    uint32_t             nsqe;
    uint64_t             cookie;
    int                  fd = -1;

    (void) ctx;
    (void) c;

    *posted = 0;

    if (u == NULL) {
        return NGX_OK;                 /* defensive: selector already checked */
    }

    nsqe = brix_uring_nsqe(op, task);
    if (io_uring_sq_space_left(&u->ring) < nsqe) {
        return NGX_OK;                 /* SQ too full for the chain -> pool    */
    }

    slot = brix_uring_slot_acquire(u, &idx);
    if (slot == NULL) {
        return NGX_OK;                 /* slot table full -> thread pool       */
    }

    sqe = io_uring_get_sqe(&u->ring);  /* non-NULL: space checked above        */
    if (brix_uring_prep_primary(sqe, op, task, &fd) != NGX_OK) {
        brix_uring_slot_release(u, idx);
        return NGX_OK;
    }

    slot->task    = task;
    slot->done_fn = task->event.handler;
    slot->op_kind = (uint8_t) op;
    /* in_use was set by slot_acquire; generation is current. */

    cookie = ((uint64_t) slot->generation << 32) | idx;
    io_uring_sqe_set_data64(sqe, cookie);

    if (nsqe == 2) {
        /* Linked, in-order FSYNC barrier (kXR_writev sync flag).  IOSQE_IO_LINK
         * makes the kernel run the fsync only after the writev succeeds; on a
         * writev failure the fsync is auto-cancelled.  Its CQE carries the
         * sentinel cookie so the reaper drops it (best-effort, ignored return,
         * matching the thread-pool path). */
        struct io_uring_sqe *fsqe;

        io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
        fsqe = io_uring_get_sqe(&u->ring);   /* non-NULL: space checked        */
        io_uring_prep_fsync(fsqe, fd, 0);
        io_uring_sqe_set_data64(fsqe, BRIX_URING_FSYNC_COOKIE);
    }

    if (io_uring_submit(&u->ring) < 0) {
        brix_uring_slot_release(u, idx);
        return NGX_OK;
    }

    u->inflight += nsqe;
    *posted = 1;
    return NGX_OK;
}

#endif /* BRIX_HAVE_LIBURING */
