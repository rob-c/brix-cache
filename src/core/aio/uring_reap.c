#include "core/ngx_brix_module.h"
#include "aio.h"
#include "uring.h"
#include "uring_internal.h"

#if (BRIX_HAVE_LIBURING)
#include <unistd.h>

/* File: src/core/aio/uring_reap.c — io_uring completion reaper and the UAF-safe
 * completion-slot table (phase-79 split from uring.c).
 * WHAT: Owns everything that runs on a completed CQE: the generation-stamped
 *       slot table that maps a CQE cookie back to its in-flight task, the
 *       per-op result translation, and the eventfd-driven harvest loop wired
 *       into the worker's epoll.  The ring singleton and bring-up live in
 *       uring.c; detection/gating lives in uring_probe.c.
 *
 * WHY:  The reaper is the security- and correctness-critical half of the
 *       backend: it must drop stale and orphaned CQEs without ever touching
 *       freed task/connection memory, and post done-callbacks out-of-line so a
 *       re-submitting callback never re-enters the harvest loop.
 *
 * HOW:  Entirely under #if (BRIX_HAVE_LIBURING) — in a stub build no ring
 *       exists, so none of this is reachable and the file is empty.  The slot
 *       acquire/release helpers are also called from the submit path
 *       (uring_submit.c); the eventfd handler is installed by uring.c. */

/* completion-slot table (UAF-safe task mapping) */
/* brix_uring_slot_at — bounds-checked slot lookup; NULL if idx is out of
 * range (a corrupt/forged user_data). */
static brix_uring_slot_t *
brix_uring_slot_at(brix_uring_t *u, uint32_t idx)
{
    return idx < u->queue_depth ? &u->slots[idx] : NULL;
}

/* brix_uring_slot_acquire — claim the first free slot.  The selector checks
 * inflight < queue_depth before calling, so a free slot always exists; the
 * linear scan over <=4096 entries is negligible.  Returns NULL only if the
 * table is unexpectedly full (caller then falls back to the thread pool).
 * Non-static: also called from uring_submit.c. */
brix_uring_slot_t *
brix_uring_slot_acquire(brix_uring_t *u, uint32_t *idx_out)
{
    uint32_t i;

    for (i = 0; i < u->queue_depth; i++) {
        if (!u->slots[i].in_use) {
            u->slots[i].in_use = 1;
            *idx_out = i;
            return &u->slots[i];
        }
    }

    return NULL;
}

/* brix_uring_slot_release — free a slot and bump its generation so any later
 * CQE carrying the old generation is recognised as stale and dropped.
 * Non-static: also called from uring_submit.c. */
void
brix_uring_slot_release(brix_uring_t *u, uint32_t idx)
{
    brix_uring_slot_t *s = &u->slots[idx];

    s->in_use     = 0;
    s->task       = NULL;
    s->done_fn    = NULL;
    s->owner      = NULL;
    s->orphaned   = 0;
    s->generation++;
    (void) u;
}

/* brix_uring_orphan_owner — mark every in-flight slot owned by a dying
 * connection so the reaper drops its late CQE without touching the task (freed
 * with the connection pool) or posting its completion event.  See uring.h. */
void
brix_uring_orphan_owner(void *owner)
{
    brix_uring_t *u = brix_uring_worker();
    uint32_t        i;

    if (u == NULL || !u->ring_active || owner == NULL) {
        return;
    }
    for (i = 0; i < u->queue_depth; i++) {
        if (u->slots[i].in_use && u->slots[i].owner == owner) {
            u->slots[i].orphaned = 1;
        }
    }
}

/*
 * brix_uring_apply_cqe — translate cqe->res into the task's OUT fields, the
 * same fields the worker-thread fn would have set.  io_uring reports failures
 * as a negative -errno in cqe->res (it does NOT set errno).
 *
 * Returns 1 when the task is fully complete and its done-callback should be
 * posted, 0 when more CQEs are still expected for this task (the linked
 * writev+fsync chain, added in SB-W4).  READV/WRITEV cases also land in SB-W4;
 * READ/WRITE are handled here so the reaper is complete for the hot path.
 */
static ngx_int_t
brix_uring_apply_cqe(brix_uring_slot_t *slot, struct io_uring_cqe *cqe)
{
    ngx_thread_task_t *task = slot->task;
    int32_t            res  = cqe->res;

    switch (slot->op_kind) {

    case XRD_URING_OP_READ: {
        brix_read_aio_t *t = task->ctx;
        if (res < 0) { t->nread = -1;  t->io_errno = -res; }
        else         { t->nread = res; t->io_errno = 0;    }
        return 1;
    }

    case XRD_URING_OP_WRITE: {
        brix_write_aio_t *t = task->ctx;
        if (res < 0) { t->nwritten = -1;  t->io_errno = -res; }
        else         { t->nwritten = res; t->io_errno = 0;    }
        return 1;
    }

    case XRD_URING_OP_READV: {
        brix_readv_aio_t *t = task->ctx;
        size_t              total = 0, i;

        /* Single contiguous group (op_for gated it): one IORING_OP_READV
         * scattered into the per-segment payload pointers.  The wire segment
         * headers were already written at plan-build, so nothing to fix up here
         * — only the totals + error state, matching brix_readv_aio_thread. */
        for (i = 0; i < t->segment_count; i++) {
            total += t->segments[i].read_length;
        }
        if (res < 0) {
            t->io_error = 1; t->bytes_read_total = 0; t->response_bytes = 0;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "readv I/O error: %s", strerror(-res));
        } else if ((size_t) res != total) {
            t->io_error = 1; t->bytes_read_total = 0; t->response_bytes = 0;
            snprintf(t->err_msg, sizeof(t->err_msg), "readv past EOF");
        } else {
            t->io_error = 0;
            t->bytes_read_total = (size_t) res;
            t->response_bytes   = t->segment_count * BRIX_READV_SEGSIZE
                                  + (size_t) res;
        }
        return 1;
    }

    case XRD_URING_OP_WRITEV: {
        brix_writev_aio_t *t = task->ctx;
        size_t               total = 0, i;

        /* Single contiguous same-fd group: one IORING_OP_WRITEV gathering the
         * segment buffers.  io_error encodes the failure kind exactly as
         * brix_writev_write_aio_thread (1 = hard error, 2 = short write).  A
         * trailing FSYNC (when do_sync) is a separate linked SQE whose CQE the
         * reaper drops — best-effort, matching the pool path's ignored return. */
        for (i = 0; i < t->n_segs; i++) {
            total += t->segs[i].wlen;
        }
        if (res < 0) {
            t->io_error = 1; t->bytes_total = 0;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "writev I/O error: %s", strerror(-res));
        } else if ((size_t) res < total) {
            t->io_error = 2; t->bytes_total = (size_t) res;
            snprintf(t->err_msg, sizeof(t->err_msg), "writev short write");
        } else {
            t->io_error = 0; t->bytes_total = (size_t) res;
        }
        return 1;
    }

    default:
        /* pgread/dirlist are never routed to io_uring (op_for -> NONE). */
        return 1;
    }
}

/*
 * uring_cqe_retire — acknowledge one CQE and balance the in-flight counter.
 *
 * WHAT: Marks the CQE seen (returning its ring slot to the kernel) and
 *       decrements the inflight gauge that the submission selector consults.
 * WHY:  Every CQE — real completion, stale generation, orphan, or trailing
 *       FSYNC — must be retired exactly once; centralising the pair keeps the
 *       accounting impossible to miss on any per-CQE early return.
 * HOW:  io_uring_cqe_seen + a guarded decrement (never underflows).
 */
static void
uring_cqe_retire(brix_uring_t *u, struct io_uring_cqe *cqe)
{
    io_uring_cqe_seen(&u->ring, cqe);
    if (u->inflight > 0) { u->inflight--; }
}

/*
 * uring_complete_one — classify and complete a single harvested CQE.
 *
 * WHAT: The per-CQE body of the completion reaper: decode the slot cookie,
 *       run the generation/orphan guards, translate the result into the task
 *       and post its done-callback.
 * WHY:  Extracted from brix_uring_eventfd_handler so the reaper loop stays a
 *       trivial drain and each guard reads as one early return.
 * HOW:  Early-return ladder — trailing-FSYNC drop, stale-generation drop,
 *       orphaned-owner drop (slot recycled, task never touched), then the
 *       normal translate + ngx_post_event path.  Every exit retires the CQE
 *       via uring_cqe_retire; done-callbacks are never invoked inline.
 */
static void
uring_complete_one(brix_uring_t *u, struct io_uring_cqe *cqe)
{
    uint64_t             ud = io_uring_cqe_get_data64(cqe);
    uint32_t             idx;
    uint32_t             gen;
    brix_uring_slot_t *slot;

    /* 2-pre. trailing FSYNC of a linked writev+fsync chain: carries no slot;
     * fsync is best-effort (the pool path ignores its return), so drop the
     * CQE and just balance inflight. */
    if (ud == BRIX_URING_FSYNC_COOKIE) {
        uring_cqe_retire(u, cqe);
        return;
    }

    idx  = (uint32_t) (ud & 0xffffffffULL);
    gen  = (uint32_t) (ud >> 32);
    slot = brix_uring_slot_at(u, idx);

    /* 2a. generation guard: a stale CQE for a recycled/dead slot is dropped
     * safely.  (The done-callback's own ctx->destroyed check remains the
     * authoritative guard for the connection.) */
    if (slot == NULL || !slot->in_use || slot->generation != gen) {
        uring_cqe_retire(u, cqe);
        return;
    }

    /* 2a'. orphaned slot: the owning connection was torn down while this
     * op was in flight — the task's memory died with the connection pool.
     * Drop the CQE without dereferencing the task or posting its (equally
     * dead) completion event, and recycle the slot. */
    if (slot->orphaned) {
        brix_uring_slot_release(u, idx);
        uring_cqe_retire(u, cqe);
        return;
    }

    /* 2b. translate + post (the done-callback is task->event.handler, set
     * at brix_task_bind time). */
    if (brix_uring_apply_cqe(slot, cqe)) {
        ngx_thread_task_t *task = slot->task;

        task->event.complete = 1;
        ngx_post_event(&task->event, &ngx_posted_events);
        brix_uring_slot_release(u, idx);
    }

    uring_cqe_retire(u, cqe);
}

/*
 * brix_uring_eventfd_handler — the completion reaper.
 *
 * Wired into the worker's epoll as the read handler of the fake connection that
 * wraps the ring's registered eventfd.  This is the public-API analogue of
 * nginx core's ngx_epoll_eventfd_handler() (the libaio bridge): drain the
 * eventfd counter, then harvest every ready CQE — validating each slot's
 * generation, translating the result into the task, and posting the task's
 * done-callback to ngx_posted_events.  Done-callbacks are NEVER invoked inline
 * here: nginx's posted-events drain runs them after process_events, so a
 * callback that re-submits the next read window never re-enters the harvest
 * loop (re-entrancy-safe).  Non-static: installed by uring_install_eventfd()
 * in uring.c.
 */
void
brix_uring_eventfd_handler(ngx_event_t *ev)
{
    ngx_connection_t    *evc = ev->data;
    brix_uring_t      *u   = evc->data;
    struct io_uring_cqe *cqe;
    uint64_t             counter;
    ssize_t              n;

    /* 1. drain the eventfd counter (mirrors core's first step). */
    n = read(u->eventfd, &counter, sizeof(counter));
    if (n != (ssize_t) sizeof(counter)) {
        if (n == -1 && (ngx_errno == NGX_EAGAIN || ngx_errno == NGX_EINTR)) {
            return;
        }
        ngx_log_error(NGX_LOG_ALERT, evc->log, ngx_errno,
                      "brix: io_uring eventfd read() failed");
        return;
    }

    /* 2. harvest all ready completions. */
    while (io_uring_peek_cqe(&u->ring, &cqe) == 0) {
        uring_complete_one(u, cqe);
    }
}

#endif /* BRIX_HAVE_LIBURING */
