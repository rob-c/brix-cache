/*
 * aio_engine_cqe.c - io_uring CQE translation + completion wait loop.
 * Phase-38 split of aio_engine.c; behavior-identical.
 */
#include "aio_internal.h"

#if (BRIX_HAVE_LIBURING)

/* ---- Translate one slot-poll CQE into a readiness event ----
 *
 * WHAT: Given a poll CQE whose user_data is `ud` (slot-generation in the high
 * 32 bits, slot index in the low 32), validate it against the live slot table
 * and, if current, fill *ev with the aconn pointer + EPOLL* mask and re-arm the
 * multishot poll if it auto-disarmed.  Returns 1 if *ev was written, 0 if the
 * CQE was stale/cancelled and dropped.  Does NOT mark the CQE seen (caller does).
 *
 * WHY: Preserves the UAF discipline shared with the server ring — a poll that
 * completes after its aconn was reconnected or freed carries an outdated
 * generation and must be dropped.  Isolating the guard + translation keeps the
 * wait loop within complexity limits without altering the drop semantics.
 *
 * HOW:
 *   1. Split `ud` into slot index and generation.
 *   2. Drop (return 0) unless the slot is in range, in use, generation-matched,
 *      still bound to an aconn, and the CQE result is non-negative.
 *   3. Map poll bits to EPOLL* bits: POLLIN|POLLHUP|POLLERR -> EPOLLIN,
 *      POLLOUT -> EPOLLOUT; write aconn pointer + mask into *ev.
 *   4. If the multishot auto-disarmed (no IORING_CQE_F_MORE), re-arm it.
 *   5. Return 1.
 */
static int
uring_translate_slot_cqe(brix_loop *l, struct io_uring_cqe *cqe,
    struct epoll_event *ev, uint64_t ud)
{
    uint32_t    slot = AIO_UD_SLOT(ud);
    uint32_t    gen  = AIO_UD_GEN(ud);
    brix_aconn *ac;
    uint32_t    ev_mask = 0;

    if (!(slot < AIO_URING_SLOTS && l->uslots[slot].in_use
          && l->uslots[slot].gen == gen
          && l->uslots[slot].ac != NULL && cqe->res >= 0)) {
        return 0;   /* stale/cancelled CQE for a recycled slot — dropped. */
    }

    ac = l->uslots[slot].ac;
    if (cqe->res & (POLLIN | POLLHUP | POLLERR)) { ev_mask |= EPOLLIN; }
    if (cqe->res & POLLOUT)                      { ev_mask |= EPOLLOUT; }
    ev->data.ptr = ac;
    ev->events   = ev_mask;
    /* Re-arm if the multishot auto-disarmed (no F_MORE). */
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        (void) uring_poll_submit(l, ac, ac->epoll_events);
    }
    return 1;
}


/* ---- P44-C: complete one multishot RECV CQE ----
 *
 * WHAT: Validate the CQE against the slot table, append the provided buffer's
 * bytes to ac->rbuf, recycle the buffer, and parse — the CQE *is* the read, so
 * no readiness event is produced (always returns 0 events).
 *
 * WHY: This is the ii-b replacement for the plaintext arm of aconn_do_read:
 * completions carry the bytes, so calling read(2) as well would race the
 * kernel for the socket's byte stream.  Error/EOF handling mirrors
 * aconn_read_plain exactly (parse buffered frames first, then fail).
 *
 * HOW: stale gen -> recycle buffer + drop.  res > 0 -> copy into rbuf, recycle,
 * parse.  res == 0 -> peer close.  -ENOBUFS -> transient (buffers were all in
 * flight); just re-arm.  Other negatives -> transport error.  If the multishot
 * auto-disarmed (!F_MORE) and the conn survived, re-arm it.
 */
/* Validate a RECV CQE against the slot table and return the live conn, or NULL
 * (recycling the rx buffer) when the slot is stale — the conn re-armed or was
 * torn down while this completion sat in the CQ ring. */
static brix_aconn *
uring_rxtx_recv_resolve(brix_loop *l, struct io_uring_cqe *cqe, uint64_t ud)
{
    uint32_t slot = AIO_UD_SLOT(ud);

    if (slot < AIO_URING_SLOTS && l->uslots[slot].in_use
        && l->uslots[slot].gen == AIO_UD_GEN(ud)
        && l->uslots[slot].ac != NULL) {
        return l->uslots[slot].ac;
    }
    uring_rxtx_recycle(l, cqe);          /* stale: never leak the rx buffer */
    return NULL;
}

/* Append a positive-length RECV CQE's provided-buffer bytes to ac->rbuf,
 * recycle the buffer, and parse.  Returns -1 (transport error already posted)
 * if the read buffer can't grow, 0 otherwise. */
static int
uring_rxtx_recv_data(brix_loop *l, brix_aconn *ac, struct io_uring_cqe *cqe)
{
    brix_status st;

    if (xbuf_reserve(&ac->rbuf, (size_t) cqe->res) != 0) {
        uring_rxtx_recycle(l, cqe);
        brix_status_set(&st, XRDC_EPROTO, 0, "out of memory (read buffer)");
        aconn_on_transport_error(ac, &st);
        return -1;
    }
    if (cqe->flags & IORING_CQE_F_BUFFER) {
        uint16_t bid = (uint16_t) (cqe->flags >> IORING_CQE_BUFFER_SHIFT);
        memcpy(ac->rbuf.buf + ac->rbuf.len,
               l->brx_pool + (size_t) bid * AIO_URING_RXBUF_SZ,
               (size_t) cqe->res);
        ac->rbuf.len += (size_t) cqe->res;
    }
    uring_rxtx_recycle(l, cqe);          /* copy done — buffer back to kernel */
    aconn_parse(ac);
    return 0;
}

static void
uring_rxtx_recv_cqe(brix_loop *l, struct io_uring_cqe *cqe, uint64_t ud)
{
    uint32_t    slot = AIO_UD_SLOT(ud);
    brix_aconn *ac;
    brix_status st;

    ac = uring_rxtx_recv_resolve(l, cqe, ud);
    if (ac == NULL) {
        return;
    }

    if (cqe->res > 0) {
        if (uring_rxtx_recv_data(l, ac, cqe) != 0) {
            return;
        }
    } else if (cqe->res == 0) {
        brix_status_set(&st, XRDC_ESOCK, 0, "connection closed by peer");
        aconn_parse(ac);                 /* deliver any final complete frame */
        if (!ac->dead) {
            aconn_on_transport_error(ac, &st);
        }
        return;
    } else if (cqe->res != -ENOBUFS && cqe->res != -EAGAIN
               && cqe->res != -EINTR) {
        brix_status_set(&st, XRDC_ESOCK, -cqe->res, "read: %s",
                        strerror(-cqe->res));
        aconn_on_transport_error(ac, &st);
        return;
    }

    /* Re-arm if the multishot auto-disarmed and the conn is still with us
     * (parse may have killed it). */
    if (!(cqe->flags & IORING_CQE_F_MORE)
        && slot < AIO_URING_SLOTS && l->uslots[slot].in_use
        && l->uslots[slot].gen == AIO_UD_GEN(ud) && !ac->dead) {
        l->uslots[slot].recv_armed = 0;
        (void) uring_recv_submit(l, ac);
    }
}


/* ---- P44-C: complete one one-shot SEND CQE ----
 *
 * WHAT: Advance ac->wbuf.start by the sent byte count — exactly what
 * aconn_do_write does on a send(2) return — and submit the next staged slice
 * if the queue is still non-empty (short send, or frames appended while this
 * SEND was in flight).
 *
 * HOW: stale gen -> drop (the cancel path already cleared send_inflight).
 * res < 0: EINTR/EAGAIN retries the same slice; anything else is a transport
 * error (EPIPE from a dead peer lands here — MSG_NOSIGNAL semantics).
 */
static void
uring_rxtx_send_cqe(brix_loop *l, struct io_uring_cqe *cqe, uint64_t ud)
{
    uint32_t    slot = AIO_UD_SLOT(ud);
    brix_aconn *ac;
    brix_status st;

    if (!(slot < AIO_URING_SLOTS && l->uslots[slot].in_use
          && l->uslots[slot].gen == AIO_UD_GEN(ud)
          && l->uslots[slot].ac != NULL)) {
        return;                          /* stale: conn re-armed or gone */
    }
    ac = l->uslots[slot].ac;
    l->uslots[slot].send_inflight = 0;
    l->uslots[slot].stage_len     = 0;

    if (cqe->res < 0) {
        if (cqe->res == -EINTR || cqe->res == -EAGAIN) {
            (void) uring_rxtx_send_submit(l, ac);   /* retry the slice */
            return;
        }
        brix_status_set(&st, XRDC_ESOCK, -cqe->res, "write: %s",
                        strerror(-cqe->res));
        aconn_on_transport_error(ac, &st);
        return;
    }

    ac->wbuf.start += (size_t) cqe->res;
    if (ac->wbuf.start >= ac->wbuf.len) {
        ac->wbuf.start = ac->wbuf.len = 0;          /* fully flushed */
    } else {
        (void) uring_rxtx_send_submit(l, ac);       /* short send / more queued */
    }
}


/* ---- Translate one CQE into at most one readiness event ----
 *
 * WHAT: Classify a single CQE by its user_data and, for the evfd wake and live
 * slot polls, fill *ev with the corresponding readiness event.  Returns 1 if
 * *ev was written, 0 otherwise.  Always marks the CQE seen before returning.
 *
 * WHY: Factors the user_data classification (ignore / evfd / slot-op) out of
 * the wait loop so each case is a single linear path; the loop then just
 * accumulates the return count.  The seen-marking is centralised here so every
 * consumed CQE is retired exactly once regardless of classification.
 *
 * HOW:
 *   1. Read the CQE's user_data.
 *   2. AIO_URING_IGNORE_UD (a cancel echo): mark seen, return 0.
 *   3. AIO_URING_EVFD_UD (cross-thread wake): write a loop-tagged EPOLLIN event,
 *      mark seen, return 1.
 *   4. Otherwise dispatch on the packed op kind: RECV/SEND CQEs (P44-C) carry
 *      the bytes and are completed in place (0 events); a poll CQE goes through
 *      uring_translate_slot_cqe.  Mark seen, return the result.
 */
static int
uring_translate_cqe(brix_loop *l, struct io_uring_cqe *cqe,
    struct epoll_event *ev)
{
    uint64_t ud = io_uring_cqe_get_data64(cqe);
    int      produced = 0;

    if (ud == AIO_URING_IGNORE_UD) {
        io_uring_cqe_seen(&l->uring, cqe);
        return 0;
    }
    if (ud == AIO_URING_EVFD_UD) {
        ev->data.ptr = l;
        ev->events   = EPOLLIN;
        io_uring_cqe_seen(&l->uring, cqe);
        return 1;
    }

    switch (AIO_UD_KIND(ud)) {
    case AIO_UD_RECV:
        uring_rxtx_recv_cqe(l, cqe, ud);
        break;
    case AIO_UD_SEND:
        uring_rxtx_send_cqe(l, cqe, ud);
        break;
    default:
        produced = uring_translate_slot_cqe(l, cqe, ev, ud);
        break;
    }
    io_uring_cqe_seen(&l->uring, cqe);
    return produced;
}


/* ---- Drain ready io_uring poll CQEs into evs[] ----
 *
 * WHAT: Block up to `timeout_ms` for at least one CQE, then peek and translate
 * up to `max` CQEs into evs[], returning the number of readiness events written
 * (never negative — a timeout yields 0).
 *
 * WHY: Mirrors epoll_wait's contract for the io_uring engine so io_engine_wait
 * can select an engine and return, staying a flat two-branch function.
 *
 * HOW:
 *   1. Convert timeout_ms to a __kernel_timespec and wait for one CQE; on any
 *      wait error (timeout / -ETIME / -EINTR) return 0.
 *   2. While there is room (n < max) and a CQE can be peeked, translate it and
 *      add its 0/1 event contribution to n.
 *   3. Return n.
 */
static int
uring_drain_cqes(brix_loop *l, struct epoll_event *evs, int max, int timeout_ms)
{
    struct io_uring_cqe     *cqe;
    struct __kernel_timespec ts;
    int                      n = 0;

    ts.tv_sec  = timeout_ms / 1000;
    ts.tv_nsec = (long) (timeout_ms % 1000) * 1000000L;

    /* Block until at least one CQE or the timeout. */
    if (io_uring_wait_cqe_timeout(&l->uring, &cqe, &ts) < 0) {
        return 0;   /* timeout / -ETIME / -EINTR: no events this tick */
    }

    while (n < max && io_uring_peek_cqe(&l->uring, &cqe) == 0) {
        n += uring_translate_cqe(l, cqe, &evs[n]);
    }
    return n;
}

#endif /* BRIX_HAVE_LIBURING */


/* Fill evs[] with up to `max` readiness events (data.ptr + EPOLL* mask) and
 * return the count, or -1 on a hard wait error.  For io_uring, translate poll
 * CQEs (generation-guarded) and re-arm any multishot that auto-disarmed. */
int
io_engine_wait(brix_loop *l, struct epoll_event *evs, int max, int timeout_ms)
{
#if (BRIX_HAVE_LIBURING)
    if (l->use_uring) {
        return uring_drain_cqes(l, evs, max, timeout_ms);
    }
#endif
    return epoll_wait(l->epfd, evs, max, timeout_ms);
}
