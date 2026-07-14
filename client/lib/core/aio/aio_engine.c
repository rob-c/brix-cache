/*
 * aio_engine.c - extracted concern
 * Phase-38 split of aio.c; behavior-identical.
 */
#include "aio_internal.h"


/* ============ Phase 44: pluggable loop I/O engine (epoll | io_uring) ============
 *
 * Two readiness engines share one interface.  The epoll branch is the historical
 * code, preserved verbatim.  The io_uring branch (multishot IORING_OP_POLL_ADD,
 * default OFF — gated by XRDC_IO_URING_LOOP=on + a runtime probe, best-effort
 * fallback to epoll) is a drop-in readiness source: the loop still runs
 * aconn_do_read/aconn_do_write unchanged, so TLS (which drives the fd through
 * OpenSSL itself) is safe.  Cross-thread wake is write(evfd) for BOTH engines —
 * the io_uring engine arms a multishot poll on the same evfd.
 *
 * UAF safety: a poll's user_data carries (slot-generation<<32 | slot); the slot
 * table maps back to the aconn and the reaper drops any CQE whose generation no
 * longer matches (poll completing after its aconn was reconnected/freed) — the
 * same discipline as the server ring.  fd changes (reconnect) cancel the old
 * poll and bump the slot generation before re-arming the new fd. */




#if (BRIX_HAVE_LIBURING)

/* epoll interest mask -> poll(2) mask for io_uring_prep_poll_*. */
unsigned
uring_pollmask(int want)
{
    unsigned m = 0;
    if (want & EPOLLIN)  { m |= POLLIN;  }
    if (want & EPOLLOUT) { m |= POLLOUT; }
    return m;
}


/* Claim a free poll slot for ac (loop-thread only; no lock). Returns 0 / -1. */
int
uring_slot_alloc(brix_loop *l, brix_aconn *ac)
{
    unsigned i;
    for (i = 0; i < AIO_URING_SLOTS; i++) {
        if (!l->uslots[i].in_use) {
            l->uslots[i].in_use = 1;
            l->uslots[i].ac     = ac;
            ac->uring_slot      = (int) i;
            return 0;
        }
    }
    return -1;   /* table full — pool has more conns than slots (shouldn't happen) */
}


/* Submit a multishot poll for ac with the current slot generation as user_data. */
int
uring_poll_submit(brix_loop *l, brix_aconn *ac, int want)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&l->uring);
    uint32_t             slot = (uint32_t) ac->uring_slot;

    if (sqe == NULL) {
        return -1;
    }
    io_uring_prep_poll_multishot(sqe, ac->fd, uring_pollmask(want));
    io_uring_sqe_set_data64(sqe, ((uint64_t) l->uslots[slot].gen << 32) | slot);
    return io_uring_submit(&l->uring) < 0 ? -1 : 0;
}


/* Cancel ac's outstanding poll (by current user_data) and bump the slot gen so
 * any late CQE for it is dropped.  Keeps the slot allocated (caller re-arms) or
 * frees it when freeing == 1. */
void
uring_poll_cancel(brix_loop *l, brix_aconn *ac, int freeing)
{
    uint32_t             slot = (uint32_t) ac->uring_slot;
    struct io_uring_sqe *sqe;

    if (ac->uring_slot < 0) {
        return;
    }
    sqe = io_uring_get_sqe(&l->uring);
    if (sqe != NULL) {
        io_uring_prep_poll_remove(sqe,
            ((uint64_t) l->uslots[slot].gen << 32) | slot);
        io_uring_sqe_set_data64(sqe, AIO_URING_IGNORE_UD);
        (void) io_uring_submit(&l->uring);
    }
    l->uslots[slot].gen++;          /* invalidate the old poll's user_data */
    if (freeing) {
        l->uslots[slot].in_use = 0;
        l->uslots[slot].ac     = NULL;
        ac->uring_slot = -1;
    }
}

#endif /* BRIX_HAVE_LIBURING */



/* Create the readiness set + the wake eventfd.  evfd is used by both engines;
 * epoll registers it in the set, io_uring arms a multishot poll on it. */
int
io_engine_setup(brix_loop *l, brix_status *st)
{
    l->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (l->evfd < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "eventfd: %s", strerror(errno));
        return -1;
    }

#if (BRIX_HAVE_LIBURING)
    if (l->use_uring) {
        struct io_uring_sqe *sqe;
        if (io_uring_queue_init(256, &l->uring, 0) < 0) {
            brix_status_set(st, XRDC_ESOCK, errno, "io_uring_queue_init");
            return -1;
        }
        l->uring_ok = 1;
        sqe = io_uring_get_sqe(&l->uring);     /* multishot poll on the evfd */
        if (sqe == NULL) {
            brix_status_set(st, XRDC_ESOCK, 0, "io_uring evfd arm");
            return -1;
        }
        io_uring_prep_poll_multishot(sqe, l->evfd, POLLIN);
        io_uring_sqe_set_data64(sqe, AIO_URING_EVFD_UD);
        if (io_uring_submit(&l->uring) < 0) {
            brix_status_set(st, XRDC_ESOCK, errno, "io_uring evfd submit");
            return -1;
        }
        return 0;
    }
#endif

    l->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (l->epfd < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "epoll_create1: %s",
                        strerror(errno));
        return -1;
    }
    {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events   = EPOLLIN;
        ev.data.ptr = l;                       /* loop pointer tags the eventfd */
        if (epoll_ctl(l->epfd, EPOLL_CTL_ADD, l->evfd, &ev) != 0) {
            brix_status_set(st, XRDC_ESOCK, errno, "epoll_ctl(evfd): %s",
                            strerror(errno));
            return -1;
        }
    }
    return 0;
}


void
io_engine_teardown(brix_loop *l)
{
#if (BRIX_HAVE_LIBURING)
    if (l->use_uring) {
        if (l->uring_ok) {
            io_uring_queue_exit(&l->uring);
            l->uring_ok = 0;
        }
        if (l->evfd >= 0) { close(l->evfd); l->evfd = -1; }
        return;
    }
#endif
    if (l->epfd >= 0) { close(l->epfd); l->epfd = -1; }
    if (l->evfd >= 0) { close(l->evfd); l->evfd = -1; }
}


/* Arm/modify interest for ac to `want`; sets ac->epoll_events on success.
 * Returns 0 / -1 (caller keeps its own failure handling). */
int
io_engine_arm(brix_loop *l, brix_aconn *ac, int want)
{
#if (BRIX_HAVE_LIBURING)
    if (l->use_uring) {
        if (ac->uring_slot < 0) {
            if (uring_slot_alloc(l, ac) != 0) { return -1; }
        } else {
            uring_poll_cancel(l, ac, 0);   /* drop the old mask's poll, keep slot */
        }
        ac->fd_gen++;
        if (uring_poll_submit(l, ac, want) != 0) { return -1; }
        ac->epoll_events = want;
        return 0;
    }
#endif
    {
        struct epoll_event ev;
        int op = (ac->epoll_events == 0) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        memset(&ev, 0, sizeof(ev));
        ev.events   = (uint32_t) want;
        ev.data.ptr = ac;
        if (epoll_ctl(l->epfd, op, ac->fd, &ev) != 0) {
            return -1;
        }
        ac->epoll_events = want;
        return 0;
    }
}


void
io_engine_del(brix_loop *l, brix_aconn *ac)
{
#if (BRIX_HAVE_LIBURING)
    if (l->use_uring) {
        uring_poll_cancel(l, ac, 1);       /* cancel + free the slot */
        ac->epoll_events = 0;
        return;
    }
#endif
    if (ac->fd >= 0) {
        epoll_ctl(l->epfd, EPOLL_CTL_DEL, ac->fd, NULL);
    }
    ac->epoll_events = 0;
}


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
    uint32_t    slot = (uint32_t) (ud & 0xffffffffULL);
    uint32_t    gen  = (uint32_t) (ud >> 32);
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


/* ---- Translate one CQE into at most one readiness event ----
 *
 * WHAT: Classify a single CQE by its user_data and, for the evfd wake and live
 * slot polls, fill *ev with the corresponding readiness event.  Returns 1 if
 * *ev was written, 0 otherwise.  Always marks the CQE seen before returning.
 *
 * WHY: Factors the three-way user_data classification (ignore / evfd / slot)
 * out of the wait loop so each case is a single linear path; the loop then just
 * accumulates the return count.  The seen-marking is centralised here so every
 * consumed CQE is retired exactly once regardless of classification.
 *
 * HOW:
 *   1. Read the CQE's user_data.
 *   2. AIO_URING_IGNORE_UD (a cancel echo): mark seen, return 0.
 *   3. AIO_URING_EVFD_UD (cross-thread wake): write a loop-tagged EPOLLIN event,
 *      mark seen, return 1.
 *   4. Otherwise treat it as a slot poll via uring_translate_slot_cqe, mark
 *      seen, and return its result.
 */
static int
uring_translate_cqe(brix_loop *l, struct io_uring_cqe *cqe,
    struct epoll_event *ev)
{
    uint64_t ud = io_uring_cqe_get_data64(cqe);
    int      produced;

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

    produced = uring_translate_slot_cqe(l, cqe, ev, ud);
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
