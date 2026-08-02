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
    io_uring_sqe_set_data64(sqe,
        AIO_URING_UD(AIO_UD_POLL, l->uslots[slot].gen, slot));
    return io_uring_submit(&l->uring) < 0 ? -1 : 0;
}


/* ---- P44-C (ii-b): cleartext RECV/SEND multishot tier ---- */

/* Return one provided buffer to the RX ring (kernel may refill it after this —
 * always copy out of it first). */
void
uring_rxtx_recycle(brix_loop *l, struct io_uring_cqe *cqe)
{
    uint16_t bid;

    if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
        return;
    }
    bid = (uint16_t) (cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    io_uring_buf_ring_add(l->brx,
        l->brx_pool + (size_t) bid * AIO_URING_RXBUF_SZ,
        AIO_URING_RXBUF_SZ, bid,
        io_uring_buf_ring_mask(AIO_URING_RXBUFS), 0);
    io_uring_buf_ring_advance(l->brx, 1);
}


/* Arm (or re-arm) the persistent multishot RECV for a cleartext conn.  Buffers
 * are kernel-selected from the BGID_RX provided ring. */
int
uring_recv_submit(brix_loop *l, brix_aconn *ac)
{
    struct io_uring_sqe *sqe  = io_uring_get_sqe(&l->uring);
    uint32_t             slot = (uint32_t) ac->uring_slot;

    if (sqe == NULL) {
        return -1;
    }
    io_uring_prep_recv_multishot(sqe, ac->fd, NULL, 0, 0);
    sqe->flags    |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = AIO_URING_BGID_RX;
    io_uring_sqe_set_data64(sqe,
        AIO_URING_UD(AIO_UD_RECV, l->uslots[slot].gen, slot));
    if (io_uring_submit(&l->uring) < 0) {
        return -1;
    }
    l->uslots[slot].recv_armed = 1;
    return 0;
}


/* Stage + submit one one-shot SEND for the current wbuf tail.  The bytes are
 * copied into the slot's staging slice first: wbuf may be realloc'd by new
 * frames while the kernel still reads the send buffer, so the SQE must never
 * point into wbuf itself.  Returns 0 with the SEND in flight (or nothing to
 * do), -1 when the ring can't take it (caller may fall back to send(2) —
 * safe, as nothing is in flight then). */
int
uring_rxtx_send_submit(brix_loop *l, brix_aconn *ac)
{
    struct io_uring_sqe   *sqe;
    struct brix_poll_slot *s;
    size_t                 avail;
    uint32_t               n;

    if (ac->uring_slot < 0 && io_engine_arm(l, ac, EPOLLIN) != 0) {
        return -1;
    }
    s = &l->uslots[ac->uring_slot];

    if (s->send_inflight || ac->wbuf.start >= ac->wbuf.len) {
        return 0;
    }
    if (s->stage == NULL) {
        s->stage = (uint8_t *) malloc(AIO_URING_STAGE_SZ);
        if (s->stage == NULL) {
            return -1;
        }
    }
    avail = ac->wbuf.len - ac->wbuf.start;
    n = (uint32_t) (avail > AIO_URING_STAGE_SZ ? AIO_URING_STAGE_SZ : avail);
    memcpy(s->stage, ac->wbuf.buf + ac->wbuf.start, n);

    sqe = io_uring_get_sqe(&l->uring);
    if (sqe == NULL) {
        return -1;
    }
    io_uring_prep_send(sqe, ac->fd, s->stage, n, MSG_NOSIGNAL);
    io_uring_sqe_set_data64(sqe,
        AIO_URING_UD(AIO_UD_SEND, s->gen, (uint32_t) ac->uring_slot));
    if (io_uring_submit(&l->uring) < 0) {
        return -1;
    }
    s->send_inflight = 1;
    s->stage_len     = n;
    return 0;
}


/* Cancel every outstanding rxtx op on ac's fd (multishot RECV + any SEND) and
 * invalidate their CQEs via the generation bump.  The cancel acks come back
 * with AIO_URING_IGNORE_UD-free cookies but stale gens, so they are dropped. */
static void
uring_rxtx_cancel(brix_loop *l, brix_aconn *ac, int freeing)
{
    uint32_t               slot = (uint32_t) ac->uring_slot;
    struct brix_poll_slot *s    = &l->uslots[slot];
    struct io_uring_sqe   *sqe;

    sqe = io_uring_get_sqe(&l->uring);
    if (sqe != NULL) {
        io_uring_prep_cancel_fd(sqe, ac->fd, IORING_ASYNC_CANCEL_ALL);
        io_uring_sqe_set_data64(sqe, AIO_URING_IGNORE_UD);
        (void) io_uring_submit(&l->uring);
    }
    s->gen++;                       /* stale CQEs (incl. in-flight SEND) drop */
    s->recv_armed    = 0;
    s->send_inflight = 0;
    s->stage_len     = 0;
    if (freeing) {
        free(s->stage);
        s->stage   = NULL;
        s->in_use  = 0;
        s->ac      = NULL;
        s->rxtx    = 0;
        ac->uring_slot = -1;
    }
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

        if (l->use_rxtx) {
            /* P44-C: provided-buffer ring for the cleartext RECV tier.
             * Best-effort — on an old kernel (needs 5.19+) degrade to the
             * POLL_ADD-only engine instead of failing the loop. */
            int rr = 0;
            l->brx_pool = (uint8_t *)
                malloc((size_t) AIO_URING_RXBUFS * AIO_URING_RXBUF_SZ);
            if (l->brx_pool != NULL) {
                l->brx = io_uring_setup_buf_ring(&l->uring, AIO_URING_RXBUFS,
                                                 AIO_URING_BGID_RX, 0, &rr);
            }
            if (l->brx != NULL) {
                unsigned i;
                for (i = 0; i < AIO_URING_RXBUFS; i++) {
                    io_uring_buf_ring_add(l->brx,
                        l->brx_pool + (size_t) i * AIO_URING_RXBUF_SZ,
                        AIO_URING_RXBUF_SZ, (unsigned short) i,
                        io_uring_buf_ring_mask(AIO_URING_RXBUFS), (int) i);
                }
                io_uring_buf_ring_advance(l->brx, AIO_URING_RXBUFS);
            } else {
                free(l->brx_pool);
                l->brx_pool = NULL;
                l->use_rxtx = 0;
            }
        }

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
            unsigned i;
            for (i = 0; i < AIO_URING_SLOTS; i++) {   /* rxtx send stages */
                free(l->uslots[i].stage);
                l->uslots[i].stage = NULL;
            }
            if (l->brx != NULL) {
                io_uring_free_buf_ring(&l->uring, l->brx, AIO_URING_RXBUFS,
                                       AIO_URING_BGID_RX);
                l->brx = NULL;
            }
            free(l->brx_pool);
            l->brx_pool = NULL;
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
            l->uslots[ac->uring_slot].rxtx = aconn_is_rxtx(ac) ? 1 : 0;
        }

        if (l->uslots[ac->uring_slot].rxtx) {
            /* P44-C: the multishot RECV is the only persistent op — POLLOUT
             * interest is meaningless (SENDs are submitted directly by
             * aconn_do_write), so mask changes are no-ops once armed. */
            if (!l->uslots[ac->uring_slot].recv_armed) {
                ac->fd_gen++;
                if (uring_recv_submit(l, ac) != 0) {
                    l->uslots[ac->uring_slot].rxtx = 0;  /* degrade to poll */
                } else {
                    ac->epoll_events = want;
                    return 0;
                }
            } else {
                ac->epoll_events = want;
                return 0;
            }
        } else if (ac->epoll_events != 0) {
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
        if (ac->uring_slot >= 0 && l->uslots[ac->uring_slot].rxtx) {
            uring_rxtx_cancel(l, ac, 1);   /* cancel RECV/SEND + free the slot */
        } else {
            uring_poll_cancel(l, ac, 1);   /* cancel + free the slot */
        }
        ac->epoll_events = 0;
        return;
    }
#endif
    if (ac->fd >= 0) {
        epoll_ctl(l->epfd, EPOLL_CTL_DEL, ac->fd, NULL);
    }
    ac->epoll_events = 0;
}
