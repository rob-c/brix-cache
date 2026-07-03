/*
 * aio_conn.c - extracted concern
 * Phase-38 split of aio.c; behavior-identical.
 */
#include "aio_internal.h"


/* epoll */
void
aconn_update_epoll(brix_aconn *ac)
{
    int want = EPOLLIN;
    if (ac->wbuf.start < ac->wbuf.len || ac->tls_want_write_on_read) {
        want |= EPOLLOUT;
    }
    if (want == ac->epoll_events) {
        return;
    }
    (void) io_engine_arm(ac->loop, ac, want);
}


/* conn */
/* Fail every in-flight request with `st`, leaving the map empty. */
void
aconn_drain_inflight(brix_aconn *ac, const brix_status *st)
{
    for (uint32_t i = 0; i < ac->inflight.cap; i++) {
        brix_areq *r = ac->inflight.slots[i];
        if (r == NULL || r == REQMAP_TOMB) {
            continue;
        }
        ac->inflight.slots[i] = NULL;
        areq_complete(r, -1, (uint16_t) (st->kxr & 0xffff), st);
    }
    ac->inflight.count = 0;
    ac->inflight.tomb = 0;
}


/* reconnect *//*
 * On a transport drop the connection does not fail its callers outright; it goes
 * RECONNECTING: a worker thread re-establishes the session (off the loop thread so
 * other connections keep flowing), retry-safe in-flight requests are parked, and
 * once the new socket is back they are re-issued — so a stat/ping/dirlist that was
 * mid-flight when the server bounced simply succeeds, transparently. Non-retry-safe
 * (mutating or handle-bound) requests fail so the higher layer (M3) can reopen.
 */

/* Fail every parked request with `st`, emptying the pending list. */
void
aconn_pending_fail_all(brix_aconn *ac, const brix_status *st)
{
    brix_areq *p = ac->pending;
    ac->pending = NULL;
    while (p != NULL) {
        brix_areq *nx = p->pend_next;
        p->pend_next = NULL;
        areq_complete(p, -1, (uint16_t) (st->kxr & 0xffff), st);
        p = nx;
    }
}


/* Enter RECONNECTING: pull the dead fd from epoll, partition in-flight requests
 * (retry-safe → parked, others → failed), and spawn the reconnect worker. */
void
aconn_on_transport_error(brix_aconn *ac, const brix_status *st)
{
    if (ac->state != ACONN_ALIVE) {
        return;   /* already reconnecting or dead */
    }
    io_engine_del(ac->loop, ac);   /* epoll DEL or io_uring poll cancel */
    ac->dead = 1;

    if (ac->max_stall_ms <= 0) {   /* reconnect disabled — fail outright */
        ac->state = ACONN_DEAD;
        aconn_drain_inflight(ac, st);
        aconn_pending_fail_all(ac, st);
        return;
    }

    uint64_t now = brix_mono_ns();
    ac->state = ACONN_RECONNECTING;
    ac->reconnect_deadline_ns = now + (uint64_t) ac->max_stall_ms * 1000000ULL;
    ac->ping_inflight = 0;
    ac->tls_want_read_on_write = ac->tls_want_write_on_read = 0;

    for (uint32_t i = 0; i < ac->inflight.cap; i++) {
        brix_areq *r = ac->inflight.slots[i];
        if (r == NULL || r == REQMAP_TOMB) {
            continue;
        }
        ac->inflight.slots[i] = NULL;
        if (r->retry_safe && r->retries_left > 0) {
            r->retries_left--;
            r->deadline_ns = ac->reconnect_deadline_ns;   /* patience through reconnect */
            r->pend_next = ac->pending;
            ac->pending = r;
        } else {
            areq_complete(r, -1, (uint16_t) (st->kxr & 0xffff), st);
        }
    }
    ac->inflight.count = 0;
    ac->inflight.tomb = 0;
    ac->wbuf.start = ac->wbuf.len = 0;   /* stale: belonged to the dead socket */
    ac->rbuf.start = ac->rbuf.len = 0;

    if (pthread_create(&ac->rc_thread, NULL, rc_worker_main, ac) == 0) {
        ac->rc_thread_live = 1;
    } else {
        ac->state = ACONN_DEAD;
        aconn_pending_fail_all(ac, st);
    }
}


/* Loop-thread side of a successful reconnect: adopt the new socket and re-issue
 * every parked request. */
void
aconn_reconnect_succeeded(brix_aconn *ac)
{
    ac->fd  = ac->conn->io.fd;
    ac->ssl = ac->conn->io.ssl;

    int fl = fcntl(ac->fd, F_GETFL, 0);
    if (fl >= 0) {
        fcntl(ac->fd, F_SETFL, fl | O_NONBLOCK);
    }

    if (io_engine_arm(ac->loop, ac, EPOLLIN) != 0) {
        brix_status st;
        brix_status_set(&st, XRDC_ESOCK, errno, "poll re-register failed");
        ac->state = ACONN_DEAD;
        aconn_pending_fail_all(ac, &st);
        return;
    }
    ac->dead = 0;
    ac->state = ACONN_ALIVE;
    ac->last_activity_ns = brix_mono_ns();
    ac->reconnect_deadline_ns = 0;

    brix_areq *p = ac->pending;
    ac->pending = NULL;
    while (p != NULL) {
        brix_areq *nx = p->pend_next;
        p->pend_next = NULL;
        aconn_issue_areq(ac, p);
        if (ac->state != ACONN_ALIVE) {
            /* a re-issue tripped another drop; the rest were re-parked or failed */
            p = ac->pending;
            ac->pending = NULL;
            continue;
        }
        p = nx;
    }
}


/* Detect a finished reconnect worker (called each tick) and apply its result. */
void
aconn_poll_reconnect(brix_aconn *ac)
{
    if (ac->state != ACONN_RECONNECTING) {
        return;
    }
    if (!__atomic_load_n(&ac->rc_finished, __ATOMIC_ACQUIRE)) {
        return;
    }
    if (ac->rc_thread_live) {
        pthread_join(ac->rc_thread, NULL);
        ac->rc_thread_live = 0;
    }
    ac->rc_finished = 0;
    if (ac->rc_result == 0) {
        aconn_reconnect_succeeded(ac);
    } else {
        ac->state = ACONN_DEAD;
        aconn_pending_fail_all(ac, &ac->rc_st);
    }
}


/* keepalive */
/* Internal heartbeat-ping completion: just clear the in-flight marker (a failed
 * ping is turned into a transport error by the timeout scan, not here). */
void
aconn_ping_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen,
              const brix_status *st)
{
    (void) rc; (void) kxr; (void) blen; (void) st;
    brix_aconn *ac = (brix_aconn *) ctx;
    ac->ping_inflight = 0;
    free(body);
}


/* Send a kXR_ping if the link has been idle past the keepalive threshold. */
void
aconn_maybe_ping(brix_aconn *ac)
{
    if (ac->state != ACONN_ALIVE || ac->keepalive_ms <= 0 || ac->ping_inflight) {
        return;
    }
    uint64_t now = brix_mono_ns();
    if (now - ac->last_activity_ns < (uint64_t) ac->keepalive_ms * 1000000ULL) {
        return;
    }
    brix_areq *r = (brix_areq *) calloc(1, sizeof(*r));
    if (r == NULL) {
        return;
    }
    uint16_t rid = htons(kXR_ping);
    memcpy(r->hdr + 2, &rid, 2);
    r->cb = aconn_ping_cb;
    r->ctx = ac;
    r->is_ping = 1;
    r->retry_safe = 1;
    r->retries_left = ac->def_retries;
    uint64_t dl = aconn_rto_ns(ac) * 4;
    if (dl < 2000000000ULL) { dl = 2000000000ULL; }
    if (dl > 10000000000ULL) { dl = 10000000000ULL; }
    r->deadline_ns = now + dl;
    ac->ping_inflight = 1;
    aconn_issue_areq(ac, r);
}


/* Unlink from the loop list, free buffers + struct (loop thread only). Joins a
 * running reconnect worker first so conn is no longer touched by another thread. */
void
aconn_destroy(brix_aconn *ac)
{
    brix_loop  *l = ac->loop;
    brix_status st;
    brix_status_set(&st, XRDC_ESOCK, 0, "connection closed");

    if (ac->rc_thread_live) {
        pthread_join(ac->rc_thread, NULL);   /* bounded by the connect timeout */
        ac->rc_thread_live = 0;
    }
    if (!ac->dead) {
        io_engine_del(l, ac);
        aconn_drain_inflight(ac, &st);
    }
    aconn_pending_fail_all(ac, &st);   /* fail any parked requests */
    brix_aconn **pp = &l->aconns;
    while (*pp != NULL) {
        if (*pp == ac) {
            *pp = ac->next;
            break;
        }
        pp = &(*pp)->next;
    }
    xbuf_free(&ac->wbuf);
    xbuf_free(&ac->rbuf);
    free(ac->inflight.slots);
    free(ac);
}


/* Assign a fresh, currently-unused streamid (skips 0 and 0xffff). */
uint16_t
aconn_alloc_sid(brix_aconn *ac)
{
    for (int tries = 0; tries < 65536; tries++) {
        uint16_t s = ac->next_sid++;
        if (ac->next_sid == 0xffff) {
            ac->next_sid = 1;
        }
        if (s == 0 || s == 0xffff) {
            continue;
        }
        if (reqmap_get(&ac->inflight, s) == NULL) {
            return s;
        }
    }
    return 0;   /* pipeline saturated (should never happen with bounded depth) */
}


/* Stamp a fresh streamid + dlen, queue the bytes on the wire, and register the
 * request as in-flight. Used for a new submission and for re-issuing a parked
 * request after a reconnect (the header's requestid + body are preserved; only
 * streamid/dlen are re-stamped). */
void
aconn_issue_areq(brix_aconn *ac, brix_areq *r)
{
    uint16_t sid = aconn_alloc_sid(ac);
    r->sid = sid;
    r->hdr[0] = (uint8_t) (sid >> 8);
    r->hdr[1] = (uint8_t) (sid & 0xff);
    uint32_t be = htonl(r->plen);
    memcpy(r->hdr + 20, &be, 4);
    r->submit_ns = brix_mono_ns();

    if (xbuf_append(&ac->wbuf, r->hdr, XRD_REQUEST_HDR_LEN) != 0 ||
        (r->plen > 0 && xbuf_append(&ac->wbuf, r->payload, r->plen) != 0) ||
        reqmap_put(&ac->inflight, r) != 0) {
        brix_status st;
        brix_status_set(&st, XRDC_EPROTO, 0, "out of memory (queue)");
        areq_complete(r, -1, XRDC_EPROTO, &st);
        return;
    }

    aconn_do_write(ac);
    if (!ac->dead) {
        aconn_update_epoll(ac);
    }
}


/* Compute a request's hard deadline: the caller's explicit ms, else an adaptive
 * value derived from the RTO and bounded by the reconnect patience budget. */
uint64_t
aconn_deadline_ns(brix_aconn *ac, int deadline_ms)
{
    uint64_t now = brix_mono_ns();
    uint64_t ms;
    if (deadline_ms > 0) {
        ms = (uint64_t) deadline_ms;
    } else {
        uint64_t cap = (ac->max_stall_ms > 0) ? (uint64_t) ac->max_stall_ms : 60000;
        ms = (aconn_rto_ns(ac) / 1000000ULL) * 20;   /* ~20 RTOs of patience */
        if (ms < 5000) {
            ms = 5000;
        }
        if (ms > cap) {
            ms = cap;
        }
    }
    return now + ms * 1000000ULL;
}


/* Turn a SUBMIT command into a request. If the socket is mid-reconnect the request
 * is parked (it has not been sent, so it is safe to issue fresh once the socket is
 * back); otherwise it goes out immediately. Consumes cmd->payload ownership. */
void
aconn_submit_cmd(brix_aconn *ac, cmd *c)
{
    if (ac->state == ACONN_DEAD) {
        brix_status st;
        brix_status_set(&st, XRDC_ESOCK, 0, "connection is down");
        c->cb(c->ctx, -1, XRDC_ESOCK, NULL, 0, &st);
        free(c->payload);
        return;
    }

    brix_areq *r = (brix_areq *) calloc(1, sizeof(*r));
    if (r == NULL) {
        brix_status st;
        brix_status_set(&st, XRDC_EPROTO, 0, "out of memory (request)");
        c->cb(c->ctx, -1, XRDC_EPROTO, NULL, 0, &st);
        free(c->payload);
        return;
    }

    memcpy(r->hdr, c->hdr, XRD_REQUEST_HDR_LEN);
    r->payload      = c->payload;     /* move */
    r->plen         = c->plen;
    r->cb           = c->cb;
    r->ctx          = c->ctx;
    r->retry_safe   = c->retry_safe;
    r->retries_left = (c->max_retries >= 0) ? c->max_retries : ac->def_retries;
    r->deadline_ns  = aconn_deadline_ns(ac, c->deadline_ms);

    if (ac->state == ACONN_RECONNECTING) {
        /* Give a parked request the full reconnect budget so it survives the drop. */
        uint64_t stall = (ac->max_stall_ms > 0) ? (uint64_t) ac->max_stall_ms : 60000;
        r->deadline_ns = brix_mono_ns() + stall * 1000000ULL;
        r->pend_next = ac->pending;
        ac->pending = r;
        return;
    }

    aconn_issue_areq(ac, r);
}
