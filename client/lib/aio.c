/*
 * aio.c - (kept) routing + shared helpers
 * Phase-38 split of aio.c; behavior-identical.
 */
#include "aio_internal.h"


/* Reconnect worker (its own thread). Retries xrdc_reconnect with exponential
 * backoff + jitter until success or the reconnect deadline, then signals the loop
 * via rc_finished + the eventfd. Touches only conn (via xrdc_reconnect) and the
 * rc_* handoff fields — never the loop-owned per-conn state. */
void *
rc_worker_main(void *arg)
{
    xrdc_aconn *ac = arg;
    uint64_t    seed = (uint64_t) (uintptr_t) ac ^ xrdc_mono_ns();
    int         attempt = 0;
    xrdc_status st;
    char        host[256];
    int         port;

    xrdc_status_set(&st, XRDC_ESOCK, 0, "reconnect not attempted");
    snprintf(host, sizeof(host), "%s", ac->conn->host);
    port = ac->conn->port;

    while (xrdc_mono_ns() < ac->reconnect_deadline_ns) {
        if (xrdc_reconnect(ac->conn, host, port, &st) == 0) {
            ac->rc_result = 0;
            __atomic_store_n(&ac->rc_finished, 1, __ATOMIC_RELEASE);
            uint64_t one = 1;
            ssize_t  w = write(ac->loop->evfd, &one, sizeof(one));
            (void) w;
            return NULL;
        }
        attempt++;
        /* Fast reconnect cadence: a transport drop is instant, not server
         * overload, so retry promptly — 100ms..1s — which is what lets a session
         * recover on a high packet-loss link where each multi-RTT bring-up is
         * frequently severed. Total reconnect time is still bounded by max_stall
         * (reconnect_deadline_ns). */
        uint64_t base_ms = 100ULL << ((attempt < 4) ? attempt : 4);   /* 100ms..1.6s */
        if (base_ms > 1000) {
            base_ms = 1000;
        }
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;    /* xorshift */
        uint64_t sleep_ms = base_ms + (seed % 100);                   /* + jitter */
        uint64_t now = xrdc_mono_ns();
        if (now >= ac->reconnect_deadline_ns) {
            break;
        }
        uint64_t remain_ns = ac->reconnect_deadline_ns - now;
        uint64_t sleep_ns = sleep_ms * 1000000ULL;
        if (sleep_ns > remain_ns) {
            sleep_ns = remain_ns;
        }
        struct timespec ts = { (time_t) (sleep_ns / 1000000000ULL),
                               (long) (sleep_ns % 1000000000ULL) };
        nanosleep(&ts, NULL);
    }

    ac->rc_result = -1;
    ac->rc_st = st;
    __atomic_store_n(&ac->rc_finished, 1, __ATOMIC_RELEASE);
    uint64_t one = 1;
    ssize_t  w = write(ac->loop->evfd, &one, sizeof(one));
    (void) w;
    return NULL;
}


/* commands */
void
loop_push_cmd(xrdc_loop *l, cmd *c)
{
    pthread_mutex_lock(&l->cq_lock);
    c->next = NULL;
    if (l->cq_tail != NULL) {
        l->cq_tail->next = c;
    } else {
        l->cq_head = c;
    }
    l->cq_tail = c;
    pthread_mutex_unlock(&l->cq_lock);

    uint64_t one = 1;
    ssize_t wr = write(l->evfd, &one, sizeof(one));
    (void) wr;
}


/* Run a synchronous control command (ADD/CLOSE/STOP) and wait for the loop. */
void
loop_run_control(xrdc_loop *l, cmd_type type, xrdc_aconn *ac)
{
    pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t  cv = PTHREAD_COND_INITIALIZER;
    int             done = 0;

    cmd *c = (cmd *) calloc(1, sizeof(*c));
    if (c == NULL) {
        return;   /* best-effort; nothing else we can do */
    }
    c->type = type;
    c->ac   = ac;
    c->dmx  = &mx;
    c->dcv  = &cv;
    c->done = &done;

    loop_push_cmd(l, c);

    pthread_mutex_lock(&mx);
    while (!done) {
        pthread_cond_wait(&cv, &mx);
    }
    pthread_mutex_unlock(&mx);
}


void
loop_drain_commands(xrdc_loop *l)
{
    pthread_mutex_lock(&l->cq_lock);
    cmd *head = l->cq_head;
    l->cq_head = l->cq_tail = NULL;
    pthread_mutex_unlock(&l->cq_lock);

    while (head != NULL) {
        cmd *c = head;
        head = head->next;

        switch (c->type) {
        case CMD_ADD_ACONN: {
            xrdc_aconn *ac = c->ac;
            if (io_engine_arm(l, ac, EPOLLIN) == 0) {
                ac->next = l->aconns;
                l->aconns = ac;
            } else {
                ac->dead = 1;   /* attach will surface failure via submits */
            }
            break;
        }
        case CMD_SUBMIT:
            aconn_submit_cmd(c->ac, c);
            break;
        case CMD_CLOSE_ACONN:
            aconn_destroy(c->ac);
            break;
        case CMD_STOP:
            l->stop = 1;
            break;
        }

        if (c->done != NULL) {
            pthread_mutex_lock(c->dmx);
            *c->done = 1;
            pthread_cond_signal(c->dcv);
            pthread_mutex_unlock(c->dmx);
        }
        free(c);
    }
}


/* timers */
/* Fail any request whose deadline has passed; a timed-out heartbeat ping is
 * promoted to a transport error (the link is presumed dead → reconnect). Returns
 * ms until the next deadline (capped at AIO_TICK_MS) for the next epoll_wait. */
int
loop_process_timeouts(xrdc_loop *l)
{
    uint64_t now  = xrdc_mono_ns();
    uint64_t next = 0;   /* nearest future deadline (ns), 0 = none */

    for (xrdc_aconn *ac = l->aconns; ac != NULL; ac = ac->next) {
        if (ac->state == ACONN_RECONNECTING) {
            /* expire parked requests that ran out the reconnect budget */
            xrdc_areq **pp = &ac->pending;
            while (*pp != NULL) {
                xrdc_areq *r = *pp;
                if (r->deadline_ns != 0 && now >= r->deadline_ns) {
                    *pp = r->pend_next;
                    xrdc_status st;
                    xrdc_status_set(&st, XRDC_ESOCK, ETIMEDOUT,
                                    "request deadline exceeded (reconnecting)");
                    areq_complete(r, -1, XRDC_ESOCK, &st);
                } else {
                    if (r->deadline_ns != 0 && (next == 0 || r->deadline_ns < next)) {
                        next = r->deadline_ns;
                    }
                    pp = &r->pend_next;
                }
            }
            continue;
        }
        if (ac->state != ACONN_ALIVE) {
            continue;
        }

        int ping_timed_out = 0;
        for (uint32_t i = 0; i < ac->inflight.cap; i++) {
            xrdc_areq *r = ac->inflight.slots[i];
            if (r == NULL || r == REQMAP_TOMB || r->deadline_ns == 0) {
                continue;
            }
            if (now >= r->deadline_ns) {
                ac->inflight.slots[i] = REQMAP_TOMB;
                ac->inflight.count--;
                ac->inflight.tomb++;
                if (r->is_ping) {
                    ping_timed_out = 1;
                }
                xrdc_status st;
                xrdc_status_set(&st, XRDC_ESOCK, ETIMEDOUT,
                                "request deadline exceeded");
                areq_complete(r, -1, XRDC_ESOCK, &st);
            } else if (next == 0 || r->deadline_ns < next) {
                next = r->deadline_ns;
            }
        }
        if (ping_timed_out) {   /* inflight scan for this ac is done — safe to recurse */
            xrdc_status st;
            xrdc_status_set(&st, XRDC_ESOCK, 0, "keepalive heartbeat timed out");
            aconn_on_transport_error(ac, &st);
        }
    }

    if (next == 0) {
        return AIO_TICK_MS;
    }
    uint64_t dt_ns = (next > now) ? next - now : 0;
    int ms = (int) (dt_ns / 1000000ULL) + 1;
    if (ms > AIO_TICK_MS) {
        ms = AIO_TICK_MS;
    }
    if (ms < 1) {
        ms = 1;
    }
    return ms;
}


/* loop */
void *
loop_thread(void *arg)
{
    xrdc_loop *l = (xrdc_loop *) arg;
    struct epoll_event events[AIO_MAXEV];

    int timeout = AIO_TICK_MS;
    while (!l->stop) {
        int n = io_engine_wait(l, events, AIO_MAXEV, timeout);

        loop_drain_commands(l);
        if (l->stop) {
            break;
        }

        for (int i = 0; i < n; i++) {
            void *ptr = events[i].data.ptr;
            if (ptr == l) {                 /* eventfd wakeup */
                uint64_t v;
                ssize_t rd = read(l->evfd, &v, sizeof(v));
                (void) rd;
                continue;
            }
            aconn_handle_io((xrdc_aconn *) ptr, events[i].events);
        }

        /* adopt finished reconnects + send heartbeats on idle links */
        for (xrdc_aconn *ac = l->aconns; ac != NULL; ac = ac->next) {
            aconn_poll_reconnect(ac);
            aconn_maybe_ping(ac);
        }

        timeout = loop_process_timeouts(l);
    }

    /* shutdown: tear down every remaining connection (fails their in-flight) */
    while (l->aconns != NULL) {
        aconn_destroy(l->aconns);
    }
    return NULL;
}


/* public */
/* WHAT: Tear down a partially-initialized loop and return NULL for the caller.
 * WHY:  xrdc_loop_create acquires epfd, evfd, and an always-initialized cq_lock
 *       in sequence; any step can fail. Centralizing the unwind keeps each error
 *       path a flat `return` (no goto) while freeing exactly what was acquired.
 * HOW:  Both fds start at -1 and are only set once successfully opened, so the
 *       >=0 guards close only real descriptors; cq_lock is initialized before any
 *       failure can reach here, so it is always safe to destroy. Mirrors the
 *       original single-exit `fail:` ladder byte-for-byte. */
xrdc_loop *
xrdc_loop_create_fail(xrdc_loop *l)
{
    io_engine_teardown(l);
    pthread_mutex_destroy(&l->cq_lock);
    free(l);
    return NULL;
}


/* Decide the loop readiness engine: io_uring only when XRDC_IO_URING_LOOP=on
 * (or =1) AND the runtime probe passes; otherwise epoll.  Default OFF — the
 * loop engine is the experimental, highest-risk tier.  Best-effort: an
 * unavailable ring silently falls back to epoll (not a hard error). */
int
xrdc_loop_want_uring(void)
{
#if (XROOTD_HAVE_LIBURING)
    const char *e = getenv("XRDC_IO_URING_LOOP");
    if (e == NULL || (strcmp(e, "on") != 0 && strcmp(e, "1") != 0)) {
        return 0;
    }
    return xrdc_uring_available();
#else
    return 0;
#endif
}


xrdc_loop *
xrdc_loop_create(xrdc_status *st)
{
    xrdc_loop *l = (xrdc_loop *) calloc(1, sizeof(*l));
    if (l == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (loop)");
        return NULL;
    }
    pthread_mutex_init(&l->cq_lock, NULL);
    l->epfd = -1;
    l->evfd = -1;
    l->use_uring = xrdc_loop_want_uring();   /* phase-44 loop engine (default off) */

    if (io_engine_setup(l, st) != 0) {
        return xrdc_loop_create_fail(l);
    }
    if (pthread_create(&l->thread, NULL, loop_thread, l) != 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "pthread_create: %s", strerror(errno));
        return xrdc_loop_create_fail(l);
    }
    l->thread_ok = 1;
    return l;
}


void
xrdc_loop_destroy(xrdc_loop *l)
{
    if (l == NULL) {
        return;
    }
    if (l->thread_ok) {
        cmd *c = (cmd *) calloc(1, sizeof(*c));
        if (c != NULL) {
            c->type = CMD_STOP;
            loop_push_cmd(l, c);
        } else {
            l->stop = 1;                /* fallback: still wakes via any traffic */
            uint64_t one = 1;
            ssize_t wr = write(l->evfd, &one, sizeof(one));
            (void) wr;
        }
        pthread_join(l->thread, NULL);
    }
    io_engine_teardown(l);
    pthread_mutex_destroy(&l->cq_lock);
    free(l);
}


xrdc_aconn *
xrdc_aconn_attach(xrdc_loop *l, xrdc_conn *conn, xrdc_status *st)
{
    if (l == NULL || conn == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "attach: null argument");
        return NULL;
    }
    if (conn->signing_active) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "request signing active — async pipelining not supported; "
                        "use the synchronous path");
        return NULL;
    }

    int flags = fcntl(conn->io.fd, F_GETFL, 0);
    if (flags < 0 || fcntl(conn->io.fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "set non-blocking: %s", strerror(errno));
        return NULL;
    }

    xrdc_aconn *ac = (xrdc_aconn *) calloc(1, sizeof(*ac));
    if (ac == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (aconn)");
        return NULL;
    }
    ac->loop     = l;
    ac->conn     = conn;
    ac->fd       = conn->io.fd;
    ac->ssl      = conn->io.ssl;
    ac->next_sid = 1;
    ac->uring_slot = -1;   /* phase-44: no io_uring poll slot yet (0 is valid!) */
    ac->state    = ACONN_ALIVE;
    ac->last_activity_ns = xrdc_mono_ns();

    /* resilience defaults (override with xrdc_aconn_set_resilience) */
    ac->max_stall_ms = 60000;   /* 60 s of reconnect patience */
    ac->keepalive_ms = 15000;   /* heartbeat after 15 s idle */
    ac->def_retries  = 5;

    loop_run_control(l, CMD_ADD_ACONN, ac);

    if (ac->dead) {
        xrdc_status_set(st, XRDC_ESOCK, 0, "epoll registration failed");
        free(ac->inflight.slots);
        free(ac);
        return NULL;
    }
    return ac;
}


void
xrdc_aconn_close(xrdc_aconn *ac)
{
    if (ac == NULL) {
        return;
    }
    loop_run_control(ac->loop, CMD_CLOSE_ACONN, ac);
    /* ac is freed by the loop thread; do not touch it after this point */
}


void
xrdc_aconn_set_resilience(xrdc_aconn *ac, int max_stall_ms,
                          int keepalive_ms, int max_retries)
{
    if (ac == NULL) {
        return;
    }
    /* A negative value means "leave unchanged"; these scalars are read only by the
     * loop thread, so a relaxed store from the caller thread is fine in practice
     * (set before traffic starts in the expected usage). */
    if (max_stall_ms >= 0) { ac->max_stall_ms = max_stall_ms; }
    if (keepalive_ms >= 0) { ac->keepalive_ms = keepalive_ms; }
    if (max_retries >= 0)  { ac->def_retries  = max_retries; }
}


int
xrdc_aio_submit_ex(xrdc_aconn *ac, const void *hdr24,
                   const void *payload, uint32_t plen,
                   const xrdc_aio_opts *opts,
                   xrdc_aio_cb cb, void *ctx, xrdc_status *st)
{
    if (ac == NULL || hdr24 == NULL || cb == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "submit: null argument");
        return -1;
    }

    cmd *c = (cmd *) calloc(1, sizeof(*c));
    if (c == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (submit)");
        return -1;
    }
    c->type = CMD_SUBMIT;
    c->ac   = ac;
    memcpy(c->hdr, hdr24, XRD_REQUEST_HDR_LEN);
    if (plen > 0 && payload != NULL) {
        c->payload = (uint8_t *) malloc(plen);
        if (c->payload == NULL) {
            free(c);
            xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (payload)");
            return -1;
        }
        memcpy(c->payload, payload, plen);
        c->plen = plen;
    }
    c->cb = cb;
    c->ctx = ctx;
    c->deadline_ms = opts ? opts->deadline_ms : 0;
    c->max_retries = opts ? opts->max_retries : -1;
    c->retry_safe  = opts ? opts->retry_safe : 0;

    loop_push_cmd(ac->loop, c);
    return 0;
}


int
xrdc_aio_submit(xrdc_aconn *ac, const void *hdr24,
                const void *payload, uint32_t plen,
                xrdc_aio_cb cb, void *ctx, int deadline_ms, xrdc_status *st)
{
    xrdc_aio_opts o = { deadline_ms, -1, 0 };   /* default: not auto-retried */
    return xrdc_aio_submit_ex(ac, hdr24, payload, plen, &o, cb, ctx, st);
}


/* blocking convenience wrapper */

void
call_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen,
        const xrdc_status *st)
{
    call_wait *w = (call_wait *) ctx;
    pthread_mutex_lock(&w->mx);
    w->rc   = rc;
    w->kxr  = kxr;
    w->body = body;
    w->blen = blen;
    if (st != NULL) {
        w->st = *st;
    }
    w->done = 1;
    pthread_cond_signal(&w->cv);
    pthread_mutex_unlock(&w->mx);
}


int
xrdc_aio_call_ex(xrdc_aconn *ac, const void *hdr24,
                 const void *payload, uint32_t plen,
                 const xrdc_aio_opts *opts,
                 uint16_t *kxr, uint8_t **body, uint32_t *blen,
                 xrdc_status *st)
{
    call_wait w;
    memset(&w, 0, sizeof(w));
    pthread_mutex_init(&w.mx, NULL);
    pthread_cond_init(&w.cv, NULL);

    if (xrdc_aio_submit_ex(ac, hdr24, payload, plen, opts, call_cb, &w, st) != 0) {
        pthread_mutex_destroy(&w.mx);
        pthread_cond_destroy(&w.cv);
        return -1;
    }

    pthread_mutex_lock(&w.mx);
    while (!w.done) {
        pthread_cond_wait(&w.cv, &w.mx);
    }
    pthread_mutex_unlock(&w.mx);
    pthread_mutex_destroy(&w.mx);
    pthread_cond_destroy(&w.cv);

    if (w.rc < 0) {
        if (st != NULL) {
            *st = w.st;
        }
        free(w.body);
        return -1;
    }
    if (kxr != NULL) {
        *kxr = w.kxr;
    }
    if (body != NULL) {
        *body = w.body;
    } else {
        free(w.body);
    }
    if (blen != NULL) {
        *blen = w.blen;
    }
    return 0;
}


int
xrdc_aio_call(xrdc_aconn *ac, const void *hdr24,
              const void *payload, uint32_t plen,
              uint16_t *kxr, uint8_t **body, uint32_t *blen,
              int deadline_ms, xrdc_status *st)
{
    xrdc_aio_opts o = { deadline_ms, -1, 0 };
    return xrdc_aio_call_ex(ac, hdr24, payload, plen, &o, kxr, body, blen, st);
}
