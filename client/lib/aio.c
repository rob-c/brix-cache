/*
 * aio.c — the epoll event loop + non-blocking connections behind aio.h (M1).
 *
 * WHAT: One loop thread owns an epoll set, an eventfd (cross-thread wakeup), and a
 *       list of attached connections. Each connection has an outgoing byte queue,
 *       an incoming parse buffer, and an in-flight map (streamid → request). Other
 *       threads never touch that per-connection state: they post commands onto a
 *       mutex-guarded queue and kick the eventfd; the loop drains the queue and
 *       does all socket I/O itself. Replies are demultiplexed by streamid and the
 *       per-request callback fires inline on the loop thread.
 * WHY:  See aio.h — pipelining hides RTT, per-request deadlines stop a flaky link
 *       from hanging, and a single-threaded data plane keeps it race-free.
 * HOW:  Sections below: [buffers] growable byte buffer · [reqmap] open-addressing
 *       streamid map · [request] lifecycle + completion · [io] non-blocking read/
 *       write (cleartext + TLS) + frame parser · [conn] attach/teardown/fail ·
 *       [commands] cross-thread queue · [loop] the thread · [public] the API.
 *
 * Clean-room: epoll/eventfd/pthreads + OpenSSL (already linked for tls.c) + the
 * existing wire framing. No XrdCl.
 */
#include "aio.h"
#include "uring.h"                 /* phase-44: xrdc_uring_available() + ring */
#include "protocol/frame_hdr.h"   /* shared resp-hdr / error / wait codecs */

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#if (XROOTD_HAVE_LIBURING)
#include <liburing.h>
#endif

#define AIO_MAXEV      64        /* epoll_wait batch size */
#define AIO_URING_SLOTS 128      /* phase-44 loop-engine poll-slot table size */
#define AIO_READ_CHUNK 65536u    /* read headroom reserved per recv attempt */
#define AIO_TICK_MS    1000      /* idle epoll_wait cap (deadline granularity) */

/* ---------------------------------------------------------------- buffers ---- */
/*
 * A simple grow-only byte buffer with a consumed cursor. For the write queue,
 * bytes live in [start,len) and drain from `start`; for the read buffer, [start,
 * len) holds unparsed bytes and `start` is the parse cursor. Both compact to the
 * front once fully consumed.
 */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   start;
    size_t   len;
} xbuf;

static int
xbuf_reserve(xbuf *b, size_t need)
{
    if (b->len + need <= b->cap) {
        return 0;
    }
    size_t ncap = (b->cap == 0) ? 4096 : b->cap;
    while (ncap < b->len + need) {
        ncap *= 2;
    }
    uint8_t *nb = (uint8_t *) realloc(b->buf, ncap);
    if (nb == NULL) {
        return -1;
    }
    b->buf = nb;
    b->cap = ncap;
    return 0;
}

static int
xbuf_append(xbuf *b, const void *data, size_t n)
{
    if (n == 0) {
        return 0;
    }
    if (xbuf_reserve(b, n) != 0) {
        return -1;
    }
    memcpy(b->buf + b->len, data, n);
    b->len += n;
    return 0;
}

/* Drop the consumed prefix [0,start) so the live bytes sit at the front. */
static void
xbuf_compact(xbuf *b)
{
    if (b->start == 0) {
        return;
    }
    if (b->start >= b->len) {
        b->start = b->len = 0;
        return;
    }
    memmove(b->buf, b->buf + b->start, b->len - b->start);
    b->len -= b->start;
    b->start = 0;
}

static void
xbuf_free(xbuf *b)
{
    free(b->buf);
    b->buf = NULL;
    b->cap = b->start = b->len = 0;
}

/* ---------------------------------------------------------------- request ---- */
/*
 * One in-flight request. The finalized 24-byte header and the (owned) payload are
 * retained so M2/M3 can re-issue the request after a reconnect. Reply bytes from
 * one or more kXR_oksofar frames plus the terminal frame accumulate into `acc`,
 * which is handed to the callback on completion.
 */
typedef struct xrdc_areq {
    uint16_t    sid;
    uint8_t     hdr[XRD_REQUEST_HDR_LEN];
    uint8_t    *payload;     /* owned copy, or NULL */
    uint32_t    plen;

    uint8_t    *acc;         /* accumulated reply body (owned until delivered) */
    uint32_t    acc_len;
    uint32_t    acc_cap;

    xrdc_aio_cb cb;
    void       *ctx;
    uint64_t    deadline_ns; /* 0 = none */

    /* resilience (M2) */
    int         retry_safe;  /* may be re-issued verbatim after a reconnect */
    int         retries_left;/* transport re-issues remaining */
    int         is_ping;     /* internal keepalive heartbeat (no user cb) */
    uint64_t    submit_ns;   /* when the current attempt was written (RTT sample) */
    struct xrdc_areq *pend_next;  /* link in the aconn pending (re-issue) list */
} xrdc_areq;

static void
areq_free(xrdc_areq *r)
{
    if (r == NULL) {
        return;
    }
    free(r->payload);
    free(r->acc);
    free(r);
}

static int
areq_accumulate(xrdc_areq *r, const uint8_t *body, uint32_t n)
{
    if (n == 0) {
        return 0;
    }
    if (r->acc_len + n > r->acc_cap) {
        uint32_t ncap = (r->acc_cap == 0) ? n : r->acc_cap;
        while (ncap < r->acc_len + n) {
            ncap *= 2;
        }
        uint8_t *na = (uint8_t *) realloc(r->acc, ncap);
        if (na == NULL) {
            return -1;
        }
        r->acc = na;
        r->acc_cap = ncap;
    }
    memcpy(r->acc + r->acc_len, body, n);
    r->acc_len += n;
    return 0;
}

/* Invoke the completion callback exactly once and free the request. On success the
 * accumulated body ownership transfers to the callback; on failure body is NULL. */
static void
areq_complete(xrdc_areq *r, int rc, uint16_t kxr, const xrdc_status *st)
{
    uint8_t  *body = NULL;
    uint32_t  blen = 0;

    if (rc == 0) {
        body = r->acc;
        blen = r->acc_len;
        r->acc = NULL;          /* ownership moves to the callback */
    }
    r->cb(r->ctx, rc, kxr, body, blen, st);
    areq_free(r);
}

/* ----------------------------------------------------------------- reqmap ---- */
/*
 * Open-addressing (linear-probe) map from streamid → in-flight request. The key
 * space is dense and the live count is bounded by the pipeline depth, so this stays
 * tiny and fast. Deleted slots are tombstoned and reclaimed on the next rehash.
 */
#define REQMAP_TOMB ((xrdc_areq *) -1)

typedef struct {
    xrdc_areq **slots;
    uint32_t    cap;        /* power of two */
    uint32_t    count;      /* live entries */
    uint32_t    tomb;       /* tombstones */
} reqmap;

static int
reqmap_rehash(reqmap *m, uint32_t newcap)
{
    xrdc_areq **ns = (xrdc_areq **) calloc(newcap, sizeof(*ns));
    if (ns == NULL) {
        return -1;
    }
    for (uint32_t i = 0; i < m->cap; i++) {
        xrdc_areq *r = m->slots[i];
        if (r == NULL || r == REQMAP_TOMB) {
            continue;
        }
        uint32_t idx = r->sid & (newcap - 1);
        while (ns[idx] != NULL) {
            idx = (idx + 1) & (newcap - 1);
        }
        ns[idx] = r;
    }
    free(m->slots);
    m->slots = ns;
    m->cap = newcap;
    m->tomb = 0;
    return 0;
}

static int
reqmap_put(reqmap *m, xrdc_areq *r)
{
    if (m->cap == 0) {
        if (reqmap_rehash(m, 64) != 0) {
            return -1;
        }
    }
    if ((m->count + m->tomb + 1) * 4 >= m->cap * 3) {
        uint32_t newcap = (m->count * 2 < m->cap) ? m->cap : m->cap * 2;
        if (newcap < 64) {
            newcap = 64;
        }
        if (reqmap_rehash(m, newcap) != 0) {
            return -1;
        }
    }
    uint32_t idx = r->sid & (m->cap - 1);
    while (m->slots[idx] != NULL && m->slots[idx] != REQMAP_TOMB) {
        idx = (idx + 1) & (m->cap - 1);
    }
    if (m->slots[idx] == REQMAP_TOMB) {
        m->tomb--;
    }
    m->slots[idx] = r;
    m->count++;
    return 0;
}

static xrdc_areq *
reqmap_get(reqmap *m, uint16_t sid)
{
    if (m->cap == 0) {
        return NULL;
    }
    uint32_t idx = sid & (m->cap - 1);
    for (uint32_t n = 0; n < m->cap; n++) {
        xrdc_areq *r = m->slots[idx];
        if (r == NULL) {
            return NULL;
        }
        if (r != REQMAP_TOMB && r->sid == sid) {
            return r;
        }
        idx = (idx + 1) & (m->cap - 1);
    }
    return NULL;
}

static void
reqmap_del(reqmap *m, uint16_t sid)
{
    if (m->cap == 0) {
        return;
    }
    uint32_t idx = sid & (m->cap - 1);
    for (uint32_t n = 0; n < m->cap; n++) {
        xrdc_areq *r = m->slots[idx];
        if (r == NULL) {
            return;
        }
        if (r != REQMAP_TOMB && r->sid == sid) {
            m->slots[idx] = REQMAP_TOMB;
            m->count--;
            m->tomb++;
            return;
        }
        idx = (idx + 1) & (m->cap - 1);
    }
}

/* ------------------------------------------------------------------- types ---- */

/* aconn lifecycle state. */
typedef enum {
    ACONN_ALIVE = 0,    /* normal: doing I/O on a healthy socket */
    ACONN_RECONNECTING, /* socket dropped; a worker thread is re-establishing it */
    ACONN_DEAD          /* reconnect budget exhausted; no recovery */
} aconn_state;

struct xrdc_aconn {
    xrdc_loop     *loop;
    xrdc_conn     *conn;     /* borrowed brought-up session */
    int            fd;
    struct ssl_st *ssl;      /* mirrors conn->io.ssl (NULL = cleartext) */
    uint16_t       next_sid;

    xbuf           wbuf;     /* outgoing serialized frames */
    xbuf           rbuf;     /* incoming bytes being parsed */
    reqmap         inflight;

    int            epoll_events;          /* currently registered interest */
    int            uring_slot;            /* phase-44: io_uring poll-slot idx, or -1 */
    uint32_t       fd_gen;                /* phase-44: bumped per (re)arm; guards CQEs */
    int            dead;                  /* socket not usable right now */
    int            tls_want_write_on_read;/* SSL_read returned WANT_WRITE */
    int            tls_want_read_on_write;/* SSL_write returned WANT_READ */

    /* resilience (M2) */
    aconn_state    state;
    int            max_stall_ms;          /* reconnect patience budget */
    int            keepalive_ms;          /* idle-before-heartbeat (0=off) */
    int            def_retries;           /* default per-request retry budget */
    uint64_t       last_activity_ns;      /* last frame heard from the server */
    uint64_t       srtt_ns, rttvar_ns;    /* RTT EWMA (TCP-style) */
    int            have_rtt;              /* srtt seeded */
    int            ping_inflight;         /* heartbeat ping outstanding */
    uint64_t       reconnect_deadline_ns; /* give up reconnecting past this */
    xrdc_areq     *pending;               /* parked requests awaiting re-issue */

    /* reconnect worker handoff (worker writes rc_*, loop polls rc_finished) */
    pthread_t      rc_thread;
    int            rc_thread_live;
    volatile int   rc_finished;           /* set by worker just before it returns */
    int            rc_result;             /* 0 = reconnected, -1 = gave up */
    xrdc_status    rc_st;                 /* failure detail when rc_result < 0 */

    struct xrdc_aconn *next; /* loop->aconns singly-linked list */
};

typedef enum {
    CMD_ADD_ACONN,
    CMD_SUBMIT,
    CMD_CLOSE_ACONN,
    CMD_STOP
} cmd_type;

typedef struct cmd {
    cmd_type     type;
    xrdc_aconn  *ac;

    /* SUBMIT payload (header copied inline; payload owned, moved into the areq) */
    uint8_t      hdr[XRD_REQUEST_HDR_LEN];
    uint8_t     *payload;
    uint32_t     plen;
    xrdc_aio_cb  cb;
    void        *ctx;
    int          deadline_ms;
    int          max_retries;   /* < 0 ⇒ aconn default */
    int          retry_safe;    /* idempotent + not handle-bound */

    /* synchronous control ops signal the caller through these (NULL for SUBMIT) */
    pthread_mutex_t *dmx;
    pthread_cond_t  *dcv;
    int             *done;

    struct cmd  *next;
} cmd;

/* Phase 44: io_uring loop-engine poll slot — UAF-safe CQE→aconn mapping.  The
 * poll's user_data carries (generation<<32 | slot); a stale CQE for a recycled
 * slot is dropped, so a poll completing after its aconn was freed/reconnected
 * never dereferences freed memory (the same discipline as the server ring). */
struct xrdc_poll_slot {
    xrdc_aconn *ac;
    uint32_t    gen;
    int         in_use;
};

struct xrdc_loop {
    int             epfd;
    int             evfd;
    pthread_t       thread;
    int             thread_ok;

    pthread_mutex_t cq_lock;
    cmd            *cq_head;
    cmd            *cq_tail;

    xrdc_aconn     *aconns;   /* loop-thread-owned list */
    int             stop;

    int             use_uring; /* phase-44: loop engine is io_uring (default 0) */
#if (XROOTD_HAVE_LIBURING)
    struct io_uring uring;
    int             uring_ok;  /* ring initialized (teardown guard)             */
    struct xrdc_poll_slot uslots[AIO_URING_SLOTS];
#endif
};

/* forward decls */
static void aconn_update_epoll(xrdc_aconn *ac);
static void aconn_on_transport_error(xrdc_aconn *ac, const xrdc_status *st);
static void aconn_issue_areq(xrdc_aconn *ac, xrdc_areq *r);
static uint64_t aconn_rto_ns(const xrdc_aconn *ac);
static void aconn_note_rtt(xrdc_aconn *ac, const xrdc_areq *r);
static void aconn_poll_reconnect(xrdc_aconn *ac);
static void aconn_maybe_ping(xrdc_aconn *ac);
static void aconn_pending_fail_all(xrdc_aconn *ac, const xrdc_status *st);

/* ---------------------------------------------------------------------- io ---- */

/* Drain the outgoing queue. Non-blocking; tolerates short writes and TLS WANT_*. */
static void
aconn_do_write(xrdc_aconn *ac)
{
    ac->tls_want_read_on_write = 0;

    while (ac->wbuf.start < ac->wbuf.len) {
        size_t   n = ac->wbuf.len - ac->wbuf.start;
        uint8_t *p = ac->wbuf.buf + ac->wbuf.start;
        ssize_t  w;

        if (ac->ssl != NULL) {
            ERR_clear_error();
            int ret = SSL_write(ac->ssl, p, (int) (n > INT32_MAX ? INT32_MAX : n));
            if (ret > 0) {
                ac->wbuf.start += (size_t) ret;
                continue;
            }
            int err = SSL_get_error(ac->ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE) {
                break;                       /* re-armed via EPOLLOUT */
            }
            if (err == SSL_ERROR_WANT_READ) {
                ac->tls_want_read_on_write = 1;  /* retry on EPOLLIN */
                break;
            }
            {
                xrdc_status st;
                xrdc_status_set(&st, XRDC_ESOCK, 0, "TLS write failed (ssl err %d)", err);
                aconn_on_transport_error(ac, &st);
            }
            return;
        }

        w = send(ac->fd, p, n, MSG_NOSIGNAL);   /* MSG_NOSIGNAL: a dead peer is an
                                                  * EPIPE return, never a signal */
        if (w > 0) {
            ac->wbuf.start += (size_t) w;
            continue;
        }
        if (w < 0 && (errno == EINTR)) {
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;                           /* re-armed via EPOLLOUT */
        }
        {
            xrdc_status st;
            xrdc_status_set(&st, XRDC_ESOCK, errno, "write: %s", strerror(errno));
            aconn_on_transport_error(ac, &st);
        }
        return;
    }

    if (ac->wbuf.start >= ac->wbuf.len) {
        ac->wbuf.start = ac->wbuf.len = 0;   /* fully flushed */
    }
}

/* -------------------------------------------------------------------- rtt ---- */
/*
 * RTT smoothing (RFC-6298 style) and the derived retransmit/timeout estimate. The
 * adaptive default request deadline and the keepalive probe interval are derived
 * from this, so a slow link gets patience and a fast link gets prompt failure
 * detection — all bounded.
 */
static void
aconn_note_rtt(xrdc_aconn *ac, const xrdc_areq *r)
{
    if (r->submit_ns == 0) {
        return;
    }
    uint64_t now = xrdc_mono_ns();
    if (now <= r->submit_ns) {
        return;
    }
    uint64_t sample = now - r->submit_ns;
    if (!ac->have_rtt) {
        ac->srtt_ns = sample;
        ac->rttvar_ns = sample / 2;
        ac->have_rtt = 1;
        return;
    }
    uint64_t d = (ac->srtt_ns > sample) ? ac->srtt_ns - sample : sample - ac->srtt_ns;
    ac->rttvar_ns = (3 * ac->rttvar_ns + d) / 4;
    ac->srtt_ns = (7 * ac->srtt_ns + sample) / 8;
}

/* srtt + 4·rttvar, clamped to [200 ms, 30 s]; 1 s before any sample. */
static uint64_t
aconn_rto_ns(const xrdc_aconn *ac)
{
    if (!ac->have_rtt) {
        return 1000000000ULL;
    }
    uint64_t rto = ac->srtt_ns + 4 * ac->rttvar_ns;
    if (rto < 200000000ULL) {
        rto = 200000000ULL;
    }
    if (rto > 30000000000ULL) {
        rto = 30000000000ULL;
    }
    return rto;
}

/* Dispatch one fully-received response frame to its in-flight request. */
static void
aconn_dispatch_frame(xrdc_aconn *ac, uint16_t sid, uint16_t stat,
                     const uint8_t *body, uint32_t dlen)
{
    xrdc_areq *r = reqmap_get(&ac->inflight, sid);
    if (r == NULL) {
        return;   /* late frame for a completed/cancelled request — ignore */
    }

    ac->last_activity_ns = xrdc_mono_ns();   /* we heard from the server */

    switch (stat) {
    case kXR_oksofar:
        (void) areq_accumulate(r, body, dlen);
        return;   /* more frames follow; keep the entry */

    case kXR_ok:
        aconn_note_rtt(ac, r);   /* RTT sample feeds the adaptive deadline/RTO */
        /* fallthrough */
    case kXR_redirect:   /* delivered to the upper layer (M2/M3 acts) */
    case kXR_wait:
    case kXR_authmore:
        (void) areq_accumulate(r, body, dlen);
        reqmap_del(&ac->inflight, sid);
        areq_complete(r, 0, stat, NULL);
        return;

    case kXR_error: {
        int         errnum = 0;
        const char *emsg = "";
        size_t      emlen = 0;
        xrdc_status st;
        /* msg is NOT NUL-terminated on the wire — decode to a bounded slice and
         * print with %.*s (the old %s on body+4 was a heap over-read). */
        xrd_error_body_decode(body, dlen, &errnum, &emsg, &emlen);
        xrdc_status_set(&st, errnum, 0, "%.*s (%s)", (int) emlen,
                        emsg ? emsg : "", xrdc_kxr_name(errnum));
        reqmap_del(&ac->inflight, sid);
        areq_complete(r, -1, (uint16_t) errnum, &st);
        return;
    }

    default: {
        xrdc_status st;
        xrdc_status_set(&st, XRDC_EPROTO, 0, "unexpected response status %u", stat);
        reqmap_del(&ac->inflight, sid);
        areq_complete(r, -1, XRDC_EPROTO, &st);
        return;
    }
    }
}

/* Parse all complete frames sitting in rbuf, then compact. */
static void
aconn_parse(xrdc_aconn *ac)
{
    for (;;) {
        size_t avail = ac->rbuf.len - ac->rbuf.start;
        if (avail < XRD_RESPONSE_HDR_LEN) {
            break;
        }
        const uint8_t *p = ac->rbuf.buf + ac->rbuf.start;
        uint16_t sid, stat;
        uint32_t dlen;
        xrd_resp_hdr_unpack(p, &sid, &stat, &dlen);   /* unaligned-safe */

        if (dlen > XRDC_DLEN_MAX) {
            xrdc_status st;
            xrdc_status_set(&st, XRDC_EPROTO, 0, "response body too large (%u)", dlen);
            aconn_on_transport_error(ac, &st);
            return;
        }
        if (avail < (size_t) XRD_RESPONSE_HDR_LEN + dlen) {
            break;   /* need more bytes */
        }
        aconn_dispatch_frame(ac, sid, stat, p + XRD_RESPONSE_HDR_LEN, dlen);
        if (ac->dead) {
            return;
        }
        ac->rbuf.start += (size_t) XRD_RESPONSE_HDR_LEN + dlen;
    }
    xbuf_compact(&ac->rbuf);
}

/* Read everything available into rbuf, then parse. Non-blocking; tolerates TLS. */
static void
aconn_do_read(xrdc_aconn *ac)
{
    ac->tls_want_write_on_read = 0;

    for (;;) {
        if (xbuf_reserve(&ac->rbuf, AIO_READ_CHUNK) != 0) {
            xrdc_status st;
            xrdc_status_set(&st, XRDC_EPROTO, 0, "out of memory (read buffer)");
            aconn_on_transport_error(ac, &st);
            return;
        }
        uint8_t *dst = ac->rbuf.buf + ac->rbuf.len;
        size_t   room = ac->rbuf.cap - ac->rbuf.len;

        if (ac->ssl != NULL) {
            ERR_clear_error();
            int ret = SSL_read(ac->ssl, dst, (int) (room > INT32_MAX ? INT32_MAX : room));
            if (ret > 0) {
                ac->rbuf.len += (size_t) ret;
                continue;
            }
            int err = SSL_get_error(ac->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                break;
            }
            if (err == SSL_ERROR_WANT_WRITE) {
                ac->tls_want_write_on_read = 1;  /* retry on EPOLLOUT */
                break;
            }
            {
                xrdc_status st;
                if (err == SSL_ERROR_ZERO_RETURN) {
                    xrdc_status_set(&st, XRDC_ESOCK, 0, "connection closed by peer (TLS)");
                } else {
                    xrdc_status_set(&st, XRDC_ESOCK, 0, "TLS read failed (ssl err %d)", err);
                }
                aconn_parse(ac);             /* deliver any complete frames first */
                if (!ac->dead) {
                    aconn_on_transport_error(ac, &st);
                }
            }
            return;
        }

        ssize_t r = read(ac->fd, dst, room);
        if (r > 0) {
            ac->rbuf.len += (size_t) r;
            continue;
        }
        if (r == 0) {
            xrdc_status st;
            xrdc_status_set(&st, XRDC_ESOCK, 0, "connection closed by peer");
            aconn_parse(ac);
            if (!ac->dead) {
                aconn_on_transport_error(ac, &st);
            }
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        {
            xrdc_status st;
            xrdc_status_set(&st, XRDC_ESOCK, errno, "read: %s", strerror(errno));
            aconn_on_transport_error(ac, &st);
        }
        return;
    }

    aconn_parse(ac);
}

/* React to epoll readiness for one connection. */
static void
aconn_handle_io(xrdc_aconn *ac, uint32_t events)
{
    if (ac->dead) {
        return;
    }
    if (events & (EPOLLERR | EPOLLHUP)) {
        /* still try to drain any final readable bytes before failing */
        aconn_do_read(ac);
        if (!ac->dead) {
            xrdc_status st;
            xrdc_status_set(&st, XRDC_ESOCK, 0, "socket error/hangup");
            aconn_on_transport_error(ac, &st);
        }
        return;
    }
    if ((events & EPOLLOUT) || ac->tls_want_read_on_write) {
        aconn_do_write(ac);
    }
    if (!ac->dead && ((events & EPOLLIN) || ac->tls_want_write_on_read)) {
        aconn_do_read(ac);
    }
    if (!ac->dead) {
        aconn_update_epoll(ac);
    }
}

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

static int  io_engine_arm(xrdc_loop *l, xrdc_aconn *ac, int want);
static void io_engine_del(xrdc_loop *l, xrdc_aconn *ac);

#if (XROOTD_HAVE_LIBURING)

#define AIO_URING_EVFD_UD    0xffffffffffffffffULL  /* evfd readiness poll       */
#define AIO_URING_IGNORE_UD  0xfffffffffffffffeULL  /* cancel-ack CQE (drop)     */

/* epoll interest mask -> poll(2) mask for io_uring_prep_poll_*. */
static unsigned
uring_pollmask(int want)
{
    unsigned m = 0;
    if (want & EPOLLIN)  { m |= POLLIN;  }
    if (want & EPOLLOUT) { m |= POLLOUT; }
    return m;
}

/* Claim a free poll slot for ac (loop-thread only; no lock). Returns 0 / -1. */
static int
uring_slot_alloc(xrdc_loop *l, xrdc_aconn *ac)
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
static int
uring_poll_submit(xrdc_loop *l, xrdc_aconn *ac, int want)
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
static void
uring_poll_cancel(xrdc_loop *l, xrdc_aconn *ac, int freeing)
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

#endif /* XROOTD_HAVE_LIBURING */

/* Create the readiness set + the wake eventfd.  evfd is used by both engines;
 * epoll registers it in the set, io_uring arms a multishot poll on it. */
static int
io_engine_setup(xrdc_loop *l, xrdc_status *st)
{
    l->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (l->evfd < 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "eventfd: %s", strerror(errno));
        return -1;
    }

#if (XROOTD_HAVE_LIBURING)
    if (l->use_uring) {
        struct io_uring_sqe *sqe;
        if (io_uring_queue_init(256, &l->uring, 0) < 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "io_uring_queue_init");
            return -1;
        }
        l->uring_ok = 1;
        sqe = io_uring_get_sqe(&l->uring);     /* multishot poll on the evfd */
        if (sqe == NULL) {
            xrdc_status_set(st, XRDC_ESOCK, 0, "io_uring evfd arm");
            return -1;
        }
        io_uring_prep_poll_multishot(sqe, l->evfd, POLLIN);
        io_uring_sqe_set_data64(sqe, AIO_URING_EVFD_UD);
        if (io_uring_submit(&l->uring) < 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "io_uring evfd submit");
            return -1;
        }
        return 0;
    }
#endif

    l->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (l->epfd < 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "epoll_create1: %s",
                        strerror(errno));
        return -1;
    }
    {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events   = EPOLLIN;
        ev.data.ptr = l;                       /* loop pointer tags the eventfd */
        if (epoll_ctl(l->epfd, EPOLL_CTL_ADD, l->evfd, &ev) != 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "epoll_ctl(evfd): %s",
                            strerror(errno));
            return -1;
        }
    }
    return 0;
}

static void
io_engine_teardown(xrdc_loop *l)
{
#if (XROOTD_HAVE_LIBURING)
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
static int
io_engine_arm(xrdc_loop *l, xrdc_aconn *ac, int want)
{
#if (XROOTD_HAVE_LIBURING)
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

static void
io_engine_del(xrdc_loop *l, xrdc_aconn *ac)
{
#if (XROOTD_HAVE_LIBURING)
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

/* Fill evs[] with up to `max` readiness events (data.ptr + EPOLL* mask) and
 * return the count, or -1 on a hard wait error.  For io_uring, translate poll
 * CQEs (generation-guarded) and re-arm any multishot that auto-disarmed. */
static int
io_engine_wait(xrdc_loop *l, struct epoll_event *evs, int max, int timeout_ms)
{
#if (XROOTD_HAVE_LIBURING)
    if (l->use_uring) {
        struct io_uring_cqe *cqe;
        struct __kernel_timespec ts;
        int n = 0;

        ts.tv_sec  = timeout_ms / 1000;
        ts.tv_nsec = (long) (timeout_ms % 1000) * 1000000L;

        /* Block until at least one CQE or the timeout. */
        if (io_uring_wait_cqe_timeout(&l->uring, &cqe, &ts) < 0) {
            return 0;   /* timeout / -ETIME / -EINTR: no events this tick */
        }

        while (n < max && io_uring_peek_cqe(&l->uring, &cqe) == 0) {
            uint64_t ud = io_uring_cqe_get_data64(cqe);

            if (ud == AIO_URING_IGNORE_UD) {
                io_uring_cqe_seen(&l->uring, cqe);
                continue;
            }
            if (ud == AIO_URING_EVFD_UD) {
                evs[n].data.ptr = l;
                evs[n].events   = EPOLLIN;
                n++;
                io_uring_cqe_seen(&l->uring, cqe);
                continue;
            }
            {
                uint32_t slot = (uint32_t) (ud & 0xffffffffULL);
                uint32_t gen  = (uint32_t) (ud >> 32);

                if (slot < AIO_URING_SLOTS && l->uslots[slot].in_use
                    && l->uslots[slot].gen == gen
                    && l->uslots[slot].ac != NULL && cqe->res >= 0)
                {
                    xrdc_aconn *ac = l->uslots[slot].ac;
                    uint32_t    ev = 0;
                    if (cqe->res & (POLLIN | POLLHUP | POLLERR)) { ev |= EPOLLIN; }
                    if (cqe->res & POLLOUT)                      { ev |= EPOLLOUT; }
                    evs[n].data.ptr = ac;
                    evs[n].events   = ev;
                    n++;
                    /* Re-arm if the multishot auto-disarmed (no F_MORE). */
                    if (!(cqe->flags & IORING_CQE_F_MORE)) {
                        (void) uring_poll_submit(l, ac, ac->epoll_events);
                    }
                }
                /* else: stale/cancelled CQE for a recycled slot — dropped. */
                io_uring_cqe_seen(&l->uring, cqe);
            }
        }
        return n;
    }
#endif
    return epoll_wait(l->epfd, evs, max, timeout_ms);
}

/* ----------------------------------------------------------------- epoll ----- */

static void
aconn_update_epoll(xrdc_aconn *ac)
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

/* ------------------------------------------------------------------- conn ----- */

/* Fail every in-flight request with `st`, leaving the map empty. */
static void
aconn_drain_inflight(xrdc_aconn *ac, const xrdc_status *st)
{
    for (uint32_t i = 0; i < ac->inflight.cap; i++) {
        xrdc_areq *r = ac->inflight.slots[i];
        if (r == NULL || r == REQMAP_TOMB) {
            continue;
        }
        ac->inflight.slots[i] = NULL;
        areq_complete(r, -1, (uint16_t) (st->kxr & 0xffff), st);
    }
    ac->inflight.count = 0;
    ac->inflight.tomb = 0;
}

/* ------------------------------------------------------------- reconnect ----- */
/*
 * On a transport drop the connection does not fail its callers outright; it goes
 * RECONNECTING: a worker thread re-establishes the session (off the loop thread so
 * other connections keep flowing), retry-safe in-flight requests are parked, and
 * once the new socket is back they are re-issued — so a stat/ping/dirlist that was
 * mid-flight when the server bounced simply succeeds, transparently. Non-retry-safe
 * (mutating or handle-bound) requests fail so the higher layer (M3) can reopen.
 */

/* Fail every parked request with `st`, emptying the pending list. */
static void
aconn_pending_fail_all(xrdc_aconn *ac, const xrdc_status *st)
{
    xrdc_areq *p = ac->pending;
    ac->pending = NULL;
    while (p != NULL) {
        xrdc_areq *nx = p->pend_next;
        p->pend_next = NULL;
        areq_complete(p, -1, (uint16_t) (st->kxr & 0xffff), st);
        p = nx;
    }
}

/* Reconnect worker (its own thread). Retries xrdc_reconnect with exponential
 * backoff + jitter until success or the reconnect deadline, then signals the loop
 * via rc_finished + the eventfd. Touches only conn (via xrdc_reconnect) and the
 * rc_* handoff fields — never the loop-owned per-conn state. */
static void *
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

/* Enter RECONNECTING: pull the dead fd from epoll, partition in-flight requests
 * (retry-safe → parked, others → failed), and spawn the reconnect worker. */
static void
aconn_on_transport_error(xrdc_aconn *ac, const xrdc_status *st)
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

    uint64_t now = xrdc_mono_ns();
    ac->state = ACONN_RECONNECTING;
    ac->reconnect_deadline_ns = now + (uint64_t) ac->max_stall_ms * 1000000ULL;
    ac->ping_inflight = 0;
    ac->tls_want_read_on_write = ac->tls_want_write_on_read = 0;

    for (uint32_t i = 0; i < ac->inflight.cap; i++) {
        xrdc_areq *r = ac->inflight.slots[i];
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
static void
aconn_reconnect_succeeded(xrdc_aconn *ac)
{
    ac->fd  = ac->conn->io.fd;
    ac->ssl = ac->conn->io.ssl;

    int fl = fcntl(ac->fd, F_GETFL, 0);
    if (fl >= 0) {
        fcntl(ac->fd, F_SETFL, fl | O_NONBLOCK);
    }

    if (io_engine_arm(ac->loop, ac, EPOLLIN) != 0) {
        xrdc_status st;
        xrdc_status_set(&st, XRDC_ESOCK, errno, "poll re-register failed");
        ac->state = ACONN_DEAD;
        aconn_pending_fail_all(ac, &st);
        return;
    }
    ac->dead = 0;
    ac->state = ACONN_ALIVE;
    ac->last_activity_ns = xrdc_mono_ns();
    ac->reconnect_deadline_ns = 0;

    xrdc_areq *p = ac->pending;
    ac->pending = NULL;
    while (p != NULL) {
        xrdc_areq *nx = p->pend_next;
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
static void
aconn_poll_reconnect(xrdc_aconn *ac)
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

/* ------------------------------------------------------------- keepalive ----- */

/* Internal heartbeat-ping completion: just clear the in-flight marker (a failed
 * ping is turned into a transport error by the timeout scan, not here). */
static void
aconn_ping_cb(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen,
              const xrdc_status *st)
{
    (void) rc; (void) kxr; (void) blen; (void) st;
    xrdc_aconn *ac = (xrdc_aconn *) ctx;
    ac->ping_inflight = 0;
    free(body);
}

/* Send a kXR_ping if the link has been idle past the keepalive threshold. */
static void
aconn_maybe_ping(xrdc_aconn *ac)
{
    if (ac->state != ACONN_ALIVE || ac->keepalive_ms <= 0 || ac->ping_inflight) {
        return;
    }
    uint64_t now = xrdc_mono_ns();
    if (now - ac->last_activity_ns < (uint64_t) ac->keepalive_ms * 1000000ULL) {
        return;
    }
    xrdc_areq *r = (xrdc_areq *) calloc(1, sizeof(*r));
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
static void
aconn_destroy(xrdc_aconn *ac)
{
    xrdc_loop  *l = ac->loop;
    xrdc_status st;
    xrdc_status_set(&st, XRDC_ESOCK, 0, "connection closed");

    if (ac->rc_thread_live) {
        pthread_join(ac->rc_thread, NULL);   /* bounded by the connect timeout */
        ac->rc_thread_live = 0;
    }
    if (!ac->dead) {
        io_engine_del(l, ac);
        aconn_drain_inflight(ac, &st);
    }
    aconn_pending_fail_all(ac, &st);   /* fail any parked requests */
    xrdc_aconn **pp = &l->aconns;
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
static uint16_t
aconn_alloc_sid(xrdc_aconn *ac)
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
static void
aconn_issue_areq(xrdc_aconn *ac, xrdc_areq *r)
{
    uint16_t sid = aconn_alloc_sid(ac);
    r->sid = sid;
    r->hdr[0] = (uint8_t) (sid >> 8);
    r->hdr[1] = (uint8_t) (sid & 0xff);
    uint32_t be = htonl(r->plen);
    memcpy(r->hdr + 20, &be, 4);
    r->submit_ns = xrdc_mono_ns();

    if (xbuf_append(&ac->wbuf, r->hdr, XRD_REQUEST_HDR_LEN) != 0 ||
        (r->plen > 0 && xbuf_append(&ac->wbuf, r->payload, r->plen) != 0) ||
        reqmap_put(&ac->inflight, r) != 0) {
        xrdc_status st;
        xrdc_status_set(&st, XRDC_EPROTO, 0, "out of memory (queue)");
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
static uint64_t
aconn_deadline_ns(xrdc_aconn *ac, int deadline_ms)
{
    uint64_t now = xrdc_mono_ns();
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
static void
aconn_submit_cmd(xrdc_aconn *ac, cmd *c)
{
    if (ac->state == ACONN_DEAD) {
        xrdc_status st;
        xrdc_status_set(&st, XRDC_ESOCK, 0, "connection is down");
        c->cb(c->ctx, -1, XRDC_ESOCK, NULL, 0, &st);
        free(c->payload);
        return;
    }

    xrdc_areq *r = (xrdc_areq *) calloc(1, sizeof(*r));
    if (r == NULL) {
        xrdc_status st;
        xrdc_status_set(&st, XRDC_EPROTO, 0, "out of memory (request)");
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
        r->deadline_ns = xrdc_mono_ns() + stall * 1000000ULL;
        r->pend_next = ac->pending;
        ac->pending = r;
        return;
    }

    aconn_issue_areq(ac, r);
}

/* --------------------------------------------------------------- commands ----- */

static void
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
static void
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

static void
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

/* ------------------------------------------------------------------- timers --- */

/* Fail any request whose deadline has passed; a timed-out heartbeat ping is
 * promoted to a transport error (the link is presumed dead → reconnect). Returns
 * ms until the next deadline (capped at AIO_TICK_MS) for the next epoll_wait. */
static int
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

/* -------------------------------------------------------------------- loop ---- */

static void *
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

/* ------------------------------------------------------------------ public ---- */

/* WHAT: Tear down a partially-initialized loop and return NULL for the caller.
 * WHY:  xrdc_loop_create acquires epfd, evfd, and an always-initialized cq_lock
 *       in sequence; any step can fail. Centralizing the unwind keeps each error
 *       path a flat `return` (no goto) while freeing exactly what was acquired.
 * HOW:  Both fds start at -1 and are only set once successfully opened, so the
 *       >=0 guards close only real descriptors; cq_lock is initialized before any
 *       failure can reach here, so it is always safe to destroy. Mirrors the
 *       original single-exit `fail:` ladder byte-for-byte. */
static xrdc_loop *
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
static int
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

/* ---- blocking convenience wrapper ---- */

typedef struct {
    pthread_mutex_t mx;
    pthread_cond_t  cv;
    int             done;
    int             rc;
    uint16_t        kxr;
    uint8_t        *body;
    uint32_t        blen;
    xrdc_status     st;
} call_wait;

static void
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
