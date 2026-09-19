/*
 * aio_io.c - moving bytes on an async connection
 *
 * WHAT: The socket half: draining the write queue (TLS and cleartext), the
 *       RTT/RTO estimator those writes feed, filling rbuf and framing what
 *       lands in it, and the read steps that put a bulk body straight into the
 *       caller's buffer.
 * WHY:  Phase-38 split of aio.c; what a frame then DOES to its request lives in
 *       aio_io_dispatch.c, which this file reaches only through the four entry
 *       points aio_internal.h declares for it. Behaviour-identical to both.
 */
#include "aio_internal.h"


/* types */
/* aconn lifecycle state. */




/* Phase 44: io_uring loop-engine poll slot — UAF-safe CQE→aconn mapping.  The
 * poll's user_data carries (generation<<32 | slot); a stale CQE for a recycled
 * slot is dropped, so a poll completing after its aconn was freed/reconnected
 * never dereferences freed memory (the same discipline as the server ring). */


/* forward decls */

/* io */
/* Drain the outgoing queue. Non-blocking; tolerates short writes and TLS WANT_*. */
/* One write attempt for a single buffer chunk.  Returns 1 when it made
 * progress (wbuf.start advanced — keep draining), 0 when the socket would block
 * (parked; re-armed via epoll), and -1 on a fatal error (transport error
 * already posted; the caller must abort). */
enum { ACONN_WSTEP_PROGRESS = 1, ACONN_WSTEP_BLOCKED = 0, ACONN_WSTEP_ERROR = -1 };

static int
aconn_write_ssl_step(brix_aconn *ac, uint8_t *p, size_t n)
{
    int ret, err;

    ERR_clear_error();
    ret = SSL_write(ac->ssl, p, (int) (n > INT32_MAX ? INT32_MAX : n));
    if (ret > 0) {
        ac->wbuf.start += (size_t) ret;
        return ACONN_WSTEP_PROGRESS;
    }
    err = SSL_get_error(ac->ssl, ret);
    if (err == SSL_ERROR_WANT_WRITE) {
        return ACONN_WSTEP_BLOCKED;              /* re-armed via EPOLLOUT */
    }
    if (err == SSL_ERROR_WANT_READ) {
        ac->tls_want_read_on_write = 1;          /* retry on EPOLLIN */
        return ACONN_WSTEP_BLOCKED;
    }
    {
        brix_status st;
        brix_status_set(&st, XRDC_ESOCK, 0, "TLS write failed (ssl err %d)", err);
        aconn_on_transport_error(ac, &st);
    }
    return ACONN_WSTEP_ERROR;
}

static int
aconn_write_plain_step(brix_aconn *ac, uint8_t *p, size_t n)
{
    ssize_t  w;

    w = send(ac->fd, p, n, MSG_NOSIGNAL);   /* MSG_NOSIGNAL: a dead peer is an
                                             * EPIPE return, never a signal */
    if (w > 0) {
        ac->wbuf.start += (size_t) w;
        return ACONN_WSTEP_PROGRESS;
    }
    if (w < 0 && errno == EINTR) {
        return ACONN_WSTEP_PROGRESS;             /* retry the same chunk */
    }
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return ACONN_WSTEP_BLOCKED;              /* re-armed via EPOLLOUT */
    }
    {
        brix_status st;
        brix_status_set(&st, XRDC_ESOCK, errno, "write: %s", strerror(errno));
        aconn_on_transport_error(ac, &st);
    }
    return ACONN_WSTEP_ERROR;
}

void
aconn_do_write(brix_aconn *ac)
{
    ac->tls_want_read_on_write = 0;

    /* P44-C (ii-b): cleartext conns on the rxtx engine flush via one-shot
     * IORING_OP_SEND — the CQE advances wbuf.start exactly as send(2) would
     * here.  A refused submit (ring full / no slot) means nothing is in
     * flight, so falling through to the syscall loop below stays ordered. */
    if (aconn_is_rxtx(ac)
        && uring_rxtx_send_submit(ac->loop, ac) == 0) {
        return;
    }

    while (ac->wbuf.start < ac->wbuf.len) {
        size_t   n = ac->wbuf.len - ac->wbuf.start;
        uint8_t *p = ac->wbuf.buf + ac->wbuf.start;
        int      r = ac->ssl != NULL ? aconn_write_ssl_step(ac, p, n)
                                     : aconn_write_plain_step(ac, p, n);

        if (r == ACONN_WSTEP_PROGRESS) {
            continue;
        }
        if (r == ACONN_WSTEP_BLOCKED) {
            break;
        }
        return;                                  /* r == ACONN_WSTEP_ERROR */
    }

    if (ac->wbuf.start >= ac->wbuf.len) {
        ac->wbuf.start = ac->wbuf.len = 0;   /* fully flushed */
    }
}


/* rtt *//*
 * RTT smoothing (RFC-6298 style) and the derived retransmit/timeout estimate. The
 * adaptive default request deadline and the keepalive probe interval are derived
 * from this, so a slow link gets patience and a fast link gets prompt failure
 * detection — all bounded.
 */
void
aconn_note_rtt(brix_aconn *ac, const brix_areq *r)
{
    if (r->submit_ns == 0) {
        return;
    }
    uint64_t now = brix_mono_ns();
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
uint64_t
aconn_rto_ns(const brix_aconn *ac)
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


/* Parse all complete frames sitting in rbuf, then compact. */
void
aconn_parse(brix_aconn *ac)
{
    for (;;) {
        size_t avail = ac->rbuf.len - ac->rbuf.start;
        if (avail < XRD_RESPONSE_HDR_LEN) {
            break;
        }
        const uint8_t *p = ac->rbuf.buf + ac->rbuf.start;
        uint16_t sid, stat;
        uint32_t dlen;
        brix_areq *direct;
        xrd_resp_hdr_unpack(p, &sid, &stat, &dlen);   /* unaligned-safe */

        if (dlen > XRDC_DLEN_MAX) {
            brix_status st;
            brix_status_set(&st, XRDC_EPROTO, 0, "response body too large (%u)", dlen);
            aconn_on_transport_error(ac, &st);
            return;
        }
        direct = aconn_direct_target(ac, sid, stat, dlen);
        if (direct != NULL) {
            ac->last_activity_ns = brix_mono_ns();   /* we heard from the server */
            if (aconn_direct_begin(ac, direct, sid, stat, dlen) != 0) {
                xbuf_compact(&ac->rbuf);
                return;   /* armed (tail lands in dst) or the conn was failed */
            }
            if (ac->dead) {
                return;
            }
            continue;
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


/* Outcome of one read-loop iteration, shared by the TLS and plaintext read
 * helpers so aconn_do_read can drive both through the same three-way branch
 * without duplicating the loop or the terminal-parse logic. */
#define AIO_RD_CONTINUE 0   /* bytes appended (or benign EINTR): keep pulling */
#define AIO_RD_BREAK    1   /* would-block: stop the loop and parse what we have */
#define AIO_RD_RETURN   2   /* terminal (peer close / error): fully handled, return */


/* ---- Attempt one TLS read into rbuf ----
 *
 * WHAT: Performs a single non-blocking SSL_read of up to `room` bytes into
 * `dst`. On success reports the byte count in *got and returns AIO_RD_CONTINUE. On WANT_READ/WANT_WRITE returns
 * AIO_RD_BREAK (setting tls_want_write_on_read for the WANT_WRITE case). On a
 * hard error or peer close it delivers any already-buffered frames, fails the
 * connection unless it died during that delivery, and returns AIO_RD_RETURN.
 *
 * WHY: Isolates the OpenSSL error ladder so the read loop stays under the
 * complexity cap while preserving the exact "parse first, then fail" ordering
 * (a clean close may still carry a final complete frame in rbuf).
 *
 * HOW:
 *   1. Clear the OpenSSL error queue and read at most INT32_MAX bytes.
 *   2. ret > 0: report the count in *got and signal CONTINUE.
 *   3. WANT_READ: signal BREAK; WANT_WRITE: arm EPOLLOUT retry, signal BREAK.
 *   4. Otherwise build a status (ZERO_RETURN vs generic), parse buffered frames,
 *      fail the connection if still alive, and signal RETURN.
 */
static int
aconn_read_tls(brix_aconn *ac, uint8_t *dst, size_t room, size_t *got)
{
    ERR_clear_error();
    int ret = SSL_read(ac->ssl, dst, (int) (room > INT32_MAX ? INT32_MAX : room));
    if (ret > 0) {
        *got = (size_t) ret;
        return AIO_RD_CONTINUE;
    }
    int err = SSL_get_error(ac->ssl, ret);
    if (err == SSL_ERROR_WANT_READ) {
        return AIO_RD_BREAK;
    }
    if (err == SSL_ERROR_WANT_WRITE) {
        ac->tls_want_write_on_read = 1;      /* retry on EPOLLOUT */
        return AIO_RD_BREAK;
    }

    brix_status st;
    if (err == SSL_ERROR_ZERO_RETURN) {
        brix_status_set(&st, XRDC_ESOCK, 0, "connection closed by peer (TLS)");
    } else {
        brix_status_set(&st, XRDC_ESOCK, 0, "TLS read failed (ssl err %d)", err);
    }
    aconn_parse(ac);                         /* deliver any complete frames first */
    if (!ac->dead) {
        aconn_on_transport_error(ac, &st);
    }
    return AIO_RD_RETURN;
}


/* ---- Attempt one plaintext read into rbuf ----
 *
 * WHAT: Performs a single non-blocking read(2) of up to `room` bytes into
 * `dst`. On success reports the byte count in *got and returns AIO_RD_CONTINUE
 * (a benign EINTR also returns CONTINUE, with *got left at 0). On
 * EAGAIN/EWOULDBLOCK returns AIO_RD_BREAK. On EOF (r == 0) or a hard errno it
 * delivers any already-buffered frames (EOF path), fails the connection unless
 * it died during that delivery, and returns AIO_RD_RETURN.
 *
 * WHY: Isolates the read(2)/errno ladder so the read loop stays under the
 * complexity cap while preserving the exact EOF "parse first, then fail"
 * ordering (a peer close may still carry a final complete frame in rbuf).
 *
 * HOW:
 *   1. read() into dst; r > 0: report the count in *got and signal CONTINUE.
 *   2. r == 0 (EOF): parse buffered frames, fail if still alive, signal RETURN.
 *   3. EINTR: signal CONTINUE; EAGAIN/EWOULDBLOCK: signal BREAK.
 *   4. Any other errno: fail the connection and signal RETURN.
 */
static int
aconn_read_plain(brix_aconn *ac, uint8_t *dst, size_t room, size_t *got)
{
    ssize_t r = read(ac->fd, dst, room);
    if (r > 0) {
        *got = (size_t) r;
        return AIO_RD_CONTINUE;
    }
    if (r == 0) {
        brix_status st;
        brix_status_set(&st, XRDC_ESOCK, 0, "connection closed by peer");
        aconn_parse(ac);
        if (!ac->dead) {
            aconn_on_transport_error(ac, &st);
        }
        return AIO_RD_RETURN;
    }
    if (errno == EINTR) {
        return AIO_RD_CONTINUE;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return AIO_RD_BREAK;
    }

    brix_status st;
    brix_status_set(&st, XRDC_ESOCK, errno, "read: %s", strerror(errno));
    aconn_on_transport_error(ac, &st);
    return AIO_RD_RETURN;
}


/* ---- One read attempt, TLS or plaintext ----
 *
 * WHAT: Reads up to `room` bytes into `dst`, reporting the count in *got and
 *       returning one of the AIO_RD_* outcomes.
 *
 * WHY:  The two receive modes below (into rbuf, or straight into a caller
 *       buffer) differ only in WHERE the bytes go and which counter advances,
 *       so the transport choice belongs in one place they both call.
 *
 * HOW:  Zero *got, then dispatch on ac->ssl.
 */
static int
aconn_read_step(brix_aconn *ac, uint8_t *dst, size_t room, size_t *got)
{
    *got = 0;
    return (ac->ssl != NULL) ? aconn_read_tls(ac, dst, room, got)
                             : aconn_read_plain(ac, dst, room, got);
}


/* ---- Pull the tail of a frame straight into the caller's buffer ----
 *
 * WHAT: Performs one read into the in-progress direct request's landing buffer,
 *       advancing its accumulated length, and finishes the frame once the last
 *       owed byte has arrived. Returns the AIO_RD_* outcome of the read.
 *
 * WHY:  This is the copy that the whole dst mechanism exists to remove: a bulk
 *       reply's bytes go socket → caller buffer and are never staged in rbuf.
 *
 * HOW:  Read at most rx_need bytes to dst + acc_len; add the count to acc_len
 *       and subtract it from rx_need; at zero, complete the frame.
 */
static int
aconn_read_direct(brix_aconn *ac)
{
    brix_areq *r = ac->rx_direct;
    size_t     got = 0;
    int        step = aconn_read_step(ac, r->dst + r->acc_len, ac->rx_need, &got);

    if (got > 0) {
        r->acc_len  += (uint32_t) got;
        ac->rx_need -= (uint32_t) got;
        if (ac->rx_need == 0) {
            aconn_direct_frame_done(ac);
        }
    }
    return step;
}


/* ---- Stage bytes into the connection's parse buffer ----
 *
 * WHAT: Reserves room in rbuf, performs one read into it and advances rbuf.len
 *       by whatever arrived. Returns the AIO_RD_* outcome.
 *
 * WHY:  The ordinary (non-direct) receive mode; split out so aconn_do_read is
 *       just the two-mode choice plus the loop.
 *
 * HOW:  xbuf_reserve(AIO_READ_CHUNK) — a failure is a transport error — then
 *       read into the free tail and grow len.
 */
static int
aconn_read_buffered(brix_aconn *ac)
{
    size_t got = 0;
    int    step;

    if (xbuf_reserve(&ac->rbuf, AIO_READ_CHUNK) != 0) {
        brix_status st;
        brix_status_set(&st, XRDC_EPROTO, 0, "out of memory (read buffer)");
        aconn_on_transport_error(ac, &st);
        return AIO_RD_RETURN;
    }
    step = aconn_read_step(ac, ac->rbuf.buf + ac->rbuf.len,
                           ac->rbuf.cap - ac->rbuf.len, &got);
    ac->rbuf.len += got;
    return step;
}


/* ---- Is a direct-capable frame sitting at the head of rbuf? ----
 *
 * WHAT: Returns 1 when rbuf starts with a complete response header whose frame
 *       may be received straight into a caller buffer, 0 otherwise.
 *
 * WHY:  The read loop would otherwise drain the whole socket into rbuf before
 *       parsing anything, so a bulk reply would be staged here and copied out
 *       again — precisely the copy dst exists to avoid. Spotting the header the
 *       moment it lands lets the parse run early enough that the REST of that
 *       body goes straight to its destination; only the handful of bytes that
 *       shared the header's read are ever staged.
 *
 * HOW:  Need 8 buffered bytes; unpack them and ask aconn_direct_target.
 */
static int
aconn_head_is_direct(brix_aconn *ac)
{
    size_t   avail = ac->rbuf.len - ac->rbuf.start;
    uint16_t sid, stat;
    uint32_t dlen;

    if (avail < XRD_RESPONSE_HDR_LEN) {
        return 0;
    }
    xrd_resp_hdr_unpack(ac->rbuf.buf + ac->rbuf.start, &sid, &stat, &dlen);
    return aconn_direct_target(ac, sid, stat, dlen) != NULL;
}


/* Read everything available (into rbuf, or into a caller buffer while a direct
 * frame is in progress), then parse. Non-blocking; tolerates TLS. */
void
aconn_do_read(brix_aconn *ac)
{
    ac->tls_want_write_on_read = 0;

    /* P44-C (ii-b): on the rxtx engine the multishot RECV owns the socket's
     * byte stream — a read(2) here would race the kernel for it.  Bytes land
     * in rbuf (and are parsed) by the engine's RECV-CQE handler instead. */
    if (aconn_is_rxtx(ac)) {
        return;
    }

    for (;;) {
        int step = (ac->rx_direct != NULL) ? aconn_read_direct(ac)
                                           : aconn_read_buffered(ac);
        if (step == AIO_RD_RETURN) {
            return;
        }
        if (step == AIO_RD_BREAK) {
            break;                           /* socket would block */
        }
        if (ac->dead) {
            return;
        }
        if (ac->rx_direct == NULL && aconn_head_is_direct(ac)) {
            aconn_parse(ac);                 /* arm dst before reading further */
            if (ac->dead) {
                return;
            }
        }
    }

    aconn_parse(ac);
}


/* React to epoll readiness for one connection. */
void
aconn_handle_io(brix_aconn *ac, uint32_t events)
{
    if (ac->dead) {
        return;
    }
    if (events & (EPOLLERR | EPOLLHUP)) {
        /* still try to drain any final readable bytes before failing */
        aconn_do_read(ac);
        if (!ac->dead) {
            brix_status st;
            brix_status_set(&st, XRDC_ESOCK, 0, "socket error/hangup");
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
