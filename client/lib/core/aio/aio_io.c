/*
 * aio_io.c - extracted concern
 * Phase-38 split of aio.c; behavior-identical.
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


/* kXR_waitresp: the reply arrives later as an unsolicited kXR_attn(asynresp).
 * Park the request across the server's advertised delay — extend the deadline
 * (never shorten it) past that delay plus margin so the timeout sweep doesn't
 * fail the request while the server is legitimately working, and mark it
 * deferred so its eventual completion is not taken as an RTT sample (it would
 * measure the deferral, not the link). Mirrors the sync path's read-window
 * extension (frame.c recv_after_waitresp); clamps match frame.c (570 s + 30 s). */
static void
areq_note_deferral(brix_areq *r, const uint8_t *body, uint32_t dlen)
{
    uint64_t secs = xrd_wait_secs_parse(body, dlen, 0, 570);

    r->deferred = 1;
    if (r->deadline_ns != 0) {
        uint64_t want = brix_mono_ns() + secs * 1000000000ULL + 30000000000ULL;
        if (want > r->deadline_ns) {
            r->deadline_ns = want;
        }
    }
}


/* Dispatch one response (direct, or unwrapped from an asynresp envelope) to its
 * in-flight request by streamid. Handles response statuses ONLY — kXR_attn never
 * reaches here from the wire (aconn_dispatch_frame routes it first), so a nested
 * attn inside an asynresp lands in the unexpected-status arm and fails the
 * request cleanly instead of recursing. */
static void
aconn_dispatch_response(brix_aconn *ac, uint16_t sid, uint16_t stat,
                        const uint8_t *body, uint32_t dlen)
{
    brix_areq *r = reqmap_get(&ac->inflight, sid);
    if (r == NULL) {
        return;   /* late frame for a completed/cancelled request — ignore */
    }

    switch (stat) {
    case kXR_oksofar:
        (void) areq_accumulate(r, body, dlen);
        return;   /* more frames follow; keep the entry */

    case kXR_waitresp:
        areq_note_deferral(r, body, dlen);
        return;   /* the deferred reply arrives as kXR_attn(asynresp); keep the
                   * entry (a repeat waitresp simply re-arms the wait) */

    case kXR_ok:
        if (!r->deferred) {
            aconn_note_rtt(ac, r);   /* RTT sample feeds the adaptive deadline/RTO */
        }
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
        brix_status st;
        /* msg is NOT NUL-terminated on the wire — decode to a bounded slice and
         * print with %.*s (the old %s on body+4 was a heap over-read). */
        xrd_error_body_decode(body, dlen, &errnum, &emsg, &emlen);
        brix_status_set(&st, errnum, 0, "%.*s (%s)", (int) emlen,
                        emsg ? emsg : "", brix_kxr_name(errnum));
        reqmap_del(&ac->inflight, sid);
        areq_complete(r, -1, (uint16_t) errnum, &st);
        return;
    }

    default: {
        brix_status st;
        brix_status_set(&st, XRDC_EPROTO, 0, "unexpected response status %u", stat);
        reqmap_del(&ac->inflight, sid);
        areq_complete(r, -1, XRDC_EPROTO, &st);
        return;
    }
    }
}


/* Handle an unsolicited kXR_attn push. Body = [actnum u32 BE][payload]. Only
 * kXR_asynresp carries a reply — envelope [actnum 4][reserved 4][inner
 * ServerResponseHdr 8][data] — which is unwrapped and dispatched by its INNER
 * streamid (the outer one is not a request key: asyncms uses {0,0}, and a
 * deferring server need not mirror the deferred sid). Everything else (asyncms
 * text, obsolete actions, truncated envelopes) is informational at most: drop
 * it — it must never complete or fail an in-flight request. */
static void
aconn_handle_attn(brix_aconn *ac, const uint8_t *body, uint32_t dlen)
{
    uint16_t esid, estat;
    uint32_t edlen;

    if (dlen < 4 || xrd_get_u32_be(body) != (uint32_t) kXR_asynresp) {
        return;   /* not a deferred reply (e.g. asyncms notice) — ignore */
    }
    if (dlen < 16) {
        return;   /* truncated asynresp envelope: no inner header to trust */
    }
    xrd_resp_hdr_unpack(body + 8, &esid, &estat, &edlen);
    if (edlen > dlen - 16) {
        edlen = dlen - 16;   /* never read past the outer frame */
    }
    aconn_dispatch_response(ac, esid, estat, body + 16, edlen);
}


/* Dispatch one fully-received frame: unsolicited kXR_attn pushes are routed
 * BEFORE any in-flight lookup (their outer streamid is not a reliable request
 * key); everything else is a direct response matched by streamid. */
void
aconn_dispatch_frame(brix_aconn *ac, uint16_t sid, uint16_t stat,
                     const uint8_t *body, uint32_t dlen)
{
    ac->last_activity_ns = brix_mono_ns();   /* we heard from the server */

    if (stat == kXR_attn) {
        aconn_handle_attn(ac, body, dlen);
        return;
    }
    aconn_dispatch_response(ac, sid, stat, body, dlen);
}


/* ---- Complete a frame whose body was received straight into a caller buffer ----
 *
 * WHAT: Finishes the frame identified by ac->rx_sid / ac->rx_stat once all of
 *       its body bytes have landed in the request's dst, then clears the
 *       direct-receive state. A kXR_oksofar frame just leaves the request
 *       in-flight for its next frame; a kXR_ok completes it.
 *
 * WHY:  The body bytes were consumed outside aconn_dispatch_response (that is
 *       the whole point — they were never buffered), so the terminal half of
 *       that dispatch has to be reachable on its own. Keeping it here, next to
 *       the parser that armed the direct receive, keeps the two halves of the
 *       split frame readable as one thing.
 *
 * HOW:  1. Clear rx_direct/rx_need first so any error path below sees a clean
 *          connection state.
 *       2. kXR_oksofar → return (more frames follow for the same request).
 *       3. kXR_ok → note the RTT sample, drop the in-flight entry and complete.
 */
static void
aconn_direct_frame_done(brix_aconn *ac)
{
    brix_areq *r    = ac->rx_direct;
    uint16_t   sid  = ac->rx_sid;
    uint16_t   stat = ac->rx_stat;

    ac->rx_direct = NULL;
    ac->rx_need   = 0;
    if (stat == kXR_oksofar) {
        return;
    }
    if (!r->deferred) {
        aconn_note_rtt(ac, r);
    }
    reqmap_del(&ac->inflight, sid);
    areq_complete(r, 0, stat, NULL);
}


/* ---- Can this frame's body be received straight into the caller's buffer? ----
 *
 * WHAT: Returns the in-flight request when the frame (sid, stat) carries read
 *       data for a request that supplied a landing buffer big enough for dlen,
 *       and NULL otherwise.
 *
 * WHY:  Direct receive is only safe for the data-bearing statuses of a request
 *       that asked for it. Error/redirect/wait/attn bodies are small control
 *       payloads that the ordinary buffered dispatch decodes.
 *
 * HOW:  Look the streamid up; require r->dst and a non-empty data frame.
 */
static brix_areq *
aconn_direct_target(brix_aconn *ac, uint16_t sid, uint16_t stat, uint32_t dlen)
{
    brix_areq *r;

    if (stat != kXR_ok && stat != kXR_oksofar) {
        return NULL;
    }
    r = reqmap_get(&ac->inflight, sid);
    if (r == NULL || r->dst == NULL || dlen == 0) {
        return NULL;
    }
    return r;
}


/* ---- Start receiving one frame's body straight into the caller's buffer ----
 *
 * WHAT: Consumes the frame header from rbuf, copies whatever of its body is
 *       already buffered into the request's dst, and either finishes the frame
 *       (everything was buffered) or arms the direct-receive state for the rest.
 *       Returns 0 when the parse loop may continue with the next frame, 1 when
 *       it must stop (the remainder comes off the socket), and -1 when the frame
 *       would overrun the caller's buffer (the connection is failed here).
 *
 * WHY:  A bulk read reply is far larger than anything that can arrive in one
 *       read(2), so the tail of it should land in the caller's buffer instead of
 *       being staged in rbuf and copied again. Handling the already-buffered
 *       head here is what makes the switch seamless at any frame boundary. An
 *       over-long body is refused BEFORE a byte is written, because from here on
 *       the bytes go straight into memory the caller owns.
 *
 * HOW:  1. Refuse dlen beyond the buffer's remaining capacity.
 *       2. Advance past the 8-byte header.
 *       3. Copy min(available, dlen) into dst via areq_accumulate.
 *       4. All of it? finish the frame and continue parsing. Otherwise record
 *          rx_direct/rx_need/rx_sid/rx_stat and stop the loop (rbuf is now
 *          empty, so nothing is stranded behind the direct read).
 */
static int
aconn_direct_begin(brix_aconn *ac, brix_areq *r, uint16_t sid, uint16_t stat,
                   uint32_t dlen)
{
    size_t   avail;
    uint32_t take;

    if (dlen > r->dst_cap - r->acc_len) {
        brix_status st;
        brix_status_set(&st, XRDC_EPROTO, 0,
                        "reply body %u exceeds the caller buffer", dlen);
        aconn_on_transport_error(ac, &st);
        return -1;
    }
    ac->rbuf.start += XRD_RESPONSE_HDR_LEN;
    avail = ac->rbuf.len - ac->rbuf.start;
    take  = (avail < (size_t) dlen) ? (uint32_t) avail : dlen;
    (void) areq_accumulate(r, ac->rbuf.buf + ac->rbuf.start, take);
    ac->rbuf.start += take;

    ac->rx_direct = r;
    ac->rx_need   = dlen - take;
    ac->rx_sid    = sid;
    ac->rx_stat   = stat;
    if (ac->rx_need == 0) {
        aconn_direct_frame_done(ac);
        return 0;
    }
    return 1;
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
