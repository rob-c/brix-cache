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
void
aconn_do_write(brix_aconn *ac)
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
                brix_status st;
                brix_status_set(&st, XRDC_ESOCK, 0, "TLS write failed (ssl err %d)", err);
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
            brix_status st;
            brix_status_set(&st, XRDC_ESOCK, errno, "write: %s", strerror(errno));
            aconn_on_transport_error(ac, &st);
        }
        return;
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
        xrd_resp_hdr_unpack(p, &sid, &stat, &dlen);   /* unaligned-safe */

        if (dlen > XRDC_DLEN_MAX) {
            brix_status st;
            brix_status_set(&st, XRDC_EPROTO, 0, "response body too large (%u)", dlen);
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
void
aconn_do_read(brix_aconn *ac)
{
    ac->tls_want_write_on_read = 0;

    for (;;) {
        if (xbuf_reserve(&ac->rbuf, AIO_READ_CHUNK) != 0) {
            brix_status st;
            brix_status_set(&st, XRDC_EPROTO, 0, "out of memory (read buffer)");
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
                brix_status st;
                if (err == SSL_ERROR_ZERO_RETURN) {
                    brix_status_set(&st, XRDC_ESOCK, 0, "connection closed by peer (TLS)");
                } else {
                    brix_status_set(&st, XRDC_ESOCK, 0, "TLS read failed (ssl err %d)", err);
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
            brix_status st;
            brix_status_set(&st, XRDC_ESOCK, 0, "connection closed by peer");
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
            brix_status st;
            brix_status_set(&st, XRDC_ESOCK, errno, "read: %s", strerror(errno));
            aconn_on_transport_error(ac, &st);
        }
        return;
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
