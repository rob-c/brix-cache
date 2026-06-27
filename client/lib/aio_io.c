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


/* rtt *//*
 * RTT smoothing (RFC-6298 style) and the derived retransmit/timeout estimate. The
 * adaptive default request deadline and the keepalive probe interval are derived
 * from this, so a slow link gets patience and a fast link gets prompt failure
 * detection — all bounded.
 */
void
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
uint64_t
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
void
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
void
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
void
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
void
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
