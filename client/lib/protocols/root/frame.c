/*
 * frame.c — request/response framing on the wire.
 *
 * WHAT: Finalize+send a 24-byte ClientRequestHdr (+ optional payload), and read
 *       one 8-byte ServerResponseHdr (+ body), interpreting the status field.
 * WHY:  Every opcode shares this framing (wire_core_requests.h); centralising it
 *       keeps each op in ops_*.c tiny and the byte-twiddling in one audited place.
 * HOW:  streamid is any 2 bytes echoed back by the server; we assign a per-conn
 *       counter so future parallel/pipelined requests can be matched by it. All
 *       multi-byte header fields are big-endian.
 *
 * wire: XProtocol.hh ClientRequestHdr — streamid[2] reqid[2] body[16] dlen[4];
 * wire: XProtocol.hh ServerResponseHdr — streamid[2] status[2] dlen[4].
 */
#include "brix.h"

#include <arpa/inet.h>
#include <stdio.h>     /* snprintf for the tried-set host:port key */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>   /* sleep() for kXR_wait backoff */
#include <time.h>     /* nanosleep() for sub-second kXR_wait jitter */
#include "protocols/root/protocol/frame_hdr.h"   /* shared resp-hdr / wait / error codecs */
#include "core/compat/host_format.h"   /* IPv6-bracketing host:port (libxrdproto) */

int
brix_send_ext(brix_conn *c, void *hdr24, const brix_payload_ext *pl,
              uint16_t *out_sid, brix_status *st)
{
    const void *payload  = (pl != NULL) ? pl->data : NULL;
    uint32_t    send_len = (pl != NULL) ? pl->len : 0;
    uint32_t    dlen     = (pl != NULL) ? pl->dlen : 0;

    uint8_t *h   = (uint8_t *) hdr24;
    uint16_t sid = c->next_sid++;
    uint32_t be  = htonl(dlen);

    h[0] = (uint8_t) (sid >> 8);
    h[1] = (uint8_t) (sid & 0xff);
    memcpy(h + 20, &be, 4);   /* dlen at offset 20 */

    if (out_sid != NULL) {
        *out_sid = sid;
    }

    /* §15: remember the in-flight requestid (for trace + timing), trace the
     * request, and stamp the send time. All inert unless armed. */
    c->diag.inflight_reqid = xrd_get_u16_be(h + 2);
    if (c->diag.wire_trace) {
        brix_trace_frame(c, '>', sid, c->diag.inflight_reqid, 1, dlen,
                         payload, send_len);
    }
    if (c->diag.cap != NULL) {   /* §15.1: record the full request wire bytes */
        brix_capture_frame(c->diag.cap, '>', sid, c->diag.inflight_reqid, 1,
                           h, XRD_REQUEST_HDR_LEN, payload, send_len);
    }
    if (c->diag.timing) {
        c->diag.t_send_ns = brix_mono_ns();
    }

    /* When GSI signing is active and the server's security level requires it,
     * prepend a kXR_sigver frame covering this request (no-op otherwise).
     * The signature covers the dlen-framed payload — for kXR_writev that is
     * the descriptor block only, matching what the server hashes. */
    if (brix_sigver_maybe(c, h, payload, dlen, st) != 0) {
        return -1;
    }

    if (brix_write_full(&c->io, h, XRD_REQUEST_HDR_LEN, st) != 0) {
        return -1;
    }
    if (send_len > 0 && payload != NULL) {
        if (brix_write_full(&c->io, payload, send_len, st) != 0) {
            return -1;
        }
    }
    return 0;
}

int
brix_send(brix_conn *c, void *hdr24, const brix_payload *pl, uint16_t *out_sid,
          brix_status *st)
{
    uint32_t         len = (pl != NULL) ? pl->len : 0;
    brix_payload_ext e   = { (pl != NULL) ? pl->data : NULL, len, len };

    return brix_send_ext(c, hdr24, &e, out_sid, st);
}

/* One decoded server frame: unpacked ServerResponseHdr fields + the malloc'd
 * body (NULL when dlen == 0; the consumer frees or hands it off). Bundles the
 * four values every receiver threads around so helpers stay under the
 * 5-parameter gate without changing any wire semantics. */
typedef struct {
    uint16_t sid;    /* outer streamid */
    uint16_t stat;   /* outer status */
    uint32_t dlen;   /* body length */
    uint8_t *buf;    /* malloc'd body, or NULL */
} rx_frame_t;

/* The caller-provided response out-params travel as a brix_resp_out (promoted
 * to brix_net.h in phase-73) so the delivery helpers shared by brix_recv /
 * recv_after_waitresp take one arg. */

/*
 * WHAT: read + unpack one 8-byte ServerResponseHdr into f, with the standard
 *       size cap; the raw header bytes land in hdr (for wire capture).
 * WHY:  shared by every receiver (brix_recv + the raw waitresp reader) so the
 *       cap check and unaligned-safe unpack live in exactly one place.
 * HOW:  brix_read_full for the 8 bytes, xrd_resp_hdr_unpack, cap against
 *       XRDC_DLEN_MAX. f->buf is reset to NULL. 0 / -1 (st set).
 */
static int
frame_read_header(brix_conn *c, uint8_t *hdr, rx_frame_t *f, brix_status *st)
{
    f->buf = NULL;
    if (brix_read_full(&c->io, hdr, XRD_RESPONSE_HDR_LEN, st) != 0) {
        return -1;
    }
    xrd_resp_hdr_unpack(hdr, &f->sid, &f->stat, &f->dlen);   /* unaligned-safe */
    if (f->dlen > XRDC_DLEN_MAX) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "response body too large (%u bytes)", f->dlen);
        return -1;
    }
    return 0;
}

/*
 * WHAT: allocate + read the dlen-byte frame body into f->buf.
 * WHY:  the malloc/read/cleanup triple was duplicated verbatim in brix_recv
 *       and recv_raw_frame; one copy keeps the OOM + short-read handling audited.
 * HOW:  no-op for dlen == 0 (buf stays NULL); on a short read the buffer is
 *       freed and NULLed so callers never see a half-filled body. 0 / -1.
 */
static int
frame_read_body(brix_conn *c, rx_frame_t *f, brix_status *st)
{
    f->buf = NULL;
    if (f->dlen == 0) {
        return 0;
    }
    f->buf = (uint8_t *) malloc(f->dlen);
    if (f->buf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory (%u bytes)", f->dlen);
        return -1;
    }
    if (brix_read_full(&c->io, f->buf, f->dlen, st) != 0) {
        free(f->buf);
        f->buf = NULL;
        return -1;
    }
    return 0;
}

/*
 * WHAT: format a kXR_error body (errnum[4 BE] + message) into st.
 * WHY:  identical decoding in the synchronous (brix_recv) and asynresp
 *       (recv_after_waitresp) error paths; sharing it keeps the %.*s bound
 *       (wire message is NOT NUL-terminated) in one audited spot.
 * HOW:  tolerates short bodies (errnum 0 / empty message) exactly as before;
 *       the caller still owns + frees the frame buffer AFTER this returns
 *       (the message is formatted out of the live buffer).
 */
static void
set_kxr_error_status(const uint8_t *data, uint32_t dlen, brix_status *st)
{
    int errnum = (dlen >= 4) ? (int) xrd_get_u32_be(data) : 0;
    int mlen   = (dlen > 4) ? (int) (dlen - 4) : 0;

    /* The wire message is NOT NUL-terminated; bound %s with %.*s so a
     * hostile server can't drive a heap over-read past the frame. */
    brix_status_set(st, errnum, 0, "%.*s (%s)", mlen,
                    (const char *) (data + 4), brix_kxr_name(errnum));
}

/* Read one full server frame (header + body) with the standard size cap; fills
 * f (caller frees f->buf). No streamid matching — used by the kXR_waitresp
 * async path, where the deferred reply arrives as an unsolicited frame whose
 * outer streamid may differ from the request's. 0 / -1. */
static int
recv_raw_frame(brix_conn *c, rx_frame_t *f, brix_status *st)
{
    uint8_t hdr[XRD_RESPONSE_HDR_LEN];

    if (frame_read_header(c, hdr, f, st) != 0) {
        return -1;
    }
    if (frame_read_body(c, f, st) != 0) {
        return -1;
    }
    if (c->diag.wire_trace) {
        brix_trace_frame(c, '<', f->sid, f->stat, 0, f->dlen, f->buf, f->dlen);
    }
    return 0;
}

/*
 * WHAT: handle a re-deferral (another kXR_waitresp while awaiting an asynresp):
 *       consume the frame and extend the read window to the new advertised delay.
 * WHY:  keeps the waitresp wait-loop a flat sequence of early-return guards.
 * HOW:  seconds clamp to 570 before *1000 (no int overflow UB), +30s margin,
 *       and the window only ever grows — same arithmetic as the initial arm.
 */
static void
waitresp_extend_window(brix_conn *c, rx_frame_t *f)
{
    unsigned more = (f->dlen >= 4) ? xrd_get_u32_be(f->buf) : 0;
    int      w;

    free(f->buf);
    if (more > 570) { more = 570; }      /* clamp before *1000 (no UB) */
    w = (int) more * 1000 + 30000;
    if (w > c->io.timeout_ms) { c->io.timeout_ms = w; }
}

/*
 * WHAT: unwrap a validated kXR_attn(asynresp) envelope and surface the inner
 *       status+data exactly as a synchronous reply would.
 * WHY:  the envelope decode is the bulky tail of the waitresp wait-loop;
 *       isolating it leaves the loop as the retry state machine only.
 * HOW:  nested ServerResponseHdr at buf+8, data at buf+16, inner dlen clamped
 *       to the frame; inner-streamid mismatch and inner kXR_error fail exactly
 *       like the synchronous path. Consumes f->buf on every exit. 0 / -1.
 */
static int
asynresp_deliver(uint16_t want_sid, rx_frame_t *f, brix_resp_out *out,
                 brix_status *st)
{
    uint16_t esid, estat;
    uint32_t edlen;
    uint8_t *edata = f->buf + 16;

    xrd_resp_hdr_unpack(f->buf + 8, &esid, &estat, &edlen);  /* nested hdr */
    if ((size_t) edlen + 16 > f->dlen) { edlen = f->dlen - 16; }   /* clamp to frame */

    if (want_sid != 0xffff && esid != want_sid) {
        free(f->buf);
        brix_status_set(st, XRDC_EPROTO, 0,
                        "asynresp stream mismatch (got %u, want %u)",
                        esid, want_sid);
        return -1;
    }
    if (estat == kXR_error) {
        set_kxr_error_status(edata, edlen, st);
        free(f->buf);
        return -1;
    }
    if (out->status != NULL) { *out->status = estat; }
    if (out->body != NULL) {
        *out->body = NULL;
        if (edlen > 0) {
            uint8_t *copy = (uint8_t *) malloc(edlen);
            if (copy == NULL) {
                free(f->buf);
                brix_status_set(st, XRDC_EPROTO, 0, "out of memory (%u)", edlen);
                return -1;
            }
            memcpy(copy, edata, edlen);
            *out->body = copy;
        }
    }
    if (out->blen != NULL) { *out->blen = edlen; }
    free(f->buf);
    return 0;
}

/* Handle a kXR_waitresp acknowledgement: the real reply for `want_sid` arrives
 * later, unsolicited, as a kXR_attn carrying an asynresp envelope
 *   [actnum=kXR_asynresp 4][reserved 4][inner ServerResponseHdr 8][data dlen].
 * Wait for it (extending the read window to the server's advertised delay) and
 * surface the inner status+data exactly as a synchronous reply would. Another
 * kXR_waitresp simply re-arms the wait. 0 / -1.
 *
 * The server answers synchronously in this codebase, so this path is exercised
 * against a real (deferring) XRootD or the mock in test_client_async_tpc.py. */
static int
recv_after_waitresp(brix_conn *c, uint16_t want_sid, unsigned secs,
                    brix_resp_out *out, brix_status *st)
{
    int      saved_to = c->io.timeout_ms;
    int      rounds   = 0;
    unsigned s        = (secs > 570) ? 570 : secs;   /* clamp before *1000 (no UB) */
    int      want_ms  = (int) s * 1000 + 30000;       /* delay + margin, <= 600000 */

    if (want_ms > c->io.timeout_ms) { c->io.timeout_ms = want_ms; }

    for (;;) {
        rx_frame_t f;

        if (++rounds > XRDC_REDIR_MAX) {
            c->io.timeout_ms = saved_to;
            brix_status_set(st, XRDC_EPROTO, 0,
                            "waitresp: no async response after %d frames", rounds);
            return -1;
        }
        if (recv_raw_frame(c, &f, st) != 0) {
            c->io.timeout_ms = saved_to;
            return -1;
        }
        if (f.stat == kXR_waitresp) {            /* server re-deferred — keep waiting */
            waitresp_extend_window(c, &f);
            continue;
        }
        if (f.stat != kXR_attn) {
            free(f.buf);
            c->io.timeout_ms = saved_to;
            brix_status_set(st, XRDC_EPROTO, 0,
                            "waitresp: expected attn(asynresp), got status %u", f.stat);
            return -1;
        }
        if (f.dlen < 16 || xrd_get_u32_be(f.buf) != (uint32_t) kXR_asynresp) {
            free(f.buf);
            c->io.timeout_ms = saved_to;
            brix_status_set(st, XRDC_EPROTO, 0, "waitresp: malformed asynresp envelope");
            return -1;
        }
        c->io.timeout_ms = saved_to;
        return asynresp_deliver(want_sid, &f, out, st);
    }
}

/*
 * WHAT: §15 response-side diagnostics — wire trace, full-frame capture, and
 *       per-opcode RTT accumulation. Inert unless armed.
 * WHY:  pure observability side-band; hoisting it out of brix_recv leaves the
 *       receive path as read/validate/dispatch only.
 * HOW:  hdr is the raw 8-byte ServerResponseHdr (capture records the exact
 *       wire bytes); RTT matches the request stamped by brix_send_ext via
 *       diag.inflight_reqid / diag.t_send_ns, then clears the stamp.
 */
static void
recv_note_diag(brix_conn *c, const uint8_t *hdr, const rx_frame_t *f)
{
    if (c->diag.wire_trace) {
        brix_trace_frame(c, '<', f->sid, f->stat, 0, f->dlen, f->buf, f->dlen);
    }
    if (c->diag.cap != NULL) {   /* §15.1: record the full response wire bytes */
        brix_capture_frame(c->diag.cap, '<', f->sid, f->stat, 0, hdr,
                           XRD_RESPONSE_HDR_LEN, f->buf, f->dlen);
    }
    if (c->diag.timing && c->diag.t_send_ns != 0) {
        uint64_t dt  = brix_mono_ns() - c->diag.t_send_ns;
        int      idx = (int) c->diag.inflight_reqid - kXR_1stRequest;
        if (idx >= 0 && idx < XRDC_NOP) {
            uint64_t n = c->diag.rtt[idx].n;
            c->diag.rtt[idx].n++;
            c->diag.rtt[idx].tot_ns += dt;
            if (n == 0 || dt < c->diag.rtt[idx].min_ns) { c->diag.rtt[idx].min_ns = dt; }
            if (dt > c->diag.rtt[idx].max_ns) { c->diag.rtt[idx].max_ns = dt; }
        }
        c->diag.t_send_ns = 0;
    }
}

/*
 * WHAT: hand a successful frame's status/body/length to the caller's out-params.
 * WHY:  every success exit (ok/oksofar/authmore/redirect/wait, the waitresp
 *       TPC-defer surface) performs the same NULL-tolerant delivery.
 * HOW:  when the caller declined the body, free it here so ownership is never
 *       ambiguous. Always returns 0 so dispatch sites can `return` it.
 */
static int
resp_deliver(brix_resp_out *out, uint16_t stat, uint8_t *buf, uint32_t dlen)
{
    if (out->status != NULL) { *out->status = stat; }
    if (out->body != NULL) { *out->body = buf; } else { free(buf); }
    if (out->blen != NULL) { *out->blen = dlen; }
    return 0;
}

/*
 * WHAT: interpret a validated frame's status field — the brix_recv switch.
 * WHY:  isolates the per-status policy (which statuses surface, which defer,
 *       which fail) from the read/validate mechanics.
 * HOW:  passthrough statuses deliver the body as-is; kXR_waitresp either
 *       surfaces the deferral (TPC coordinator open — blocking would deadlock
 *       the rendezvous) or blocks in recv_after_waitresp; kXR_error and
 *       unknown statuses consume the body and fail. 0 / -1 (st set).
 */
static int
recv_dispatch(brix_conn *c, uint16_t want_sid, rx_frame_t *f, brix_resp_out *out,
              brix_status *st)
{
    switch (f->stat) {
    case kXR_ok:
    case kXR_oksofar:
    case kXR_authmore:   /* auth driver consumes the challenge body */
    case kXR_redirect:   /* brix_roundtrip follows it */
    case kXR_wait:       /* brix_roundtrip honors the backoff */
        return resp_deliver(out, f->stat, f->buf, f->dlen);

    case kXR_waitresp: {
        /* Server acknowledged the request but the real reply comes later as an
         * unsolicited kXR_attn(asynresp). Transparent to every caller... */
        unsigned secs = (f->dlen >= 4) ? xrd_get_u32_be(f->buf) : 0;
        free(f->buf);
        /* ...EXCEPT a TPC coordinator open: the source registers the rendezvous key
         * and defers its open reply until the copy completes — but that copy can only
         * happen once the orchestrator opens the DESTINATION and triggers the pull.
         * Blocking here for the deferred reply would deadlock (source waits for the
         * pull; the pull waits for this call to return). Surface the deferral so the
         * caller proceeds; the deferred reply is drained after the dest sync. */
        if (c->tpc_coord_defer) {
            return resp_deliver(out, kXR_waitresp, NULL, 0);
        }
        return recv_after_waitresp(c, want_sid, secs, out, st);
    }

    case kXR_error:
        /* errmsg is wire data with no guaranteed NUL — bound %s with %.*s. */
        set_kxr_error_status(f->buf, f->dlen, st);
        free(f->buf);
        return -1;

    default:
        brix_status_set(st, XRDC_EPROTO, 0,
                        "unexpected response status %u", f->stat);
        free(f->buf);
        return -1;
    }
}

int
brix_recv(brix_conn *c, uint16_t want_sid, brix_resp_out *out, brix_status *st)
{
    uint8_t    hdr[XRD_RESPONSE_HDR_LEN];
    rx_frame_t f;

    if (out->body != NULL) { *out->body = NULL; }
    if (out->blen != NULL) { *out->blen = 0; }

    if (frame_read_header(c, hdr, &f, st) != 0) {
        return -1;
    }
    if (want_sid != 0xffff && f.sid != want_sid) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "stream id mismatch (got %u, want %u)", f.sid, want_sid);
        return -1;
    }
    if (frame_read_body(c, &f, st) != 0) {
        return -1;
    }

    recv_note_diag(c, hdr, &f);
    return recv_dispatch(c, want_sid, &f, out, st);
}

/* redirect/wait-following request wrapper (M5) */

/* One parsed ServerRedirectBody: connectable host, port, and any capability
 * opaque split off the host field (see parse_redirect). Sized so a long EOS
 * cap.sym/cap.msg opaque is never truncated by the host buffer. */
typedef struct {
    char host[256];
    int  port;
    char opaque[4096];
} redir_tgt_t;

/* ServerRedirectBody = port[4 BE] + host[NUL] (host already IPv6-bracketed).
 * The host field may carry a "?<opaque>" tail: a redirector (notably EOS/cmsd)
 * appends the open CAPABILITY (cap.sym/cap.msg) that the open MUST replay to the
 * chosen data server, else the DS cannot authorize it and bounces the open back
 * (an endless manager↔DS redirect loop). We split it off so `host` is connectable
 * and `opaque` can be re-attached to the open's path. */
static int
parse_redirect(const uint8_t *body, uint32_t blen, redir_tgt_t *t)
{
    const char *field, *qmark;
    uint32_t    flen, hlen;
    if (blen < 5) {
        return -1;
    }
    t->port = (int) xrd_get_u32_be(body);

    /* The host field runs from body+4 to the first NUL/CR/LF (or end of body). We
     * scan it IN PLACE and split host vs opaque straight into their own buffers, so
     * a long capability opaque (EOS cap.sym/cap.msg, often >256B) is NOT truncated
     * by the host buffer — the bug that made the DS reject the capability. */
    field = (const char *) body + 4;
    flen  = blen - 4;
    {
        const char *nl = memchr(field, '\0', flen);
        if (nl == NULL) { nl = memchr(field, '\r', flen); }
        if (nl == NULL) { nl = memchr(field, '\n', flen); }
        if (nl != NULL) {
            flen = (uint32_t) (nl - field);
        }
    }

    qmark = memchr(field, '?', flen);
    hlen  = qmark != NULL ? (uint32_t) (qmark - field) : flen;
    if (hlen >= sizeof(t->host)) {
        hlen = (uint32_t) sizeof(t->host) - 1;
    }
    memcpy(t->host, field, hlen);
    t->host[hlen] = '\0';

    t->opaque[0] = '\0';
    if (qmark != NULL) {
        const char *o   = qmark + 1;
        uint32_t    olen = (uint32_t) (field + flen - o);
        while (olen > 0 && (*o == '&' || *o == '?')) {   /* EOS sends "?&cap.sym=" */
            o++;
            olen--;
        }
        if (olen >= sizeof(t->opaque)) {
            olen = (uint32_t) sizeof(t->opaque) - 1;
        }
        memcpy(t->opaque, o, olen);
        t->opaque[olen] = '\0';
    }
    return 0;
}

static int
tried_seen(brix_conn *c, const char *hostport)
{
    int i;
    for (i = 0; i < c->tried_n; i++) {
        if (strcmp(c->tried[i], hostport) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Phase 40 (a): reconnect to a redirect target, surviving a DEAD target.
 *
 * WHAT: bring up a session against rhost:rport; if that target is unreachable,
 *       fall back ONCE to the home manager (c->home_host/home_port) so it can
 *       re-select a live data server.
 * WHY:  official-parity hard-fail (`brix_reconnect != 0 → give up`) turns one
 *       dead replica into a failed op even when other replicas are healthy, and
 *       surfaces a confusing connect error against a host the user never typed.
 * HOW:  the dead target is already recorded in tried[] by the caller, so the
 *       loop guard prevents the manager bouncing us straight back to it. Returns
 *       0 if a session is up (target or manager), -1 with a clear combined error.
 *       NEVER calls brix_close between attempts — brix_reconnect/bringup own their
 *       own teardown-on-failure, and a close on a torn-down socket would misfire.
 */
static int
follow_redirect(brix_conn *c, const char *rhost, int rport, brix_status *st)
{
    char tgt_msg[XRDC_MSG_MAX];

    if (brix_reconnect(c, rhost, rport, st) == 0) {
        return 0;
    }
    snprintf(tgt_msg, sizeof(tgt_msg), "%s", st->msg);   /* keep target error */

    if (c->home_host[0] == '\0'
        || (strcmp(rhost, c->home_host) == 0 && rport == c->home_port)) {
        brix_status_set(st, XRDC_ESOCK, 0,
                        "redirect target %s:%d unreachable: %s",
                        rhost, rport, tgt_msg);
        return -1;
    }
    if (brix_reconnect(c, c->home_host, c->home_port, st) == 0) {
        return 0;   /* manager re-selects; the dead target is in tried[] */
    }
    brix_status_set(st, XRDC_ESOCK, 0,
                    "redirect target %s:%d unreachable (%s); manager %s:%d "
                    "fallback also failed", rhost, rport, tgt_msg,
                    c->home_host, c->home_port);
    return -1;
}

/* One in-flight roundtrip request: the immutable original payload (opaque
 * rebuilds always start from it so successive redirects swap rather than
 * accumulate), the payload actually sent this iteration, and the rebuilt
 * buffer (owned + freed once by brix_roundtrip — so the in-loop early
 * returns need no per-exit cleanup). */
typedef struct {
    uint16_t    reqid;      /* request opcode (kXR_open gets opaque replay) */
    const void *orig_pl;    /* original payload, never rewritten */
    uint32_t    orig_len;
    const void *cur_pl;     /* payload actually sent (may be rebuilt) */
    uint32_t    cur_len;
    char       *rebuilt;    /* opaque-carrying open payload, if any */
} rt_req_t;

/* Rebuild a kXR_open payload as "<original-path><sep><opaque>" so a redirected
 * open replays the redirector's capability to the data server. Always built from
 * the ORIGINAL path (never an earlier rebuild) so successive redirects swap rather
 * than accumulate opaques. rq->rebuilt is freed once by the wrapper. On success
 * points rq->cur_pl and rq->cur_len at the new buffer. 0 / -1 (st set). */
static int
open_payload_with_opaque(const char *opaque, rt_req_t *rq, brix_status *st)
{
    const char *p   = (const char *) rq->orig_pl;
    int         hasq = (rq->orig_len > 0 && memchr(p, '?', rq->orig_len) != NULL);
    size_t      ol  = strlen(opaque);
    size_t      need = (size_t) rq->orig_len + 1 + ol + 1;
    char       *nb  = (char *) malloc(need);
    if (nb == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory (redirect opaque)");
        return -1;
    }
    memcpy(nb, p, rq->orig_len);
    nb[rq->orig_len] = hasq ? '&' : '?';
    memcpy(nb + rq->orig_len + 1, opaque, ol + 1);   /* includes the NUL */
    free(rq->rebuilt);
    rq->rebuilt = nb;
    rq->cur_pl  = nb;
    rq->cur_len = (uint32_t) (rq->orig_len + 1 + ol);
    return 0;
}

/*
 * WHAT: process one kXR_redirect frame — parse the target, run the loop guards
 *       (budget / self-loop / already-tried), carry an open capability opaque,
 *       and reconnect to the target (with manager fallback).
 * WHY:  this is the entire redirect policy; hoisting it leaves roundtrip_loop
 *       as the bare retry state machine.
 * HOW:  consumes bd on every path. Records the target in tried[] BEFORE
 *       reconnecting so a manager fallback can't bounce us straight back.
 *       Returns 0 = session up, replay the request; -1 = fail (st set).
 */
static int
rt_handle_redirect(brix_conn *c, rt_req_t *rq, uint8_t *bd, uint32_t bl,
                   brix_status *st)
{
    redir_tgt_t t;
    char        hp[XRDC_HOSTPORT_MAX];

    if (parse_redirect(bd, bl, &t) != 0) {
        free(bd);
        brix_status_set(st, XRDC_EPROTO, 0, "malformed redirect");
        return -1;
    }
    free(bd);
    if (c->diag.redir_trace) {   /* §15.4: surface each hop on stderr */
        fprintf(stderr, "redirect[%d] -> %s:%d%s\n", c->redir_depth + 1,
                t.host, t.port, t.opaque[0] ? " (+opaque)" : "");
    }
    if (++c->redir_depth > XRDC_REDIR_MAX) {
        if (c->diag.redir_trace) {
            fprintf(stderr, "redirect: budget exhausted (>%d hops)\n",
                    XRDC_REDIR_MAX);
        }
        brix_status_set(st, XRDC_EREDIRECT, 0,
                        "too many redirects (>%d)", XRDC_REDIR_MAX);
        return -1;
    }
    brix_format_host_port(t.host, (uint16_t) t.port, hp, sizeof(hp));
    /* Immediate self-redirect: the server we are talking to right now
     * bounced us straight back to itself.  That is an unambiguous loop;
     * fail fast here rather than reconnecting to it (which would chase
     * the loop until the connect timeout — up to 15s per hop). */
    if (t.port == c->port && strcmp(t.host, c->host) == 0) {
        if (c->diag.redir_trace) {
            fprintf(stderr, "redirect: self-loop to %s\n", hp);
        }
        brix_status_set(st, XRDC_EREDIRECT, 0,
                        "redirect loop: server redirected to itself (%s)",
                        hp);
        return -1;
    }
    if (tried_seen(c, hp)) {
        if (c->diag.redir_trace) {
            fprintf(stderr, "redirect: LOOP to already-tried %s\n", hp);
        }
        brix_status_set(st, XRDC_EREDIRECT, 0,
                        "redirect loop to already-tried %s", hp);
        return -1;
    }
    if (c->tried_n < XRDC_REDIR_MAX) {
        snprintf(c->tried[c->tried_n++], sizeof(c->tried[0]), "%s", hp);
    }
    /* EOS/cmsd redirects an open to a data server with a one-shot capability
     * opaque; carry it onto the open's path so the DS authorizes the open
     * (else it bounces back → the endless loop the guard above trips on). */
    if (rq->reqid == kXR_open && t.opaque[0] != '\0'
        && open_payload_with_opaque(t.opaque, rq, st) != 0) {
        return -1;
    }
    return follow_redirect(c, t.host, t.port, st);   /* 0 = target or manager up */
}

/*
 * WHAT: honor one kXR_wait frame — sleep for the server's advised delay
 *       (clamped [1,30]s) plus additive sub-second jitter.
 * WHY:  keeps the backoff policy out of the retry state machine.
 * HOW:  consumes bd; bumps *waits against XRDC_REDIR_MAX so a server that
 *       stalls forever fails cleanly. Phase 40 (a): the jitter is ADDITIVE so
 *       a fleet handed the same advised wait doesn't resend in lockstep —
 *       never shorten the server's requested delay. 0 = resend / -1 (st set).
 */
static int
rt_handle_wait(brix_conn *c, uint8_t *bd, uint32_t bl, int *waits,
               brix_status *st)
{
    unsigned secs = xrd_wait_secs_parse(bd, bl, 1, 30);  /* clamp [1,30] */
    unsigned jms;

    (void) c;
    free(bd);
    if (++(*waits) > XRDC_REDIR_MAX) {
        brix_status_set(st, XRDC_EPROTO, 0, "server kept asking to wait");
        return -1;
    }
    sleep(secs);
    jms = brix_jitter_ms(secs >= 1 ? 1000u : 250u);
    if (jms > 0) {
        struct timespec ts;
        ts.tv_sec  = 0;
        ts.tv_nsec = (long) jms * 1000000L;
        (void) nanosleep(&ts, NULL);
    }
    return 0;
}

/* The redirect/wait-following request loop: send, receive, and either deliver
 * the reply or hand kXR_redirect / kXR_wait to their policy helpers and replay.
 * rq->rebuilt is owned + freed once by brix_roundtrip, so the in-loop early
 * returns need no per-exit cleanup. */
static int
roundtrip_loop(brix_conn *c, void *hdr24, rt_req_t *rq, brix_resp_out *out,
               brix_status *st)
{
    int waits = 0;

    /* Each top-level op gets a fresh redirect budget + loop-guard. */
    c->redir_depth = 0;
    c->tried_n = 0;

    for (;;) {
        uint16_t sid, stt;
        uint8_t *bd = NULL;
        uint32_t bl = 0;
        brix_payload  pl = { rq->cur_pl, rq->cur_len };
        brix_resp_out rr = { &stt, &bd, &bl };

        if (brix_send(c, hdr24, &pl, &sid, st) != 0) {
            return -1;
        }
        if (brix_recv(c, sid, &rr, st) != 0) {
            return -1;   /* kXR_error / transport → st already set */
        }

        if (stt == kXR_redirect) {
            if (rt_handle_redirect(c, rq, bd, bl, st) != 0) {
                return -1;
            }
            continue;   /* replay against the redirect target (or manager) */
        }
        if (stt == kXR_wait) {
            if (rt_handle_wait(c, bd, bl, &waits, st) != 0) {
                return -1;
            }
            continue;   /* resend the same request to the same server */
        }

        /* kXR_ok / kXR_oksofar */
        if (out->status != NULL) { *out->status = stt; }
        *out->body = bd;
        *out->blen = bl;
        return 0;
    }
}

int
brix_roundtrip(brix_conn *c, void *hdr24, const brix_payload *pl,
               brix_resp_out *out, brix_status *st)
{
    rt_req_t rq;
    int      rc;

    rq.reqid    = xrd_get_u16_be((uint8_t *) hdr24 + 2);
    rq.orig_pl  = (pl != NULL) ? pl->data : NULL;
    rq.orig_len = (pl != NULL) ? pl->len : 0;
    rq.cur_pl   = rq.orig_pl;
    rq.cur_len  = rq.orig_len;
    rq.rebuilt  = NULL;   /* opaque-carrying open payload, if a redirect needs it */

    rc = roundtrip_loop(c, hdr24, &rq, out, st);
    free(rq.rebuilt);
    return rc;
}
