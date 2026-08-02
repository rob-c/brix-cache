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
