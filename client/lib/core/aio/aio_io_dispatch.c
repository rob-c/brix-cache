/*
 * aio_io_dispatch.c - what a received frame does to its request
 *
 * WHAT: The frame half of the async connection: routing one fully-received
 *       frame to its in-flight request (kXR_attn unwrapping, oksofar
 *       accumulation, waitresp deferral, terminal completion), plus the
 *       bookkeeping for a body received straight into the caller's buffer.
 *
 * WHY:  Split out of aio_io.c, which had grown past the size limit carrying
 *       two unrelated concerns. The other half is byte movement — draining the
 *       write queue, filling rbuf, the TLS/plain/direct read steps — and it
 *       only ever touches a request through the four entry points declared for
 *       it in aio_internal.h. The seam is where the bytes stop being bytes.
 *
 * HOW:  Behaviour-identical to the code it came from; the only change is that
 *       aconn_direct_{target,begin,frame_done} are no longer static, because
 *       the parser and the direct read step that call them stayed behind.
 */
#include "aio_internal.h"


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
 *       the dispatch it completes, keeps the two halves of the split frame
 *       readable as one thing.
 *
 * HOW:  1. Clear rx_direct/rx_need first so any error path below sees a clean
 *          connection state.
 *       2. kXR_oksofar → return (more frames follow for the same request).
 *       3. kXR_ok → note the RTT sample, drop the in-flight entry and complete.
 */
void
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
brix_areq *
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
int
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
