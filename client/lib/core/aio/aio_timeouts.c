/*
 * aio_timeouts.c - per-connection deadline scan feeding epoll_wait timeout.
 * Phase-38 split of aio.c; behavior-identical.
 */
#include "aio_internal.h"

/* timers */

/* WHAT: Fold one request's future deadline into the running "nearest deadline"
 *       accumulator *next (ns; 0 = none seen yet).
 * WHY:  Both the reconnecting-parked scan and the alive-inflight scan must track
 *       the soonest un-expired deadline to size the next epoll_wait; sharing one
 *       helper keeps that min-reduction identical across both paths.
 * HOW:  A zero deadline_ns means "no deadline" and is ignored; otherwise the
 *       value replaces *next when it is the first candidate or strictly sooner —
 *       byte-for-byte the original inline `(next == 0 || dl < next)` test. */
static void
timeouts_track_next(uint64_t deadline_ns, uint64_t *next)
{
    if (deadline_ns != 0 && (*next == 0 || deadline_ns < *next)) {
        *next = deadline_ns;
    }
}

/* WHAT: Expire every parked request on a RECONNECTING conn whose deadline has
 *       passed; fold survivors into *next.
 * WHY:  While a link is rebuilding, parked requests still owe their caller a
 *       deadline; ones that ran out the reconnect budget must fail with the
 *       "(reconnecting)" status, the rest keep the loop's wake timer tight.
 * HOW:  Walks the pending singly-linked list via a pointer-to-pointer so an
 *       expired node is unlinked in place before areq_complete frees it; live
 *       nodes advance the cursor and feed timeouts_track_next. Preserves the
 *       original unlink-then-complete ordering exactly. */
static void
timeouts_expire_parked(brix_aconn *ac, uint64_t now, uint64_t *next)
{
    brix_areq **pp = &ac->pending;
    while (*pp != NULL) {
        brix_areq *r = *pp;
        if (r->deadline_ns != 0 && now >= r->deadline_ns) {
            *pp = r->pend_next;
            brix_status st;
            brix_status_set(&st, XRDC_ESOCK, ETIMEDOUT,
                            "request deadline exceeded (reconnecting)");
            areq_complete(r, -1, XRDC_ESOCK, &st);
        } else {
            timeouts_track_next(r->deadline_ns, next);
            pp = &r->pend_next;
        }
    }
}

/* WHAT: Expire every in-flight request on an ALIVE conn whose deadline has
 *       passed; fold survivors into *next. Returns 1 if a timed-out request was
 *       a keepalive ping (the link is presumed dead), else 0.
 * WHY:  Isolating the inflight-slot scan keeps loop_process_timeouts flat and
 *       lets the caller run the transport-error recovery only AFTER the whole
 *       slot array is drained — recursing mid-scan would corrupt the walk.
 * HOW:  Tombstones an expired slot (dropping count, bumping tomb) before
 *       areq_complete frees the request, matching the original bookkeeping order;
 *       live slots feed timeouts_track_next. The ping-timeout flag is only
 *       reported, never acted on here. */
static int
timeouts_expire_inflight(brix_aconn *ac, uint64_t now, uint64_t *next)
{
    int ping_timed_out = 0;
    for (uint32_t i = 0; i < ac->inflight.cap; i++) {
        brix_areq *r = ac->inflight.slots[i];
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
            brix_status st;
            brix_status_set(&st, XRDC_ESOCK, ETIMEDOUT,
                            "request deadline exceeded");
            areq_complete(r, -1, XRDC_ESOCK, &st);
        } else {
            timeouts_track_next(r->deadline_ns, next);
        }
    }
    return ping_timed_out;
}

/* WHAT: Run the deadline scan for one connection, folding its soonest survivor
 *       into *next.
 * WHY:  Each conn state routes to a different expiry path; centralizing the
 *       dispatch keeps the top-level sweep a single clean loop body.
 * HOW:  RECONNECTING → parked-request expiry; ALIVE → inflight expiry followed
 *       by a post-scan transport-error kick when a heartbeat ping timed out
 *       (safe now that the slot array is fully drained); any other state is
 *       skipped, matching the original early-`continue` structure. */
static void
timeouts_scan_conn(brix_aconn *ac, uint64_t now, uint64_t *next)
{
    if (ac->state == ACONN_RECONNECTING) {
        timeouts_expire_parked(ac, now, next);
        return;
    }
    if (ac->state != ACONN_ALIVE) {
        return;
    }

    if (timeouts_expire_inflight(ac, now, next)) {
        /* inflight scan for this ac is done — safe to recurse */
        brix_status st;
        brix_status_set(&st, XRDC_ESOCK, 0, "keepalive heartbeat timed out");
        aconn_on_transport_error(ac, &st);
    }
}

/* WHAT: Convert the nearest future deadline into the epoll_wait timeout (ms).
 * WHY:  The sweep produces an absolute ns deadline; the event loop needs a
 *       relative, clamped millisecond budget for its next block.
 * HOW:  No deadline → the idle tick; otherwise round the remaining ns up by 1ms,
 *       clamp to [1, AIO_TICK_MS]. Byte-for-byte the original tail arithmetic. */
static int
timeouts_next_wait_ms(uint64_t next, uint64_t now)
{
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

/* Fail any request whose deadline has passed; a timed-out heartbeat ping is
 * promoted to a transport error (the link is presumed dead -> reconnect). Returns
 * ms until the next deadline (capped at AIO_TICK_MS) for the next epoll_wait. */
int
loop_process_timeouts(brix_loop *l)
{
    uint64_t now  = brix_mono_ns();
    uint64_t next = 0;   /* nearest future deadline (ns), 0 = none */

    for (brix_aconn *ac = l->aconns; ac != NULL; ac = ac->next) {
        timeouts_scan_conn(ac, now, &next);
    }

    return timeouts_next_wait_ms(next, now);
}


