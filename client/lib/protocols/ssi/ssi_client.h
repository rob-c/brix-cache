#ifndef XRDC_SSI_CLIENT_H
#define XRDC_SSI_CLIENT_H

/*
 * ssi_client.h — native (ngx-free) client for the SSI request/response plane.
 *
 * WHAT: open a session on "/.ssi/<service>", submit a request, collect the
 *       reply stream (zero or more alerts, then one terminal response), pull a
 *       streamed body, cancel, close.
 *
 * WHY:  src/protocols/ssi/ is a complete server plane, but the only client that
 *       ever spoke to it was tests/ssi_client.cc driving the real C++
 *       libXrdSsi. The pure-C suite could not reach its own server's SSI
 *       surface without that stack — exactly the dependency the C suite exists
 *       to avoid — so the plane's wire behaviour was untested from this side.
 *
 * HOW:  the calls mirror the server's responder hooks one-for-one
 *       (src/protocols/ssi/ssi_service.h): set_response -> EV_RESPONSE,
 *       alert -> EV_ALERT, a streaming response -> EV_PENDING + brix_ssi_read,
 *       error -> a filled brix_status. The control word is packed by the SHARED
 *       codec (src/protocols/ssi/ssi_rrinfo.c, in libxrdproto), so the bytes
 *       this client sends and the bytes the server decodes cannot drift.
 *
 * ------------------------------------------------------------------------
 * THE TWO THINGS THAT ARE NOT OBVIOUS
 *
 * 1. ONE control word, TWO carriers. The 8-byte XrdSsiRRInfo rides the kXR
 *    OFFSET FIELD of a read/write, but rides the PAYLOAD of a kXR_query
 *    (brix_ssi_query takes `body`; brix_ssi_write takes `off8`). Swapping them
 *    does not look like a framing bug — the server answers "short SSI control"
 *    or silently decodes a different command — so the carrier is part of the
 *    contract, not an implementation detail.
 *
 * 2. TWO reply paths, and the client cannot choose which it gets. A SYNCHRONOUS
 *    service has its reply ready when the submit returns, and the client PULLS
 *    it with kXR_query(kXR_Qopaqug, RRInfo{Rwt}) — an ordinary kXR_ok, no attn
 *    envelope anywhere. A DEFERRING service acks the submit with kXR_waitresp
 *    and later PUSHES kXR_attn(asynresp) frames. brix_ssi_await() hides the
 *    difference; both paths end in the same classifier, because the discriminator
 *    is identical in both: the payload's leading XrdSsiRRInfoAttn tag byte, and
 *    nothing else. src/protocols/root/response/async.c builds the SAME envelope
 *    for an alert and for the terminal response (same actnum, same inner
 *    kXR_ok), so the transport genuinely cannot tell them apart.
 *
 * Together those are why await() returns ONE frame at a time and says which
 * kind it was: the caller loops until it sees EV_RESPONSE.
 * ------------------------------------------------------------------------
 */

/* brix.h is the umbrella: protocol.h (kXR_*, XRD_FHANDLE_LEN) + the wire codec
 * + brix_net.h -> brix_net_frame.h (brix_conn, brix_resp_out, brix_status). */
#include "brix.h"
#include "protocols/ssi/ssi_rrinfo.h"   /* BRIX_SSI_PREFIX, _CMD_*, _ATTN_* */

/*
 * An unbounded alert stream must not read as a hung server, so it carries its
 * own budget and its own wording — distinct from the transport's "no async
 * response after N frames" (XRDC_REDIR_MAX, frame.c), which counts frames of
 * any kind and would blame the wire for a service that simply never finishes.
 */
#define BRIX_SSI_ALERT_MAX 64

/* One SSI session: a kXR_open handle plus the request correlation state. */
typedef struct {
    brix_conn *conn;                        /* borrowed, not owned */
    uint8_t    fhandle[XRD_FHANDLE_LEN];    /* from the open reply */
    uint32_t   req_id;                      /* 24-bit; masked by the codec */
    uint16_t   sid;                         /* streamid the deferred reply rides */
    int        alerts_seen;                 /* against BRIX_SSI_ALERT_MAX */
    int        deferred;                    /* submit was acked with kXR_waitresp */
} brix_ssi_sess;

/* What one await() call surfaced, decided by the RRInfoAttn tag byte. */
typedef enum {
    BRIX_SSI_EV_ALERT = 0,     /* '!' BRIX_SSI_ATTN_ALRT — progress alert     */
    BRIX_SSI_EV_RESPONSE,      /* ':' BRIX_SSI_ATTN_FULL — terminal, inline   */
    BRIX_SSI_EV_PENDING        /* '*' BRIX_SSI_ATTN_PEND — pull with _read()  */
} brix_ssi_ev;

/*
 * One delivered frame. The server lays a reply out as
 *   [XrdSsiRRInfoAttn pfx_len][metadata md_len][data]
 * and NOTHING on the wire states the data length: it is only recoverable as
 * total - pfx_len - md_len. `meta` and `data` therefore point INTO `raw` rather
 * than being separate allocations — free `raw` once, via brix_ssi_reply_free,
 * and never free the halves.
 */
typedef struct {
    brix_ssi_ev    ev;
    uint8_t       *raw;        /* the whole payload; the only owned pointer */
    const uint8_t *meta;       /* NULL when meta_len == 0 */
    uint32_t       meta_len;
    const uint8_t *data;       /* NULL when data_len == 0 */
    uint32_t       data_len;
} brix_ssi_reply;

/* Release a reply and re-zero it. Safe on an already-freed or zeroed struct. */
void brix_ssi_reply_free(brix_ssi_reply *r);

/*
 * kXR_open "/.ssi/<service>" with kXR_open_read | kXR_retstat, keeping the
 * handle. retstat is deliberate and is NOT what brix_open_options_build()
 * produces: the server synthesizes a StatInfo only when it is asked
 * (ssi_open_send_reply, ssi.c), because stock's libXrdSsi refuses an open reply
 * without one — and no other client in this tree has ever set the bit, so that
 * server branch had no exerciser. 0 / -1 (st set).
 */
int brix_ssi_sess_open(brix_ssi_sess *s, brix_conn *c, const char *service,
                       brix_status *st);

/*
 * kXR_write the request bytes with an RXQ control word in the OFFSET field
 * carrying req_id and the declared total size, so the server dispatches on the
 * last byte rather than waiting for a read. A deferring service acks
 * kXR_waitresp; that is recorded on the session and is NOT an error. 0 / -1.
 */
int brix_ssi_submit(brix_ssi_sess *s, const void *req, size_t len,
                    brix_status *st);

/*
 * Collect the NEXT frame of the reply stream and classify it. Returns 0 with
 * *r filled (the caller frees it with brix_ssi_reply_free), or -1 with st set —
 * including the alert-budget refusal, which is its own message and not the
 * transport's. Call in a loop until r->ev is BRIX_SSI_EV_RESPONSE (or PENDING,
 * which is also terminal for the metadata and hands the body to _read).
 */
int brix_ssi_await(brix_ssi_sess *s, brix_ssi_reply *r, brix_status *st);

/*
 * kXR_read with an RXQ control word in the offset field: pull the body of a
 * response the server reported as PENDING rather than inline. Returns the byte
 * count (0 at end of stream), or -1.
 */
int brix_ssi_read(brix_ssi_sess *s, void *buf, size_t len, brix_status *st);

/*
 * Cancel the in-flight request with a CAN control word. Sent on the QUERY
 * carrier (ssi.c) rather than the write carrier, because a request already
 * dispatched has no write left to ride on; the request-phase cancel in
 * ssi_dispatch.c is reachable the same way once the write is in flight.
 * 0 / -1.
 */
int brix_ssi_cancel(brix_ssi_sess *s, brix_status *st);

/* kXR_close the handle. Best-effort; the session is unusable afterwards. */
void brix_ssi_close(brix_ssi_sess *s);

#endif /* XRDC_SSI_CLIENT_H */
