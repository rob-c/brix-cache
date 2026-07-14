/*
 * stream_wmirror_state.c — XRootD stream data-write mirror: replay protocol
 * state machine (see stream_wmirror_internal.h).
 *
 * WHAT: The per-phase half of the detached replay.  Builds and sends each
 *       protocol frame (open -> write -> close) to the shadow, decides what a
 *       just-received response means, and drives the linear phase progression.
 *
 * WHY:  Split out of stream_wmirror.c under the phase-79 500-line cap.  The frame
 *       construction and the six per-phase decisions form one cohesive concern —
 *       the shadow-side protocol — that reads cleanly apart from the socket
 *       lifecycle and event plumbing (stream_wmirror_replay.c).
 *
 * HOW:  wmir_read_handler (replay.c) parses one frame and calls wmir_dispatch,
 *       which indexes the wmir_step_table by phase.  A request phase queues its
 *       next frame via wmir_send_* (each of which flushes and re-arms the read);
 *       a bootstrap phase advances the phase and re-posts the read to drain
 *       pipelined frames.  All buffer draining goes through wmir_flush and every
 *       failure through wmir_finish — both owned by stream_wmirror_replay.c.
 */
#include "stream_wmirror.h"
#include "stream_wmirror_internal.h"

#include <arpa/inet.h>              /* htonl / ntohl */


/* Clear the response accumulator before awaiting the next frame: zero the
 * header read cursor and the parsed status/dlen/body so a stale value from the
 * previous phase cannot leak into the next response. */
static void
wmir_reset_frame(brix_wmirror_replay_t *r)
{
    r->rhdr_pos = 0;
    r->resp_status = 0;
    r->resp_dlen = 0;
    r->resp_body = NULL;
    r->resp_body_pos = 0;
}

/*
 * Replay the client's original open frame (header[24] + path/cgi payload) to the
 * shadow.  WHAT: re-sends the captured open verbatim so the shadow recreates the
 * same path under its own namespace.  HOW: copy into a fresh pool buffer (the
 * saved open_frame is reused per launch and must stay intact), overwrite the
 * streamid to 0x0002 (marks this as a mirror request, matching the read mirror),
 * then flush.  The original open's create/truncate flags are preserved as-is.
 */
static void
wmir_send_open(brix_wmirror_replay_t *r)
{
    u_char *p = ngx_palloc(r->pool, r->open_frame_len);

    if (p == NULL) { wmir_finish(r, 0); return; }
    ngx_memcpy(p, r->open_frame, r->open_frame_len);
    p[0] = 0; p[1] = 2;                              /* streamid 0x0002 */
    r->wbuf = p; r->wbuf_len = r->open_frame_len; r->wbuf_pos = 0;
    wmir_reset_frame(r);
    r->phase = WMIR_OPEN;
    if (wmir_flush(r) == NGX_ERROR) { wmir_finish(r, 0); }
}

/*
 * Send the whole accumulated file as a SINGLE kXR_write to the shadow.
 *
 * WHAT/WHY: the accumulator only ever captured sequential writes starting at
 * offset 0 (wmir_observe enforces contiguity), so the entire file collapses into
 * one write at offset 0 — we do NOT need to replay the client's original chunk
 * boundaries.  HOW: hand-build the 24-byte ClientWriteRequest header:
 *   [0..1]  streamid  = 0x0002 (mirror marker)
 *   [2..3]  requestid = kXR_write, big-endian
 *   [4..7]  fhandle   = the shadow's handle from the open response
 *   [8..15] offset    = 0 (whole file from start; off_be is already zero)
 *   [16..19] reserved (left zero by ngx_memzero)
 *   [20..23] dlen     = data_len, big-endian
 * followed by data_len payload bytes.  All multi-byte fields are network order.
 */
static void
wmir_send_write(brix_wmirror_replay_t *r)
{
    size_t   total = (size_t) 24 + r->data_len;
    u_char  *p = ngx_palloc(r->pool, total);
    uint32_t dlen_be;
    uint64_t off_be = 0;

    if (p == NULL) { wmir_finish(r, 0); return; }
    ngx_memzero(p, 24);
    p[0] = 0; p[1] = 2;
    p[2] = (u_char) (kXR_write >> 8); p[3] = (u_char) (kXR_write & 0xff);
    ngx_memcpy(p + 4, r->shadow_fhandle, 4);
    ngx_memcpy(p + 8, &off_be, 8);                   /* whole file at offset 0 */
    dlen_be = htonl((uint32_t) r->data_len);
    ngx_memcpy(p + 20, &dlen_be, 4);
    if (r->data_len) { ngx_memcpy(p + 24, r->data, r->data_len); }
    r->wbuf = p; r->wbuf_len = total; r->wbuf_pos = 0;
    wmir_reset_frame(r);
    r->phase = WMIR_WRITE;
    if (wmir_flush(r) == NGX_ERROR) { wmir_finish(r, 0); }
}

/*
 * Send kXR_close for the shadow handle — finalizes the replayed file.  Same
 * 24-byte header layout as the write: streamid 0x0002, requestid kXR_close at
 * [2..3], the shadow fhandle at [4..7]; all other fields stay zero.
 */
static void
wmir_send_close(brix_wmirror_replay_t *r)
{
    u_char *p = ngx_palloc(r->pool, 24);

    if (p == NULL) { wmir_finish(r, 0); return; }
    ngx_memzero(p, 24);
    p[0] = 0; p[1] = 2;
    p[2] = (u_char) (kXR_close >> 8); p[3] = (u_char) (kXR_close & 0xff);
    ngx_memcpy(p + 4, r->shadow_fhandle, 4);
    r->wbuf = p; r->wbuf_len = 24; r->wbuf_pos = 0;
    wmir_reset_frame(r);
    r->phase = WMIR_CLOSE;
    if (wmir_flush(r) == NGX_ERROR) { wmir_finish(r, 0); }
}

/* A shadow op succeeded if it returned kXR_ok or kXR_oksofar (the latter is a
 * partial-but-fine status the server may use for streamed writes). */
static int
wmir_status_ok(uint16_t st)
{
    return st == kXR_ok || st == kXR_oksofar;
}

/*
 * Outcome of a single per-phase step, telling wmir_dispatch what to do next.
 * WHAT: decouples the phase decision from the loop plumbing so each phase handler
 * stays a small pure decision.  WHY: a request phase queues its own next frame
 * (whose flush re-arms the read) and is DONE; a bootstrap phase only advanced the
 * state and needs the read re-posted to drain pipelined frames; a failure tears
 * down.  HOW: handlers return one of these and never touch the loop directly.
 */
typedef enum {
    WMIR_STEP_FAIL = 0,     /* terminal failure — finish(r, 0)                 */
    WMIR_STEP_SENT,         /* request phase queued its next frame — done      */
    WMIR_STEP_REPOST,       /* bootstrap phase advanced — re-post the read     */
} wmir_step_t;

/*
 * Bootstrap-handshake phase: the shadow's handshake response must be kXR_ok.
 * WHAT: validate the handshake and advance to PROTOCOL.  HOW: any non-ok status
 * fails; otherwise move to the next bootstrap phase and re-post the read.
 */
static wmir_step_t
wmir_step_handshake(brix_wmirror_replay_t *r)
{
    if (r->resp_status != kXR_ok) { return WMIR_STEP_FAIL; }
    r->phase = WMIR_PROTOCOL;
    return WMIR_STEP_REPOST;
}

/*
 * Bootstrap-protocol phase: validate the ClientProtocol response.  WHAT: require
 * kXR_ok and reject a shadow that demands TLS.  WHY: a gotoTLS shadow cannot
 * continue the cleartext replay.  HOW: the flag lives in the response body at
 * byte offset 4 (a 4-byte big-endian word); if set, fail; else advance to LOGIN.
 */
static wmir_step_t
wmir_step_protocol(brix_wmirror_replay_t *r)
{
    if (r->resp_status != kXR_ok) { return WMIR_STEP_FAIL; }
    if (r->resp_dlen >= 8 && r->resp_body != NULL) {
        uint32_t flags_be;
        ngx_memcpy(&flags_be, r->resp_body + 4, sizeof(flags_be));
        if (ntohl(flags_be) & kXR_gotoTLS) { return WMIR_STEP_FAIL; }
    }
    r->phase = WMIR_LOGIN;
    return WMIR_STEP_REPOST;
}

/*
 * Bootstrap-login phase: on a clean login, send the shadow open.  WHAT: require a
 * plain kXR_ok.  WHY: kXR_authmore means the shadow wants credentials we cannot
 * supply on this anonymous replay (non-fatal stop, counted as error).  HOW: on
 * success queue the open frame (which arms the read itself) and report SENT.
 */
static wmir_step_t
wmir_step_login(brix_wmirror_replay_t *r)
{
    if (r->resp_status != kXR_ok) { return WMIR_STEP_FAIL; }
    wmir_send_open(r);              /* resets accumulator + sends + arms read */
    return WMIR_STEP_SENT;
}

/*
 * Open-response phase: capture the shadow file handle, then send the write.
 * WHAT: the open response body begins with the shadow's 4-byte fhandle that all
 * downstream ops address.  HOW: a bad status or a short/missing body fails; else
 * copy the handle and queue the single whole-file write.
 */
static wmir_step_t
wmir_step_open(brix_wmirror_replay_t *r)
{
    if (!wmir_status_ok(r->resp_status) || r->resp_dlen < 4
        || r->resp_body == NULL)
    {
        return WMIR_STEP_FAIL;             /* shadow open failed/diverged */
    }
    ngx_memcpy(r->shadow_fhandle, r->resp_body, 4);
    wmir_send_write(r);
    return WMIR_STEP_SENT;
}

/*
 * Write-response phase: on an accepted write, send the close.  WHAT: require an
 * ok/oksofar status.  HOW: on success queue the close frame and report SENT.
 */
static wmir_step_t
wmir_step_write(brix_wmirror_replay_t *r)
{
    if (!wmir_status_ok(r->resp_status)) { return WMIR_STEP_FAIL; }
    wmir_send_close(r);
    return WMIR_STEP_SENT;
}

/*
 * Close-response phase: terminal success.  WHAT: this is the only path that
 * reports the replay fully succeeded (ok=1) — iff the close was accepted.
 */
static wmir_step_t
wmir_step_close(brix_wmirror_replay_t *r)
{
    wmir_finish(r, wmir_status_ok(r->resp_status) ? 1 : 0);
    return WMIR_STEP_SENT;              /* already finished; do not re-post */
}

/*
 * Re-post the read after a bootstrap phase advanced.  WHAT: clear the frame
 * accumulator and re-arm+post the read event.  WHY: the pipelined bootstrap
 * responses may already be sitting in the socket buffer, so re-posting drains
 * them within the same loop cycle rather than waiting for a fresh readable event.
 */
static void
wmir_repost_read(brix_wmirror_replay_t *r)
{
    wmir_reset_frame(r);
    if (ngx_handle_read_event(r->conn->read, 0) != NGX_OK) {
        wmir_finish(r, 0);
        return;
    }
    ngx_post_event(r->conn->read, &ngx_posted_events);
}

/* Per-phase step handlers, indexed by wmir_phase_t.  Table-driven dispatch keeps
 * the flow linear and each phase in one focused function. */
static wmir_step_t (*const wmir_step_table[])(brix_wmirror_replay_t *) = {
    [WMIR_HANDSHAKE] = wmir_step_handshake,
    [WMIR_PROTOCOL]  = wmir_step_protocol,
    [WMIR_LOGIN]     = wmir_step_login,
    [WMIR_OPEN]      = wmir_step_open,
    [WMIR_WRITE]     = wmir_step_write,
    [WMIR_CLOSE]     = wmir_step_close,
};

/* Advance one phase; bootstrap phases re-post the read so pipelined frames are
 * processed; request phases send the next frame (which arms the read itself). */
void
wmir_dispatch(brix_wmirror_replay_t *r)
{
    wmir_step_t step = wmir_step_table[r->phase](r);

    if (step == WMIR_STEP_FAIL)   { wmir_finish(r, 0); return; }
    if (step == WMIR_STEP_REPOST) { wmir_repost_read(r); }
    /* WMIR_STEP_SENT: the phase already queued its next frame (or finished). */
}
