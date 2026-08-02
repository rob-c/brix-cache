/*
 * brix_net_frame.h — client wire framing, connection lifecycle, the connection
 * pool and parallel-stream helpers for the ngx-free client (libbrix).
 *
 * Phase-38 split of brix_net.h; declaration-identical. These are the
 * frame.c / conn.c / pool.c / streams.c decls, moved out to keep brix_net.h
 * within the file-size budget. brix_net.h #includes this at its tail, so
 * consumers that include brix_net.h are unaffected; it is guard-safe to
 * include directly too (it pulls brix_net.h for the foundational types).
 * See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XRDC_NET_FRAME_H
#define XRDC_NET_FRAME_H

#include "brix_net.h"   /* brix_conn, brix_status, brix_url/opts, fixed-width ints */

/* ---- frame.c ---- */
/* One outbound request payload: the bytes written after the 24-byte header.
 * A NULL brix_payload argument means "no payload" ({NULL, 0}). */
typedef struct {
    const void *data;   /* payload bytes (may be NULL when len == 0) */
    uint32_t    len;    /* payload byte count (brix_send frames dlen == len) */
} brix_payload;

/* brix_send_ext payload: `dlen` — the wire dlen written into hdr[20..23] (also
 * the sigver-signed span) — may be smaller than `len`, the payload bytes
 * actually written.  Needed by kXR_writev, whose dlen frames only the 16-byte
 * descriptor block while the segment data streams after the frame (stock
 * XrdXrootdProtocol::do_WriteV).  brix_send == brix_send_ext with dlen == len. */
typedef struct {
    const void *data;   /* payload bytes (may be NULL when len == 0) */
    uint32_t    len;    /* payload bytes actually written after the header */
    uint32_t    dlen;   /* wire dlen framed in the header */
} brix_payload_ext;

/* Caller-provided response out-params. The struct pointer itself must be
 * non-NULL; any field may be NULL to decline that value. *body receives a
 * malloc'd buffer the caller frees (NULL when the reply has no body). */
typedef struct {
    uint16_t *status;
    uint8_t **body;
    uint32_t *blen;
} brix_resp_out;

/* Assign a fresh streamid into hdr[0..1] and write dlen into hdr[20..23] (the
 * caller has already filled requestid + the 16-byte body). Sends header+payload. */
int brix_send(brix_conn *c, void *hdr24, const brix_payload *pl,
              uint16_t *out_sid, brix_status *st);
/* As brix_send, but with independent wire dlen (see brix_payload_ext). */
int brix_send_ext(brix_conn *c, void *hdr24, const brix_payload_ext *pl,
                  uint16_t *out_sid, brix_status *st);
/* Read one response frame for streamid want_sid. Returns 0 with *out->status set
 * and a malloc'd *out->body / *out->blen (caller frees) for kXR_ok/oksofar/authmore
 * AND kXR_redirect/kXR_wait (so the roundtrip wrapper can act on them). Returns
 * -1 on kXR_error (st filled from errnum+errmsg) or any other status / transport
 * fault. */
int brix_recv(brix_conn *c, uint16_t want_sid, brix_resp_out *out,
              brix_status *st);

/* Send a request and read its reply, transparently following kXR_redirect
 * (reconnect+replay, bounded by XRDC_REDIR_MAX + a visited-set loop guard) and
 * honoring kXR_wait (sleep+resend). Use this for path-based ops so cluster
 * redirectors work. hdr24 is re-stamped (streamid/dlen) on each attempt.
 * out->body and out->blen must be non-NULL here. Returns 0 with *out->status =
 * kXR_ok/oksofar + body/blen; -1 (st set) on error. */
int brix_roundtrip(brix_conn *c, void *hdr24, const brix_payload *pl,
                   brix_resp_out *out, brix_status *st);

/* ---- conn.c ---- */
/* connect → handshake → [TLS upgrade] → kXR_protocol → kXR_login → [auth].
 * opts may be NULL (anonymous, no TLS). */
int  brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o,
                  brix_status *st);
/* Tear down the current transport and re-establish the full session (handshake →
 * [TLS] → login → auth) against host:port, preserving the stored opts/creds. Used
 * by the redirect follower. 0 / -1. */
int  brix_reconnect(brix_conn *c, const char *host, int port, brix_status *st);
void brix_close(brix_conn *c);

/* ---- pool.c — thread-safe pool of connections for concurrent callers ---- */
/* An brix_conn is one-request-in-flight and NOT thread-safe; a multi-threaded
 * consumer (e.g. the FUSE driver) checks out an independent connected conn per
 * operation. The struct is opaque; callers hold only the handle. */
typedef struct brix_pool brix_pool;
/* Create a pool of `n` connections to `u` (opts `o`, may be NULL). Connects one
 * eagerly so a bad endpoint/auth fails up front; the rest connect on demand.
 * Returns NULL + sets st on failure. */
brix_pool *brix_pool_create(const brix_url *u, const brix_opts *o, int n,
                            brix_status *st);
/* Borrow a connected conn, blocking until one is free; reconnects a dropped slot
 * transparently. Returns NULL + sets st only if (re)connect fails. */
brix_conn *brix_pool_checkout(brix_pool *p, brix_status *st);
/* Return a checked-out conn. healthy==0 (the op hit a connection-level error,
 * i.e. st->kxr == XRDC_ESOCK/XRDC_EPROTO) drops the conn so the next checkout
 * reconnects on a clean session. */
void       brix_pool_checkin(brix_pool *p, brix_conn *c, int healthy);
void       brix_pool_destroy(brix_pool *p);
/* Establish a secondary data stream bound to `primary`'s session: handshake +
 * kXR_protocol [+ TLS] then kXR_bind{primary->sessid}, skipping kXR_login (the
 * server inherits identity from the primary). `sec` is fully initialised here.
 * Tear it down with brix_streams_close (no endsess). 0 / -1. */
int  brix_bind(brix_conn *sec, const brix_conn *primary, brix_status *st);

/* ---- streams.c (M8 parallel streams) ---- */
#define XRDC_MAX_STREAMS 16
typedef struct {
    int       n;                              /* secondaries actually bound */
    brix_conn sec[XRDC_MAX_STREAMS - 1];
} brix_streamset;
/* Best-effort: bind up to (streams-1) secondaries to `primary` (capped at
 * XRDC_MAX_STREAMS-1). Never fails the caller — returns the number bound; a
 * secondary that won't bind is simply skipped. */
int  brix_streams_open(brix_streamset *ss, brix_conn *primary, int streams,
                       brix_status *st);
void brix_streams_close(brix_streamset *ss);

#endif /* XRDC_NET_FRAME_H */
