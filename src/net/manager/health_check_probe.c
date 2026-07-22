/*
 * health_check_probe.c — Phase 22 active stream health-check probe I/O state
 * machine (see health_check.h / health_check_internal.h).
 *
 * This is the async half of the health check: once health_check.c has opened a
 * non-blocking connection and queued the pipelined bootstrap, everything here
 * runs off the event loop — flushing the write buffer, accumulating uniform
 * 8-byte ServerResponseHdr + dlen-byte body frames, driving the
 * HANDSHAKE -> PROTOCOL -> LOGIN -> PROBE phase machine, and (Step F) upgrading
 * the probe to TLS on a kXR_gotoTLS verdict.  Every terminal path reports the
 * verdict through brix_hc_finish() (defined in health_check.c).
 */
#include "health_check.h"
#include "registry.h"
#include "observability/metrics/metrics_macros.h"
#include "core/compat/log_diag.h"
#include "health_check_internal.h"

#include <netdb.h>
#include <sys/socket.h>

/* Built by src/upstream/bootstrap.c; pure wire framing, no client context. */
extern void brix_upstream_build_login(ClientLoginRequest *req);

#if (NGX_SSL)
/* Shared outbound kXR_gotoTLS upgrade (src/net/upstream/tls.c, phase-22 Step F). */
extern ngx_int_t brix_outbound_start_tls(ngx_ssl_t *ssl_ctx,
    ngx_connection_t *c, const char *sni,
    void (*handler)(ngx_connection_t *c));
#endif

#if (NGX_SSL)
static void brix_hc_tls_handshake_done(ngx_connection_t *c);
#endif


/* write side */
/*
 * Drain hc->wbuf to the socket without blocking.  Returns NGX_OK once the whole
 * buffer is sent (and read events re-armed so the reply can arrive), NGX_AGAIN
 * if the socket is full (write event re-armed; brix_hc_write_handler resumes
 * here), or NGX_ERROR on a fatal send error.
 */
ngx_int_t
brix_hc_flush(brix_hc_ctx_t *hc)
{
    ngx_connection_t *c = hc->conn;
    ssize_t           n;

    /* Partial-write loop: send() may consume only part of the buffer, so track
     * wbuf_pos and resume from there on the next writable event. */
    while (hc->wbuf_pos < hc->wbuf_len) {
        n = c->send(c, hc->wbuf + hc->wbuf_pos, hc->wbuf_len - hc->wbuf_pos);
        if (n > 0) {
            hc->wbuf_pos += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * Build and send the final liveness probe (kXR_ping or kXR_stat "/") after a
 * successful login, transitioning to XRD_HC_PROBE.  The reply's status is the
 * pass/fail verdict, decided back in brix_hc_dispatch().
 */
static void
brix_hc_send_probe(brix_hc_ctx_t *hc)
{
    if (hc->probe_type == BRIX_HC_TYPE_STAT) {
        /* kXR_stat request followed by a 1-byte path body "/".  Over-allocate
         * by 1 so the path char sits immediately after the fixed header. */
        size_t total = sizeof(ClientStatRequest) + 1;   /* path "/" */
        ClientStatRequest *r = ngx_palloc(hc->pool, total);
        if (r == NULL) { brix_hc_finish(hc, 0); return; }
        ngx_memzero(r, sizeof(*r));
        /* streamid is a 2-byte client tag echoed in the reply; {0,2} marks this
         * as a health request (see ping branch below). */
        r->streamid[0] = 0;
        r->streamid[1] = 2;
        r->requestid   = htons(kXR_stat);          /* opcode, network order */
        r->dlen        = htonl((kXR_int32) 1);      /* body length = 1 ("/") */
        ((u_char *) r)[sizeof(*r)] = '/';           /* append path after header */
        hc->wbuf     = (u_char *) r;
        hc->wbuf_len = total;
    } else {
        ClientPingRequest *r = ngx_palloc(hc->pool, sizeof(*r));
        if (r == NULL) { brix_hc_finish(hc, 0); return; }
        ngx_memzero(r, sizeof(*r));
        r->streamid[0] = 0;
        r->streamid[1] = 2;            /* streamid 2 marks a health request */
        r->requestid   = htons(kXR_ping);
        r->dlen        = 0;            /* ping carries no body */
        hc->wbuf     = (u_char *) r;
        hc->wbuf_len = sizeof(*r);
    }
    /* Reset both write and read accumulators for this fresh request/response. */
    hc->wbuf_pos      = 0;
    hc->rhdr_pos      = 0;
    hc->resp_dlen     = 0;
    hc->resp_body     = NULL;
    hc->resp_body_pos = 0;
    hc->phase         = XRD_HC_PROBE;

    if (brix_hc_flush(hc) == NGX_ERROR) {
        brix_hc_finish(hc, 0);
    }
}

/*
 * Writable-event handler.  First writable event after a non-blocking connect()
 * confirms (or rejects) the TCP connection via SO_ERROR; subsequent calls just
 * resume a partially-flushed write buffer.
 */
void
brix_hc_write_handler(ngx_event_t *wev)
{
    ngx_connection_t *c  = wev->data;
    brix_hc_ctx_t  *hc = c->data;
    ngx_int_t         rc;

    if (wev->timedout) {
        brix_hc_finish(hc, 0);
        return;
    }

    /* Non-blocking connect completes asynchronously: the first writable event
     * means connect() finished — SO_ERROR carries success (0) or the failure
     * code, since connect() itself returned EINPROGRESS earlier. */
    if (hc->connecting) {
        int       err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (char *) &err, &len) == -1
            || err != 0)
        {
            BRIX_DIAG_WARN(hc->log, err, /* may be 0 */
                "brix: health check failed to connect to %s:%d",
                "the cluster member is down or unreachable from the manager",
                "check that member's xrootd/data service and the network path "
                "to it; it is marked DOWN and clients are routed elsewhere "
                "until it passes again",
                hc->host, (int) hc->port);
            brix_hc_finish(hc, 0);
            return;
        }
        hc->connecting = 0;
    }

    rc = brix_hc_flush(hc);
    if (rc == NGX_ERROR) {
        brix_hc_finish(hc, 0);
    }
}


/* read side */
/* Accumulate one full ServerResponseHdr + body frame; return NGX_OK when a
 * complete frame is ready, NGX_AGAIN to wait for more, NGX_ERROR on close. */
static ngx_int_t
brix_hc_recv_frame(brix_hc_ctx_t *hc)
{
    ngx_connection_t *c = hc->conn;
    ssize_t           n;

    /* Stage 1: fill the fixed 8-byte header, possibly across several reads
     * (rhdr_pos tracks how much has arrived).  Only once it is complete do we
     * decode status/dlen and learn the body length. */
    if (hc->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
        size_t need = XRD_RESPONSE_HDR_LEN - hc->rhdr_pos;
        n = c->recv(c, hc->rhdr + hc->rhdr_pos, need);
        if (n == NGX_AGAIN) { return NGX_AGAIN; }
        if (n <= 0)         { return NGX_ERROR; }  /* 0 = peer closed */
        hc->rhdr_pos += (size_t) n;
        if (hc->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
            return NGX_AGAIN;
        }
        /* Header complete: decode the wire fields (big-endian on the wire). */
        {
            ServerResponseHdr *h = (ServerResponseHdr *) (void *) hc->rhdr;
            hc->resp_status = ntohs(h->status);
            hc->resp_dlen   = ntohl(h->dlen);
        }
        if (hc->resp_dlen > 0) {
            /* Bound attacker/garbage-controlled body length: a probe reply is
             * tiny, so cap the allocation rather than trust the wire dlen. */
            if (hc->resp_dlen > 4096) {     /* bound probe response bodies */
                return NGX_ERROR;
            }
            hc->resp_body = ngx_palloc(c->pool, hc->resp_dlen);
            if (hc->resp_body == NULL) { return NGX_ERROR; }
            hc->resp_body_pos = 0;
        }
    }

    /* Stage 2: fill the dlen-byte body (again possibly across several reads).
     * Skipped entirely when dlen == 0. */
    if (hc->resp_body_pos < hc->resp_dlen) {
        size_t need = hc->resp_dlen - hc->resp_body_pos;
        n = c->recv(c, hc->resp_body + hc->resp_body_pos, need);
        if (n == NGX_AGAIN) { return NGX_AGAIN; }
        if (n <= 0)         { return NGX_ERROR; }
        hc->resp_body_pos += (size_t) n;
        if (hc->resp_body_pos < hc->resp_dlen) {
            return NGX_AGAIN;
        }
    }

    return NGX_OK;
}

#if (NGX_SSL)
/*
 * Handshake-done callback for a Step-F TLS-upgraded probe.  Mirrors the
 * upstream brix_upstream_tls_handshake_done(): verify the handshake (and the
 * peer, explicitly), restore the probe's event handlers, and resend a fresh
 * kXR_login over the TLS channel — the probe then continues LOGIN -> PROBE
 * exactly as on cleartext.  Any failure is a probe failure: a server that
 * demands TLS but cannot complete it cannot serve TLS clients.
 */
static void
brix_hc_tls_handshake_done(ngx_connection_t *c)
{
    brix_hc_ctx_t     *hc = c->data;
    ClientLoginRequest  *req;

    if (!c->ssl->handshaked) {
        ngx_log_error(NGX_LOG_WARN, hc->log, 0,
                      "brix: health check: %s:%d TLS handshake failed",
                      hc->host, (int) hc->port);
        brix_hc_finish(hc, 0);
        return;
    }
    if (SSL_get_verify_result(c->ssl->connection) != X509_V_OK) {
        ngx_log_error(NGX_LOG_WARN, hc->log, 0,
                      "brix: health check: %s:%d TLS peer verification failed",
                      hc->host, (int) hc->port);
        brix_hc_finish(hc, 0);
        return;
    }

    hc->tls = 1;

    /* Restore normal event handlers (the TLS handshake replaces them). */
    c->read->handler  = brix_hc_read_handler;
    c->write->handler = brix_hc_write_handler;

    /* Fresh kXR_login for the TLS channel (the plaintext one is discarded). */
    req = ngx_palloc(hc->pool, sizeof(*req));
    if (req == NULL) {
        brix_hc_finish(hc, 0);
        return;
    }
    brix_upstream_build_login(req);

    hc->wbuf     = (u_char *) req;
    hc->wbuf_len = sizeof(*req);
    hc->wbuf_pos = 0;
    hc->phase    = XRD_HC_LOGIN;

    hc->rhdr_pos      = 0;
    hc->resp_dlen     = 0;
    hc->resp_body     = NULL;
    hc->resp_body_pos = 0;

    if (brix_hc_flush(hc) == NGX_ERROR) {
        brix_hc_finish(hc, 0);
    }
}
#endif /* NGX_SSL */

/*
 * XRD_HC_PROTOCOL step of brix_hc_dispatch(): consume the kXR_protocol reply
 * and decide how the probe proceeds.  Returns NGX_DONE when the step reached a
 * verdict or issued its own follow-up send (the caller must return without
 * touching hc — it may already be freed), or NGX_OK when the phase advanced to
 * LOGIN and the caller should fall through to the accumulator reset.
 */
static ngx_int_t
brix_hc_dispatch_protocol(brix_hc_ctx_t *hc)
{
    if (hc->resp_status != kXR_ok) { brix_hc_finish(hc, 0); return NGX_DONE; }

    /* If the server demands TLS we don't probe deeper (no TLS in the
     * probe path); it answered at the protocol level, so treat it as
     * alive rather than blacklisting it.
     *
     * ServerResponseBody_Protocol layout: bytes 0-3 = pval (protocol
     * version), bytes 4-7 = flags.  Read the flags word at offset 4 and
     * test the kXR_gotoTLS bit.  Guard on dlen >= 8 so short/old replies
     * that omit the flags simply fall through to the LOGIN phase. */
    if (hc->resp_dlen >= 8) {
        uint32_t flags_be;
        ngx_memcpy(&flags_be, hc->resp_body + 4, sizeof(flags_be));
        if (ntohl(flags_be) & kXR_gotoTLS) {
#if (NGX_SSL)
            /* Step F: with an outbound TLS ctx configured, probe DEEP —
             * upgrade this connection and continue LOGIN -> PROBE over
             * TLS, exactly as the upstream bootstrap does (the server
             * discards the plaintext login pre-sent in the pipelined
             * bootstrap).  The probe deadline timer keeps running. */
            if (hc->conf->upstream_tls
                && hc->conf->upstream_tls_ctx != NULL)
            {
                ngx_log_debug2(NGX_LOG_DEBUG_STREAM, hc->log, 0,
                    "brix: health check: %s:%d wants TLS; upgrading probe",
                    hc->host, (int) hc->port);
                if (brix_outbound_start_tls(hc->conf->upstream_tls_ctx,
                                            hc->conn, hc->host,
                                            brix_hc_tls_handshake_done)
                    != NGX_OK)
                {
                    brix_hc_finish(hc, 0);
                }
                return NGX_DONE;
            }
#endif
            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, hc->log, 0,
                "brix: health check: %s:%d wants TLS; "
                "treating protocol-OK as alive", hc->host, (int) hc->port);
            brix_hc_finish(hc, 1);
            return NGX_DONE;
        }
    }
    if (hc->tls_capable) {
        /* No gotoTLS: send the deferred login now, in cleartext.  (A
         * TLS-capable probe never pipelined it — see brix_hc_start.) */
        ClientLoginRequest *req = ngx_palloc(hc->pool, sizeof(*req));
        if (req == NULL) { brix_hc_finish(hc, 0); return NGX_DONE; }
        brix_upstream_build_login(req);
        hc->wbuf          = (u_char *) req;
        hc->wbuf_len      = sizeof(*req);
        hc->wbuf_pos      = 0;
        hc->phase         = XRD_HC_LOGIN;
        hc->rhdr_pos      = 0;
        hc->resp_dlen     = 0;
        hc->resp_body     = NULL;
        hc->resp_body_pos = 0;
        if (brix_hc_flush(hc) == NGX_ERROR) { brix_hc_finish(hc, 0); }
        return NGX_DONE;
    }
    hc->phase = XRD_HC_LOGIN;
    return NGX_OK;
}

/*
 * Consume one complete response frame and advance the probe state machine.
 * Several phases short-circuit to a verdict (alive/dead) without reaching the
 * final PROBE phase — see the per-case comments.  On a non-terminal transition
 * it resets the accumulator and re-posts the read event so any already-buffered
 * pipelined reply is processed in the same event cycle.
 */

static void
brix_hc_dispatch(brix_hc_ctx_t *hc)
{
    switch (hc->phase) {

    case XRD_HC_HANDSHAKE:
        if (hc->resp_status != kXR_ok) { brix_hc_finish(hc, 0); return; }
        hc->phase = XRD_HC_PROTOCOL;
        break;

    case XRD_HC_PROTOCOL:
        if (brix_hc_dispatch_protocol(hc) == NGX_DONE) {
            return;
        }
        break;

    case XRD_HC_LOGIN:
        /* authmore => server is alive but wants credentials; we don't carry
         * any, so accept protocol liveness rather than fail. */
        if (hc->resp_status == kXR_authmore) {
            brix_hc_finish(hc, 1);
            return;
        }
        if (hc->resp_status != kXR_ok) { brix_hc_finish(hc, 0); return; }
        brix_hc_send_probe(hc);      /* sets phase = PROBE, sends ping/stat */
        return;

    case XRD_HC_PROBE:
        brix_hc_finish(hc, hc->resp_status == kXR_ok ? 1 : 0);
        return;
    }

    /* Reset accumulator for the next frame and post a synthetic read so any
     * pipelined bytes already in the socket buffer are processed this cycle. */
    hc->rhdr_pos      = 0;
    hc->resp_dlen     = 0;
    hc->resp_body     = NULL;
    hc->resp_body_pos = 0;

    if (ngx_handle_read_event(hc->conn->read, 0) != NGX_OK) {
        brix_hc_finish(hc, 0);
        return;
    }
    ngx_post_event(hc->conn->read, &ngx_posted_events);
}

/*
 * Readable-event handler.  Pulls exactly one complete frame per invocation and
 * hands it to brix_hc_dispatch(), which re-arms (or posts) the read event for
 * the next frame; this keeps each event-loop iteration bounded.
 */
void
brix_hc_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *c  = rev->data;
    brix_hc_ctx_t  *hc = c->data;
    ngx_int_t         rc;

    if (rev->timedout) {
        brix_hc_finish(hc, 0);
        return;
    }

    /* Loop is structural only: every branch returns.  It exists so a future
     * "read another frame inline" change has an obvious place to continue. */
    for ( ;; ) {
        rc = brix_hc_recv_frame(hc);
        if (rc == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                brix_hc_finish(hc, 0);
            }
            return;
        }
        if (rc == NGX_ERROR) {
            brix_hc_finish(hc, 0);
            return;
        }
        brix_hc_dispatch(hc);
        return;                        /* dispatch re-arms / posts as needed */
    }
}
