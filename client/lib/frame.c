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
#include "xrdc.h"

#include <arpa/inet.h>
#include <stdio.h>     /* snprintf for the tried-set host:port key */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>   /* sleep() for kXR_wait backoff */
#include <time.h>     /* nanosleep() for sub-second kXR_wait jitter */
#include "protocol/frame_hdr.h"   /* shared resp-hdr / wait / error codecs */
#include "compat/host_format.h"   /* IPv6-bracketing host:port (libxrdproto) */

int
xrdc_send(xrdc_conn *c, void *hdr24, const void *payload, uint32_t plen,
          uint16_t *out_sid, xrdc_status *st)
{
    uint8_t *h   = (uint8_t *) hdr24;
    uint16_t sid = c->next_sid++;
    uint32_t be  = htonl(plen);

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
        xrdc_trace_frame(c, '>', sid, c->diag.inflight_reqid, 1, plen, payload, plen);
    }
    if (c->diag.cap != NULL) {   /* §15.1: record the full request wire bytes */
        xrdc_capture_frame(c->diag.cap, '>', sid, c->diag.inflight_reqid, 1,
                           h, XRD_REQUEST_HDR_LEN, payload, plen);
    }
    if (c->diag.timing) {
        c->diag.t_send_ns = xrdc_mono_ns();
    }

    /* When GSI signing is active and the server's security level requires it,
     * prepend a kXR_sigver frame covering this request (no-op otherwise). */
    if (xrdc_sigver_maybe(c, h, payload, plen, st) != 0) {
        return -1;
    }

    if (xrdc_write_full(&c->io, h, XRD_REQUEST_HDR_LEN, st) != 0) {
        return -1;
    }
    if (plen > 0 && payload != NULL) {
        if (xrdc_write_full(&c->io, payload, plen, st) != 0) {
            return -1;
        }
    }
    return 0;
}

/* Read one full server frame (header + body) with the standard size cap; fills
 * the sid, stat, buf and dlen out-params (caller frees buf). No streamid matching
 * — used by the kXR_waitresp async path, where the deferred reply arrives as an
 * unsolicited frame whose outer streamid may differ from the request's. 0 / -1. */
static int
recv_raw_frame(xrdc_conn *c, uint16_t *sid, uint16_t *stat, uint8_t **buf,
               uint32_t *dlen, xrdc_status *st)
{
    uint8_t  hdr[XRD_RESPONSE_HDR_LEN];
    uint32_t dl;
    uint8_t *b = NULL;

    *buf = NULL;
    *dlen = 0;
    if (xrdc_read_full(&c->io, hdr, sizeof(hdr), st) != 0) {
        return -1;
    }
    xrd_resp_hdr_unpack(hdr, sid, stat, &dl);   /* unaligned-safe */
    if (dl > XRDC_DLEN_MAX) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "response body too large (%u bytes)", dl);
        return -1;
    }
    if (dl > 0) {
        b = (uint8_t *) malloc(dl);
        if (b == NULL) {
            xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (%u bytes)", dl);
            return -1;
        }
        if (xrdc_read_full(&c->io, b, dl, st) != 0) {
            free(b);
            return -1;
        }
    }
    if (c->diag.wire_trace) {
        xrdc_trace_frame(c, '<', *sid, *stat, 0, dl, b, dl);
    }
    *buf  = b;
    *dlen = dl;
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
recv_after_waitresp(xrdc_conn *c, uint16_t want_sid, unsigned secs,
                    uint16_t *status, uint8_t **body, uint32_t *blen,
                    xrdc_status *st)
{
    int      saved_to = c->io.timeout_ms;
    int      rounds   = 0;
    unsigned s        = (secs > 570) ? 570 : secs;   /* clamp before *1000 (no UB) */
    int      want_ms  = (int) s * 1000 + 30000;       /* delay + margin, <= 600000 */

    if (want_ms > c->io.timeout_ms) { c->io.timeout_ms = want_ms; }

    for (;;) {
        uint16_t sid = 0, stat = 0;
        uint8_t *buf = NULL;
        uint32_t dlen = 0;

        if (++rounds > XRDC_REDIR_MAX) {
            c->io.timeout_ms = saved_to;
            xrdc_status_set(st, XRDC_EPROTO, 0,
                            "waitresp: no async response after %d frames", rounds);
            return -1;
        }
        if (recv_raw_frame(c, &sid, &stat, &buf, &dlen, st) != 0) {
            c->io.timeout_ms = saved_to;
            return -1;
        }
        if (stat == kXR_waitresp) {              /* server re-deferred — keep waiting */
            unsigned more = (dlen >= 4) ? xrd_get_u32_be(buf) : 0;
            int      w;
            free(buf);
            if (more > 570) { more = 570; }      /* clamp before *1000 (no UB) */
            w = (int) more * 1000 + 30000;
            if (w > c->io.timeout_ms) { c->io.timeout_ms = w; }
            continue;
        }
        if (stat != kXR_attn) {
            free(buf);
            c->io.timeout_ms = saved_to;
            xrdc_status_set(st, XRDC_EPROTO, 0,
                            "waitresp: expected attn(asynresp), got status %u", stat);
            return -1;
        }
        if (dlen < 16 || xrd_get_u32_be(buf) != (uint32_t) kXR_asynresp) {
            free(buf);
            c->io.timeout_ms = saved_to;
            xrdc_status_set(st, XRDC_EPROTO, 0, "waitresp: malformed asynresp envelope");
            return -1;
        }
        {
            uint16_t esid, estat;
            uint32_t edlen;
            xrd_resp_hdr_unpack(buf + 8, &esid, &estat, &edlen);  /* nested hdr */
            uint8_t *edata = buf + 16;

            if ((size_t) edlen + 16 > dlen) { edlen = dlen - 16; }   /* clamp to frame */
            c->io.timeout_ms = saved_to;
            if (want_sid != 0xffff && esid != want_sid) {
                free(buf);
                xrdc_status_set(st, XRDC_EPROTO, 0,
                                "asynresp stream mismatch (got %u, want %u)",
                                esid, want_sid);
                return -1;
            }
            if (estat == kXR_error) {
                int errnum = (edlen >= 4) ? (int) xrd_get_u32_be(edata) : 0;
                int mlen   = (edlen > 4) ? (int) (edlen - 4) : 0;
                /* The wire message is NOT NUL-terminated; bound %s with %.*s so a
                 * hostile server can't drive a heap over-read past the frame. */
                xrdc_status_set(st, errnum, 0, "%.*s (%s)", mlen,
                                (const char *) (edata + 4), xrdc_kxr_name(errnum));
                free(buf);
                return -1;
            }
            if (status != NULL) { *status = estat; }
            if (body != NULL) {
                *body = NULL;
                if (edlen > 0) {
                    uint8_t *out = (uint8_t *) malloc(edlen);
                    if (out == NULL) {
                        free(buf);
                        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (%u)", edlen);
                        return -1;
                    }
                    memcpy(out, edata, edlen);
                    *body = out;
                }
            }
            if (blen != NULL) { *blen = edlen; }
            free(buf);
            return 0;
        }
    }
}

int
xrdc_recv(xrdc_conn *c, uint16_t want_sid, uint16_t *status,
          uint8_t **body, uint32_t *blen, xrdc_status *st)
{
    uint8_t  hdr[XRD_RESPONSE_HDR_LEN];
    uint16_t sid, stat;
    uint32_t dlen;
    uint8_t *buf = NULL;

    if (body != NULL) { *body = NULL; }
    if (blen != NULL) { *blen = 0; }

    if (xrdc_read_full(&c->io, hdr, sizeof(hdr), st) != 0) {
        return -1;
    }

    xrd_resp_hdr_unpack(hdr, &sid, &stat, &dlen);   /* unaligned-safe */

    if (dlen > XRDC_DLEN_MAX) {
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "response body too large (%u bytes)", dlen);
        return -1;
    }
    if (want_sid != 0xffff && sid != want_sid) {
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "stream id mismatch (got %u, want %u)", sid, want_sid);
        return -1;
    }

    if (dlen > 0) {
        buf = (uint8_t *) malloc(dlen);
        if (buf == NULL) {
            xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (%u bytes)", dlen);
            return -1;
        }
        if (xrdc_read_full(&c->io, buf, dlen, st) != 0) {
            free(buf);
            return -1;
        }
    }

    /* §15: trace the response + accumulate per-opcode RTT. Inert unless armed. */
    if (c->diag.wire_trace) {
        xrdc_trace_frame(c, '<', sid, stat, 0, dlen, buf, dlen);
    }
    if (c->diag.cap != NULL) {   /* §15.1: record the full response wire bytes */
        xrdc_capture_frame(c->diag.cap, '<', sid, stat, 0, hdr,
                           XRD_RESPONSE_HDR_LEN, buf, dlen);
    }
    if (c->diag.timing && c->diag.t_send_ns != 0) {
        uint64_t dt  = xrdc_mono_ns() - c->diag.t_send_ns;
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

    switch (stat) {
    case kXR_ok:
    case kXR_oksofar:
    case kXR_authmore:   /* auth driver consumes the challenge body */
    case kXR_redirect:   /* xrdc_roundtrip follows it */
    case kXR_wait:       /* xrdc_roundtrip honors the backoff */
        if (status != NULL) { *status = stat; }
        if (body != NULL) { *body = buf; } else { free(buf); }
        if (blen != NULL) { *blen = dlen; }
        return 0;

    case kXR_waitresp: {
        /* Server acknowledged the request but the real reply comes later as an
         * unsolicited kXR_attn(asynresp). Transparent to every caller. */
        unsigned secs = (dlen >= 4) ? xrd_get_u32_be(buf) : 0;
        free(buf);
        return recv_after_waitresp(c, want_sid, secs, status, body, blen, st);
    }

    case kXR_error: {
        int errnum = (dlen >= 4) ? (int) xrd_get_u32_be(buf) : 0;
        int mlen   = (dlen > 4) ? (int) (dlen - 4) : 0;
        /* errmsg is wire data with no guaranteed NUL — bound %s with %.*s. */
        xrdc_status_set(st, errnum, 0, "%.*s (%s)", mlen,
                        (const char *) (buf + 4), xrdc_kxr_name(errnum));
        free(buf);
        return -1;
    }

    default:
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "unexpected response status %u", stat);
        free(buf);
        return -1;
    }
}

/* ---- redirect/wait-following request wrapper (M5) ---- */

/* ServerRedirectBody = port[4 BE] + host[NUL] (host already IPv6-bracketed).
 * The host field may carry a "?<opaque>" tail: a redirector (notably EOS/cmsd)
 * appends the open CAPABILITY (cap.sym/cap.msg) that the open MUST replay to the
 * chosen data server, else the DS cannot authorize it and bounces the open back
 * (an endless manager↔DS redirect loop). We split it off so `host` is connectable
 * and `opaque` can be re-attached to the open's path. */
static int
parse_redirect(const uint8_t *body, uint32_t blen, char *host, size_t hostsz,
               int *port, char *opaque, size_t opaquesz)
{
    const char *field, *qmark;
    uint32_t    flen, hlen;
    if (blen < 5) {
        return -1;
    }
    *port = (int) xrd_get_u32_be(body);

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
    if (hlen >= hostsz) {
        hlen = (uint32_t) hostsz - 1;
    }
    memcpy(host, field, hlen);
    host[hlen] = '\0';

    opaque[0] = '\0';
    if (qmark != NULL) {
        const char *o   = qmark + 1;
        uint32_t    olen = (uint32_t) (field + flen - o);
        while (olen > 0 && (*o == '&' || *o == '?')) {   /* EOS sends "?&cap.sym=" */
            o++;
            olen--;
        }
        if (olen >= opaquesz) {
            olen = (uint32_t) opaquesz - 1;
        }
        memcpy(opaque, o, olen);
        opaque[olen] = '\0';
    }
    return 0;
}

static int
tried_seen(xrdc_conn *c, const char *hostport)
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
 * WHY:  official-parity hard-fail (`xrdc_reconnect != 0 → give up`) turns one
 *       dead replica into a failed op even when other replicas are healthy, and
 *       surfaces a confusing connect error against a host the user never typed.
 * HOW:  the dead target is already recorded in tried[] by the caller, so the
 *       loop guard prevents the manager bouncing us straight back to it. Returns
 *       0 if a session is up (target or manager), -1 with a clear combined error.
 *       NEVER calls xrdc_close between attempts — xrdc_reconnect/bringup own their
 *       own teardown-on-failure, and a close on a torn-down socket would misfire.
 */
static int
follow_redirect(xrdc_conn *c, const char *rhost, int rport, xrdc_status *st)
{
    char tgt_msg[XRDC_MSG_MAX];

    if (xrdc_reconnect(c, rhost, rport, st) == 0) {
        return 0;
    }
    snprintf(tgt_msg, sizeof(tgt_msg), "%s", st->msg);   /* keep target error */

    if (c->home_host[0] == '\0'
        || (strcmp(rhost, c->home_host) == 0 && rport == c->home_port)) {
        xrdc_status_set(st, XRDC_ESOCK, 0,
                        "redirect target %s:%d unreachable: %s",
                        rhost, rport, tgt_msg);
        return -1;
    }
    if (xrdc_reconnect(c, c->home_host, c->home_port, st) == 0) {
        return 0;   /* manager re-selects; the dead target is in tried[] */
    }
    xrdc_status_set(st, XRDC_ESOCK, 0,
                    "redirect target %s:%d unreachable (%s); manager %s:%d "
                    "fallback also failed", rhost, rport, tgt_msg,
                    c->home_host, c->home_port);
    return -1;
}

/* Rebuild a kXR_open payload as "<original-path><sep><opaque>" so a redirected
 * open replays the redirector's capability to the data server. Always built from
 * the ORIGINAL path (never an earlier rebuild) so successive redirects swap rather
 * than accumulate opaques. *rebuilt is caller-owned; the wrapper frees it once.
 * On success points cur_pl and cur_len at the new buffer. 0 / -1 (st set). */
static int
open_payload_with_opaque(const void *orig_pl, uint32_t orig_len,
                         const char *opaque, char **rebuilt,
                         const void **cur_pl, uint32_t *cur_len, xrdc_status *st)
{
    const char *p   = (const char *) orig_pl;
    int         hasq = (orig_len > 0 && memchr(p, '?', orig_len) != NULL);
    size_t      ol  = strlen(opaque);
    size_t      need = (size_t) orig_len + 1 + ol + 1;
    char       *nb  = (char *) malloc(need);
    if (nb == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (redirect opaque)");
        return -1;
    }
    memcpy(nb, p, orig_len);
    nb[orig_len] = hasq ? '&' : '?';
    memcpy(nb + orig_len + 1, opaque, ol + 1);   /* includes the NUL */
    free(*rebuilt);
    *rebuilt = nb;
    *cur_pl  = nb;
    *cur_len = (uint32_t) (orig_len + 1 + ol);
    return 0;
}

/* The redirect/wait-following request loop. `rebuilt` (caller-owned, freed once by
 * the wrapper) holds any payload we had to rewrite to carry a redirect's open
 * capability — so the in-loop early returns need no per-exit cleanup. */
static int
roundtrip_loop(xrdc_conn *c, void *hdr24, const void *payload, uint32_t plen,
               uint16_t *status, uint8_t **body, uint32_t *blen,
               char **rebuilt, xrdc_status *st)
{
    int            waits  = 0;
    const uint16_t reqid  = xrd_get_u16_be((uint8_t *) hdr24 + 2);
    const void    *cur_pl = payload;    /* payload actually sent (may be rebuilt) */
    uint32_t       cur_len = plen;

    /* Each top-level op gets a fresh redirect budget + loop-guard. */
    c->redir_depth = 0;
    c->tried_n = 0;

    for (;;) {
        uint16_t sid, stt;
        uint8_t *bd = NULL;
        uint32_t bl = 0;

        if (xrdc_send(c, hdr24, cur_pl, cur_len, &sid, st) != 0) {
            return -1;
        }
        if (xrdc_recv(c, sid, &stt, &bd, &bl, st) != 0) {
            return -1;   /* kXR_error / transport → st already set */
        }

        if (stt == kXR_redirect) {
            char rhost[256], hp[XRDC_HOSTPORT_MAX], opaque[4096];
            int  rport = 0;
            if (parse_redirect(bd, bl, rhost, sizeof(rhost), &rport,
                               opaque, sizeof(opaque)) != 0) {
                free(bd);
                xrdc_status_set(st, XRDC_EPROTO, 0, "malformed redirect");
                return -1;
            }
            free(bd);
            if (c->diag.redir_trace) {   /* §15.4: surface each hop on stderr */
                fprintf(stderr, "redirect[%d] -> %s:%d%s\n", c->redir_depth + 1,
                        rhost, rport, opaque[0] ? " (+opaque)" : "");
            }
            if (++c->redir_depth > XRDC_REDIR_MAX) {
                if (c->diag.redir_trace) {
                    fprintf(stderr, "redirect: budget exhausted (>%d hops)\n",
                            XRDC_REDIR_MAX);
                }
                xrdc_status_set(st, XRDC_EREDIRECT, 0,
                                "too many redirects (>%d)", XRDC_REDIR_MAX);
                return -1;
            }
            xrootd_format_host_port(rhost, (uint16_t) rport, hp, sizeof(hp));
            /* Immediate self-redirect: the server we are talking to right now
             * bounced us straight back to itself.  That is an unambiguous loop;
             * fail fast here rather than reconnecting to it (which would chase
             * the loop until the connect timeout — up to 15s per hop). */
            if (rport == c->port && strcmp(rhost, c->host) == 0) {
                if (c->diag.redir_trace) {
                    fprintf(stderr, "redirect: self-loop to %s\n", hp);
                }
                xrdc_status_set(st, XRDC_EREDIRECT, 0,
                                "redirect loop: server redirected to itself (%s)",
                                hp);
                return -1;
            }
            if (tried_seen(c, hp)) {
                if (c->diag.redir_trace) {
                    fprintf(stderr, "redirect: LOOP to already-tried %s\n", hp);
                }
                xrdc_status_set(st, XRDC_EREDIRECT, 0,
                                "redirect loop to already-tried %s", hp);
                return -1;
            }
            if (c->tried_n < XRDC_REDIR_MAX) {
                snprintf(c->tried[c->tried_n++], sizeof(c->tried[0]), "%s", hp);
            }
            /* EOS/cmsd redirects an open to a data server with a one-shot capability
             * opaque; carry it onto the open's path so the DS authorizes the open
             * (else it bounces back → the endless loop the guard above trips on). */
            if (reqid == kXR_open && opaque[0] != '\0'
                && open_payload_with_opaque(payload, plen, opaque, rebuilt,
                                            &cur_pl, &cur_len, st) != 0) {
                return -1;
            }
            if (follow_redirect(c, rhost, rport, st) != 0) {
                return -1;   /* dead target AND manager fallback failed */
            }
            continue;   /* replay against the redirect target (or manager) */
        }

        if (stt == kXR_wait) {
            unsigned secs = xrd_wait_secs_parse(bd, bl, 1, 30);  /* clamp [1,30] */
            unsigned jms;
            free(bd);
            if (++waits > XRDC_REDIR_MAX) {
                xrdc_status_set(st, XRDC_EPROTO, 0, "server kept asking to wait");
                return -1;
            }
            sleep(secs);
            /* Phase 40 (a): ADDITIVE sub-second jitter so a fleet handed the same
             * advised wait doesn't resend in lockstep — never shorten the
             * server's requested delay. */
            jms = xrdc_jitter_ms(secs >= 1 ? 1000u : 250u);
            if (jms > 0) {
                struct timespec ts;
                ts.tv_sec  = 0;
                ts.tv_nsec = (long) jms * 1000000L;
                (void) nanosleep(&ts, NULL);
            }
            continue;   /* resend the same request to the same server */
        }

        /* kXR_ok / kXR_oksofar */
        if (status != NULL) { *status = stt; }
        *body = bd;
        *blen = bl;
        return 0;
    }
}

int
xrdc_roundtrip(xrdc_conn *c, void *hdr24, const void *payload, uint32_t plen,
               uint16_t *status, uint8_t **body, uint32_t *blen, xrdc_status *st)
{
    char *rebuilt = NULL;   /* opaque-carrying open payload, if a redirect needs it */
    int   rc = roundtrip_loop(c, hdr24, payload, plen, status, body, blen,
                              &rebuilt, st);
    free(rebuilt);
    return rc;
}
