/*
 * frame_roundtrip.c - resilient roundtrip: redirect/wait following over brix_send/brix_recv.
 * Phase-38 split of frame.c; behavior-identical.
 */
#include "brix.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "protocols/root/protocol/frame_hdr.h"
#include "core/compat/host_format.h"

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
