/*
 * conn.c — connection / session bring-up and teardown.
 *
 * WHAT: connect → (20B handshake + kXR_protocol, pipelined) → kXR_login (anon) →
 *       ready; and a best-effort kXR_endsess + close on teardown.
 * WHY:  Everything else (stat/ls/get/put) needs a logged-in session; this is the
 *       one place that drives the handshake state machine.
 * HOW:  We send the 20-byte ClientInitHandShake and the 24-byte protocol request
 *       as one 44-byte segment (as modern clients do). The server replies with a
 *       handshake frame (streamid {0,0}) AND a protocol frame (streamid = our
 *       protocol request's id); we tolerate either ordering / a combined reply by
 *       keying on the streamid. Anonymous login sends no credential payload; if
 *       the server demands a security protocol we fail cleanly (auth is M4).
 *
 * wire: XProtocol.hh ClientInitHandShake — {0,0,0,htonl(4),htonl(2012=ROOTD_PQ)}.
 * wire: XProtocol.hh ServerProtocolBody — pval[4] flags[4]; flags carry server caps.
 * wire: XProtocol.hh ServerLoginBody — sessid[16] [+ "&P=..." security list].
 */
#include "brix.h"
#include "protocols/root/protocol/frame_hdr.h"      /* shared resp-hdr codec (libxrdproto) */
#include "protocols/root/protocol/bootstrap_pack.h" /* shared handshake/protocol/login packers */
#include "core/compat/host_format.h"   /* IPv6-bracketing host:port (libxrdproto) */
#include "core/compat/crypto.h"        /* brix_crypto_init (SHA/HMAC arming)     */

#include <pthread.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <openssl/crypto.h>   /* OPENSSL_cleanse */

#define XRDC_DEFAULT_TIMEOUT_MS  30000

/* Well-known IGTF/grid CA trust directory shipped by fetch-crl / ca-policy RPMs.
 * Grid server certs (dCache, EOS, ...) chain to these CAs, which are NOT in the
 * OpenSSL system bundle, so falling back to it gives "unable to get local issuer
 * certificate". */
#define XRDC_GRID_CA_DIR  "/etc/grid-security/certificates"

/*
 * Resolve the CA trust directory for TLS peer verification using the same search
 * order as the stock xrootd/globus tooling, so the client trusts grid CAs out of
 * the box:
 *   1. explicit caller value (e.g. --ca-dir)   2. $X509_CERT_DIR
 *   3. /etc/grid-security/certificates (if present and readable)
 *   4. NULL  ⇒ caller falls back to OpenSSL system defaults
 * Returns a borrowed string (env/literal/argument); never allocates.
 */
const char *
brix_resolve_ca_dir(const char *opt_ca_dir)
{
    const char *env;

    if (opt_ca_dir != NULL && opt_ca_dir[0] != '\0') {
        return opt_ca_dir;
    }

    env = getenv("X509_CERT_DIR");
    if (env != NULL && env[0] != '\0') {
        return env;
    }

    if (access(XRDC_GRID_CA_DIR, R_OK | X_OK) == 0) {
        return XRDC_GRID_CA_DIR;
    }

    return NULL;
}

static void
fill_username(char out[9])
{
    /* The login username is the OS identity advertised for monitoring/default
     * mapping (real authz comes from the chosen sec protocol). Prefer $LOGNAME/
     * $USER — set in every interactive/login shell — so the common path skips the
     * getpwuid() NSS lookup entirely (it lazy-loads libnss_* on first call, a
     * measurable per-process cost the async manager would otherwise pay once per
     * parallel stream). Fall back to getpwuid() when the environment is unset. */
    const char    *name = getenv("LOGNAME");
    struct passwd *pw;
    size_t         n;

    if (name == NULL || name[0] == '\0') { name = getenv("USER"); }
    if (name == NULL || name[0] == '\0') {
        pw = getpwuid(geteuid());
        name = (pw != NULL && pw->pw_name != NULL) ? pw->pw_name : "nobody";
    }
    n = strlen(name);

    if (n > 8) { n = 8; }       /* the wire field is 8 bytes; truncate */
    memcpy(out, name, n);
    out[n] = '\0';              /* NUL-terminated for xrd_pack_login_request */
}

/* Read one response frame raw (header + body), bypassing streamid checks; used
 * for the handshake exchange where the first reply carries streamid {0,0}. */
static int
recv_raw(brix_conn *c, uint16_t *sid, uint16_t *status,
         uint8_t *body, uint32_t bodycap, uint32_t *blen, brix_status *st)
{
    uint8_t  hdr[XRD_RESPONSE_HDR_LEN];
    uint32_t dlen;

    if (brix_read_full(&c->io, hdr, sizeof(hdr), st) != 0) {
        return -1;
    }
    xrd_resp_hdr_unpack(hdr, sid, status, &dlen);   /* unaligned-safe */

    if (dlen > bodycap) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "handshake body too large (%u > %u)", dlen, bodycap);
        return -1;
    }
    if (dlen > 0 && brix_read_full(&c->io, body, dlen, st) != 0) {
        return -1;
    }
    *blen = dlen;
    if (c->diag.wire_trace) {   /* §15: trace handshake/protocol replies too */
        brix_trace_frame(c, '<', *sid, *status, 0, dlen, body, dlen);
    }
    return 0;
}

static int
do_handshake(brix_conn *c, uint16_t proto_sid, int want_tls, brix_status *st)
{
    uint8_t              seg[XRD_HANDSHAKE_LEN + XRD_REQUEST_HDR_LEN];
    ClientInitHandShake  hs;
    ClientProtocolRequest pr;
    uint16_t             sid, status;
    uint8_t              body[256];
    uint32_t             blen;
    int                  saw_proto = 0;
    int                  rounds;

    xrd_pack_handshake(&hs);

    /* The client owns its protocol streamid; ask for the security-requirements
     * trailer (to learn the signing level) and advertise TLS capability,
     * requiring TLS for roots:// / --tls. */
    {
        const uint8_t sid[2] = { (uint8_t) (proto_sid >> 8),
                                 (uint8_t) (proto_sid & 0xff) };
        uint8_t flags = (uint8_t) (kXR_secreqs | kXR_ableTLS |
                                   (want_tls ? kXR_wantTLS : 0));
        xrd_pack_protocol_request(&pr, sid, flags);
    }

    memcpy(seg, &hs, XRD_HANDSHAKE_LEN);
    memcpy(seg + XRD_HANDSHAKE_LEN, &pr, XRD_REQUEST_HDR_LEN);

    if (brix_write_full(&c->io, seg, sizeof(seg), st) != 0) {
        return -1;
    }
    if (c->diag.wire_trace) {   /* §15: the 20B init has no streamid/requestid */
        fprintf(stderr, "> handshake-init (20B) + kXR_protocol sid=%u\n", proto_sid);
    }

    /* Expect up to two frames: a handshake reply (streamid {0,0}) and the
     * protocol reply (streamid == proto_sid). Some servers may send only the
     * protocol reply; key on the streamid rather than assume an ordering. */
    for (rounds = 0; rounds < 2 && !saw_proto; rounds++) {
        if (recv_raw(c, &sid, &status, body, sizeof(body), &blen, st) != 0) {
            return -1;
        }
        if (status != kXR_ok) {
            /* The server completed the framing and EXPLICITLY rejected the
             * handshake (e.g. kXR_error because we asked for TLS on a non-TLS
             * port).  That is a permanent decision: classify it by the server's
             * own status code (not the retryable XRDC_EPROTO framing-desync
             * code) so the resilient loop fails fast instead of re-handshaking
             * the same rejection until its stall window expires. */
            brix_status_set(st, (int) status, 0,
                            "handshake: server status %u", status);
            return -1;
        }
        if (sid == proto_sid) {
            if (blen < sizeof(ServerProtocolBody)) {
                brix_status_set(st, XRDC_EPROTO, 0,
                                "protocol reply too short (%u bytes)", blen);
                return -1;
            }
            /* ServerProtocolBody = pval[4] flags[4]; capabilities in flags. */
            c->server_flags = xrd_get_u32_be(body + 4);   /* unaligned-safe */
            /* Optional SecurityInfo trailer (present because we set kXR_secreqs):
             * 4-byte header {0, hasSec, sec_count, 0}, sec_count*8 protocol
             * entries, then a 6-byte 'S' section whose byte[4] is the signing
             * security level. Defensive: default 0 (no signing). */
            c->sec_level = 0;
            if (blen >= 12) {
                uint8_t sec_count = body[10];
                size_t  sp = 12u + (size_t) sec_count * 8u;
                if (sp + 6u <= blen && body[sp] == 'S') {
                    c->sec_level = body[sp + 4];
                }
            }
            saw_proto = 1;
        }
        /* else: handshake reply (streamid {0,0}); keep reading for the protocol. */
    }

    if (!saw_proto) {
        brix_status_set(st, XRDC_EPROTO, 0, "no protocol reply from server");
        return -1;
    }
    return 0;
}

static int
do_login(brix_conn *c, const brix_opts *o, brix_status *st)
{
    ClientLoginRequest req;
    uint16_t           sid, status;
    uint8_t           *body = NULL;
    uint32_t           blen = 0;

    /* streamid {0,0}: brix_send stamps the real streamid (and dlen) after
     * packing. The username is the OS identity; advertise async-response
     * capability. dlen=0 → anonymous (no credential/CGI payload). */
    {
        static const uint8_t sid0[2] = { 0, 0 };
        char uname[9];
        fill_username(uname);
        xrd_pack_login_request(&req, sid0, (int32_t) getpid(), uname,
                               (uint8_t) (kXR_ver005 | kXR_asyncap));
    }

    {
        brix_resp_out out = { &status, &body, &blen };
        if (brix_send(c, &req, NULL, &sid, st) != 0) {
            return -1;
        }
        if (brix_recv(c, sid, &out, st) != 0) {
            return -1;
        }
    }
    if (status != kXR_ok) {
        brix_status_set(st, XRDC_EPROTO, 0, "login: server status %u", status);
        free(body);
        return -1;
    }
    if (blen < BRIX_SESSION_ID_LEN) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "login reply too short (%u bytes)", blen);
        free(body);
        return -1;
    }
    memcpy(c->sessid, body, BRIX_SESSION_ID_LEN);

    /* Anything past the 16-byte sessid is a "&P=<proto>,..." security list:
     * the server demands authentication. Hand off to the auth driver. */
    if (blen > BRIX_SESSION_ID_LEN) {
        char     sec[256];
        uint32_t n = blen - BRIX_SESSION_ID_LEN;
        if (n >= sizeof(sec)) { n = sizeof(sec) - 1; }
        memcpy(sec, body + BRIX_SESSION_ID_LEN, n);
        sec[n] = '\0';
        free(body);
        snprintf(c->sec_list, sizeof(c->sec_list), "%s", sec);  /* §15 explain */
        return brix_authenticate(c, sec, o, st);
    }

    free(body);
    return 0;
}

/* Establish the session on the already-set c->host/c->port using c->want_tls +
 * c->opts: connect → handshake → [TLS] → login → auth. Resets per-connection state
 * so it is safe to call again from brix_reconnect after a redirect. */
static int
brix_bringup_ex(brix_conn *c, int want_login, brix_status *st)
{
    c->io.fd = -1;
    c->io.ssl = NULL;
    c->ssl_ctx = NULL;
    c->next_sid = 1;
    c->server_flags = 0;
    c->sec_level = 0;
    c->signing_active = 0;
    c->sig_seqno = 0;

    /* §15: arm trace/timing from opts (the per-opcode RTT table on c persists
     * across a redirect's reconnect, so the final summary aggregates all hops). */
    c->diag.wire_trace  = c->opts.wire_trace;
    c->diag.timing      = c->opts.timing;
    c->diag.redir_trace = c->opts.redir_trace;

    /* Bound the whole bring-up (connect + handshake + TLS + login) with the SHORT
     * connect timeout, not the long steady-state I/O timeout: a firewall that
     * completes the TCP handshake then black-holes the protocol bytes must fail
     * promptly so the reconnect machinery can ride over it, rather than hanging
     * the caller. The steady-state timeout is restored once the session is up. */
    c->io.timeout_ms = brix_tmo_connect_ms();

    c->diag.phase_ns[0] = brix_mono_ns();   /* §15.3: connect-phase breakdown */
    c->io.fd = brix_tcp_connect(c->host, c->port, c->io.timeout_ms, st);
    if (c->io.fd < 0) {
        return -1;
    }
    c->diag.phase_ns[1] = brix_mono_ns();   /* tcp connected */

    /* Reserve streamid 1 for the protocol request; subsequent ops start at 2. */
    c->next_sid = 2;
    if (do_handshake(c, 1, c->want_tls, st) != 0) {
        brix_close(c);
        return -1;
    }

    /* TLS decision — never silently downgrade. */
    {
        int have_tls = (c->server_flags & kXR_haveTLS) != 0;
        int goto_tls = (c->server_flags & kXR_gotoTLS) != 0;
        if (goto_tls || (c->want_tls && have_tls)) {
            const char *ca = brix_resolve_ca_dir(c->opts.ca_dir);
            if (brix_tls_upgrade(c, !c->opts.insecure_tls, c->opts.verify_host, ca, st) != 0) {
                brix_close(c);
                return -1;
            }
        } else if (c->want_tls && !have_tls) {
            if (c->tls_strict || !c->opts.notlsok) {
                brix_status_set(st, XRDC_EAUTH, 0,
                                "server offers no TLS; refusing cleartext "
                                "(use --notlsok with root:// to override)");
                brix_close(c);
                return -1;
            }
            /* root:// + --notlsok: proceed cleartext. */
        }
    }
    c->diag.phase_ns[2] = brix_mono_ns();   /* tls negotiated (==tcp if cleartext) */

    if (want_login && do_login(c, &c->opts, st) != 0) {
        brix_close(c);
        return -1;
    }
    c->diag.phase_ns[3] = brix_mono_ns();   /* login + auth done */

    /* Session is up: switch from the short bring-up cap to the steady-state I/O
     * timeout so a legitimately long read/write is not cut off. */
    c->io.timeout_ms = brix_tmo_io_ms();
    return 0;
}

/* The common case: full bring-up including kXR_login + auth. */
static int
brix_bringup(brix_conn *c, brix_status *st)
{
    return brix_bringup_ex(c, 1, st);
}

int
brix_bind(brix_conn *sec, const brix_conn *primary, brix_status *st)
{
    ClientBindRequest req;
    uint16_t          sid, status;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;

    /* A secondary stream re-runs handshake + kXR_protocol [+ TLS] against the
     * SAME target but SKIPS kXR_login; the server inherits identity from the
     * primary's session via kXR_bind{sessid}. (src/protocols/root/session/bind.c) */
    memset(sec, 0, sizeof(*sec));
    sec->io.timeout_ms = primary->io.timeout_ms;
    sec->opts          = primary->opts;
    sec->want_tls      = primary->want_tls;
    sec->tls_strict    = primary->tls_strict;
    snprintf(sec->host, sizeof(sec->host), "%s", primary->host);
    sec->port = primary->port;

    if (brix_bringup_ex(sec, 0, st) != 0) {
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_bind);
    {
        xrdw_sessid_req_t b;
        memcpy(b.sessid, primary->sessid, BRIX_SESSION_ID_LEN);
        xrdw_sessid_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    {
        brix_resp_out out = { &status, &body, &blen };
        if (brix_send(sec, &req, NULL, &sid, st) != 0
            || brix_recv(sec, sid, &out, st) != 0) {
            /* Quiet teardown: a bound stream has no session of its own to end. */
            brix_tls_free(sec);
            if (sec->io.fd >= 0) { close(sec->io.fd); sec->io.fd = -1; }
            return -1;
        }
    }
    free(body);   /* reply body = 1-byte pathid (server bookkeeping) */
    return 0;
}

/* phase-49: arm the libxrdproto crypto (SHA/HMAC) exactly once, lazily, so every
 * connecting tool gets working GSI/token digests without an explicit
 * brix_crypto_init() call — removing the easy-to-forget "GSI silently breaks if
 * you forgot to init crypto" footgun.  Idempotent + thread-safe via pthread_once;
 * any remaining explicit caller is harmless. */
static void
brix_crypto_init_void(void)
{
    (void) brix_crypto_init();   /* int-returning; pthread_once needs void(void) */
}

static void
brix_crypto_once(void)
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, brix_crypto_init_void);
}

int
brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o, brix_status *st)
{
    brix_crypto_once();
    memset(c, 0, sizeof(*c));
    c->io.timeout_ms = brix_tmo_io_ms();   /* steady-state; bring-up uses the short cap */

    if (o != NULL) {
        c->opts = *o;
    } else {
        c->opts.verify_host = 1;
    }

    if (u->scheme != XRDC_SCHEME_ROOT && u->scheme != XRDC_SCHEME_ROOTS) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "native client speaks root:// / roots:// only (scheme %d)",
                        (int) u->scheme);
        return -1;
    }

    snprintf(c->host, sizeof(c->host), "%s", u->host);
    c->port = u->port;
    /* Phase 40 (a): remember the ORIGINAL endpoint (the manager) so a dead
     * redirect target can fall back here for a fresh server selection. Set once
     * at connect; brix_reconnect deliberately does NOT touch it. */
    snprintf(c->home_host, sizeof(c->home_host), "%s", u->host);
    c->home_port = u->port;
    /* WS-3: carry the single-slash flag forward so per-op error sites can fire
     * the double-slash hint without re-parsing the original URL. */
    c->single_slash_path = u->single_slash_path;
    c->tls_strict = (u->scheme == XRDC_SCHEME_ROOTS);
    c->want_tls = c->tls_strict || c->opts.want_tls;

    /* §15.1: open the capture sink ONCE (here, not in bringup — so a redirect's
     * reconnect appends rather than truncates). Frames are recorded by frame.c. */
    if (c->opts.capture != NULL && c->opts.capture[0] != '\0') {
        char ep[320];
        c->diag.cap = brix_capture_open(c->opts.capture);
        brix_format_host_port(c->host, (uint16_t) c->port, ep, sizeof(ep));
        brix_capture_meta(c->diag.cap, "endpoint", ep);
    }

    {
        int rc = brix_bringup(c, st);
        if (rc == 0 && c->diag.cap != NULL) {   /* snapshot negotiated session */
            char buf[64], sx[2 * BRIX_SESSION_ID_LEN + 1];
            int  i;
            snprintf(buf, sizeof(buf), "0x%x", (unsigned) c->server_flags);
            brix_capture_meta(c->diag.cap, "caps", buf);
            brix_capture_meta(c->diag.cap, "auth",
                              c->diag.chosen_auth ? c->diag.chosen_auth : "anon");
            brix_capture_meta(c->diag.cap, "seclist",
                              c->sec_list[0] ? c->sec_list : "(none)");
            for (i = 0; i < BRIX_SESSION_ID_LEN; i++) {
                snprintf(sx + i * 2, 3, "%02x", c->sessid[i]);
            }
            brix_capture_meta(c->diag.cap, "sessid", sx);
        }
        return rc;
    }
}

int
brix_connect_no_login(brix_conn *c, const brix_url *u, const brix_opts *o,
                      brix_status *st)
{
    brix_crypto_once();
    memset(c, 0, sizeof(*c));
    c->io.timeout_ms = brix_tmo_io_ms();   /* steady-state; bring-up uses the short cap */
    if (o != NULL) { c->opts = *o; } else { c->opts.verify_host = 1; }

    if (u->scheme != XRDC_SCHEME_ROOT && u->scheme != XRDC_SCHEME_ROOTS) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "native client speaks root:// / roots:// only");
        return -1;
    }
    snprintf(c->host, sizeof(c->host), "%s", u->host);
    c->port = u->port;
    snprintf(c->home_host, sizeof(c->home_host), "%s", u->host);
    c->home_port = u->port;
    c->single_slash_path = u->single_slash_path;   /* WS-3: propagate for hint */
    c->tls_strict = (u->scheme == XRDC_SCHEME_ROOTS);
    /* TLS per the scheme: roots:// negotiates TLS (cert presented); a plain root://
     * server that does not mandate TLS stays cleartext (then there is simply no cert,
     * rather than a rejected wantTLS handshake). No kXR_login: cert inspection needs
     * no identity, so this works even where anon login would be rejected. A server
     * that sends kXR_gotoTLS still upgrades regardless. */
    c->want_tls     = c->tls_strict;
    c->opts.notlsok = 1;
    return brix_bringup_ex(c, 0 /*want_login*/, st);
}

int
brix_reconnect(brix_conn *c, const char *host, int port, brix_status *st)
{
    /* Abandon the current transport (no endsess — we are leaving this server) but
     * keep opts/want_tls/redirect-state, then re-establish against the new target. */
    brix_tls_free(c);
    if (c->io.fd >= 0) {
        close(c->io.fd);
        c->io.fd = -1;
    }
    snprintf(c->host, sizeof(c->host), "%s", host);
    c->port = port;
    return brix_bringup(c, st);
}

/* 1 if the session id is all-zero — i.e. no session was ever established (login
 * never completed), so there is nothing to gracefully end. */
static int
sessid_is_zero(const uint8_t *s)
{
    int i;
    for (i = 0; i < BRIX_SESSION_ID_LEN; i++) {
        if (s[i] != 0) {
            return 0;
        }
    }
    return 1;
}

void
brix_close(brix_conn *c)
{
    if (c != NULL && c->diag.timing) {   /* §15: one summary per session at exit */
        brix_timing_report(c);
    }
    if (c != NULL && c->diag.cap != NULL) {   /* §15.1: flush + close the capture */
        brix_capture_close(c->diag.cap);
        c->diag.cap = NULL;                   /* idempotent: safe on double close */
    }
    if (c == NULL || c->io.fd < 0) {
        return;
    }

    /* Best-effort graceful end-of-session: kXR_endsess{sessid[16]}, FIRE-AND-
     * FORGET. We deliberately do NOT wait for the reply: against a black-holing
     * peer (a misbehaving inline firewall) reading a reply that never comes would
     * stall teardown for a full timeout, and the server tears the session down on
     * socket close regardless. Skip it entirely when no session was established
     * (sessid still zero — e.g. a connection that failed during handshake), and
     * cap the send so even a wedged socket cannot block the close. */
    if (!sessid_is_zero(c->sessid)) {
        uint8_t     req[XRD_REQUEST_HDR_LEN];
        uint16_t    sid;
        brix_status throwaway;

        if (c->io.timeout_ms <= 0 || c->io.timeout_ms > 2000) {
            c->io.timeout_ms = 2000;   /* teardown send must not hang */
        }
        memset(req, 0, sizeof(req));
        req[2] = (uint8_t) (kXR_endsess >> 8);
        req[3] = (uint8_t) (kXR_endsess & 0xff);
        {
            xrdw_sessid_req_t b;   /* body[16] = sessid (shared codec) */
            memcpy(b.sessid, c->sessid, BRIX_SESSION_ID_LEN);
            xrdw_sessid_req_pack(&b, req + 4);
        }
        brix_status_clear(&throwaway);
        (void) brix_send(c, req, NULL, &sid, &throwaway);
    }

    brix_tls_free(c);            /* SSL_shutdown/free + SSL_CTX_free (no-op if none) */
    close(c->io.fd);
    c->io.fd = -1;
    OPENSSL_cleanse(c->signing_key, sizeof(c->signing_key));
}

/*
 * brix_explain_conn — narrate an established session: endpoint, server roles,
 * negotiated caps, signing, the auth choice, the TLS state, and the session id.
 *
 * WHAT: a read-only report over the conn fields conn.c/auth.c already populated.
 * WHY:  both `xrdfs explain` and `xrddiag check` want the same human-readable
 *       picture of what the handshake actually negotiated — single-source it here.
 * HOW:  decode server_flags into roles/caps, defer the per-module auth detail to
 *       brix_auth_explain, and call brix_tls_info for the live cipher (flagging a
 *       gotoTLS→cleartext downgrade as a warning).
 */
void
brix_explain_conn(brix_conn *c, const brix_opts *opts, FILE *out)
{
    const char *ver = NULL, *cipher = NULL;
    unsigned    f;
    int         i;

    if (c == NULL || out == NULL) {
        return;
    }
    f = (unsigned) c->server_flags;

    fprintf(out, "Endpoint: %s:%d\n", c->host, c->port);

    fprintf(out, "Roles:    %s%s%s%s\n",
            (f & kXR_isServer)  ? "server "  : "",
            (f & kXR_isManager) ? "manager " : "",
            (f & kXR_attrProxy) ? "proxy "   : "",
            (f & (kXR_isServer | kXR_isManager)) ? "" : "(unknown)");
    fprintf(out, "Caps:     TLS=%s%s pgread/pgwrite=%s POSC=%s\n",
            (f & kXR_haveTLS) ? "available" : "no",
            (f & kXR_gotoTLS) ? " (gotoTLS: required)" : "",
            (f & kXR_suppgrw) ? "yes" : "no",
            (f & kXR_supposc) ? "yes" : "no");
    fprintf(out, "Signing:  sec_level=%d%s\n", c->sec_level,
            c->signing_active ? " (kXR_sigver active)" : "");

    fprintf(out, "Auth:\n");
    brix_auth_explain(c, opts != NULL ? opts : &c->opts, out);

    if (brix_tls_info(c, &ver, &cipher)) {
        fprintf(out, "TLS:      active — %s / %s\n",
                ver ? ver : "?", cipher ? cipher : "?");
    } else if (f & kXR_gotoTLS) {
        fprintf(out, "TLS:      INACTIVE — WARNING: server advertised gotoTLS but "
                "the session is cleartext (downgrade)\n");
    } else {
        fprintf(out, "TLS:      inactive (cleartext)\n");
    }

    /* §15.2: introspect whatever credentials are in the environment — shown even
     * when not the chosen protocol, so "you have a token but the server didn't
     * offer ztn" and "your proxy is expired" are both visible. Best-effort. */
    {
        char       *tok = brix_token_discover();
        const char *proxy = getenv("X509_USER_PROXY");
        if (tok != NULL || (proxy != NULL && proxy[0] != '\0')) {
            fprintf(out, "Credentials (in environment):\n");
            if (tok != NULL) {
                brix_token_explain(tok, out);
                free(tok);
            }
            if (proxy != NULL && proxy[0] != '\0') {
                brix_gsi_cert_explain(proxy, out);
            }
        }
    }

    fprintf(out, "Session:  ");
    for (i = 0; i < (int) sizeof(c->sessid); i++) {
        fprintf(out, "%02x", c->sessid[i]);
    }
    fprintf(out, "\n");
}
