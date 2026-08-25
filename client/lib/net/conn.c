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
#include "conn_internal.h"                          /* handshake + login (conn_bootstrap.c) */
#include "core/compat/host_format.h"   /* IPv6-bracketing host:port (libxrdproto) */
#include "core/compat/crypto.h"        /* brix_crypto_init (SHA/HMAC arming)     */

#include <pthread.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
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

/*
 * Resolve the X.509 proxy PEM to present as the CLIENT certificate on a davs/
 * https mutual-TLS handshake — the HTTP-client analogue of the root:// GSI
 * resolver (sec_gsi.c). Same precedence:
 *   1. $X509_USER_PROXY  (xrdcp exports --proxy into it)
 *   2. /tmp/x509up_u<euid>  (the grid default proxy location)
 * A proxy PEM carries the proxy cert, its private key, and the EEC chain in one
 * file, so the single returned path feeds both the cert-chain and the key.
 * Writes into `buf` and returns it ONLY when the file exists and is readable;
 * returns NULL otherwise (no proxy → the client presents no cert, and TLS only
 * sends one when the server actually requests client auth, so this is safe for
 * plain https endpoints). Never allocates.
 */
const char *
brix_web_proxy_pem(char *buf, size_t buflen)
{
    const char *env;

    if (buf == NULL || buflen == 0) {
        return NULL;
    }

    env = getenv("X509_USER_PROXY");
    if (env != NULL && env[0] != '\0') {
        snprintf(buf, buflen, "%s", env);
    } else {
        snprintf(buf, buflen, "/tmp/x509up_u%u", (unsigned) geteuid());
    }

    if (access(buf, R_OK) != 0) {
        return NULL;
    }
    return buf;
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
    c->sec_odata = 0;
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
    if (brix_conn_handshake(c, 1, c->want_tls, st) != 0) {
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

    if (want_login && brix_conn_login(c, &c->opts, st) != 0) {
        brix_close(c);
        return -1;
    }
    c->diag.phase_ns[3] = brix_mono_ns();   /* login + auth done */

    /* Session is up: switch from the short bring-up cap to the steady-state I/O
     * timeout so a legitimately long read/write is not cut off. Also arm the
     * opt-in slow-drip completion deadline (0 = disabled) now that bulk reads
     * begin — a dribbling peer cannot hold a steady-state read open past it. */
    c->io.timeout_ms        = brix_tmo_io_ms();
    c->io.stall_deadline_ms = brix_tmo_stall_ms();
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
    sec->io.timeout_ms        = primary->io.timeout_ms;
    sec->io.stall_deadline_ms = primary->io.stall_deadline_ms;
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

/*
 * brix_connect_setup — the setup both connect entry points share: init crypto,
 * zero the conn, apply opts, validate the scheme, and seed the endpoint fields.
 * Returns 0, or -1 with *st set (unsupported scheme). want_tls and the bring-up
 * path are left to the caller (they differ between login and no-login connect).
 */
static int
brix_connect_setup(brix_conn *c, const brix_url *u, const brix_opts *o,
                   brix_status *st)
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
    return 0;
}

int
brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o, brix_status *st)
{
    if (brix_connect_setup(c, u, o, st) != 0) {
        return -1;
    }
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
    if (brix_connect_setup(c, u, o, st) != 0) {
        return -1;
    }
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
    OPENSSL_cleanse(c->gsi_deleg_key, sizeof(c->gsi_deleg_key));
    c->gsi_deleg_keylen = 0;
    c->gsi_deleg_ready = 0;
    c->signing_active = 0;
}

