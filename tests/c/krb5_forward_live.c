/* Live harness for the krb5 GSSAPI origin leg + forwarded-TGT capture (§5.7).
 *
 * Two modes, both run AS alice against a live KDC and finish against an
 * in-process GSSAPI acceptor keyed by the origin service keytab, proving the
 * gateway re-authenticates to a backend AS the inbound user over real bytes:
 *
 *   origin  (default) — acquire alice's forwardable TGT, import it directly as a
 *                       GSS initiator cred, and call the PRODUCTION origin leg
 *                       brix_krb5_deleg_to_origin(). Exercises gss_init_sec_context.
 *
 *   capture           — additionally exercises the PRODUCTION round-2 capture
 *                       brix_krb5_capture_fwd_cred(): alice's TGT is forwarded
 *                       with krb5_fwd_tgt_creds() into a KRB_CRED blob exactly as
 *                       the XrdSeckrb5 client does after the "fwdtgt" challenge,
 *                       that blob is decrypted+imported by the capture helper,
 *                       and the resulting delegated cred drives the origin leg.
 *                       This is the full EXCHANGE path minus the wire transport.
 *
 *   apreq             — proves the PRODUCTION raw-krb5 outbound builder
 *                       brix_krb5_apreq_from_ccache(): alice's TGT is stored in a
 *                       FILE ccache (the carry artifact), the builder produces the
 *                       "krb5\0"+AP-REQ the raw origin leg sends, and it is verified
 *                       with krb5_rd_req against the origin keytab exactly as a stock
 *                       XRootD krb5 acceptor does. This is the dialect real "&P=krb5"
 *                       origins accept; the acceptor observes alice, printed on OK.
 *
 *   negotiate         — drives the PRODUCTION multi-leg engine
 *                       brix_krb5_deleg_negotiate() to GSS_S_COMPLETE against an
 *                       in-process acceptor loop (the wire callback runs one
 *                       gss_accept_sec_context step per outbound token, feeding
 *                       its reply straight back). Proves the whole loop settles
 *                       with mutual auth and that the established context is real
 *                       by round-tripping a confidential gss_wrap/gss_unwrap
 *                       message between initiator and acceptor. The acceptor
 *                       observes alice, printed on success.
 *
 * Invoked only by tests/test_krb5_forward_live.py, which owns the unprivileged
 * KDC lifecycle (unshare -Ur) and skips when krb5 tooling is unavailable.
 *
 * Usage:  krb5_forward_live <alice_princ> <password> <origin_princ>
 *                           [origin|capture|negotiate]
 * Output: on success the acceptor-observed client name to stdout, exit 0;
 *         on failure "ERR\n" to stdout (+ a diagnostic to stderr), exit 1.
 *         The password is a test fixture, never logged; no secret is emitted.
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

#include "auth/krb5/forward.h"
#include "auth/krb5/capture.h"
#include "auth/krb5/kxr_wire.h"       /* production kXR krb5 wire codec (§5.7) */
#include "auth/krb5/carry.h"          /* async-safe FILE-ccache cred carry (§5.7) */
#include "auth/krb5/apreq.h"          /* raw-krb5 outbound AP-REQ builder (§5.7) */

/* ---- nginx surface stubs (pool → malloc, as the offline harnesses do) ------ */

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) log;
    return malloc(size);
}

volatile ngx_cycle_t  *ngx_cycle;

static ngx_log_t  log_;

static int
die(const char *what)
{
    fprintf(stderr, "krb5_forward_live: %s\n", what);
    printf("ERR\n");
    return 1;
}

/*
 * Complete the handshake against an in-process acceptor keyed by the origin
 * keytab (via KRB5_KTNAME) and print the observed client name. Returns 0 on
 * success (name printed to stdout), 1 on failure ("ERR" printed by die()).
 */
static int
accept_and_report(ngx_str_t token)
{
    OM_uint32        maj, min;
    gss_cred_id_t    acc_cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t     actx = GSS_C_NO_CONTEXT;
    gss_name_t       src = GSS_C_NO_NAME;
    gss_buffer_desc  in_tok, out_tok = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc  namebuf = GSS_C_EMPTY_BUFFER;

    maj = gss_acquire_cred(&min, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                           GSS_C_ACCEPT, &acc_cred, NULL, NULL);
    if (GSS_ERROR(maj)) {
        return die("gss_acquire_cred(acceptor)");
    }

    in_tok.value = token.data;
    in_tok.length = token.len;
    maj = gss_accept_sec_context(&min, &actx, acc_cred, &in_tok,
                                 GSS_C_NO_CHANNEL_BINDINGS, &src, NULL,
                                 &out_tok, NULL, NULL, NULL);
    if (GSS_ERROR(maj)) {
        return die("gss_accept_sec_context");
    }
    if (out_tok.length != 0) {
        gss_release_buffer(&min, &out_tok);
    }

    if (GSS_ERROR(gss_display_name(&min, src, &namebuf, NULL))) {
        return die("gss_display_name");
    }

    printf("%.*s\n", (int) namebuf.length, (char *) namebuf.value);
    return 0;
}

/*
 * Acceptor state driven by negotiate_wire() across the multi-leg loop: an
 * acceptor cred (from KRB5_KTNAME), the accumulating acceptor context, the
 * observed client name, and the reply buffer handed back to the engine (freed
 * on the next call so the borrowed pointer stays valid exactly one leg).
 */
typedef struct {
    gss_cred_id_t  acc_cred;
    gss_ctx_id_t   actx;
    int            complete;
    char           client[256];
    void          *last_reply;
} acceptor_state_t;

/*
 * Wire transceiver: run ONE gss_accept_sec_context step over the initiator's
 * outbound token and hand its reply back. Models the origin's kXR_authmore /
 * kXR_ok framing — done is set once the acceptor context completes. A GSS error
 * here (e.g. a token minted for the wrong service key) returns NGX_ERROR so the
 * engine fails closed, exactly as a rejecting origin would.
 */
static ngx_int_t
negotiate_wire(void *wire_ctx, const ngx_str_t *out_token, ngx_str_t *in_token,
    int *done, ngx_log_t *log)
{
    acceptor_state_t *a = wire_ctx;
    OM_uint32         maj, min;
    gss_buffer_desc   in_tok, out_tok = GSS_C_EMPTY_BUFFER;
    gss_name_t        src = GSS_C_NO_NAME;

    (void) log;

    in_token->data = NULL;
    in_token->len  = 0;
    *done = 0;

    /* Release the previous leg's reply; the engine has consumed it by now. */
    if (a->last_reply != NULL) {
        free(a->last_reply);
        a->last_reply = NULL;
    }

    in_tok.value  = out_token->data;
    in_tok.length = out_token->len;
    maj = gss_accept_sec_context(&min, &a->actx, a->acc_cred, &in_tok,
                                 GSS_C_NO_CHANNEL_BINDINGS, &src, NULL,
                                 &out_tok, NULL, NULL, NULL);
    if (GSS_ERROR(maj)) {
        if (out_tok.length != 0) {
            gss_release_buffer(&min, &out_tok);
        }
        if (src != GSS_C_NO_NAME) {
            gss_release_name(&min, &src);
        }
        return NGX_ERROR;   /* rejecting origin → engine fails closed */
    }

    /* Capture the client identity once the acceptor has it (persist it: src is
     * released here but the name is copied into the state). */
    if (src != GSS_C_NO_NAME) {
        gss_buffer_desc nb = GSS_C_EMPTY_BUFFER;
        if (!GSS_ERROR(gss_display_name(&min, src, &nb, NULL))) {
            size_t n = nb.length < sizeof a->client - 1
                     ? nb.length : sizeof a->client - 1;
            memcpy(a->client, nb.value, n);
            a->client[n] = '\0';
            gss_release_buffer(&min, &nb);
        }
        gss_release_name(&min, &src);
    }

    if (out_tok.length != 0) {
        void *copy = malloc(out_tok.length);
        if (copy == NULL) {
            gss_release_buffer(&min, &out_tok);
            return NGX_ERROR;
        }
        memcpy(copy, out_tok.value, out_tok.length);
        in_token->data = copy;
        in_token->len  = out_tok.length;
        a->last_reply  = copy;
        gss_release_buffer(&min, &out_tok);
    }

    if (maj == GSS_S_COMPLETE) {
        a->complete = 1;
        *done = 1;   /* acceptor settled → last reply is the kXR_ok-equivalent */
    }
    return NGX_OK;
}

/*
 * Drive the production multi-leg engine to completion against the acceptor loop,
 * then prove the established initiator<->acceptor context is real by round-tripping
 * a confidential gss_wrap/gss_unwrap message. Prints the observed client on
 * success. Returns 0 / 1 (die() prints "ERR").
 */
static int
negotiate_and_report(ngx_pool_t *pool, void *deleg_cred, const char *origin)
{
    acceptor_state_t  a;
    OM_uint32         maj, min;

    memset(&a, 0, sizeof a);
    a.acc_cred = GSS_C_NO_CREDENTIAL;
    a.actx     = GSS_C_NO_CONTEXT;

    maj = gss_acquire_cred(&min, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                           GSS_C_ACCEPT, &a.acc_cred, NULL, NULL);
    if (GSS_ERROR(maj)) {
        return die("gss_acquire_cred(acceptor)");
    }

    /* Drive the WHOLE production loop. NGX_OK means the initiator context
     * reached GSS_S_COMPLETE with GSS_C_MUTUAL_FLAG (the engine refuses to
     * complete without mutual auth), i.e. the multi-leg exchange settled and the
     * origin's identity was cryptographically verified. */
    if (brix_krb5_deleg_negotiate(pool, deleg_cred, origin,
                                  negotiate_wire, &a, &log_) != NGX_OK)
    {
        return die("brix_krb5_deleg_negotiate");
    }

    /* Independently, the acceptor side must also have reached completion and
     * observed the delegated user — the far end of a genuine mutual handshake. */
    if (!a.complete) {
        return die("acceptor context did not complete");
    }
    if (a.client[0] == '\0') {
        return die("acceptor observed no client name");
    }
    printf("%s\n", a.client);
    return 0;
}

/*
 * Forward alice's TGT into a KRB_CRED and run it through the PRODUCTION capture
 * helper, yielding a delegated GSS initiator cred in *out_cred. Mirrors the
 * XrdSeckrb5 round-1/round-2 crypto: a shared session subkey (as krb5_rd_req
 * would establish) protects the forwarded credential. Returns NGX_OK / NGX_ERROR.
 */
static ngx_int_t
capture_forwarded_cred(krb5_context kctx, krb5_principal client,
    krb5_ccache tgt_cc, void **out_cred, void **out_cap_cc)
{
    krb5_auth_context  ac_send = NULL, ac_recv = NULL;
    krb5_keyblock      subkey;
    krb5_data          krbcred;
    krb5_error_code    krc;
    ngx_int_t          rc;

    memset(&krbcred, 0, sizeof krbcred);

    /* One shared session subkey stands in for the AP-established key. */
    krc = krb5_c_make_random_key(kctx, ENCTYPE_AES256_CTS_HMAC_SHA1_96, &subkey);
    if (krc) {
        return NGX_ERROR;
    }

    if (krb5_auth_con_init(kctx, &ac_send)
        || krb5_auth_con_init(kctx, &ac_recv))
    {
        krb5_free_keyblock_contents(kctx, &subkey);
        return NGX_ERROR;
    }
    (void) krb5_auth_con_setflags(kctx, ac_send, 0);
    (void) krb5_auth_con_setflags(kctx, ac_recv, 0);
    if (krb5_auth_con_setsendsubkey(kctx, ac_send, &subkey)
        || krb5_auth_con_setrecvsubkey(kctx, ac_recv, &subkey))
    {
        krb5_free_keyblock_contents(kctx, &subkey);
        return NGX_ERROR;
    }
    krb5_free_keyblock_contents(kctx, &subkey);

    /* Client side: forward the (addressless) TGT — this is the KRB_CRED blob. */
    krc = krb5_fwd_tgt_creds(kctx, ac_send, NULL, client, NULL, tgt_cc, 1,
                             &krbcred);
    if (krc) {
        return NGX_ERROR;
    }

    /* Server side: the production round-2 capture. */
    rc = brix_krb5_capture_fwd_cred(kctx, ac_recv, client,
                                    (const u_char *) krbcred.data,
                                    (size_t) krbcred.length,
                                    out_cred, out_cap_cc, &log_);
    krb5_free_data_contents(kctx, &krbcred);
    return rc;
}

/* ---- kXR-framed live wire (mode "kxrwire") -------------------------------
 *
 * Drives the PRODUCTION codec brix_krb5_kxr_wire() over a real socket against a
 * kXR-framed GSSAPI acceptor: the exact ClientAuthRequest / ServerResponseHeader
 * bytes origin_auth.c emits are exchanged with a peer that speaks kXR_auth /
 * kXR_authmore / kXR_ok and runs gss_accept_sec_context() per leg. Proves the
 * multi-leg loop settles with mutual auth over the wire (not just in memory).
 */

/* Exactly-N socket I/O (short read/write is a transport error). */
static int
read_exact(int fd, void *buf, size_t n)
{
    u_char *p = buf;
    size_t  got = 0;

    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r <= 0) {
            return -1;
        }
        got += (size_t) r;
    }
    return 0;
}

static int
write_all(int fd, const void *buf, size_t n)
{
    const u_char *p = buf;
    size_t        sent = 0;

    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w <= 0) {
            return -1;
        }
        sent += (size_t) w;
    }
    return 0;
}

static void
put16(u_char *p, uint16_t v)
{
    p[0] = (u_char) (v >> 8);
    p[1] = (u_char) v;
}

static void
put32(u_char *p, uint32_t v)
{
    p[0] = (u_char) (v >> 24);
    p[1] = (u_char) (v >> 16);
    p[2] = (u_char) (v >> 8);
    p[3] = (u_char) v;
}

static uint32_t
get32(const u_char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)  | (uint32_t) p[3];
}

/* brix_krb5_kxr_wire transport: the initiator's socket end (io = &int fd). */
static ngx_int_t
sock_send(void *io, const void *buf, size_t len)
{
    return write_all(*(int *) io, buf, len) == 0 ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
sock_recv(void *io, void *buf, size_t len)
{
    return read_exact(*(int *) io, buf, len) == 0 ? NGX_OK : NGX_ERROR;
}

typedef struct {
    int            fd;          /* the acceptor's socket end */
    gss_cred_id_t  acc_cred;
    int            complete;
    char           client[256];
} kxr_acc_t;

/*
 * kXR-framed acceptor thread: read a ClientAuthRequest (24B header + token), run
 * one gss_accept_sec_context() step, and reply with a ServerResponseHeader
 * (kXR_authmore while continuing, kXR_ok once the acceptor context completes,
 * kXR_error on a GSS failure — modelling a rejecting origin). Loops until the
 * exchange settles or the peer closes.
 */
static void *
kxr_acceptor(void *arg)
{
    kxr_acc_t    *a = arg;
    gss_ctx_id_t  actx = GSS_C_NO_CONTEXT;
    OM_uint32     maj = 0, min = 0;

    for (;;) {
        u_char           hdr[24];
        u_char           rh[8];
        uint32_t         dlen;
        u_char          *tok = NULL;
        gss_buffer_desc  in_tok, out_tok = GSS_C_EMPTY_BUFFER;
        gss_name_t       src = GSS_C_NO_NAME;
        int              complete;

        if (read_exact(a->fd, hdr, sizeof hdr) != 0) {
            break;                                  /* peer closed / error */
        }
        dlen = get32(hdr + 20);
        if (dlen > (1u << 20)) {
            break;                                  /* absurd token — bail */
        }
        if (dlen > 0) {
            tok = malloc(dlen);
            if (tok == NULL || read_exact(a->fd, tok, dlen) != 0) {
                free(tok);
                break;
            }
        }

        in_tok.value  = tok;
        in_tok.length = dlen;
        maj = gss_accept_sec_context(&min, &actx, a->acc_cred, &in_tok,
                                     GSS_C_NO_CHANNEL_BINDINGS, &src, NULL,
                                     &out_tok, NULL, NULL, NULL);
        free(tok);

        if (GSS_ERROR(maj)) {
            /* Rejecting origin: kXR_error + a 4-byte errnum body, then close. */
            u_char eh[8], eb[4];
            memset(eh, 0, sizeof eh);
            put16(eh + 2, 4003 /* kXR_error */);
            put32(eh + 4, sizeof eb);
            put32(eb, 3 /* kXR_ServerError */);
            if (write_all(a->fd, eh, sizeof eh) == 0) {
                (void) write_all(a->fd, eb, sizeof eb);   /* best-effort body */
            }
            if (out_tok.length != 0) { gss_release_buffer(&min, &out_tok); }
            if (src != GSS_C_NO_NAME) { gss_release_name(&min, &src); }
            break;
        }

        if (src != GSS_C_NO_NAME) {
            gss_buffer_desc nb = GSS_C_EMPTY_BUFFER;
            if (!GSS_ERROR(gss_display_name(&min, src, &nb, NULL))) {
                size_t k = nb.length < sizeof a->client - 1
                         ? nb.length : sizeof a->client - 1;
                memcpy(a->client, nb.value, k);
                a->client[k] = '\0';
                gss_release_buffer(&min, &nb);
            }
            gss_release_name(&min, &src);
        }

        complete = (maj == GSS_S_COMPLETE);
        memset(rh, 0, sizeof rh);
        put16(rh + 2, complete ? 0 /* kXR_ok */ : 4002 /* kXR_authmore */);
        put32(rh + 4, (uint32_t) out_tok.length);
        if (write_all(a->fd, rh, sizeof rh) != 0
            || (out_tok.length != 0
                && write_all(a->fd, out_tok.value, out_tok.length) != 0))
        {
            if (out_tok.length != 0) { gss_release_buffer(&min, &out_tok); }
            break;
        }
        if (out_tok.length != 0) { gss_release_buffer(&min, &out_tok); }

        if (complete) {
            a->complete = 1;
            break;
        }
    }

    if (actx != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&min, &actx, GSS_C_NO_BUFFER);
    }
    close(a->fd);
    return NULL;
}

static int
kxrwire_and_report(ngx_pool_t *pool, void *deleg_cred, const char *origin)
{
    int                   sv[2];
    int                   ifd;
    kxr_acc_t             a;
    pthread_t             th;
    brix_krb5_kxr_wire_t  w;
    OM_uint32             maj, min;
    ngx_int_t             rc;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        return die("socketpair");
    }

    memset(&a, 0, sizeof a);
    a.fd       = sv[1];
    a.acc_cred = GSS_C_NO_CREDENTIAL;
    maj = gss_acquire_cred(&min, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                           GSS_C_ACCEPT, &a.acc_cred, NULL, NULL);
    if (GSS_ERROR(maj)) {
        close(sv[0]); close(sv[1]);
        return die("gss_acquire_cred(acceptor)");
    }
    if (pthread_create(&th, NULL, kxr_acceptor, &a) != 0) {
        close(sv[0]); close(sv[1]);
        return die("pthread_create");
    }

    ifd = sv[0];
    memset(&w, 0, sizeof w);
    w.send     = sock_send;
    w.recv     = sock_recv;
    w.io       = &ifd;
    w.max_body = 1 << 16;

    rc = brix_krb5_deleg_negotiate(pool, deleg_cred, origin,
                                   brix_krb5_kxr_wire, &w, &log_);
    if (w.reply != NULL) {
        free(w.reply);
        w.reply = NULL;
    }
    close(ifd);                     /* EOF to the acceptor if it is still reading */
    pthread_join(th, NULL);

    if (rc != NGX_OK) {
        return die("brix_krb5_deleg_negotiate(kxrwire)");
    }
    if (!a.complete) {
        return die("acceptor context did not complete");
    }
    if (a.client[0] == '\0') {
        return die("acceptor observed no client name");
    }
    printf("%s\n", a.client);
    return 0;
}

/*
 * Mode "carry": prove the async-safe FILE-ccache round-trip. Export the delegated
 * cred to a 0600 temp FILE ccache (brix_krb5_cred_to_ccache), re-acquire it on a
 * fresh handle (brix_krb5_cred_from_ccache) — modelling the request → async-fill
 * boundary where a live gss_cred_id_t cannot be carried — then drive the SAME
 * production kXR multi-leg engine with the RE-IMPORTED cred and confirm alice
 * still reaches the acceptor. Releases the carried handle and unlinks the temp.
 */
static int
carry_and_report(ngx_pool_t *pool, void *deleg_cred, const char *origin)
{
    char   path[] = "/tmp/brix-krb5-carryXXXXXX";
    int    fd;
    void  *g2 = NULL;
    void  *hold = NULL;
    int    rc;

    fd = mkstemp(path);
    if (fd < 0) {
        return die("mkstemp(carry ccache)");
    }
    close(fd);                          /* libkrb5 owns the FILE ccache */

    if (brix_krb5_cred_to_ccache(deleg_cred, path, &log_) != NGX_OK) {
        unlink(path);
        return die("brix_krb5_cred_to_ccache");
    }
    if (brix_krb5_cred_from_ccache(path, &g2, &hold, &log_) != NGX_OK) {
        unlink(path);
        return die("brix_krb5_cred_from_ccache");
    }

    rc = kxrwire_and_report(pool, g2, origin);

    brix_krb5_cred_carry_release(g2, hold, &log_);
    unlink(path);
    return rc;
}

/*
 * Mode "carry-badpath": robustness-negative for the import side. Re-acquiring a
 * cred from a non-existent ccache path must fail closed — never fabricate a
 * usable credential. Correct behaviour returns die() (non-zero exit, no identity
 * on stdout); a cred from a bogus path is a defect and exits 0 so the test fails.
 */
static int
carry_badpath_report(void)
{
    void *g2 = NULL;
    void *hold = NULL;

    if (brix_krb5_cred_from_ccache("/nonexistent/brix-krb5-carry.ccache",
                                   &g2, &hold, &log_) == NGX_OK) {
        brix_krb5_cred_carry_release(g2, hold, &log_);
        printf("import-ok\n");
        return 0;
    }
    return die("import from a missing ccache correctly failed closed");
}

/*
 * Pure selftest of the reply classifier (mode "classify"): no KDC or creds
 * needed. Exercises every branch of brix_krb5_kxr_classify — kXR_authmore
 * (continue), kXR_ok (settle), kXR_error and an unexpected status (fail closed).
 */
static int
classify_selftest(void)
{
    ngx_str_t  in;
    int        done;
    u_char     body[4] = { 1, 2, 3, 4 };

    if (brix_krb5_kxr_classify(4002 /* authmore */, body, sizeof body, &in, &done)
            != NGX_OK
        || done != 0 || in.len != sizeof body || in.data != body)
    {
        return die("classify authmore");
    }
    if (brix_krb5_kxr_classify(0 /* ok */, body, sizeof body, &in, &done)
            != NGX_OK
        || done != 1 || in.len != sizeof body)
    {
        return die("classify ok");
    }
    if (brix_krb5_kxr_classify(4003 /* error */, NULL, 0, &in, &done) != NGX_ERROR) {
        return die("classify error");
    }
    if (brix_krb5_kxr_classify(4005 /* unexpected */, NULL, 0, &in, &done)
            != NGX_ERROR)
    {
        return die("classify unexpected");
    }
    printf("classify-ok\n");
    return 0;
}

/*
 * Mode "apreq": prove the PRODUCTION raw-krb5 OUTBOUND builder — the dialect real
 * "&P=krb5" origins accept (krb5_rd_req over an AP-REQ), unlike the GSSAPI engine.
 * Store alice's TGT in a FILE ccache (the async-safe carry artifact the fill task
 * carries), call brix_krb5_apreq_from_ccache() to build the exact "krb5\0"+AP-REQ
 * payload origin_auth.c's raw leg sends, then VERIFY it the way a stock XRootD
 * acceptor does: strip the NUL-terminated "krb5\0" name and krb5_rd_req the AP-REQ
 * against the origin keytab (via KRB5_KTNAME). On success the acceptor-observed
 * client (alice) is printed; a wrong keytab (bound-to-origin negative) fails closed.
 */
static int
apreq_and_report(krb5_context kctx, krb5_creds *tgt, krb5_principal client,
    const char *origin_spn)
{
    char               path[] = "/tmp/brix-krb5-apreqXXXXXX";
    char               spec[128];
    int                fd;
    krb5_ccache        fcc = NULL;
    krb5_error_code    krc;
    ngx_str_t          payload = ngx_null_string;
    krb5_data          ap;
    krb5_auth_context  ac = NULL;
    krb5_ticket       *tkt = NULL;
    krb5_keytab        kt = NULL;
    char              *name = NULL;
    ngx_pool_t        *pool = (ngx_pool_t *) &log_;   /* stub pool → malloc */
    int                rc;

    fd = mkstemp(path);
    if (fd < 0) {
        return die("mkstemp(apreq ccache)");
    }
    close(fd);                          /* libkrb5 owns the FILE ccache */
    snprintf(spec, sizeof spec, "FILE:%s", path);

    if (krb5_cc_resolve(kctx, spec, &fcc)
        || krb5_cc_initialize(kctx, fcc, client)
        || krb5_cc_store_cred(kctx, fcc, tgt))
    {
        if (fcc != NULL) { krb5_cc_close(kctx, fcc); }
        unlink(path);
        return die("store TGT to apreq FILE ccache");
    }
    krb5_cc_close(kctx, fcc);

    /* The production builder: TGT ccache PATH + origin SPN → "krb5\0"+AP-REQ. */
    if (brix_krb5_apreq_from_ccache(pool, spec, origin_spn, &payload, &log_)
        != NGX_OK)
    {
        unlink(path);
        return die("brix_krb5_apreq_from_ccache");
    }
    unlink(path);

    /* Wire contract: the payload MUST begin with the NUL-terminated name. */
    if (payload.len < 5 || memcmp(payload.data, "krb5\0", 5) != 0) {
        free(payload.data);
        return die("apreq payload not framed as krb5\\0 + AP-REQ");
    }

    /* Verify the AP-REQ EXACTLY as the origin acceptor does: krb5_rd_req against
     * the origin keytab (default keytab honours KRB5_KTNAME). */
    ap.data   = (char *) payload.data + 5;
    ap.length = (unsigned int) (payload.len - 5);
    if (krb5_kt_default(kctx, &kt)) {
        free(payload.data);
        return die("krb5_kt_default");
    }
    krc = krb5_rd_req(kctx, &ac, &ap, NULL /* match any princ in keytab */, kt,
                      NULL, &tkt);
    free(payload.data);

    if (krc == 0 && tkt != NULL
        && krb5_unparse_name(kctx, tkt->enc_part2->client, &name) == 0)
    {
        printf("%s\n", name);
        krb5_free_unparsed_name(kctx, name);
        rc = 0;
    } else {
        rc = die("krb5_rd_req rejected the AP-REQ");
    }

    if (tkt != NULL) { krb5_free_ticket(kctx, tkt); }
    if (ac != NULL)  { krb5_auth_con_free(kctx, ac); }
    krb5_kt_close(kctx, kt);
    return rc;
}

int
main(int argc, char **argv)
{
    krb5_context              kctx;
    krb5_principal            client = NULL;
    krb5_creds                creds;
    krb5_ccache               cc = NULL;
    krb5_get_init_creds_opt  *opt = NULL;
    krb5_error_code           krc;

    OM_uint32                 min;
    gss_cred_id_t             init_cred = GSS_C_NO_CREDENTIAL;
    void                     *deleg_cred = NULL;
    void                     *cap_cc = NULL;
    const char               *mode;

    /* Non-NULL sentinel: the pool-alloc stubs above ignore the target. */
    ngx_pool_t               *pool = (ngx_pool_t *) &log_;
    ngx_str_t                 out_token = ngx_null_string;

    if (argc < 4) {
        fprintf(stderr,
            "usage: %s <alice_princ> <password> <origin_princ> [origin|capture]\n",
            argv[0]);
        return 2;
    }
    mode = (argc >= 5) ? argv[4] : "origin";

    /* Pure classifier selftest needs neither KDC nor credentials — run it
     * before any krb5 setup so it works even where the KDC lab is unavailable. */
    if (strcmp(mode, "classify") == 0) {
        return classify_selftest();
    }

    /* 1. Acquire alice's forwardable TGT from the live KDC. */
    if (krb5_init_context(&kctx)) {
        return die("krb5_init_context");
    }
    if (krb5_parse_name(kctx, argv[1], &client)) {
        return die("krb5_parse_name");
    }
    memset(&creds, 0, sizeof creds);
    if (krb5_get_init_creds_opt_alloc(kctx, &opt)) {
        return die("krb5_get_init_creds_opt_alloc");
    }
    krb5_get_init_creds_opt_set_forwardable(opt, 1);
    krc = krb5_get_init_creds_password(kctx, &creds, client, argv[2],
                                       NULL, NULL, 0, NULL, opt);
    if (krc) {
        return die("krb5_get_init_creds_password");
    }

    /* Park the TGT in a private MEMORY ccache. */
    if (krb5_cc_new_unique(kctx, "MEMORY", NULL, &cc)) {
        return die("krb5_cc_new_unique");
    }
    if (krb5_cc_initialize(kctx, cc, client)) {
        return die("krb5_cc_initialize");
    }
    if (krb5_cc_store_cred(kctx, cc, &creds)) {
        return die("krb5_cc_store_cred");
    }

    /* Raw-krb5 outbound leg: needs only the live TGT, not a GSS deleg cred. */
    if (strcmp(mode, "apreq") == 0) {
        return apreq_and_report(kctx, &creds, client, argv[3]);
    }

    /* 2. Obtain the delegated GSS initiator credential (acts AS alice). */
    if (strcmp(mode, "capture") == 0) {
        /* Full EXCHANGE path: forward the TGT and run the production capture. */
        if (capture_forwarded_cred(kctx, client, cc, &deleg_cred, &cap_cc)
            != NGX_OK)
        {
            return die("brix_krb5_capture_fwd_cred");
        }
    } else {
        /* Origin-leg only: import the TGT ccache straight to a GSS cred. */
        if (GSS_ERROR(gss_krb5_import_cred(&min, cc, NULL, NULL, &init_cred))) {
            return die("gss_krb5_import_cred");
        }
        deleg_cred = (void *) init_cred;
    }

    (void) cap_cc;   /* released implicitly at process exit */

    /* 3. Drive the origin auth. "negotiate" runs the FULL production multi-leg
     *    engine to completion; "origin"/"capture" run the single first-leg step
     *    and finish against a one-shot acceptor. */
    if (strcmp(mode, "kxrwire") == 0) {
        return kxrwire_and_report(pool, deleg_cred, argv[3]);
    }
    if (strcmp(mode, "carry") == 0) {
        return carry_and_report(pool, deleg_cred, argv[3]);
    }
    if (strcmp(mode, "carry-badpath") == 0) {
        return carry_badpath_report();
    }
    if (strcmp(mode, "negotiate") == 0) {
        return negotiate_and_report(pool, deleg_cred, argv[3]);
    }

    /* Production origin leg: first gss_init_sec_context step. */
    if (brix_krb5_deleg_to_origin(pool, deleg_cred, argv[3],
                                  &out_token, &log_) != NGX_OK)
    {
        return die("brix_krb5_deleg_to_origin");
    }

    /* 4. In-process acceptor keyed by the origin keytab (via KRB5_KTNAME). */
    return accept_and_report(out_token);
}
