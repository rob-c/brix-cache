/*
 * sec_krb5.c — Kerberos 5 (krb5) auth module.
 *
 * WHAT: Build the kXR_auth payload for the "krb5" protocol: a Kerberos AP-REQ the
 *       server validates with krb5_rd_req against its service keytab.
 * WHY:  krb5 is one of the stream protocol's auth mechanisms (brix_auth krb5);
 *       this gives the native client a libXrdSec*-free Kerberos credential path.
 * HOW:  Use the caller's default credential cache (a TGT from kinit) to obtain a
 *       service ticket for the server principal, then krb5_mk_req_extended to
 *       produce the AP-REQ. The server principal comes from the advertised
 *       "&P=krb5,<principal>" parameter when present, else xrootd/<host> derived
 *       from the connection. Payload = the 5 bytes "krb5\0" (NUL-terminated protocol
 *       name, per XrdSecInterface) + the raw AP-REQ — byte-for-byte the framing the
 *       reference libXrdSeckrb5 acceptor and src/auth/krb5/auth.c both consume (name
 *       string + krb5_rd_req on the bytes past the NUL).
 *
 *       DELEGATION (round 2): when the server is configured `brix_krb5_delegate on`
 *       it answers the AP-REQ with a kXR_authmore "fwdtgt" continuation asking us to
 *       forward our TGT. more() then calls krb5_fwd_tgt_creds() under the round-1
 *       auth context (the subkey the server negotiated via krb5_rd_req) to build a
 *       KRB_CRED and replies "krb5\0" + KRB_CRED, which the server's round-2 capture
 *       (src/auth/krb5/deleg_capture.c brix_krb5_deleg_capture) decrypts and imports.
 *       Forwarding requires a forwardable TGT (kinit -f); otherwise more() fails
 *       closed rather than silently downgrading. Single-round when delegation is off.
 *
 * Compile-gated on BRIX_HAVE_KRB5 (pkg-config krb5). When absent the accessor
 * returns NULL so the auth driver simply skips krb5 and the build still succeeds.
 *
 * wire: XProtocol.hh kXR_auth credtype "krb5"; payload "krb5\0" + AP-REQ
 *       (src/auth/krb5/auth.c brix_handle_krb5_auth).
 */
#include "sec.h"

#ifdef BRIX_HAVE_KRB5

#include <krb5.h>
#include <stdlib.h>
#include <string.h>

/*
 * Round state parked between first() and more()/cleanup().
 *
 * WHY file-static: the native auth driver (client/lib/auth/auth.c run_module) is
 *   synchronous and authenticates one connection through one module at a time, so
 *   a single parked round context is sufficient and avoids widening the shared
 *   brix_conn ABI just for the krb5 delegation path.
 * WHAT is retained: the round-1 krb5_auth_context (whose subkey the server picked
 *   up via krb5_rd_req), the ccache + client principal, and the context that owns
 *   them all — everything krb5_fwd_tgt_creds() needs to encrypt the forwarded TGT
 *   under the shared subkey. Freed by krb5_more() after forwarding, or by
 *   krb5_cleanup() on a single-round kXR_ok. A defensive reset before every park
 *   reclaims state a prior failed attempt left behind (error paths skip cleanup).
 */
static struct {
    krb5_context      ctx;
    krb5_auth_context auth;
    krb5_ccache       cc;
    krb5_principal    client;
    int               active;
} g_round;

static void
krb5_round_reset(void)
{
    if (!g_round.active) {
        return;
    }
    if (g_round.auth != NULL)   { krb5_auth_con_free(g_round.ctx, g_round.auth); }
    if (g_round.client != NULL) { krb5_free_principal(g_round.ctx, g_round.client); }
    if (g_round.cc != NULL)     { krb5_cc_close(g_round.ctx, g_round.cc); }
    if (g_round.ctx != NULL)    { krb5_free_context(g_round.ctx); }
    memset(&g_round, 0, sizeof(g_round));
}

/* Byte-scan for a marker anywhere in a (small, untrusted) challenge body —
 * portable stand-in for memmem() with no _GNU_SOURCE dependency. */
static int
krb5_has_marker(const uint8_t *b, uint32_t n, const char *m)
{
    size_t ml = strlen(m);
    if (b == NULL || n < ml) {
        return 0;
    }
    for (uint32_t i = 0; i + ml <= n; i++) {
        if (memcmp(b + i, m, ml) == 0) {
            return 1;
        }
    }
    return 0;
}

/* True if the default ccache holds a usable client principal (a kinit'd TGT).
 * c is accepted for interface uniformity; the store path for krb5 is not yet
 * wired through first() (ccache env-pass is krb5-specific), so the probe
 * always falls through to the default ccache check. */
static int
krb5_have(brix_conn *c)
{
    krb5_context   ctx;
    krb5_ccache    cc;
    krb5_principal me = NULL;
    int            ok = 0;

    (void) c;
    if (krb5_init_context(&ctx) != 0) {
        return 0;
    }
    if (krb5_cc_default(ctx, &cc) == 0) {
        if (krb5_cc_get_principal(ctx, cc, &me) == 0) {
            ok = 1;
            krb5_free_principal(ctx, me);
        }
        krb5_cc_close(ctx, cc);
    }
    krb5_free_context(ctx);
    return ok;
}

/* Resolve the server (service) principal: prefer the advertised "&P=krb5,<p>"
 * parameter; else derive xrootd/<host> from the connection. 0 / -1. */
static int
build_server_princ(krb5_context ctx, brix_conn *c, const char *parms,
                   krb5_principal *out)
{
    if (parms != NULL && parms[0] != '\0') {
        return krb5_parse_name(ctx, parms, out) == 0 ? 0 : -1;
    }
    return krb5_sname_to_principal(ctx, c->host, "xrootd", KRB5_NT_SRV_HST,
                                   out) == 0 ? 0 : -1;
}

/*
 * Acquire the ccache/principals/ticket and emit the "krb5"+AP-REQ payload.
 *
 * WHAT: Performs every step that can fail, on a created krb5 context, writing
 *       the acquired resources back through its out-params so the caller can
 *       free exactly what was obtained (the locals start NULL/zero-init'd, so a
 *       partial-init failure leaves the not-yet-acquired ones at NULL/empty).
 * WHY:  Isolating the fallible acquisition into one early-return helper lets the
 *       orchestrator run a single linear, unconditional NULL-safe cleanup —
 *       removing the shared `goto out` ladder while keeping behaviour identical.
 * HOW:  Mirror the original step order and status messages; on any failure
 *       return -1 with *st set; on success fill the payload/plen out-params, return 0.
 *       Never frees here — ownership of every resource stays with the caller.
 */
static int
krb5_acquire(krb5_context ctx, brix_conn *c, const char *parms,
             krb5_ccache *cc, krb5_principal *client, krb5_principal *server,
             krb5_creds *in_creds, krb5_creds **out_creds,
             krb5_auth_context *auth, krb5_data *apreq,
             uint8_t **payload, uint32_t *plen, brix_status *st)
{
    if (krb5_cc_default(ctx, cc) != 0
        || krb5_cc_get_principal(ctx, *cc, client) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "krb5: no credential cache (run kinit)");
        return -1;
    }
    if (build_server_princ(ctx, c, parms, server) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0, "krb5: bad service principal");
        return -1;
    }
    in_creds->client = *client;
    in_creds->server = *server;
    if (krb5_get_credentials(ctx, 0, *cc, in_creds, out_creds) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "krb5: cannot get a service ticket (TGT expired?)");
        return -1;
    }
    if (krb5_mk_req_extended(ctx, auth, 0, NULL, *out_creds, apreq) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0, "krb5: mk_req failed");
        return -1;
    }

    uint8_t *p = (uint8_t *) malloc(5 + apreq->length);
    if (p == NULL) {
        brix_status_set(st, XRDC_EAUTH, 0, "krb5: out of memory");
        return -1;
    }
    memcpy(p, "krb5", 5);      /* NUL-terminated protocol name (XrdSec wire); */
    memcpy(p + 5, apreq->data, apreq->length);   /* then the raw AP-REQ */
    *payload = p;
    *plen = (uint32_t) (5 + apreq->length);
    return 0;
}

static int
krb5_first(brix_conn *c, const char *parms, uint8_t **payload, uint32_t *plen,
           brix_status *st)
{
    krb5_context      ctx = NULL;
    krb5_ccache       cc = NULL;
    krb5_auth_context auth = NULL;
    krb5_principal    server = NULL, client = NULL;
    krb5_creds        in_creds, *out_creds = NULL;
    krb5_data         apreq;

    memset(&in_creds, 0, sizeof(in_creds));
    memset(&apreq, 0, sizeof(apreq));

    if (krb5_init_context(&ctx) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0, "krb5: cannot init context");
        return -1;
    }

    int rc = krb5_acquire(ctx, c, parms, &cc, &client, &server, &in_creds,
                          &out_creds, &auth, &apreq, payload, plen, st);

    /* Transients are never needed past round 1. */
    if (apreq.data != NULL) { krb5_free_data_contents(ctx, &apreq); }
    if (out_creds != NULL)  { krb5_free_creds(ctx, out_creds); }
    if (server != NULL)     { krb5_free_principal(ctx, server); }

    if (rc != 0) {
        if (auth != NULL)   { krb5_auth_con_free(ctx, auth); }
        if (client != NULL) { krb5_free_principal(ctx, client); }
        if (cc != NULL)     { krb5_cc_close(ctx, cc); }
        krb5_free_context(ctx);
        return -1;
    }

    /* Success: park {context, auth-context subkey, ccache, client principal} so a
     * server "fwdtgt" continuation (brix_krb5_delegate on) can forward the TGT
     * under the SAME auth context the server negotiated via krb5_rd_req. A
     * single-round server (delegation off) never re-enters, so krb5_cleanup()
     * reclaims this on kXR_ok instead. */
    krb5_round_reset();
    g_round.ctx    = ctx;
    g_round.auth   = auth;
    g_round.cc     = cc;
    g_round.client = client;
    g_round.active = 1;
    return 0;
}

/*
 * Round 2 — forward the TGT in answer to the server's "fwdtgt" continuation.
 *
 * WHAT: The server (brix_krb5_delegate on) replied to our AP-REQ with a
 *       kXR_authmore body "krb5\0fwdtgt\0". Build a KRB_CRED forwarding our TGT
 *       and reply "krb5\0" + KRB_CRED — the framing src/auth/krb5/deleg_capture.c
 *       (brix_krb5_deleg_credbytes) strips before krb5_rd_cred.
 * WHY:  Closes the inbound delegation-capture loop end-to-end: the server imports
 *       the forwarded TGT to act on the user's behalf against a per-user backend.
 * HOW:  krb5_fwd_tgt_creds under the round-1 auth context (shared subkey). The
 *       ticket must be forwardable (kinit -f) — otherwise we fail closed with a
 *       clear message rather than silently downgrading to a non-delegated login.
 */
static int
krb5_more(brix_conn *c, const uint8_t *sbody, uint32_t slen,
          uint8_t **payload, uint32_t *plen, brix_status *st)
{
    (void) c;
    if (!g_round.active) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "krb5: no round-1 state for continuation");
        return -1;
    }
    /* The only continuation we understand is the forwarded-TGT request. */
    if (!krb5_has_marker(sbody, slen, "fwdtgt")) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "krb5: unexpected authmore challenge");
        krb5_round_reset();
        return -1;
    }

    krb5_data fwd;
    memset(&fwd, 0, sizeof(fwd));
    krb5_error_code krc = krb5_fwd_tgt_creds(g_round.ctx, g_round.auth,
                                             NULL, g_round.client, NULL,
                                             g_round.cc, 1 /* forwardable */,
                                             &fwd);
    if (krc != 0) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "krb5: cannot forward TGT (need a forwardable "
                        "ticket: kinit -f)");
        krb5_round_reset();
        return -1;
    }

    uint8_t *p = (uint8_t *) malloc(5 + fwd.length);
    if (p == NULL) {
        krb5_free_data_contents(g_round.ctx, &fwd);
        krb5_round_reset();
        brix_status_set(st, XRDC_EAUTH, 0, "krb5: out of memory");
        return -1;
    }
    memcpy(p, "krb5", 5);      /* NUL-terminated name, then the KRB_CRED */
    memcpy(p + 5, fwd.data, fwd.length);
    *payload = p;
    *plen = (uint32_t) (5 + fwd.length);

    krb5_free_data_contents(g_round.ctx, &fwd);
    krb5_round_reset();   /* forwarding is terminal — the next reply is kXR_ok */
    return 0;
}

/* Reclaim parked round state on a single-round kXR_ok (delegation off). */
static void
krb5_cleanup(brix_conn *c)
{
    (void) c;
    krb5_round_reset();
}

const brix_sec_module *
brix_sec_krb5(void)
{
    static const brix_sec_module m = {
        "krb5",
        { 'k', 'r', 'b', '5' },
        krb5_have,
        krb5_first,
        krb5_more,      /* round 2: forward the TGT on the "fwdtgt" challenge */
        krb5_cleanup,   /* free parked round state on a single-round kXR_ok */
    };
    return &m;
}

#else  /* !BRIX_HAVE_KRB5 */

const brix_sec_module *
brix_sec_krb5(void)
{
    return NULL;   /* krb5 dev libs absent at build time → driver skips krb5 */
}

#endif
