/*
 * sec_krb5.c — Kerberos 5 (krb5) auth module.
 *
 * WHAT: Build the kXR_auth payload for the "krb5" protocol: a Kerberos AP-REQ the
 *       server validates with krb5_rd_req against its service keytab.
 * WHY:  krb5 is one of the stream protocol's auth mechanisms (xrootd_auth krb5);
 *       this gives the native client a libXrdSec*-free Kerberos credential path.
 * HOW:  Use the caller's default credential cache (a TGT from kinit) to obtain a
 *       service ticket for the server principal, then krb5_mk_req_extended to
 *       produce the AP-REQ. The server principal comes from the advertised
 *       "&P=krb5,<principal>" parameter when present, else xrootd/<host> derived
 *       from the connection. Payload = the 4 bytes "krb5" + the raw AP-REQ — the
 *       exact framing src/krb5/auth.c expects (prefix check + krb5_rd_req on the
 *       bytes past offset 4). Single round.
 *
 * Compile-gated on XROOTD_HAVE_KRB5 (pkg-config krb5). When absent the accessor
 * returns NULL so the auth driver simply skips krb5 and the build still succeeds.
 *
 * wire: XProtocol.hh kXR_auth credtype "krb5"; payload "krb5" + AP-REQ
 *       (src/krb5/auth.c xrootd_handle_krb5_auth).
 */
#include "sec.h"

#ifdef XROOTD_HAVE_KRB5

#include <krb5.h>
#include <stdlib.h>
#include <string.h>

/* True if the default ccache holds a usable client principal (a kinit'd TGT). */
static int
krb5_have(void)
{
    krb5_context   ctx;
    krb5_ccache    cc;
    krb5_principal me = NULL;
    int            ok = 0;

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
build_server_princ(krb5_context ctx, xrdc_conn *c, const char *parms,
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
krb5_acquire(krb5_context ctx, xrdc_conn *c, const char *parms,
             krb5_ccache *cc, krb5_principal *client, krb5_principal *server,
             krb5_creds *in_creds, krb5_creds **out_creds,
             krb5_auth_context *auth, krb5_data *apreq,
             uint8_t **payload, uint32_t *plen, xrdc_status *st)
{
    if (krb5_cc_default(ctx, cc) != 0
        || krb5_cc_get_principal(ctx, *cc, client) != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "krb5: no credential cache (run kinit)");
        return -1;
    }
    if (build_server_princ(ctx, c, parms, server) != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "krb5: bad service principal");
        return -1;
    }
    in_creds->client = *client;
    in_creds->server = *server;
    if (krb5_get_credentials(ctx, 0, *cc, in_creds, out_creds) != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "krb5: cannot get a service ticket (TGT expired?)");
        return -1;
    }
    if (krb5_mk_req_extended(ctx, auth, 0, NULL, *out_creds, apreq) != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "krb5: mk_req failed");
        return -1;
    }

    uint8_t *p = (uint8_t *) malloc(4 + apreq->length);
    if (p == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "krb5: out of memory");
        return -1;
    }
    memcpy(p, "krb5", 4);                       /* the prefix src/krb5 checks */
    memcpy(p + 4, apreq->data, apreq->length);
    *payload = p;
    *plen = (uint32_t) (4 + apreq->length);
    return 0;
}

static int
krb5_first(xrdc_conn *c, const char *parms, uint8_t **payload, uint32_t *plen,
           xrdc_status *st)
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
        xrdc_status_set(st, XRDC_EAUTH, 0, "krb5: cannot init context");
        return -1;
    }

    int rc = krb5_acquire(ctx, c, parms, &cc, &client, &server, &in_creds,
                          &out_creds, &auth, &apreq, payload, plen, st);

    if (apreq.data != NULL) { krb5_free_data_contents(ctx, &apreq); }
    if (out_creds != NULL)  { krb5_free_creds(ctx, out_creds); }
    if (auth != NULL)       { krb5_auth_con_free(ctx, auth); }
    if (server != NULL)     { krb5_free_principal(ctx, server); }
    if (client != NULL)     { krb5_free_principal(ctx, client); }
    if (cc != NULL)         { krb5_cc_close(ctx, cc); }
    krb5_free_context(ctx);
    return rc;
}

const xrdc_sec_module *
xrdc_sec_krb5(void)
{
    static const xrdc_sec_module m = {
        "krb5",
        { 'k', 'r', 'b', '5' },
        krb5_have,
        krb5_first,
        NULL,   /* single round (AP-REQ self-contained) */
        NULL,
    };
    return &m;
}

#else  /* !XROOTD_HAVE_KRB5 */

const xrdc_sec_module *
xrdc_sec_krb5(void)
{
    return NULL;   /* krb5 dev libs absent at build time → driver skips krb5 */
}

#endif
