#include "cache_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared handshake/protocol/login packers */
#include "core/compat/fattr_codec.h"        /* xrdp_fattr_nvec_parse (kXR_fattr replies) */
#include "protocols/root/protocol/frame_hdr.h"        /* xrd_error_body_decode (kXR_error errnum) */
#include "auth/gsi/gsi_core.h"              /* shared XrdSecgsi handshake kernel (C-3 GSI) */
#include "protocols/root/protocol/gsi.h"              /* kXRS_x509 bucket id (origin-cert verify) */
#include "auth/sss/sss_keytab_kernel.h"     /* §14 SSS: shared keytab line grammar */
#include "auth/krb5/carry.h"                /* §5.7 krb5: re-import delegated TGT from carried FILE ccache */
#include <stdio.h>                        /* fdopen/fgets for the keytab reader */


#if defined(__linux__)
#include <endian.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* Locate a protocol's parameter substring in a login advert that may carry
 * several "&P=<proto>,<parms>" entries (e.g. "&P=ztn,0:4096:&P=gsi,v:10600,
 * c:ssl,ca:HASH"). `needle` is "<proto>," including the comma; returns a
 * pointer INTO `parms` just past it, or NULL when the protocol is not
 * advertised with parameters. */
static const char *
cache_origin_proto_parms(const char *parms, size_t plen, const char *needle,
    size_t nlen)
{
    size_t i;

    if (parms == NULL || plen < nlen) {
        return NULL;
    }
    for (i = 0; i + nlen <= plen; i++) {
        if (ngx_strncmp(parms + i, needle, nlen) == 0) {
            return parms + i + nlen;
        }
    }
    return NULL;
}

/* The gsi v:/c:/ca: list brix_gsi_parse_parms wants, or NULL. */
static const char *
cache_origin_gsi_parms(const char *parms, size_t plen)
{
    return cache_origin_proto_parms(parms, plen, "gsi,", 4);
}

/* The origin's advertised krb5 service principal from "&P=krb5,<princ>"
 * (phase-70 §5.7) — the SPN the raw AP-REQ must target, exactly as the native
 * client honours it — or NULL when krb5 is advertised bare ("&P=krb5" with no
 * principal). */
static const char *
cache_origin_krb5_princ(const char *parms, size_t plen)
{
    return cache_origin_proto_parms(parms, plen, "krb5,", 5);
}

/* origin_frame_t — one decoded origin reply (status + owned body). WHY: the
 * bootstrap wire steps each read exactly one frame; bundling the status/body/dlen
 * triple keeps the step helpers under the 5-parameter cap and makes body
 * ownership explicit (whoever holds the struct frees fr->body). */
typedef struct {
    uint16_t   status;
    uint32_t   dlen;
    u_char    *body;
} origin_frame_t;

/* origin_auth_advert_t — parsed "&P=<proto>,..." login advert. WHY: the login
 * reply's protocol list drives the credential dispatch ladder; parsing it into
 * flags + a copied gsi parameter string decouples the (freed) reply body from
 * the auth decision. gsi_parms is a stable copy because the advert body is
 * released before any auth round-trip starts. */
typedef struct {
    int   needs_auth;    /* advert carries "&P=..." ⇒ session not authenticated */
    int   has_ztn;
    int   has_gsi;
    int   has_sss;
    int   has_krb5;      /* §5.7: origin advertises "&P=krb5" (delegated TGT leg) */
    char  gsi_parms[256];   /* gsi v:/c:/ca: list, NUL-terminated */
    char  krb5_princ[512];  /* §5.7: origin's advertised "&P=krb5,<princ>" SPN */
} origin_auth_advert_t;

/* origin_expect_frame — read one origin reply into fr and require kXR_ok. WHAT:
 * shared reply validator for the bootstrap wire steps. HOW: on transport/timeout
 * failure brix_cache_read_response has already set the task error; on a non-ok
 * status the body is freed and fail_msg becomes a kXR_ServerError. On success
 * fr->body is the caller's to free. Returns 0 / -1. */
static int
origin_expect_frame(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    uint32_t max_dlen, const char *fail_msg, origin_frame_t *fr)
{
    fr->body = NULL;
    if (brix_cache_read_response(t, oc, &fr->status, &fr->body,
                                   &fr->dlen, max_dlen) != 0) {
        return -1;
    }
    if (fr->status != kXR_ok) {
        free(fr->body);
        fr->body = NULL;
        brix_cache_set_error(t, kXR_ServerError, 0, fail_msg);
        return -1;
    }
    return 0;
}

/* origin_bs_handshake — bootstrap step 1: ClientInitHandShake exchange. WHY: a
 * stock XRootD server answers the 20-byte preamble with a kXR_ok frame before
 * any request is legal. Returns 0 / -1 (task error set). */
static int
origin_bs_handshake(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    ClientInitHandShake  hs;
    origin_frame_t       fr;

    xrd_pack_handshake(&hs);

    if (brix_cache_io_send(oc, &hs, sizeof(hs)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin handshake write failed");
        return -1;
    }
    if (origin_expect_frame(t, oc, 64,
                              "cache origin handshake failed", &fr) != 0) {
        return -1;
    }
    free(fr.body);
    return 0;
}

/* origin_bs_protocol — bootstrap step 2: kXR_protocol negotiation, with the
 * cleartext-handshake-then-TLS-upgrade a stock XRootD `roots://` origin demands.
 *
 * WHY: a TLS-for-ztn origin answers the CLEARTEXT kXR_protocol request with a
 *   kXR_gotoTLS advert and expects the client to upgrade THIS fd to TLS before
 *   kXR_login/auth — an immediate SSL_connect at byte 0 (the old behaviour) never
 *   reaches this exchange, so the origin was unreachable. When brix_cache_origin_tls
 *   is set we advertise kXR_ableTLS so the origin knows it may request the upgrade.
 * HOW: send the protocol request on the connector streamid (advertising ableTLS
 *   when configured), inspect the reply flags, and:
 *     - gotoTLS + tls on  → brix_cache_origin_tls_upgrade (every later frame rides
 *                           TLS via io.c once oc->ssl is set)
 *     - gotoTLS + tls off → refuse (kXR_TLSRequired) rather than a mid-session surprise
 *     - no gotoTLS        → stay cleartext
 * Returns 0 / -1 (task error set). */
static int
origin_bs_protocol(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    ClientProtocolRequest  pr;
    origin_frame_t         fr;
    static const uint8_t   sid[2] = { 0, 1 };   /* cache-origin connector streamid */
    uint8_t                cap;
    uint32_t               flags = 0;

    /* Advertise TLS capability so a TLS-requiring origin will answer with
     * kXR_gotoTLS; with tls off we send no flag and behaviour is unchanged. */
    cap = t->conf->cache_origin_tls ? (uint8_t) kXR_ableTLS : 0;
    xrd_pack_protocol_request(&pr, sid, cap);

    if (brix_cache_io_send(oc, &pr, sizeof(pr)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin protocol write failed");
        return -1;
    }
    if (origin_expect_frame(t, oc, sizeof(ServerProtocolBody),
                              "cache origin protocol negotiation failed",
                              &fr) != 0) {
        return -1;
    }

    if (fr.dlen >= sizeof(ServerProtocolBody)) {
        ServerProtocolBody *pb = (ServerProtocolBody *) fr.body;

        flags = (uint32_t) ntohl(pb->flags);
    }
    free(fr.body);

    if (flags & kXR_gotoTLS) {
        if (!t->conf->cache_origin_tls) {
            brix_cache_set_error(t, kXR_TLSRequired, 0,
                "cache origin requires TLS; enable brix_cache_origin_tls");
            return -1;
        }
        /* In-place upgrade of the connected fd BEFORE kXR_login/auth: the origin
         * cert is verified against the configured origin CA (synth->trusted_ca)
         * with hostname binding inside brix_cache_origin_tls_upgrade. */
        if (brix_cache_origin_tls_upgrade(t, oc,
                                            &t->conf->cache_origin_host) != 0)
        {
            return -1;   /* upgrade helper set t's error */
        }
    }
    return 0;
}

/* origin_bs_login — bootstrap step 3: anonymous kXR_login (user 'xrd', capver
 * kXR_ver005). WHAT: sends the login and reads the reply into fr WITHOUT
 * validating the status — kXR_authmore and an auth-advert-bearing kXR_ok are
 * both legitimate here, so the caller owns the status decision (and fr->body).
 * Returns 0 with fr populated, -1 on send/read failure (task error set). */
static int
origin_bs_login(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    origin_frame_t *fr)
{
    ClientLoginRequest    lr;
    static const uint8_t  sid[2] = { 0, 1 };    /* cache-origin connector streamid */

    xrd_pack_login_request(&lr, sid, (int32_t) ngx_pid, "xrd", kXR_ver005);

    if (brix_cache_io_send(oc, &lr, sizeof(lr)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin login write failed");
        return -1;
    }

    fr->body = NULL;
    if (brix_cache_read_response(t, oc, &fr->status, &fr->body,
                                   &fr->dlen, 4096) != 0) {
        return -1;
    }
    return 0;
}

/* origin_bs_parse_advert — pure parse of the login auth advert into ad. WHAT:
 * detects "&P=..." (needs_auth), the ztn/sss protocol names, and copies the gsi
 * v:/c:/ca: list out of the (about-to-be-freed) body, stopping at the next "&P="
 * entry so a co-advertised ztn block isn't mis-parsed. No I/O, no task state. */
static void
origin_bs_parse_advert(const u_char *parms, size_t plen,
    origin_auth_advert_t *ad)
{
    const char *gp;

    ad->needs_auth = (ngx_strlchr((u_char *) parms,
                                  (u_char *) parms + plen, '=') != NULL);
    ad->has_ztn = (ngx_strnstr((u_char *) parms, "ztn", plen) != NULL);
    ad->has_sss = (ngx_strnstr((u_char *) parms, "sss", plen) != NULL);
    ad->has_krb5 = (ngx_strnstr((u_char *) parms, "krb5", plen) != NULL);
    ad->has_gsi = 0;
    ad->gsi_parms[0] = '\0';
    ad->krb5_princ[0] = '\0';

    if (ad->has_krb5) {
        const char *kp = cache_origin_krb5_princ((const char *) parms, plen);
        if (kp != NULL) {
            size_t end = (size_t) ((const char *) parms + plen - kp);
            size_t i;

            for (i = 0; i < end && kp[i] != '&'; i++) { /* find terminator */ }
            if (i >= sizeof(ad->krb5_princ)) { i = sizeof(ad->krb5_princ) - 1; }
            ngx_memcpy(ad->krb5_princ, kp, i);
            ad->krb5_princ[i] = '\0';
        }
    }

    gp = cache_origin_gsi_parms((const char *) parms, plen);
    if (gp != NULL) {
        const char *amp = gp;
        size_t      end = (size_t) ((const char *) parms + plen - gp);
        size_t      i;

        for (i = 0; i < end && amp[i] != '&'; i++) { /* find terminator */ }
        if (i >= sizeof(ad->gsi_parms)) { i = sizeof(ad->gsi_parms) - 1; }
        ngx_memcpy(ad->gsi_parms, gp, i);
        ad->gsi_parms[i] = '\0';
        ad->has_gsi = 1;
    }
}

/* origin_bs_auth_fail_msg — pick the no-usable-protocol error text. WHY: the
 * operator needs to distinguish "you configured a credential the origin cannot
 * accept" from "you configured no credential at all"; the message is chosen from
 * the static service credential fields alone (pure). */
static const char *
origin_bs_auth_fail_msg(const brix_cache_fill_t *t)
{
    return (t->conf->cache_origin_bearer.len > 0
            || t->conf->cache_origin_x509_proxy.len > 0
            || t->conf->cache_origin_sss_keytab.len > 0)
               ? "origin requires auth but offers no protocol this backend "
                 "can present (origin advertised gsi/ztn/sss differently than "
                 "the configured credential provides)"
               : "origin requires authentication but this backend has NO "
                 "credential — set brix_storage_credential to a brix_credential "
                 "providing x509_proxy (or x509_cert+x509_key), a bearer token, "
                 "or sss_keytab. If you did set one, a duplicate brix_credential "
                 "block of the same name may be overriding it (see the "
                 "'defined more than once' warning at config load)";
}

/* origin_bs_auth_krb5 — run the origin krb5 EXCHANGE leg AS the inbound user with
 * a RAW AP-REQ (phase-70 §5.7). WHAT: the front door's krb5 delegation gate
 * (brix_vfs_deleg_krb5) serialised the captured forwardable TGT to a 0600 FILE
 * ccache and carried its PATH (async-safe) onto the fill task; here — on the async
 * fill worker — brix_cache_origin_auth_krb5_raw builds a "krb5\0"+AP-REQ straight
 * from that ccache PATH and presents it in one kXR_auth leg. WHY raw (not the
 * GSSAPI engine brix_cache_origin_auth_krb5): stock XRootD krb5 (libXrdSeckrb5)
 * validates a raw AP-REQ with krb5_rd_req, NOT a gss_init_sec_context token, so
 * the raw leg is the dialect that interoperates with real "&P=krb5" origins (and
 * brix's own acceptor). The origin's advertised "&P=krb5,<princ>" SPN is the
 * ticket target (the native client honours it the same way); it falls back to the
 * request-time derived principal carried on the fill task. Per-user only: any
 * failure fails CLOSED (kXR_AuthFailed), never a service-credential fallback.
 * Returns the auth result / -1 (task error set). */
#if (BRIX_HAVE_KRB5)
static int
origin_bs_auth_krb5(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const origin_auth_advert_t *ad)
{
    const char *spn;

    spn = (ad->krb5_princ[0] != '\0') ? ad->krb5_princ
        : (t->cred_krb5_princ[0] != '\0') ? t->cred_krb5_princ
        : NULL;

    return brix_cache_origin_auth_krb5_raw(t, oc, t->cred_krb5_ccache, spn);
}
#else
static int
origin_bs_auth_krb5(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const origin_auth_advert_t *ad)
{
    (void) oc; (void) ad;
    brix_cache_set_error(t, kXR_AuthFailed, 0,
        "cache origin krb5 auth unavailable (built without krb5 support)");
    return -1;
}
#endif

/* origin_bs_auth_dispatch — credential ladder for an auth-demanding advert.
 * WHY the ordering: per-user overrides WIN over every static service credential
 * (the session must carry the user's identity, never the service's), and x509 vs
 * bearer are mutually exclusive — at most one will be non-empty. A per-user
 * credential must NEVER fall back to a service credential: the operator
 * provisioned it for a reason, and silent fallback would change the presented
 * identity. Returns the auth round-trip result, or -1 with kXR_AuthFailed when
 * no advertised protocol matches a configured credential. */
static int
origin_bs_auth_dispatch(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const origin_auth_advert_t *ad)
{
    if (t->cred_x509_proxy[0] != '\0') {
        if (ad->has_gsi) {
            return brix_cache_origin_auth_gsi(t, oc, ad->gsi_parms,
                                                t->cred_x509_proxy);
        }
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "origin does not advertise gsi for the per-user credential");
        return -1;
    }
    if (t->cred_krb5_ccache[0] != '\0') {
        /* Delegated krb5 TGT (phase-70 §5.7): a forwarded USER credential, so it
         * outranks bearer/sss and — like every per-user branch — never falls back
         * to a service credential. */
        if (ad->has_krb5) {
            return origin_bs_auth_krb5(t, oc, ad);
        }
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "origin does not advertise krb5 for the delegated-TGT credential");
        return -1;
    }
    if (t->cred_bearer[0] != '\0') {
        if (ad->has_ztn) {
            ngx_str_t bt = {
                ngx_strlen(t->cred_bearer),
                (u_char *) t->cred_bearer
            };
            return brix_cache_origin_auth_ztn(t, oc, &bt);
        }
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "origin does not advertise ztn for the per-user bearer credential");
        return -1;
    }
    if (t->cred_sss_keytab[0] != '\0') {
        /* SSS identity injection (phase-70 §5.6 / P90-70.3): the delegation
         * gate resolved "assert the caller via SSS, signed with the export's
         * backend keytab". Per-user like the two branches above — never fall
         * through to a service credential. */
        if (ad->has_sss) {
            return brix_cache_origin_auth_sss(t, oc, t->cred_sss_keytab,
                                                t->cred_principal);
        }
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "origin does not advertise sss for the identity-injection "
            "credential");
        return -1;
    }
    if (ad->has_ztn && t->conf->cache_origin_bearer.len > 0) {
        return brix_cache_origin_auth_ztn(t, oc,
                                            &t->conf->cache_origin_bearer);
    }
    if (ad->has_gsi && t->conf->cache_origin_x509_proxy.len > 0) {
        return brix_cache_origin_auth_gsi(t, oc, ad->gsi_parms,
            (const char *) t->conf->cache_origin_x509_proxy.data);
    }
    if (ad->has_sss && t->conf->cache_origin_sss_keytab.len > 0) {
        return brix_cache_origin_auth_sss(t, oc,
            (const char *) t->conf->cache_origin_sss_keytab.data, NULL);
    }
    brix_cache_set_error(t, kXR_AuthFailed, 0, origin_bs_auth_fail_msg(t));
    return -1;
}

/* origin_bs_authmore_fallback — kXR_authmore with NO auth advert. WHY: per-user
 * credential guards hard-stop here — never present a service credential when the
 * open was dispatched with a per-user x509 proxy or bearer token, as that would
 * silently authenticate as the service rather than the requesting user. Only the
 * static service bearer may answer an advert-less authmore. Returns 0 / -1. */
static int
origin_bs_authmore_fallback(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc)
{
    if (t->cred_x509_proxy[0] != '\0') {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "origin sent kXR_authmore with no auth advert for the per-user credential");
        return -1;
    }
    if (t->cred_bearer[0] != '\0') {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "origin sent kXR_authmore with no auth advert for the per-user credential");
        return -1;
    }
    if (t->cred_sss_keytab[0] != '\0') {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "origin sent kXR_authmore with no auth advert for the "
            "identity-injection credential");
        return -1;
    }
    if (t->cred_krb5_ccache[0] != '\0') {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "origin sent kXR_authmore with no auth advert for the "
            "delegated-TGT credential");
        return -1;
    }
    if (t->conf->cache_origin_bearer.len > 0) {
        return brix_cache_origin_auth_ztn(t, oc, &t->conf->cache_origin_bearer);
    }
    brix_cache_set_error(t, kXR_AuthFailed, 0,
                           "cache origin requires authentication");
    return -1;
}

/* brix_cache_origin_bootstrap — three-phase XRootD connection bootstrap over a
 * CLEARTEXT TCP socket: ClientInitHandShake → kXR_protocol negotiation → anonymous
 * kXR_login (user 'xrd', capver kXR_ver005, streamid[1]=1). A stock XRootD
 * `roots://` origin answers the cleartext kXR_protocol with a kXR_gotoTLS advert;
 * origin_bs_protocol then upgrades THIS fd to TLS in place (verified against the
 * origin CA) BEFORE login/auth, so the ztn/GSI credential exchange rides the
 * encrypted channel. When the origin demands auth
 * (kXR_authmore) and a bearer token is configured, a ztn kXR_auth completes the
 * session. Every cache fill needs a valid session before reading. HOW: one
 * static helper per wire step (origin_bs_handshake/_protocol/_login), then the
 * login status decides between the advert-driven credential dispatch and the
 * advert-less kXR_authmore fallback. Returns 0 on success, -1 on any phase
 * failure. */
int
brix_cache_origin_bootstrap(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc)
{
    origin_frame_t  fr;

    if (origin_bs_handshake(t, oc) != 0) {
        return -1;
    }
    if (origin_bs_protocol(t, oc) != 0) {
        return -1;
    }
    if (origin_bs_login(t, oc, &fr) != 0) {
        return -1;
    }

    /* A kXR_ok login on an AUTHENTICATED origin still carries an auth advert:
     * body = sessid(16) + "&P=<proto>,..." (anonymous origins send only the 16-byte
     * sessid). So a kXR_ok with a "&P=" parameter block means the session is NOT yet
     * authenticated — present the configured bearer via ztn (§14/C-3). kXR_authmore
     * is the mid-protocol variant; handle it the same way. */
    if ((fr.status == kXR_ok || fr.status == kXR_authmore)
        && fr.dlen > BRIX_SESSION_ID_LEN)
    {
        origin_auth_advert_t  ad;

        origin_bs_parse_advert(fr.body + BRIX_SESSION_ID_LEN,
                                 fr.dlen - BRIX_SESSION_ID_LEN, &ad);
        free(fr.body);

        if (ad.needs_auth) {
            return origin_bs_auth_dispatch(t, oc, &ad);
        }
        return 0;
    }
    free(fr.body);

    if (fr.status == kXR_authmore) {
        return origin_bs_authmore_fallback(t, oc);
    }
    if (fr.status != kXR_ok) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin anonymous login failed");
        return -1;
    }

    return 0;
}
