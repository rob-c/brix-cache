#include "cache_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared handshake/protocol/login packers */
#include "core/compat/fattr_codec.h"        /* xrdp_fattr_nvec_parse (kXR_fattr replies) */
#include "protocols/root/protocol/frame_hdr.h"        /* xrd_error_body_decode (kXR_error errnum) */
#include "auth/gsi/gsi_core.h"              /* shared XrdSecgsi handshake kernel (C-3 GSI) */
#include "protocols/root/protocol/gsi.h"              /* kXRS_x509 bucket id (origin-cert verify) */
#include "auth/sss/sss_keytab_kernel.h"     /* §14 SSS: shared keytab line grammar */
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

/* Extract the "gsi" protocol's parameter substring from a login advert that may
 * carry several "&P=<proto>,<parms>" entries (e.g. "&P=ztn,v:10000&P=gsi,v:10600,
 * c:ssl,ca:HASH"). Returns a pointer INTO `parms` just past "gsi," (the v:/c:/ca:
 * list brix_gsi_parse_parms wants), or NULL when gsi is not advertised. */
static const char *
cache_origin_gsi_parms(const char *parms, size_t plen)
{
    static const char needle[] = "gsi,";
    size_t            i;

    if (parms == NULL || plen < sizeof(needle) - 1) {
        return NULL;
    }
    for (i = 0; i + (sizeof(needle) - 1) <= plen; i++) {
        if (ngx_strncmp(parms + i, needle, sizeof(needle) - 1) == 0) {
            return parms + i + (sizeof(needle) - 1);
        }
    }
    return NULL;
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
    char  gsi_parms[256];   /* gsi v:/c:/ca: list, NUL-terminated */
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
    ad->has_gsi = 0;
    ad->gsi_parms[0] = '\0';

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
            (const char *) t->conf->cache_origin_sss_keytab.data);
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

/* brix_cache_origin_open — kXR_open (read + kXR_retstat) of the source file:
 * parse ServerOpenBody for the fhandle and the appended stat string, so file_size
 * is known before a full download (the admission filter can reject oversized files
 * without fetching them). Returns 0 with fhandle set, -1 on error or redirect. */
int
brix_cache_origin_open(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, u_char fhandle[XRD_FHANDLE_LEN])
{
    size_t             pathlen, total;
    u_char            *buf;
    ClientOpenRequest *req;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body;

    pathlen = strlen(t->clean_path);
    total = sizeof(ClientOpenRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        brix_cache_set_error(t, kXR_NoMemory, 0,
                               "cache origin open allocation failed");
        return -1;
    }

    ngx_memzero(buf, total);
    req = (ClientOpenRequest *) buf;
    req->streamid[1] = 2;
    req->requestid = htons(kXR_open);
    /* kXR_retstat requests an ASCII stat string appended after the fhandle so we
     * can learn the file size before committing to a full download */
    {
        xrdw_open_req_t b = { .options = kXR_open_read | kXR_retstat };
        xrdw_open_req_pack(&b, ((ClientRequestHdr *) buf)->body);
    }
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), t->clean_path, pathlen);

    if (brix_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin open write failed");
        return -1;
    }
    free(buf);

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen,
                                   BRIX_MAX_PATH + 256) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "cache origin open failed");
        free(body);
        return -1;
    }
    if (status == kXR_redirect) {
        free(body);
        brix_cache_set_error(t, kXR_Unsupported, 0,
                               "cache origin redirected open; direct data "
                               "server origin is required");
        return -1;
    }
    if (status != kXR_ok || dlen < sizeof(ServerOpenBody)) {
        free(body);
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin open returned invalid response");
        return -1;
    }

    ngx_memcpy(fhandle, ((ServerOpenBody *) body)->fhandle, XRD_FHANDLE_LEN);

    /*
     * If kXR_retstat was honored the stat string follows ServerOpenBody.
     * Format: "<id> <size> <flags> <modtime>" — we only need the size (field 2).
     * The body is always NUL-terminated by brix_cache_read_response, so
     * strtoull is safe.
     */
    if (dlen > sizeof(ServerOpenBody)) {
        const char     *stat_str = (const char *) body + sizeof(ServerOpenBody);
        const char     *p;

        p = strchr(stat_str, ' ');
        if (p != NULL) {
            char              *endp;
            unsigned long long  sv;

            errno = 0;
            sv = strtoull(p + 1, &endp, 10);
            if (errno == 0 && endp != p + 1) {
                t->file_size = (off_t) sv;
            }
        }
    }

    free(body);
    return 0;
}

/* origin_cksum_send_query — build and send the path-based kXR_query/kXR_Qcksum
 * request for t->clean_path. WHY separate: the request assembly (malloc + pack +
 * send + free) is the only allocation in the checksum exchange; isolating it
 * keeps the best-effort orchestrator a flat status sequence. Returns 0 on send,
 * -1 on OOM or write failure — NO task error is set (best-effort). */
static int
origin_cksum_send_query(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    size_t              pathlen, total;
    u_char             *buf;
    ClientQueryRequest *req;

    pathlen = strlen(t->clean_path);
    total = sizeof(ClientQueryRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        return -1;      /* best-effort: skip verification on OOM */
    }

    ngx_memzero(buf, total);
    req = (ClientQueryRequest *) buf;
    req->streamid[1] = 6;                       /* unused stream slot */
    req->requestid = htons(kXR_query);
    {
        xrdw_query_req_t b = { .infotype = kXR_Qcksum };  /* fhandle 0 ⇒ path-based */
        xrdw_query_req_pack(&b, ((ClientRequestHdr *) buf)->body);
    }
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), t->clean_path, pathlen);

    if (brix_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        return -1;
    }
    free(buf);
    return 0;
}

/* origin_cksum_split — pure parse of the NUL-terminated "<algo> <hexvalue>"
 * reply body into the caller buffers, trimming trailing whitespace from the hex
 * field. Leaves both buffers untouched (still empty) when the body doesn't fit
 * the expected shape or exceeds the buffer sizes — the caller then treats it as
 * "no origin digest". No I/O, no task state. */
static void
origin_cksum_split(const u_char *body, char *alg_out, size_t alg_sz,
    char *hex_out, size_t hex_sz)
{
    const char *sp;

    sp = strchr((const char *) body, ' ');
    if (sp != NULL) {
        size_t       an = (size_t) (sp - (const char *) body);
        const char  *hv = sp + 1;
        const char  *end = hv + strlen(hv);
        size_t       hn;

        while (end > hv && (end[-1] == '\n' || end[-1] == '\r'
                            || end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        hn = (size_t) (end - hv);

        if (an > 0 && an < alg_sz && hn > 0 && hn < hex_sz) {
            ngx_memcpy(alg_out, body, an);
            alg_out[an] = '\0';
            ngx_memcpy(hex_out, hv, hn);
            hex_out[hn] = '\0';
        }
    }
}

/* brix_cache_origin_query_checksum — ask the origin for its stored digest of
 * t->clean_path (path-based kXR_query/kXR_Qcksum), returning "<algo> <hex>" split
 * into the caller buffers (out->alg / out->hex). Checksum-on-fill (verify.c)
 * validates downloaded bytes against this before publishing. BEST-EFFORT: an
 * origin with no checksum or a wire hiccup must NOT fail an otherwise-complete
 * fill (data is already on disk) — on ANY failure it restores t's error state
 * and returns 0 with out->alg emptied, so the caller treats it as "no origin
 * digest" and the verify policy decides.
 *
 * WAITRESP: a real origin usually does NOT have the digest cached at fill time —
 * it computes it on demand and PARKS the query with kXR_waitresp, then delivers
 * the answer as an unsolicited kXR_attn(kXR_asynresp) frame (exactly what a stock
 * XRootD client absorbs transparently). We follow that handshake for a bounded
 * number of hops so the common lazy-checksum origin still yields a digest for
 * verify=require, while a hostile origin that streams frames forever cannot wedge
 * the fill thread — each recv is bounded by the origin socket timeout and the hop
 * count caps the exchange. Unrelated async pushes (kXR_asyncms) are skipped. */
int
brix_cache_origin_query_checksum(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const brix_cache_cksum_out_t *out)
{
    uint16_t  status;
    uint32_t  dlen;
    u_char   *body;
    int       saved_result, saved_xrd;
    int       hops;

    if (out->alg_sz > 0) {
        out->alg[0] = '\0';
    }
    if (out->hex_sz > 0) {
        out->hex[0] = '\0';
    }

    /* The download already succeeded; never let a checksum-query failure leak an
     * error onto the task. Snapshot and restore the error triple. */
    saved_result = t->result;
    saved_xrd    = t->xrd_error;

    if (origin_cksum_send_query(t, oc) != 0) {
        return 0;
    }

    for (hops = 0; hops < 8; hops++) {
        body = NULL;
        if (brix_cache_read_response(t, oc, &status, &body, &dlen, 512) != 0) {
            t->result    = saved_result;
            t->xrd_error = saved_xrd;
            return 0;
        }

        if (status == kXR_waitresp) {
            free(body);      /* body = advised seconds; the answer frame follows */
            continue;
        }

        if (status == kXR_attn) {
            /* kXR_attn asynresp body layout (opcodes.h):
             *   actnum[4] reserved[4] ServerResponseHdr[8] response[inner_dlen] */
            uint32_t  actnum;
            uint16_t  inner_status;
            uint32_t  inner_dlen;

            if (body == NULL || dlen < 16) {
                free(body);
                return 0;
            }
            actnum = xrd_get_u32_be(body);
            if (actnum != (uint32_t) kXR_asynresp) {
                free(body);                 /* asyncms / other push — keep going */
                continue;
            }
            xrd_resp_hdr_unpack(body + 8, NULL, &inner_status, &inner_dlen);
            if (inner_status != kXR_ok || inner_dlen == 0
                || (size_t) 16 + inner_dlen > (size_t) dlen)
            {
                free(body);                 /* deferred result was not a digest */
                return 0;
            }
            /* NUL-terminate the inner payload before the split (read_response
             * over-allocated dlen+1, and 16+inner_dlen <= dlen, so this index is
             * in bounds). */
            body[16 + inner_dlen] = '\0';
            origin_cksum_split(body + 16, out->alg, out->alg_sz,
                               out->hex, out->hex_sz);
            free(body);
            return 0;
        }

        if (status == kXR_ok) {
            if (body == NULL || dlen == 0) {
                free(body);
                return 0;
            }
            /* body is NUL-terminated "<algo> <hexvalue>". */
            origin_cksum_split(body, out->alg, out->alg_sz,
                               out->hex, out->hex_sz);
            free(body);
            return 0;
        }

        /* kXR_error or any other status: origin has no usable checksum. */
        free(body);
        return 0;
    }

    return 0;   /* too many hops — treat as no origin digest (verify decides) */
}


/* brix_cache_origin_read_chunk — kXR_read at (rng->read_off, rng->want),
 * writing each reply payload to the sink via brix_cache_sink_pwrite and looping
 * over kXR_oksofar until the final kXR_ok. dlen is bounded (<= want, accumulated
 * rng->got within request bounds) to prevent overflow. Sets rng->got;
 * returns 0 / -1. */
int
brix_cache_origin_read_chunk(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    brix_cache_sink_t *sink, brix_cache_read_range_t *rng)
{
    ClientReadRequest req;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body;

    rng->got = 0;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 3;
    req.requestid = htons(kXR_read);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) htobe64(rng->read_off);
    req.rlen = htonl((kXR_int32) rng->want);
    req.dlen = 0;

    if (brix_cache_io_send(oc, &req, sizeof(req)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin read write failed");
        return -1;
    }

    for (;;) {
        body = NULL;
        if (brix_cache_read_response(t, oc, &status, &body, &dlen,
                                       BRIX_CACHE_FETCH_CHUNK) != 0) {
            return -1;
        }

        if (status == kXR_error) {
            brix_cache_set_origin_error(t, body, dlen,
                                          "cache origin read failed");
            free(body);
            return -1;
        }

        if (status != kXR_ok && status != kXR_oksofar) {
            free(body);
            brix_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned invalid status");
            return -1;
        }

        if ((size_t) dlen > rng->want || rng->got > rng->want - (size_t) dlen) {
            free(body);
            brix_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned too much data");
            return -1;
        }

        if (dlen > 0) {
            /* Write at dst_off + bytes already written this call (rng->got).
             * dst_off is the caller's WRITE base, decoupled from the origin READ
             * offset: the whole-file fetch passes dst_off==read_off (absolute), a
             * slice fill passes a 0-relative base. Using got alone restarts at 0
             * each 1 MiB chunk, so multi-chunk whole-file fetches overwrote at
             * offset 0 (corrupting any file > BRIX_CACHE_FETCH_CHUNK → adler32
             * mismatch). */
            if (brix_cache_sink_pwrite(sink, body, dlen,
                                         (off_t) (rng->dst_off + rng->got)) != 0)
            {
                free(body);
                brix_cache_set_syserror(t, kXR_IOError,
                                          "cache file write failed");
                return -1;
            }
            rng->got += (size_t) dlen;
        }

        free(body);

        if (status == kXR_ok) {
            return 0;
        }
    }
}

